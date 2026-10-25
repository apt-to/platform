#!/usr/bin/env python3
"""Build and test a reviewed focal packaging checkout without publishing binaries."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import urllib.request
import uuid

ROOT = Path(__file__).resolve().parents[1]


def run(command, timeout=1200, **kwargs):
    return subprocess.run(command, check=True, timeout=timeout, **kwargs)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    source = args.source.resolve()
    output = args.output.resolve()
    if output.exists() and any(output.iterdir()):
        parser.error("Use an empty output directory to avoid mixed evidence")
    output.mkdir(parents=True, exist_ok=True)
    policy = json.loads((source / "debian/aptto/release-policy.json").read_text())
    provenance = json.loads((source / "debian/aptto/source-provenance.json").read_text())
    config = json.loads((ROOT / "packages.json").read_text())
    package = policy["source"]
    expected = config["packages"][package]
    if policy["baseVersion"] != expected["baselineVersion"] or policy["sponsorDelayHours"] != expected["sponsorDelayHours"]:
        raise RuntimeError("Packaging policy disagrees with project configuration")
    if expected["targetCve"] not in policy["targetCves"] or policy["version"] != policy["baseVersion"] + "+aptto1":
        raise RuntimeError("Unexpected pilot backport identity")
    if run(["git", "-C", str(source), "status", "--porcelain"], capture_output=True, text=True).stdout.strip():
        raise RuntimeError("Commit the reviewed packaging changes before recording build evidence")
    commit = run(["git", "-C", str(source), "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
    name = "aptto-build-" + package + "-" + uuid.uuid4().hex[:12]
    container = name + "-job"
    built = False
    started = False
    with tempfile.TemporaryDirectory(prefix="aptto-build-inputs-") as directory:
        originals = Path(directory)
        for item in provenance["source_integrity"]["archives"]:
            if ".orig.tar." not in item["name"]:
                continue
            if item["bytes"] > 128 * 1024 * 1024:
                raise RuntimeError("Original archive exceeds pilot resource bound")
            request = urllib.request.Request(item["url"], headers={"User-Agent": "apt.to-build/0.1"})
            with urllib.request.urlopen(request, timeout=60) as response:
                content = response.read(item["bytes"] + 1)
            if len(content) != item["bytes"] or hashlib.sha256(content).hexdigest() != item["sha256"]:
                raise RuntimeError("Original archive size/hash mismatch")
            (originals / item["name"]).write_bytes(content)
        try:
            run([
                "docker", "build", "--no-cache", "--platform", "linux/amd64", "--tag", name,
                "--file", str(ROOT / "build/packaging.Containerfile"),
                "--build-arg", "BASE_IMAGE=" + config["baseImage"],
                "--build-arg", "TRUST_IMAGE=" + config["scannerImage"],
                "--build-arg", "ARCHIVE_SNAPSHOT=" + config["archiveSnapshot"],
                "--build-arg", "SOURCE_PACKAGE=" + package,
                "--build-arg", "EXPECTED_VERSION=" + policy["baseVersion"], str(ROOT),
            ])
            built = True
            builder = run(["docker", "image", "inspect", name, "--format", "{{.Id}}"], capture_output=True, text=True).stdout.strip()
            started = True
            run([
                "docker", "run", "--rm", "--name", container, "--platform", "linux/amd64",
                "--network", "none", "--cpus", "2", "--memory", "4g", "--pids-limit", "512",
                "--security-opt", "no-new-privileges:true",
                "--mount", "type=bind,source=" + str(source) + ",target=/input,readonly",
                "--mount", "type=bind,source=" + str(originals) + ",target=/originals,readonly",
                "--mount", "type=bind,source=" + str(ROOT / "verification") + ",target=/verification,readonly",
                "--mount", "type=bind,source=" + str(ROOT / "build/package.sh") + ",target=/recipe.sh,readonly",
                "--mount", "type=bind,source=" + str(output) + ",target=/output",
                name, "bash", "/recipe.sh", str(os.getuid()), str(os.getgid()),
            ], timeout=2400)
            result = {"source": package, "version": policy["version"], "sourceCommit": commit, "baseImage": config["baseImage"], "trustBundleImage": config["scannerImage"], "archiveSnapshot": config["archiveSnapshot"], "builderImageId": builder, "toolchainInventory": "build-toolchain.tsv", "publication": "none; binary outputs remained inside the disposable container"}
            (output / "build-provenance.json").write_text(json.dumps(result, indent=2) + "\n")
            print(package + ": build, installed regressions, consumer checks and version ordering passed")
        finally:
            try:
                if started:
                    remaining = run(["docker", "container", "ls", "--all", "--filter", "name=^/" + container + "$", "--format", "{{.ID}}"], timeout=60, capture_output=True, text=True)
                    if remaining.stdout.strip():
                        run(["docker", "container", "rm", "--force", container], timeout=60)
            finally:
                if built:
                    run(["docker", "image", "rm", name], timeout=60)


if __name__ == "__main__":
    main()
