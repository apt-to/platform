#!/usr/bin/env python3
"""Build and test a reviewed focal packaging checkout without publishing binaries."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.request
import uuid

ROOT = Path(__file__).resolve().parents[1]


def run(command, timeout=1200, **kwargs):
    return subprocess.run(command, check=True, timeout=timeout, **kwargs)


def sha256(path):
    result = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            result.update(block)
    return result.hexdigest()


def persist_release_candidates(selected, binary_manifest, output, package, version, source_commit):
    entries = {item["name"]: item for item in binary_manifest["packages"]}
    binary_output = output / "binary"
    binary_output.mkdir()
    release_candidates = []
    for source_path in sorted(selected):
        item = entries.get(source_path.name)
        if not item:
            raise RuntimeError("Selected package is missing from the verified binary manifest")
        destination = binary_output / source_path.name
        shutil.copyfile(source_path, destination)
        digest = sha256(destination)
        if digest != item["sha256"]:
            raise RuntimeError("Persisted release candidate differs from the verified binary manifest")
        control = dict(
            line.split(": ", 1)
            for line in item["control"].splitlines()
            if ": " in line
        )
        release_candidates.append({
            "name": destination.name,
            "package": control["Package"],
            "version": control["Version"],
            "architecture": control["Architecture"],
            "bytes": destination.stat().st_size,
            "sha256": digest,
        })
    source_dir = output / "source"
    source_paths = sorted(source_dir.glob("*"))
    if not source_paths or not any(path.suffix == ".dsc" for path in source_paths):
        raise RuntimeError("Complete Debian source package is required for a release candidate")
    source_candidates = []
    source_prefix = f"{package}_{version}"
    for path in source_paths:
        if path.is_symlink() or not path.is_file() or path.parent != source_dir:
            raise RuntimeError("Source package contains a non-regular or nested candidate")
        if not (path.name.endswith(".dsc") or ".orig.tar." in path.name or ".debian.tar." in path.name):
            raise RuntimeError("Unexpected file in the Debian source package candidate")
        is_original = ".orig.tar." in path.name
        is_debian = ".debian.tar." in path.name
        expected_prefix = f"{package}_{version}" if not is_original else f"{package}_"
        if not path.name.startswith(expected_prefix):
            raise RuntimeError("Source package filename does not match the candidate source and version")
        if is_original and not re.fullmatch(re.escape(package) + r"_[A-Za-z0-9.+~:-]+\.orig\.tar\.[A-Za-z0-9]+", path.name):
            raise RuntimeError("Original source tarball filename is invalid")
        if is_debian and not path.name.startswith(source_prefix + ".debian.tar."):
            raise RuntimeError("Debian source tarball filename does not match the candidate version")
        source_candidates.append({
            "name": path.name,
            "bytes": path.stat().st_size,
            "sha256": sha256(path),
        })
    (output / "release-candidates.json").write_text(json.dumps({
        "source": package,
        "sourceVersion": version,
        "sourceCommit": source_commit,
        "distribution": "focal",
        "architecture": "amd64",
        "publication": "not published; runner-local candidates for a protected staging job",
        "packages": release_candidates,
        "sourceFiles": source_candidates,
    }, indent=2) + "\n")


def run_aptto_scan(image, image_id, phase, output, temp, package, expected):
    status_result = run(["docker", "run", "--rm", "--network", "none", image, "cat", "/var/lib/dpkg/status"], capture_output=True, text=True, timeout=60)
    if len(status_result.stdout.encode()) > 16 * 1024 * 1024:
        raise RuntimeError("Installed dpkg status inventory exceeds the scanner input bound")
    status_path = output / (package + "-aptto-status-" + phase + ".txt")
    status_path.write_text(status_result.stdout)
    scan = subprocess.run([
        sys.executable, str(ROOT / "scripts/aptto-scan.py"), "--feed", str(ROOT / "advisories/aptto-osv.json"),
        "--status-file", str(status_path), "--release", "focal", "--architecture", "amd64", "--image-id", image_id,
    ], capture_output=True, text=True, timeout=60, check=False)
    if scan.returncode not in (0, 1):
        raise RuntimeError("AptTo advisory scan failed: " + scan.stderr[-2000:])
    report = json.loads(scan.stdout)
    report_path = output / (package + "-aptto-scan-" + phase + ".json")
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    target_cves = set(expected["targetCves"])
    versions = report.get("scannedPackageVersions", {})
    if report.get("imageId") != image_id or not set(expected["binaryPackages"]).issubset(versions):
        raise RuntimeError("AptTo scan did not identify every expected installed binary package and image")
    expected_version = expected["baselineVersion"] if phase == "before" else expected["baselineVersion"] + "+aptto1"
    if any(versions[name] != expected_version for name in expected["binaryPackages"]):
        raise RuntimeError("AptTo scan identified an unexpected installed package version")
    target_findings = set(report.get("findingsById", [])) & target_cves
    finding_pairs = {(finding.get("id"), finding.get("package")) for finding in report.get("findings", [])}
    expected_pairs = {(cve, binary) for cve in target_cves for binary in expected["binaryPackages"]}
    if phase == "before" and (not target_cves.issubset(target_findings) or not expected_pairs.issubset(finding_pairs)):
        raise RuntimeError("AptTo advisory scan did not detect every target CVE for every installed binary on the vulnerable baseline")
    if phase == "after" and target_findings:
        raise RuntimeError("AptTo advisory scan reported target findings on the tested patched image")
    return {"report": report_path, "status": status_path}


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
    with tempfile.TemporaryDirectory(prefix="aptto-build-inputs-") as directory:
        temp = Path(directory)
        name = "aptto-build-" + package + "-" + uuid.uuid4().hex[:12]
        container = name + "-job"
        scan_base = name + "-baseline"
        scan_patched = name + "-patched"
        built = False
        started = False
        scan_images = []
        originals = temp / "originals"
        originals.mkdir()
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
                "docker", "run", "--name", container, "--platform", "linux/amd64",
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
            (output / "build-container-id.txt").write_text(run(["docker", "container", "inspect", container, "--format", "{{.Id}}"], capture_output=True, text=True).stdout.strip() + "\n")
            debs = temp / "patched-debs"
            debs.mkdir()
            binary_manifest = json.loads((output / "binary-manifest.json").read_text())
            selected = []
            for item in binary_manifest["packages"]:
                binary_name = item["control"].splitlines()[0].split(": ", 1)[1]
                if binary_name not in expected["binaryPackages"]:
                    continue
                target = debs / item["name"]
                run(["docker", "cp", container + ":/build/" + item["name"], str(target)])
                if sha256(target) != item["sha256"]:
                    raise RuntimeError("Extracted package differs from recorded binary manifest")
                selected.append(target)
            if {p.name.split("_", 1)[0] for p in selected} != set(expected["binaryPackages"]):
                raise RuntimeError("Could not extract every patched runtime package")
            persist_release_candidates(selected, binary_manifest, output, package, policy["version"], commit)
            patched_context = temp / "patched-context"
            patched_context.mkdir()
            (patched_context / "aptto").mkdir()
            for deb in selected:
                shutil.copyfile(deb, patched_context / "aptto" / deb.name)
            shutil.copyfile(ROOT / "build/patched-scan.Containerfile", patched_context / "Dockerfile")
            scan_args = [
                "docker", "build", "--no-cache", "--platform", "linux/amd64", "--tag", scan_patched,
                "--file", str(patched_context / "Dockerfile"),
                "--build-arg", "BASE_IMAGE=" + config["baseImage"],
                "--build-arg", "TRUST_IMAGE=" + config["scannerImage"],
                "--build-arg", "SOURCE_PACKAGE=" + package,
                "--build-arg", "BASELINE_VERSION=" + policy["baseVersion"],
                "--build-arg", "EXPECTED_VERSION=" + policy["version"],
                "--build-arg", "ARCHIVE_SNAPSHOT=" + config["archiveSnapshot"],
                "--build-arg", "BINARY_PACKAGES=" + " ".join(expected["binaryPackages"]),
                str(patched_context),
            ]
            run(scan_args)
            scan_images.append(scan_patched)
            run([
                "docker", "build", "--no-cache", "--platform", "linux/amd64", "--tag", scan_base,
                "--file", str(ROOT / "build/baseline.Containerfile"),
                "--build-arg", "BASE_IMAGE=" + config["baseImage"],
                "--build-arg", "TRUST_IMAGE=" + config["scannerImage"],
                "--build-arg", "SOURCE_PACKAGE=" + package,
                "--build-arg", "EXPECTED_VERSION=" + policy["baseVersion"],
                "--build-arg", "ARCHIVE_SNAPSHOT=" + config["archiveSnapshot"],
                str(ROOT),
            ])
            scan_images.append(scan_base)
            scan_identity = {"baselineImageId": run(["docker", "image", "inspect", scan_base, "--format", "{{.Id}}"], capture_output=True, text=True).stdout.strip(), "patchedImageId": run(["docker", "image", "inspect", scan_patched, "--format", "{{.Id}}"], capture_output=True, text=True).stdout.strip()}
            (output / "scan-images.json").write_text(json.dumps(scan_identity, indent=2) + "\n")
            aptto_scan_paths = {}
            for phase, image, image_id in (("before", scan_base, scan_identity["baselineImageId"]), ("after", scan_patched, scan_identity["patchedImageId"])):
                aptto_scan_paths[phase] = run_aptto_scan(image, image_id, phase, output, temp, package, expected)
            for phase, image in (("before", scan_base), ("after", scan_patched)):
                image_tar = temp / (phase + ".tar")
                run(["docker", "save", "--output", str(image_tar), image])
                command = [
                    "docker", "run", "--rm", "--platform", "linux/amd64",
                    "--mount", "type=bind,source=" + str(temp) + ",target=/work",
                    "--user", str(os.getuid()) + ":" + str(os.getgid()), config["scannerImage"],
                    "image", "--input", "/work/" + image_tar.name,
                    "--cache-dir", "/work/trivy-cache", "--db-repository", config["scannerDatabaseReference"],
                    "--scanners", "vuln", "--list-all-pkgs", "--format", "json", "--output", "/work/" + phase + "-trivy.json",
                ]
                if phase == "after":
                    command.append("--skip-db-update")
                run(command)
                shutil.copyfile(temp / (phase + "-trivy.json"), output / (package + "-trivy-" + phase + ".json"))
                image_tar.unlink()
            db_files = list((temp / "trivy-cache/db").glob("trivy.db"))
            if len(db_files) != 1 or sha256(db_files[0]) != config["scannerDatabaseSha256"]:
                raise RuntimeError("Paired scans did not use the configured pinned Trivy database digest")
            database_hash = sha256(db_files[0])
            (output / "trivy-database.json").write_text(json.dumps({"reference": config["scannerDatabaseReference"], "sha256": database_hash}, indent=2) + "\n")
            for phase in ("before", "after"):
                report_path = output / (package + "-trivy-" + phase + ".json")
                image_id = scan_identity["baselineImageId" if phase == "before" else "patchedImageId"]
                (output / (package + "-trivy-" + phase + "-metadata.json")).write_text(json.dumps({"phase": phase, "scannerImage": config["scannerImage"], "imageId": image_id, "databaseReference": config["scannerDatabaseReference"], "databaseSha256": database_hash, "reportSha256": sha256(report_path)}, indent=2) + "\n")
            osv_evidence = {}
            for phase, version in (("before", policy["baseVersion"]), ("after", policy["version"])):
                request_body = {"package": {"name": package, "ecosystem": config["advisoryEcosystem"]}, "version": version}
                request = urllib.request.Request("https://api.osv.dev/v1/query", data=json.dumps(request_body).encode(), headers={"Content-Type": "application/json", "User-Agent": "apt.to-advisory-audit/0.1"})
                with urllib.request.urlopen(request, timeout=45) as response:
                    response_body = response.read(16 * 1024 * 1024 + 1)
                if len(response_body) > 16 * 1024 * 1024:
                    raise RuntimeError("Canonical OSV response exceeds evidence size bound")
                path = output / (package + "-osv-" + phase + ".json")
                path.write_text(json.dumps({"request": request_body, "endpoint": "https://api.osv.dev/v1/query", "response": json.loads(response_body)}, indent=2) + "\n")
                osv_evidence[phase] = str(path)
            audit_input = {
                "source": package, "baselineVersion": policy["baseVersion"], "patchedVersion": policy["version"],
                "targetCves": policy["targetCves"], "beforeTrivy": str(output / (package + "-trivy-before.json")),
                "afterTrivy": str(output / (package + "-trivy-after.json")), "beforeOsv": osv_evidence["before"], "afterOsv": osv_evidence["after"],
                "baselineRegression": str(output / "baseline-regression.json"), "patchedRegression": str(output / "patched-regression.json"),
                "buildProvenance": str(output / "build-provenance.json"), "binaryManifest": str(output / "binary-manifest.json"),
                "packagePolicy": str(source / "debian/aptto/release-policy.json"), "databaseSha256": database_hash, "sourceCommit": commit,
                "beforeScanMetadata": str(output / (package + "-trivy-before-metadata.json")),
                "afterScanMetadata": str(output / (package + "-trivy-after-metadata.json")), "scanImages": str(output / "scan-images.json"),
                "aptToFeed": str(ROOT / "advisories/aptto-osv.json"),
                "beforeAptToScan": str(aptto_scan_paths["before"]["report"]), "afterAptToScan": str(aptto_scan_paths["after"]["report"]),
                "beforeAptToStatus": str(aptto_scan_paths["before"]["status"]), "afterAptToStatus": str(aptto_scan_paths["after"]["status"]),
            }
            audit_input_path = temp / "audit-input.json"
            audit_input_path.write_text(json.dumps(audit_input))
            run(["python3", str(ROOT / "scripts/advisory-audit.py"), "--input", str(audit_input_path), "--output", str(output / "advisory-comparison.json")])
            run(["python3", str(ROOT / "scripts/test-apt-repository.py"), "--source", str(source), "--output", str(output),
                 "--work", str(temp), "--builder-image", name, "--base-image", config["baseImage"],
                 "--trust-image", config["scannerImage"], "--archive-snapshot", config["archiveSnapshot"]])
            print(package + ": build, installed regressions, AptTo advisory scan, raw Trivy/OSV audit, consumer checks, signed APT binary/source install and version ordering passed")
        finally:
            try:
                if started:
                    remaining = run(["docker", "container", "ls", "--all", "--filter", "name=^/" + container + "$", "--format", "{{.ID}}"], timeout=60, capture_output=True, text=True)
                    if remaining.stdout.strip():
                        run(["docker", "container", "rm", "--force", container], timeout=60)
            finally:
                for image in scan_images:
                    run(["docker", "image", "rm", image], timeout=60)
                if built:
                    run(["docker", "image", "rm", name], timeout=60)

if __name__ == "__main__":
    main()
