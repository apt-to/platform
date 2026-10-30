#!/usr/bin/env python3
"""Build an isolated signed APT archive and test it with a fresh target client."""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import hashlib
import uuid
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from build_environment import runner_ca_bundle
from platform_policy import package_target_policy, target_profile


def run(command, **kwargs):
    return subprocess.run(command, check=True, **kwargs)


def fingerprint_from_colons(output):
    fingerprints = []
    for line in output.splitlines():
        fields = line.split(":")
        if fields[0] == "fpr" and len(fields) > 9:
            fingerprints.append(fields[9])
    if len(fingerprints) != 1 or not re.fullmatch(r"[0-9A-Fa-f]{40}", fingerprints[0]):
        raise RuntimeError("temporary APT signing key did not yield exactly one valid fingerprint")
    return fingerprints[0].upper()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--recipe", required=True, type=Path, help="committed package recipe checkout")
    parser.add_argument("--policy", required=True, type=Path, help="validated package policy from the recipe")
    parser.add_argument("--output", required=True, type=Path, help="build output directory")
    parser.add_argument("--work", required=True, type=Path, help="private build temp directory")
    parser.add_argument("--builder-image", required=True)
    parser.add_argument("--base-image", required=True)
    parser.add_argument("--apt-sources-b64", required=True)
    args = parser.parse_args()

    policy = json.loads(args.policy.read_text())
    recipe = json.loads((args.recipe / "package-manifest.json").read_text())
    platform = json.loads((ROOT / "packages.json").read_text())
    profile = target_profile(platform, policy["targetId"])
    candidate = package_target_policy(platform, policy["source"], policy["targetId"])
    binary_packages = policy["binaryPackages"]
    if (policy["version"] != candidate["packageVersion"]
            or policy["baseVersion"] != candidate["baselineVersion"]
            or binary_packages != candidate["binaryPackages"]
            or policy["releaseSerial"] != candidate["releaseSerial"]
            or not any(target.get("id") == policy["targetId"] for target in recipe["targets"])
            or policy["architecture"] != profile["architecture"]
            or policy["release"] != profile["codename"]):
        raise RuntimeError("source package policy does not match the configured target candidate")
    manifest = json.loads((args.output / "binary-manifest.json").read_text())
    if (manifest.get("source") != policy["source"] or manifest.get("targetId") != policy["targetId"]
            or manifest.get("sourceVersion") != policy["baseVersion"]
            or manifest.get("version") != policy["version"]
            or manifest.get("architecture") != profile["architecture"]):
        raise RuntimeError("binary manifest does not identify the selected package target")
    repo = args.work / "signed-repository"
    pool = repo / "pool/main" / policy["source"][0] / policy["source"]
    pool.mkdir(parents=True)
    selected = [p for p in manifest["packages"] if p["control"].splitlines()[0].split(": ", 1)[1] in binary_packages]
    if {p["control"].splitlines()[0].split(": ", 1)[1] for p in selected} != set(binary_packages):
        raise RuntimeError("binary manifest does not contain all configured runtime packages")
    for item in selected:
        source = args.work / "patched-debs" / item["name"]
        if not source.is_file():
            raise RuntimeError("built binary missing from private build workspace: " + item["name"])
        shutil.copyfile(source, pool / item["name"])
    source_files = sorted((args.output / "source").glob("*"))
    if not any(p.suffix == ".dsc" for p in source_files):
        raise RuntimeError("complete source package is missing its .dsc")
    for source in source_files:
        shutil.copyfile(source, pool / source.name)

    codename = profile["codename"]
    architecture = profile["architecture"]
    container_platform = profile["build"]["containerPlatform"]
    dist = repo / "dists" / codename
    key_home = args.work / ("gpg-" + uuid.uuid4().hex[:12])
    key_home.mkdir(mode=0o700)
    (args.work / "repo-index.sh").write_text(f"""#!/bin/bash
set -euo pipefail
export GNUPGHOME=/gnupg
gpg --batch --pinentry-mode loopback --passphrase '' --quick-generate-key \\
  'GetPatched Temporary Repository Test <repo-test@getpatched.dev>' rsa2048 sign 0
fingerprint="$(gpg --batch --with-colons --list-keys | awk -F: '$1 == \"fpr\" {{ print $10; exit }}')"
python3 /generate-apt-index.py --repo /repo --suite {codename} --architecture {architecture} \\
  --component main --description 'GetPatched {codename} {architecture} test archive' \\
  --signing-key-home /gnupg --signing-fingerprint "$fingerprint"
""")
    try:
        run(["docker", "run", "--rm", "--platform", container_platform, "--user", f"{os.getuid()}:{os.getgid()}",
             "--mount", f"type=bind,source={repo},target=/repo",
             "--mount", f"type=bind,source={key_home},target=/gnupg",
             "--mount", f"type=bind,source={args.work / 'repo-index.sh'},target=/repo-index.sh,readonly",
             "--mount", f"type=bind,source={Path(__file__).resolve().parent / 'generate-apt-index.py'},target=/generate-apt-index.py,readonly",
             "--entrypoint", "bash", args.builder_image, "/repo-index.sh"])
        release = dist / "Release"
        text = release.read_text()
        if f"Architectures: {architecture}\n" not in text or "SHA256:\n" not in text:
            raise RuntimeError("APT Release metadata is missing required architecture or SHA-256 fields")
        if not (dist / "InRelease").is_file() or not (dist / "Release.gpg").is_file():
            raise RuntimeError("APT Release metadata was not signed")
        public_key = args.work / "getpatched-test-archive.gpg"
        shutil.copyfile(repo / "getpatched-archive-keyring.gpg", public_key)
        fingerprint = fingerprint_from_colons(run(
            ["gpg", "--batch", "--with-colons", "--show-keys", str(public_key)],
            capture_output=True, text=True,
        ).stdout)
    finally:
        shutil.rmtree(key_home, ignore_errors=True)

    client_context = args.work / "apt-client-context"
    shutil.copytree(repo, client_context / "repo")
    shutil.copyfile(public_key, client_context / "getpatched-test-archive.gpg")
    client_script = client_context / "apt-client.sh"
    client_script.write_text("""#!/bin/bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
mkdir -p /tmp/getpatched-source-test
cd /tmp/getpatched-source-test
printf '%s' "$APT_SOURCES_B64" | base64 -d > /etc/apt/sources.list
printf 'deb [arch=%s signed-by=/usr/share/keyrings/getpatched-test-archive.gpg] file:/repo %s main\\n' "$ARCHITECTURE" "$SUITE" >> /etc/apt/sources.list
printf 'deb-src [arch=%s signed-by=/usr/share/keyrings/getpatched-test-archive.gpg] file:/repo %s main\\n' "$ARCHITECTURE" "$SUITE" >> /etc/apt/sources.list
apt-get update
apt-get install -y --no-install-recommends dpkg-dev
apt-get install -y --no-install-recommends $BINARY_PACKAGES
for binary in $BINARY_PACKAGES; do
  version="$(dpkg-query -W -f='${Version}' "$binary")"
  test "$version" = "$EXPECTED_VERSION" || { echo "wrong installed version for $binary: $version" >&2; exit 1; }
done
apt-get source "$SOURCE_PACKAGE"
test -f "$SOURCE_PACKAGE"*/debian/getpatched/release-policy.json
test -f "$SOURCE_PACKAGE"*/debian/getpatched/package-manifest.json
test -f "$SOURCE_PACKAGE"*/debian/getpatched/patches.json
""")
    (client_context / "Dockerfile").write_text("""# syntax=docker/dockerfile:1.7
ARG BASE_IMAGE
FROM ${BASE_IMAGE}
COPY repo /repo
COPY getpatched-test-archive.gpg /usr/share/keyrings/getpatched-test-archive.gpg
COPY apt-client.sh /apt-client.sh
ARG APT_SOURCES_B64
ARG ARCHITECTURE
ARG SUITE
ARG BINARY_PACKAGES
ARG EXPECTED_VERSION
ARG SOURCE_PACKAGE
ENV APT_SOURCES_B64=${APT_SOURCES_B64} ARCHITECTURE=${ARCHITECTURE} SUITE=${SUITE} BINARY_PACKAGES=${BINARY_PACKAGES} EXPECTED_VERSION=${EXPECTED_VERSION} SOURCE_PACKAGE=${SOURCE_PACKAGE}
RUN --mount=type=secret,id=runner-ca,target=/tmp/getpatched-runner-ca.crt,required=true \\
    mkdir -p /etc/ssl/certs && \\
    cp /tmp/getpatched-runner-ca.crt /etc/ssl/certs/ca-certificates.crt && \\
    printf 'Acquire::https::CAInfo "/etc/ssl/certs/ca-certificates.crt";\\n' > /etc/apt/apt.conf.d/99getpatched-ca && \\
    bash /apt-client.sh
""")
    client_image = "getpatched-apt-client-test-" + uuid.uuid4().hex[:12]
    client_built = False
    try:
        ca_secret_args, ca_bundle_sha256, ca_bundle_source = runner_ca_bundle()
        run(["docker", "build", "--no-cache", "--platform", container_platform, "--tag", client_image,
             "--build-arg", "BASE_IMAGE=" + args.base_image, *ca_secret_args,
             "--build-arg", "APT_SOURCES_B64=" + args.apt_sources_b64,
             "--build-arg", "ARCHITECTURE=" + architecture, "--build-arg", "SUITE=" + codename,
         "--build-arg", "BINARY_PACKAGES=" + " ".join(binary_packages),
             "--build-arg", "EXPECTED_VERSION=" + policy["version"],
             "--build-arg", "SOURCE_PACKAGE=" + policy["source"],
             str(client_context)])
        client_built = True
    finally:
        if client_built:
            run(["docker", "image", "rm", client_image])

    def digest(path):
        return hashlib.sha256(path.read_bytes()).hexdigest()

    (args.output / "repository-smoke.json").write_text(json.dumps({
        "source": policy["source"], "targetId": policy["targetId"], "suite": codename, "architecture": architecture, "component": "main",
        "binaryPackages": binary_packages, "version": policy["version"],
        "sourcePackageFetched": True, "inReleaseVerified": True, "releaseGpgVerified": True,
        "byHashSha256": True, "temporaryTestKeyFingerprint": fingerprint,
        "supportScope": policy["targetId"],
        "ubuntuProEsmCompatibility": policy.get("ubuntuProEsmCompatibility", "not-applicable"),
        "runnerCaBundleSource": ca_bundle_source, "runnerCaBundleSha256": ca_bundle_sha256,
        "releaseSha256": digest(release), "inReleaseSha256": digest(dist / "InRelease"),
        "clientBaseImage": args.base_image, "publication": "none; repository and temporary signing key were discarded after the isolated target client test"
    }, indent=2) + "\n")
    print(policy["source"] + ": signed InRelease/Release.gpg verified; target client installed exact binaries and fetched source package")


if __name__ == "__main__":
    main()
