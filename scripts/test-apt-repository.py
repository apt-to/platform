#!/usr/bin/env python3
"""Build an isolated signed APT archive and test it with a fresh focal client."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import hashlib
import uuid


def run(command, **kwargs):
    return subprocess.run(command, check=True, **kwargs)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path, help="committed packaging source checkout")
    parser.add_argument("--output", required=True, type=Path, help="build output directory")
    parser.add_argument("--work", required=True, type=Path, help="private build temp directory")
    parser.add_argument("--builder-image", required=True)
    parser.add_argument("--base-image", required=True)
    parser.add_argument("--trust-image", required=True)
    parser.add_argument("--archive-snapshot", required=True)
    args = parser.parse_args()

    policy = json.loads((args.source / "debian/aptto/release-policy.json").read_text())
    platform = json.loads((Path(__file__).resolve().parents[1] / "packages.json").read_text())
    candidate = platform["packages"][policy["source"]]
    binary_packages = candidate["binaryPackages"]
    if (policy["version"] != policy["baseVersion"] + "+aptto1"
            or policy["baseVersion"] != candidate["baselineVersion"]
            or policy["architecture"] != platform["architecture"]
            or policy["release"] != platform["release"]):
        raise RuntimeError("source package policy does not match the reviewed focal candidate")
    manifest = json.loads((args.output / "binary-manifest.json").read_text())
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

    dist = repo / "dists/focal"
    (args.work / "repo-index.sh").write_text("""#!/bin/bash
set -euo pipefail
python3 /generate-apt-index.py --repo /repo --suite focal --architecture amd64 --component main --description 'AptTo focal amd64 test archive'
""")
    run(["docker", "run", "--rm", "--platform", "linux/amd64", "--user", f"{os.getuid()}:{os.getgid()}",
         "--mount", f"type=bind,source={repo},target=/repo",
         "--mount", f"type=bind,source={args.work / 'repo-index.sh'},target=/repo-index.sh,readonly",
         "--mount", f"type=bind,source={Path(__file__).resolve().parent / 'generate-apt-index.py'},target=/generate-apt-index.py,readonly",
         "--entrypoint", "bash", args.builder_image, "/repo-index.sh"])

    key_home = args.work / "test-keyring"
    key_home.mkdir(mode=0o700)
    env = {**os.environ, "GNUPGHOME": str(key_home)}
    run(["gpg", "--batch", "--pinentry-mode", "loopback", "--passphrase", "", "--quick-generate-key",
         "AptTo Temporary Repository Test <repo-test@apt.to>", "rsa3072", "sign", "0"], env=env)
    fingerprint = subprocess.run(["gpg", "--batch", "--with-colons", "--list-keys"], env=env,
                                 check=True, capture_output=True, text=True).stdout
    fingerprint = next(line.split(":")[9] for line in fingerprint.splitlines() if line.startswith("fpr:"))
    release = dist / "Release"
    text = release.read_text()
    if "Architectures: amd64\n" not in text or "SHA256:\n" not in text:
        raise RuntimeError("APT Release metadata is missing required architecture or SHA-256 fields")
    generator_path = Path(__file__).resolve().parent / "generate-apt-index.py"
    spec = importlib.util.spec_from_file_location("generate_apt_index", generator_path)
    generator = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(generator)
    exported_key = generator.sign_release(dist, key_home, fingerprint)
    public_key = args.work / "aptto-test-archive.gpg"
    shutil.copyfile(exported_key, public_key)

    client_context = args.work / "apt-client-context"
    shutil.copytree(repo, client_context / "repo")
    shutil.copyfile(public_key, client_context / "aptto-test-archive.gpg")
    client_script = client_context / "apt-client.sh"
    client_script.write_text("""#!/bin/bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
mkdir -p /tmp/aptto-source-test
cd /tmp/aptto-source-test
: > /etc/apt/sources.list
for suite in focal focal-updates focal-security; do
  printf 'deb https://snapshot.ubuntu.com/ubuntu/%s/ %s main universe restricted multiverse\\n' "$ARCHIVE_SNAPSHOT" "$suite" >> /etc/apt/sources.list
done
printf 'deb [arch=amd64 signed-by=/usr/share/keyrings/aptto-test-archive.gpg] file:/repo focal main\\n' >> /etc/apt/sources.list
printf 'deb-src [arch=amd64 signed-by=/usr/share/keyrings/aptto-test-archive.gpg] file:/repo focal main\\n' >> /etc/apt/sources.list
apt-get update
apt-get install -y --no-install-recommends dpkg-dev
apt-get install -y --no-install-recommends $BINARY_PACKAGES
for binary in $BINARY_PACKAGES; do
  version="$(dpkg-query -W -f='${Version}' "$binary")"
  test "$version" = "$EXPECTED_VERSION" || { echo "wrong installed version for $binary: $version" >&2; exit 1; }
done
apt-get source "$SOURCE_PACKAGE"
test -f "$SOURCE_PACKAGE"*/debian/aptto/release-policy.json
""")
    (client_context / "Dockerfile").write_text("""ARG TRUST_IMAGE
ARG BASE_IMAGE
FROM ${TRUST_IMAGE} AS trust
FROM ${BASE_IMAGE}
COPY --from=trust /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY repo /repo
COPY aptto-test-archive.gpg /usr/share/keyrings/aptto-test-archive.gpg
COPY apt-client.sh /apt-client.sh
ARG ARCHIVE_SNAPSHOT
ARG BINARY_PACKAGES
ARG EXPECTED_VERSION
ARG SOURCE_PACKAGE
ENV ARCHIVE_SNAPSHOT=${ARCHIVE_SNAPSHOT} BINARY_PACKAGES=${BINARY_PACKAGES} EXPECTED_VERSION=${EXPECTED_VERSION} SOURCE_PACKAGE=${SOURCE_PACKAGE}
RUN bash /apt-client.sh
""")
    client_image = "aptto-apt-client-test-" + uuid.uuid4().hex[:12]
    client_built = False
    try:
        run(["docker", "build", "--no-cache", "--platform", "linux/amd64", "--tag", client_image,
             "--build-arg", "BASE_IMAGE=" + args.base_image, "--build-arg", "TRUST_IMAGE=" + args.trust_image,
             "--build-arg", "ARCHIVE_SNAPSHOT=" + args.archive_snapshot,
         "--build-arg", "BINARY_PACKAGES=" + " ".join(binary_packages),
             "--build-arg", "EXPECTED_VERSION=" + policy["version"], "--build-arg", "SOURCE_PACKAGE=" + policy["source"],
             str(client_context)])
        client_built = True
    finally:
        if client_built:
            run(["docker", "image", "rm", client_image])

    def digest(path):
        return hashlib.sha256(path.read_bytes()).hexdigest()

    (args.output / "repository-smoke.json").write_text(json.dumps({
        "source": policy["source"], "suite": "focal", "architecture": "amd64", "component": "main",
        "binaryPackages": binary_packages, "version": policy["version"],
        "sourcePackageFetched": True, "inReleaseVerified": True, "releaseGpgVerified": True,
        "byHashSha256": True, "temporaryTestKeyFingerprint": fingerprint,
        "releaseSha256": digest(release), "inReleaseSha256": digest(dist / "InRelease"),
        "clientBaseImage": args.base_image, "publication": "none; repository and temporary signing key were discarded after the isolated focal client test"
    }, indent=2) + "\n")
    print(policy["source"] + ": signed InRelease/Release.gpg verified; focal client installed exact binaries and fetched source package")


if __name__ == "__main__":
    main()
