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

    policy = json.loads((args.source / "debian/getpatched/release-policy.json").read_text())
    platform = json.loads((Path(__file__).resolve().parents[1] / "packages.json").read_text())
    candidate = platform["packages"][policy["source"]]
    binary_packages = candidate["binaryPackages"]
    if (policy["version"] != policy["baseVersion"] + "+getpatched1"
            or policy["baseVersion"] != candidate["baselineVersion"]
            or policy["futureEsmVersion"] != candidate["futureEsmVersion"]
            or policy["esmPockets"] != candidate["esmPockets"]
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
python3 /generate-apt-index.py --repo /repo --suite focal --architecture amd64 --component main --description 'GetPatched focal amd64 test archive'
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
         "GetPatched Temporary Repository Test <repo-test@getpatched.dev>", "rsa3072", "sign", "0"], env=env)
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
    public_key = args.work / "getpatched-test-archive.gpg"
    shutil.copyfile(exported_key, public_key)

    client_context = args.work / "apt-client-context"
    shutil.copytree(repo, client_context / "repo")
    shutil.copyfile(public_key, client_context / "getpatched-test-archive.gpg")
    client_script = client_context / "apt-client.sh"
    client_script.write_text("""#!/bin/bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
mkdir -p /tmp/getpatched-source-test
cd /tmp/getpatched-source-test
: > /etc/apt/sources.list
for suite in focal focal-updates focal-security; do
  printf 'deb https://snapshot.ubuntu.com/ubuntu/%s/ %s main universe restricted multiverse\\n' "$ARCHIVE_SNAPSHOT" "$suite" >> /etc/apt/sources.list
done
printf 'deb [arch=amd64 signed-by=/usr/share/keyrings/getpatched-test-archive.gpg] file:/repo focal main\\n' >> /etc/apt/sources.list
printf 'deb-src [arch=amd64 signed-by=/usr/share/keyrings/getpatched-test-archive.gpg] file:/repo focal main\\n' >> /etc/apt/sources.list
apt-get update
apt-get install -y --no-install-recommends dpkg-dev
apt-get install -y --no-install-recommends $BINARY_PACKAGES
for binary in $BINARY_PACKAGES; do
  version="$(dpkg-query -W -f='${Version}' "$binary")"
  test "$version" = "$EXPECTED_VERSION" || { echo "wrong installed version for $binary: $version" >&2; exit 1; }
done
set -- $BINARY_PACKAGES
core_package="$1"
esm_pockets="${ESM_POCKETS//,/ }"
release_date="$(date -u -R -d "${ARCHIVE_SNAPSHOT:0:4}-${ARCHIVE_SNAPSHOT:4:2}-${ARCHIVE_SNAPSHOT:6:2}T${ARCHIVE_SNAPSHOT:9:2}:${ARCHIVE_SNAPSHOT:11:2}:${ARCHIVE_SNAPSHOT:13:2}Z")"
case "$core_package" in
  libxml2) preference_file=/etc/apt/preferences.d/90-getpatched-libxml2 ;;
  libarchive13) preference_file=/etc/apt/preferences.d/90-getpatched-libarchive ;;
  *) echo "No APT preference path configured for runtime package $core_package" >&2; exit 1 ;;
esac
owned_preferences="$(dpkg-query -L "$core_package" | grep ^/etc/apt/preferences.d/ || true)"
if [ ! -f "$preference_file" ] || ! grep -Fxq "$preference_file" <<< "$owned_preferences"; then
  echo "Runtime package $core_package did not install its APT preference file at $preference_file" >&2
  echo "$owned_preferences" >&2
  exit 1
fi
for pocket in $esm_pockets; do
  grep -F "Pin: release a=$pocket" "$preference_file"
done
mkdir -p /tmp/esm-test-repo/pool /tmp/esm-package-build
for binary in $BINARY_PACKAGES; do
  package_root="/tmp/esm-package-build/$binary"
  mkdir -p "$package_root/DEBIAN"
  dependency=""
  if [ "$binary" != "$core_package" ]; then
    dependency="Depends: $core_package (= $ESM_VERSION)"
  fi
  cat > "$package_root/DEBIAN/control" <<EOF
Package: $binary
Version: $ESM_VERSION
Architecture: amd64
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
EOF
  if [ -n "$dependency" ]; then
    printf '%s\n' "$dependency" >> "$package_root/DEBIAN/control"
  fi
  printf '%s\n' 'Description: isolated fixture for ESM upgrade ordering test' >> "$package_root/DEBIAN/control"
  dpkg-deb --build "$package_root" "/tmp/esm-test-repo/pool/$binary.deb"
done
(cd /tmp/esm-test-repo && dpkg-scanpackages --multiversion pool /dev/null > /tmp/esm-packages)
for pocket in $esm_pockets; do
  suite_dir="/tmp/esm-test-repo/dists/$pocket"
  mkdir -p "$suite_dir/main/binary-amd64"
  cp /tmp/esm-packages "$suite_dir/main/binary-amd64/Packages"
  gzip -k "$suite_dir/main/binary-amd64/Packages"
  packages_gz="$suite_dir/main/binary-amd64/Packages.gz"
  packages_digest="$(sha256sum "$packages_gz" | cut -d ' ' -f 1)"
  packages_size="$(stat -c '%s' "$packages_gz")"
  cat > "$suite_dir/Release" <<EOF
Origin: Ubuntu
Label: UbuntuESM
Suite: $pocket
Codename: $pocket
Date: $release_date
Architectures: amd64
Components: main
SHA256:
 $packages_digest $packages_size main/binary-amd64/Packages.gz
EOF
done
for pocket in $esm_pockets; do
  sources="/tmp/esm-sources-$pocket.list"
  lists="/tmp/esm-lists-$pocket"
  mkdir -p "$lists/partial"
  printf 'deb [arch=amd64 signed-by=/usr/share/keyrings/getpatched-test-archive.gpg] file:/repo focal main\n' > "$sources"
  printf 'deb [trusted=yes arch=amd64] file:/tmp/esm-test-repo %s main\n' "$pocket" >> "$sources"
  apt_options=(-o "Dir::Etc::sourcelist=$sources" -o Dir::Etc::sourceparts=- -o "Dir::State::lists=$lists")
  apt-get "${apt_options[@]}" -o Debug::pkgAcquire::Auth=true -o Debug::pkgAcquire::Worker=1 update
  echo "Synthetic ESM Release metadata for $pocket:" >&2
  cat "/tmp/esm-test-repo/dists/$pocket/Release" >&2
  echo "APT list files for $pocket:" >&2
  find "$lists" -maxdepth 2 -type f -print >&2
  for binary in $BINARY_PACKAGES; do
    policy="$(apt-cache "${apt_options[@]}" policy "$binary")"
    candidate="$(printf '%s\n' "$policy" | sed -n 's/^[[:space:]]*Candidate: //p')"
    if [ "$candidate" != "$ESM_VERSION" ]; then
      echo "wrong ESM candidate for $binary in $pocket: $candidate" >&2
      echo "$policy" >&2
      exit 1
    fi
    printf '%s\n' "$policy" | grep -F "1001 file:/tmp/esm-test-repo $pocket/main amd64 Packages" >/dev/null || {
      echo "ESM pocket $pocket did not receive the expected APT pin priority for $binary" >&2
      printf '%s\n' "$policy"
      exit 1
    }
  done
  apt-get "${apt_options[@]}" -s install --only-upgrade $BINARY_PACKAGES > /tmp/getpatched-esm-upgrade.txt
  for binary in $BINARY_PACKAGES; do
    grep -F "Inst $binary " /tmp/getpatched-esm-upgrade.txt | grep -F "($ESM_VERSION" >/dev/null || {
      echo "simulated upgrade did not select vendor ESM version for $binary from $pocket" >&2
      cat /tmp/getpatched-esm-upgrade.txt
      exit 1
    }
  done
done
apt-get source "$SOURCE_PACKAGE"
test -f "$SOURCE_PACKAGE"*/debian/getpatched/release-policy.json
""")
    (client_context / "Dockerfile").write_text("""ARG TRUST_IMAGE
ARG BASE_IMAGE
FROM ${TRUST_IMAGE} AS trust
FROM ${BASE_IMAGE}
COPY --from=trust /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY repo /repo
COPY getpatched-test-archive.gpg /usr/share/keyrings/getpatched-test-archive.gpg
COPY apt-client.sh /apt-client.sh
ARG ARCHIVE_SNAPSHOT
ARG BINARY_PACKAGES
ARG EXPECTED_VERSION
ARG ESM_VERSION
ARG ESM_POCKETS
ARG SOURCE_PACKAGE
ENV ARCHIVE_SNAPSHOT=${ARCHIVE_SNAPSHOT} BINARY_PACKAGES=${BINARY_PACKAGES} EXPECTED_VERSION=${EXPECTED_VERSION} ESM_VERSION=${ESM_VERSION} ESM_POCKETS=${ESM_POCKETS} SOURCE_PACKAGE=${SOURCE_PACKAGE}
RUN bash /apt-client.sh
""")
    client_image = "getpatched-apt-client-test-" + uuid.uuid4().hex[:12]
    client_built = False
    try:
        run(["docker", "build", "--no-cache", "--platform", "linux/amd64", "--tag", client_image,
             "--build-arg", "BASE_IMAGE=" + args.base_image, "--build-arg", "TRUST_IMAGE=" + args.trust_image,
             "--build-arg", "ARCHIVE_SNAPSHOT=" + args.archive_snapshot,
         "--build-arg", "BINARY_PACKAGES=" + " ".join(binary_packages),
             "--build-arg", "EXPECTED_VERSION=" + policy["version"],
             "--build-arg", "ESM_VERSION=" + policy["futureEsmVersion"],
             "--build-arg", "ESM_POCKETS=" + ",".join(policy["esmPockets"]),
             "--build-arg", "SOURCE_PACKAGE=" + policy["source"],
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
        "esmDowngradeSimulation": {"candidateVersion": policy["futureEsmVersion"], "pockets": policy["esmPockets"], "passed": True},
        "releaseSha256": digest(release), "inReleaseSha256": digest(dist / "InRelease"),
        "clientBaseImage": args.base_image, "publication": "none; repository and temporary signing key were discarded after the isolated focal client test"
    }, indent=2) + "\n")
    print(policy["source"] + ": signed InRelease/Release.gpg verified; focal client installed exact binaries and fetched source package")


if __name__ == "__main__":
    main()
