#!/usr/bin/env python3
"""Build and verify a disposable signed APT repository with the protected key."""
import importlib.util
import os
from pathlib import Path
import re
import subprocess
import tempfile
import tarfile

ROOT = Path(__file__).resolve().parents[1]
GENERATOR_SPEC = importlib.util.spec_from_file_location(
    "getpatched_index_generator", ROOT / "scripts" / "generate-apt-index.py"
)
GENERATOR = importlib.util.module_from_spec(GENERATOR_SPEC)
GENERATOR_SPEC.loader.exec_module(GENERATOR)
PUBLISH_SPEC = importlib.util.spec_from_file_location(
    "getpatched_snapshot_publisher", ROOT / "scripts" / "publish-apt-snapshot.py"
)
PUBLISH = importlib.util.module_from_spec(PUBLISH_SPEC)
PUBLISH_SPEC.loader.exec_module(PUBLISH)


def run(command, *, input_data=None, cwd=None):
    result = subprocess.run(
        command,
        input=input_data,
        cwd=cwd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError("disposable APT signing self-test command failed: " + command[0])


def parse_secret_primary_fingerprints(output):
    fingerprints = []
    awaiting_primary = False
    for line in output.splitlines():
        record = line.split(":")
        if record[0] == "sec":
            awaiting_primary = True
        elif record[0] in {"ssb", "uid", "uat", "sub"}:
            awaiting_primary = False
        elif record[0] == "fpr" and awaiting_primary:
            fingerprints.append(record[9].upper())
            awaiting_primary = False
    return fingerprints


def secret_primary_fingerprints(key_home):
    result = subprocess.run(
        ["gpg", "--batch", "--no-tty", "--homedir", str(key_home), "--with-colons", "--fingerprint", "--list-secret-keys"],
        capture_output=True,
        text=True,
        check=True,
    )
    return parse_secret_primary_fingerprints(result.stdout)


def create_fixture(repository, temporary):
    binary_root = temporary / "binary"
    control_dir = binary_root / "DEBIAN"
    control_dir.mkdir(parents=True)
    (control_dir / "control").write_text(
        "Package: getpatched-signing-probe\n"
        "Version: 0.0.1-1\n"
        "Section: misc\n"
        "Priority: optional\n"
        "Architecture: all\n"
        "Maintainer: GetPatched Signing Check <releases@getpatched.dev>\n"
        "Description: Temporary package used only to verify APT signing\n"
    )
    binary_path = temporary / "getpatched-signing-probe_0.0.1-1_all.deb"
    run(["dpkg-deb", "--root-owner-group", "--build", str(binary_root), str(binary_path)])

    source_root = temporary / "source"
    upstream_root = temporary / "getpatched-signing-probe-0.0.1"
    upstream_root.mkdir()
    (upstream_root / "README").write_text("Disposable signing verification source.\n")
    upstream_tarball = temporary / "getpatched-signing-probe_0.0.1.orig.tar.gz"
    with tarfile.open(upstream_tarball, "w:gz") as archive:
        archive.add(upstream_root, arcname="getpatched-signing-probe-0.0.1")
    debian_dir = source_root / "debian"
    (debian_dir / "source").mkdir(parents=True)
    (source_root / "README").write_text("Disposable signing verification source.\n")
    (debian_dir / "source" / "format").write_text("3.0 (quilt)\n")
    (debian_dir / "control").write_text(
        "Source: getpatched-signing-probe\n"
        "Section: misc\n"
        "Priority: optional\n"
        "Maintainer: GetPatched Signing Check <releases@getpatched.dev>\n"
        "Build-Depends: debhelper-compat (= 13)\n"
        "Standards-Version: 4.6.2\n"
        "\n"
        "Package: getpatched-signing-probe\n"
        "Architecture: all\n"
        "Description: Temporary package used only to verify APT signing\n"
    )
    (debian_dir / "changelog").write_text(
        "getpatched-signing-probe (0.0.1-1) focal; urgency=medium\n"
        "\n"
        "  * Disposable signing-key verification fixture.\n"
        "\n"
        " -- GetPatched Signing Check <releases@getpatched.dev>  "
        "Thu, 01 Jan 1970 00:00:00 +0000\n"
    )
    rules = debian_dir / "rules"
    rules.write_text("#!/usr/bin/make -f\n%:\n\tdh $@\n")
    rules.chmod(0o755)
    run(["dpkg-source", "--build", str(source_root)], cwd=temporary)

    pool = repository / "pool/main/g/getpatched-signing-probe"
    pool.mkdir(parents=True)
    for path in temporary.glob("getpatched-signing-probe_*"):
        if not (path.suffix == ".dsc" or ".tar." in path.name):
            continue
        path.rename(pool / path.name)
    (pool / binary_path.name).write_bytes(binary_path.read_bytes())


def main():
    key_data = os.environ.get("GETPATCHED_SIGNING_KEY_ARMORED", "")
    fingerprint = os.environ.get("GETPATCHED_SIGNING_FINGERPRINT", "").strip().upper()
    if not key_data or len(key_data) > 1024 * 1024:
        raise SystemExit("protected signing-key secret is missing or exceeds its size bound")
    if not re.fullmatch(r"(?:[A-F0-9]{40}|[A-F0-9]{64})", fingerprint):
        raise SystemExit("configured signing fingerprint must be a full primary-key fingerprint")

    with tempfile.TemporaryDirectory(prefix="getpatched-signing-self-test-") as directory:
        temporary = Path(directory)
        key_home = temporary / "gnupg"
        key_home.mkdir(mode=0o700)
        run(
            ["gpg", "--batch", "--no-tty", "--homedir", str(key_home), "--import"],
            input_data=key_data.encode(),
        )
        if secret_primary_fingerprints(key_home) != [fingerprint]:
            raise SystemExit("protected signing key does not match its configured primary fingerprint")

        repository = temporary / "repository"
        repository.mkdir()
        create_fixture(repository, temporary)
        GENERATOR.generate(repository, "focal", "amd64", "main", "Disposable signing-key verification")
        GENERATOR.sign_release(repository / "dists/focal", key_home, fingerprint)
        PUBLISH.verify_release(repository, fingerprint)

    print("protected APT signing key matched its configured fingerprint and verified a disposable signed Focal repository")


if __name__ == "__main__":
    main()
