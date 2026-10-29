#!/usr/bin/env python3
"""Generate deterministic target-specific Packages/Sources indexes and by-hash copies."""
import argparse
import gzip
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile


def run(command, *, cwd, stdout=None):
    return subprocess.run(command, cwd=cwd, check=True, stdout=stdout)


def release_sha256_entries(release_text):
    entries = {}
    in_sha256 = False
    for line in release_text.splitlines():
        if line == "SHA256:":
            in_sha256 = True
            continue
        if in_sha256 and line and not line[0].isspace():
            break
        if not in_sha256 or not line.strip():
            continue
        digest, size, relative = line.split()
        if relative == "Release":
            continue  # apt-ftparchive's self-checksum is necessarily stale.
        if relative in entries:
            raise ValueError(f"duplicate Release SHA256 path: {relative}")
        entries[relative] = (digest, int(size))
    if not in_sha256:
        raise ValueError("APT Release metadata has no SHA256 section")
    return entries


def rewrite_release_checksums(release_path, dist, architecture="amd64"):
    original = release_path.read_text()
    architecture_line = f"Architectures: {architecture}\n"
    if architecture_line not in original:
        raise ValueError(f"APT Release metadata is missing the expected {architecture} architecture")
    entries = release_sha256_entries(original)
    if not entries:
        raise ValueError("APT Release metadata has no index checksums")
    for relative, (expected_hash, expected_size) in entries.items():
        path = (dist / relative).resolve()
        try:
            path.relative_to(dist.resolve())
        except ValueError:
            raise ValueError(f"APT Release index path is missing or escapes the distribution: {relative}") from None
        if not path.is_file():
            raise ValueError(f"APT Release index path is missing or escapes the distribution: {relative}")
        content = path.read_bytes()
        if len(content) != expected_size or hashlib.sha256(content).hexdigest() != expected_hash:
            raise ValueError(f"APT Release checksum mismatch for {relative}")
    text = original.replace(architecture_line, architecture_line + "Acquire-By-Hash: yes\n", 1)
    lines = text.splitlines()
    rebuilt = []
    in_sha256 = False
    for line in lines:
        if line == "SHA256:":
            in_sha256 = True
            rebuilt.append(line)
            continue
        if in_sha256 and line and not line[0].isspace():
            for relative in sorted(entries):
                content = (dist / relative).read_bytes()
                rebuilt.append(f" {hashlib.sha256(content).hexdigest()} {len(content)} {relative}")
            in_sha256 = False
        if in_sha256 and line.strip():
            continue
        rebuilt.append(line)
    if in_sha256:
        for relative in sorted(entries):
            content = (dist / relative).read_bytes()
            rebuilt.append(f" {hashlib.sha256(content).hexdigest()} {len(content)} {relative}")
    release_path.write_text("\n".join(rebuilt) + "\n")
    return release_sha256_entries(release_path.read_text())


def write_by_hash(dist, entries):
    for relative, (digest, _size) in entries.items():
        source = dist / relative
        target = source.parent / "by-hash" / "SHA256" / digest
        target.parent.mkdir(parents=True, exist_ok=True)
        content = source.read_bytes()
        if hashlib.sha256(content).hexdigest() != digest:
            raise ValueError(f"index changed while creating by-hash copy: {relative}")
        target.write_bytes(content)
        if target.read_bytes() != content:
            raise ValueError(f"by-hash copy verification failed for {relative}")


def sign_release(dist, key_home, fingerprint):
    """Create and verify standard detached and inline signatures for Release."""
    if not fingerprint or not all(c in "0123456789ABCDEFabcdef" for c in fingerprint):
        raise ValueError("signing fingerprint must be hexadecimal")
    dist = Path(dist).resolve()
    key_home = Path(key_home).resolve()
    release = dist / "Release"
    if not release.is_file():
        raise ValueError("Release metadata must exist before signing")
    env = {**os.environ, "GNUPGHOME": str(key_home)}
    listed = subprocess.run(["gpg", "--batch", "--with-colons", "--list-secret-keys", fingerprint],
                            cwd=dist, check=True, capture_output=True, text=True, env=env).stdout
    fingerprints = [line.split(":")[9] for line in listed.splitlines() if line.startswith("fpr:")]
    if fingerprint.upper() not in fingerprints:
        raise ValueError("requested signing fingerprint is not present in the isolated keyring")
    subprocess.run(["gpg", "--batch", "--yes", "--local-user", fingerprint, "--digest-algo", "SHA256",
                    "--clearsign", "--output", str(dist / "InRelease"), str(release)],
                   cwd=dist, check=True, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    subprocess.run(["gpg", "--batch", "--yes", "--local-user", fingerprint, "--digest-algo", "SHA256",
                    "--armor", "--detach-sign", "--output", str(dist / "Release.gpg"), str(release)],
                   cwd=dist, check=True, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    exported = subprocess.run(["gpg", "--batch", "--export", fingerprint], cwd=dist, check=True,
                              capture_output=True, env=env).stdout
    if not exported:
        raise ValueError("public signing key export is empty")
    with tempfile.TemporaryDirectory(prefix="getpatched-gpg-verify-") as temporary:
        verify_home = Path(temporary) / "gnupg"
        verify_home.mkdir(mode=0o700)
        verify_env = {**env, "GNUPGHOME": str(verify_home)}
        subprocess.run(["gpg", "--batch", "--import"], cwd=dist, input=exported, check=True,
                       env=verify_env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["gpg", "--batch", "--verify", str(dist / "InRelease")], cwd=dist, check=True,
                       env=verify_env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["gpg", "--batch", "--verify", str(dist / "Release.gpg"), str(release)],
                       cwd=dist, check=True, env=verify_env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    public_key = dist.parent.parent / "getpatched-archive-keyring.gpg"
    public_key.write_bytes(exported)
    return public_key


def generate(repo, suite, architecture, component, description):
    repo = repo.resolve()
    pool = repo / "pool"
    if not pool.is_dir() or not any(pool.rglob("*.deb")) or not any(pool.rglob("*.dsc")):
        raise ValueError("repository pool must contain binary and complete source package files")
    dist = repo / "dists" / suite
    if dist.exists() and any(dist.iterdir()):
        raise ValueError("target suite already contains files; generate into a fresh immutable repository snapshot")
    binary_index = dist / component / f"binary-{architecture}" / "Packages"
    source_index = dist / component / "source" / "Sources"
    binary_index.parent.mkdir(parents=True, exist_ok=True)
    source_index.parent.mkdir(parents=True, exist_ok=True)
    with binary_index.open("wb") as output:
        run(["dpkg-scanpackages", "--arch", architecture, "pool", "/dev/null"], cwd=repo, stdout=output)
    with source_index.open("wb") as output:
        run(["apt-ftparchive", "sources", "pool"], cwd=repo, stdout=output)
    indexed = (binary_index, source_index)
    for path in indexed:
        raw = path.read_bytes()
        with path.with_suffix(path.suffix + ".gz").open("wb") as stream:
            with gzip.GzipFile(filename="", mode="wb", compresslevel=9, mtime=0, fileobj=stream) as zipped:
                zipped.write(raw)
        run(["xz", "--threads=1", "--check=crc64", "--lzma2=dict=64MiB", "-9", "-c", str(path)], cwd=repo, stdout=path.with_suffix(path.suffix + ".xz").open("wb"))
    release_path = dist / "Release"
    release_path.parent.mkdir(parents=True, exist_ok=True)
    command = [
        "apt-ftparchive",
        "-o", "APT::FTPArchive::Release::Origin=GetPatched",
        "-o", "APT::FTPArchive::Release::Label=getpatched.dev",
        "-o", f"APT::FTPArchive::Release::Suite={suite}",
        "-o", f"APT::FTPArchive::Release::Codename={suite}",
        "-o", f"APT::FTPArchive::Release::Architectures={architecture}",
        "-o", f"APT::FTPArchive::Release::Components={component}",
        "-o", f"APT::FTPArchive::Release::Description={description}",
        "release", f"dists/{suite}",
    ]
    with release_path.open("wb") as output:
        run(command, cwd=repo, stdout=output)
    entries = rewrite_release_checksums(release_path, dist, architecture)
    write_by_hash(dist, entries)
    return {"suite": suite, "architecture": architecture, "component": component,
            "indexes": sorted(entries), "release": str(release_path.relative_to(repo))}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True, type=Path)
    parser.add_argument("--suite", default="focal")
    parser.add_argument("--architecture", default="amd64")
    parser.add_argument("--component", default="main")
    parser.add_argument("--description", default="GetPatched maintained packages")
    parser.add_argument("--signing-key-home", type=Path, help="isolated GnuPG home containing the repository signing key")
    parser.add_argument("--signing-fingerprint", help="full fingerprint of the repository signing key")
    args = parser.parse_args()
    if bool(args.signing_key_home) != bool(args.signing_fingerprint):
        parser.error("--signing-key-home and --signing-fingerprint must be supplied together")
    result = generate(args.repo, args.suite, args.architecture, args.component, args.description)
    if args.signing_key_home:
        key = sign_release(args.repo / "dists" / args.suite, args.signing_key_home, args.signing_fingerprint)
        result["public_key"] = str(key.relative_to(args.repo.resolve()))
    print(f"generated {result['suite']} {result['architecture']} indexes: {len(result['indexes'])} hash-verified files")
    if "public_key" in result:
        print(f"signed InRelease and Release.gpg; exported public key to {result['public_key']}")


if __name__ == "__main__":
    main()
