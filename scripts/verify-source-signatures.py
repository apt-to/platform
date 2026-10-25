#!/usr/bin/env python3
"""Replay the source signature and checksum evidence from a clean checkout.

Requires Python 3.10+ and GnuPG. Downloads only the inputs listed in the
committed evidence JSON, validates key fingerprints and SHA-256/size values,
then verifies signatures in a temporary, isolated GnuPG home.
"""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import urllib.request
from urllib.parse import urlparse


ROOT = pathlib.Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "evidence/source-signature-verification.json"
ALLOWED_HOSTS = {"launchpad.net", "launchpadlibrarian.net", "keyserver.ubuntu.com"}


class SameHostHTTPSRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        target = urlparse(newurl)
        if target.scheme != "https" or target.hostname not in ALLOWED_HOSTS:
            raise ValueError(f"refusing redirect outside approved HTTPS hosts: {newurl}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch(url: str, destination: pathlib.Path) -> None:
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.hostname not in ALLOWED_HOSTS:
        raise ValueError(f"refusing unapproved source URL: {url}")
    request = urllib.request.Request(url, headers={"User-Agent": "aptto-evidence-verifier/1"})
    opener = urllib.request.build_opener(SameHostHTTPSRedirectHandler())
    with opener.open(request, timeout=60) as response, destination.open("wb") as output:
        final = urlparse(response.geturl())
        if final.scheme != "https" or final.hostname not in ALLOWED_HOSTS:
            raise ValueError(f"refusing unexpected final download URL: {response.geturl()}")
        shutil.copyfileobj(response, output)


def check_file(path: pathlib.Path, expected_bytes: int, expected_sha256: str) -> None:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            size += len(chunk)
            digest.update(chunk)
    actual = digest.hexdigest()
    if (size, actual) != (expected_bytes, expected_sha256):
        raise ValueError(f"integrity mismatch for {path.name}: {size} bytes sha256:{actual}")
    print(f"PASS checksum {path.name}: {size} bytes sha256:{actual}")


def descriptor_checksums(path: pathlib.Path) -> dict[str, tuple[int, str]]:
    """Extract the signed Checksums-Sha256 field from a clear-signed .dsc."""
    text = path.read_text(encoding="utf-8")
    begin = "-----BEGIN PGP SIGNED MESSAGE-----\n"
    signature = "-----BEGIN PGP SIGNATURE-----"
    if not text.startswith(begin) or signature not in text:
        raise ValueError(f"not an inline-signed source descriptor: {path.name}")
    cleartext = text[len(begin):].split("\n\n", 1)[1].split(signature, 1)[0]
    lines = [line[2:] if line.startswith("- ") else line for line in cleartext.splitlines()]
    in_checksums = False
    checksums: dict[str, tuple[int, str]] = {}
    for line in lines:
        if line == "Checksums-Sha256:":
            in_checksums = True
            continue
        if in_checksums and line and not line[0].isspace():
            break
        if in_checksums and line.strip():
            parts = line.split()
            if len(parts) != 3:
                raise ValueError(f"malformed Checksums-Sha256 entry in {path.name}: {line}")
            digest, size, name = parts
            if name in checksums:
                raise ValueError(f"duplicate Checksums-Sha256 member in {path.name}: {name}")
            checksums[name] = (int(size), digest.lower())
    if not checksums:
        raise ValueError(f"missing Checksums-Sha256 field in {path.name}")
    return checksums


def run(command: list[str], *, env: dict[str, str]) -> str:
    result = subprocess.run(command, check=True, text=True, capture_output=True, env=env)
    status = result.stdout + result.stderr
    if "VALIDSIG" not in status:
        raise ValueError(f"GnuPG did not report VALIDSIG: {' '.join(command)}")
    return status


def main() -> int:
    if shutil.which("gpg") is None:
        raise RuntimeError("gpg is required; install GnuPG and retry")
    evidence = json.loads(EVIDENCE.read_text())
    with tempfile.TemporaryDirectory(prefix="aptto-source-verify-") as temp:
        temp_path = pathlib.Path(temp)
        home = temp_path / "gnupg"
        home.mkdir(mode=0o700)
        env = os.environ.copy()
        env["GNUPGHOME"] = str(home)

        imported_fingerprints: set[str] = set()
        for index, key in enumerate(evidence["keys"]):
            key_path = temp_path / f"key-{index}.asc"
            fetch(key["key_source"], key_path)
            key_hash = hashlib.sha256(key_path.read_bytes()).hexdigest()
            if key["fingerprint"] in imported_fingerprints:
                raise ValueError(f"duplicate evidence key fingerprint: {key['fingerprint']}")
            imported = subprocess.run(
                ["gpg", "--batch", "--import", str(key_path)],
                text=True,
                capture_output=True,
                env=env,
            )
            fingerprint_output = subprocess.run(
                ["gpg", "--batch", "--with-colons", "--fingerprint"],
                check=True,
                text=True,
                capture_output=True,
                env=env,
            ).stdout
            fingerprints: list[str] = []
            primary_key = False
            for line in fingerprint_output.splitlines():
                if line.startswith("pub:"):
                    primary_key = True
                elif line.startswith("sub:"):
                    primary_key = False
                elif line.startswith("fpr:") and primary_key:
                    fingerprints.append(line.split(":")[9])
                    primary_key = False
            actual_fingerprints = set(fingerprints)
            expected_fingerprints = imported_fingerprints | {key["fingerprint"]}
            if actual_fingerprints != expected_fingerprints:
                raise ValueError(
                    f"key import returned {imported.returncode}; unexpected keyring fingerprint set "
                    f"for {key['name']}: "
                    f"expected {sorted(expected_fingerprints)}, got {sorted(actual_fingerprints)}"
                )
            if imported.returncode:
                print(
                    f"NOTE gpg import exited {imported.returncode}, but the isolated keyring contains "
                    f"exactly the expected fingerprint; diagnostic: {imported.stderr.strip()}"
                )
            imported_fingerprints = expected_fingerprints
            print(f"PASS key fingerprint {key['name']}: {key['fingerprint']} (download sha256:{key_hash})")

        for source in evidence["sources"]:
            descriptor_info = source["descriptor"]
            descriptor = temp_path / descriptor_info["name"]
            fetch(descriptor_info["source_url"], descriptor)
            check_file(descriptor, descriptor_info["bytes"], descriptor_info["sha256"])
            signed_members = descriptor_checksums(descriptor)
            evidence_members = {
                item["name"]: (item["bytes"], item["sha256"].lower())
                for item in source["descriptor_members"]
            }
            if signed_members != evidence_members:
                raise ValueError(
                    f"source member manifest does not exactly match signed {descriptor.name}: "
                    f"descriptor={sorted(signed_members)}, evidence={sorted(evidence_members)}"
                )
            print(f"PASS signed member manifest {descriptor.name}: {len(signed_members)} files")
            for member in source["descriptor_members"]:
                member_url = descriptor_info["source_url"].rsplit("/", 1)[0] + "/" + member["name"]
                target = temp_path / member["name"]
                fetch(member_url, target)
                check_file(target, member["bytes"], member["sha256"])
            output = run(["gpg", "--batch", "--status-fd", "1", "--verify", str(descriptor)], env=env)
            expected = source["signature"]["signer_fingerprint"]
            if not any(line.startswith("[GNUPG:] VALIDSIG " + expected + " ") for line in output.splitlines()):
                raise ValueError(f"unexpected signing key for {descriptor.name}")
            print(f"PASS source signature {source['package']} {source['version']}: {expected}")

        upstream = evidence["upstream_archive_signature"]
        for name_key, url_key, bytes_key, hash_key in (
            ("file", "signature_url", "bytes", "sha256"),
            ("data_file", "data_url", "data_bytes", "data_sha256"),
        ):
            target = temp_path / upstream[name_key]
            fetch(upstream[url_key], target)
            check_file(target, upstream[bytes_key], upstream[hash_key])
        signature = temp_path / upstream["file"]
        archive = temp_path / upstream["data_file"]
        output = run(["gpg", "--batch", "--status-fd", "1", "--verify", str(signature), str(archive)], env=env)
        expected = upstream["signer_fingerprint"]
        if not any(line.startswith("[GNUPG:] VALIDSIG " + expected + " ") for line in output.splitlines()):
            raise ValueError("unexpected signer for upstream archive signature")
        print(f"PASS upstream archive signature: {expected}")
    print("PASS all recorded source evidence reproduced")
    return 0
if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError, StopIteration, subprocess.CalledProcessError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        raise SystemExit(1)
