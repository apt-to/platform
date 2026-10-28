#!/usr/bin/env python3
"""Validate an Ubuntu Pro Focal ESM source download and write a hash-only report."""
import argparse
import hashlib
from email.parser import Parser
import json
from pathlib import Path
import re


MAX_SOURCE_BYTES = 256 * 1024 * 1024
ALLOWED_PACKAGES = {"libxml2", "libarchive"}


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def inspect(package, source_dir, policy):
    if package not in ALLOWED_PACKAGES or package not in policy.get("packages", {}):
        raise ValueError("Source package is not in the reviewed pilot policy")
    source_dir = source_dir.resolve(strict=True)
    descriptors = sorted(source_dir.glob(package + "_*.dsc"))
    if len(descriptors) != 1:
        raise ValueError("Expected exactly one downloaded Debian source descriptor")
    descriptor = descriptors[0]
    descriptor_bytes = descriptor.stat().st_size
    if descriptor_bytes > MAX_SOURCE_BYTES:
        raise ValueError("Source descriptor exceeds the pilot size bound")
    message = Parser().parsestr(descriptor.read_text(encoding="utf-8"))
    source_name = (message.get("Source") or "").split()[0]
    version = message.get("Version") or ""
    if source_name != package or not re.fullmatch(r"[A-Za-z0-9.+:~_-]+", version):
        raise ValueError("Debian source descriptor has an unexpected source identity")

    declared = {}
    for line in (message.get("Checksums-Sha256") or "").splitlines():
        fields = line.split()
        if len(fields) != 3:
            continue
        digest, size_text, name = fields
        if (not re.fullmatch(r"[0-9a-f]{64}", digest) or not size_text.isdigit()
                or Path(name).name != name or name in {".", ".."}):
            raise ValueError("Source descriptor contains an unsafe or malformed checksum entry")
        if name in declared:
            raise ValueError("Source descriptor repeats a source filename")
        declared[name] = (digest, int(size_text))
    if not declared:
        raise ValueError("Source descriptor has no SHA-256 source-file inventory")

    descriptor_files = {descriptor.name}
    report_files = []
    total_bytes = descriptor_bytes
    for name, (expected_digest, expected_size) in sorted(declared.items()):
        if expected_size > MAX_SOURCE_BYTES or total_bytes + expected_size > MAX_SOURCE_BYTES:
            raise ValueError("Downloaded source package exceeds the pilot size bound")
        path = source_dir / name
        if path.is_symlink() or not path.is_file() or path.parent != source_dir:
            raise ValueError("A source file declared by the descriptor is missing or unsafe")
        actual_size = path.stat().st_size
        if actual_size != expected_size or sha256(path) != expected_digest:
            raise ValueError("A downloaded source file does not match the signed descriptor checksums")
        total_bytes += actual_size
        report_files.append({"name": name, "bytes": actual_size, "sha256": expected_digest})
        descriptor_files.add(name)

    unexpected = {
        path.name for path in source_dir.iterdir()
        if path.name not in descriptor_files or path.is_symlink() or not path.is_file()
    }
    if unexpected:
        raise ValueError("Download directory contains files outside the verified Debian source set")
    expected_version = policy["packages"][package]["futureEsmVersion"]
    return {
        "schemaVersion": 1,
        "source": package,
        "distribution": "focal",
        "architecture": "amd64",
        "sourcePockets": ["focal-infra-security", "focal-infra-updates"],
        "retrieval": "apt-get source from authenticated Ubuntu Pro ESM Infra indexes",
        "descriptor": {
            "name": descriptor.name,
            "bytes": descriptor.stat().st_size,
            "sha256": sha256(descriptor),
        },
        "sourceVersion": version,
        "policyEsmVersion": expected_version,
        "matchesPolicyEsmVersion": version == expected_version,
        "totalBytes": total_bytes,
        "sourceFiles": report_files,
        "sourceContentsPublished": False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", required=True)
    parser.add_argument("--source-dir", required=True, type=Path)
    parser.add_argument("--policy", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    policy = json.loads(args.policy.read_text(encoding="utf-8"))
    report = inspect(args.package, args.source_dir, policy)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"source": report["source"], "sourceVersion": report["sourceVersion"],
                      "matchesPolicyEsmVersion": report["matchesPolicyEsmVersion"],
                      "sourceFiles": len(report["sourceFiles"])}))


if __name__ == "__main__":
    main()
