#!/usr/bin/env python3
"""Require a protected rebuild to match the successful public build manifest."""
import json
import sys
from pathlib import Path


def canonical(path):
    manifest = json.loads(Path(path).read_text())
    packages = sorted(manifest["packages"], key=lambda item: item["name"])
    return {
        "source": manifest["source"],
        "sourceVersion": manifest["sourceVersion"],
        "sourceCommit": manifest["sourceCommit"],
        "distribution": manifest["distribution"],
        "architecture": manifest["architecture"],
        "packages": [
            {key: item[key] for key in ("name", "package", "version", "architecture", "bytes", "sha256")}
            for item in packages
        ],
        "sourceFiles": [
            {key: item[key] for key in ("name", "bytes", "sha256")}
            for item in sorted(manifest["sourceFiles"], key=lambda item: item["name"])
        ],
    }


def main():
    if len(sys.argv) != 3:
        raise SystemExit("usage: compare-release-candidates.py EXPECTED REBUILT")
    expected, rebuilt = map(canonical, sys.argv[1:])
    if expected != rebuilt:
        raise SystemExit("protected rebuild does not match the successful run's release candidate manifest")
    print(f"release candidate hashes match for {expected['source']} {expected['sourceVersion']}")


if __name__ == "__main__":
    main()
