#!/usr/bin/env python3
"""Build the deterministic OSV-format feed for tested AptTo focal backports."""
import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKAGES = ROOT / "packages.json"
OUTPUT = ROOT / "advisories" / "aptto-osv.json"
PATCHED_VERSION_SUFFIX = "+aptto1"
UBUNTU_FIXED = {
    "libxml2": "2.9.10+dfsg-5ubuntu0.20.04.10+esm1",
    "libarchive": "3.4.0-2ubuntu1.5+esm1",
}
SUMMARIES = {
    "CVE-2025-49794": "libxml2 XPath Schematron use-after-free in Ubuntu Focal packages",
    "CVE-2025-49796": "libxml2 Schematron name-element memory corruption in Ubuntu Focal packages",
    "CVE-2026-4111": "libarchive RAR5 decompression infinite loop in Ubuntu Focal packages",
}


def build_feed(config):
    advisories = []
    for source, package in sorted(config["packages"].items()):
        baseline = package["baselineVersion"]
        fixed = baseline + PATCHED_VERSION_SUFFIX
        for cve in sorted(package["targetCves"]):
            if cve not in SUMMARIES:
                raise ValueError(f"no reviewed advisory summary for {cve}")
            advisories.append({
                "schema_version": "1.6.0",
                "id": cve,
                "modified": "2026-10-26T00:00:00Z",
                "summary": SUMMARIES[cve],
                "details": "AptTo tracks the focal amd64 binary package identities below. The exact reviewed baseline is confirmed affected; the AptTo backport and Canonical Ubuntu Pro versions are fixed-version boundaries in database_specific. Versions at or above a listed fixed-version boundary are treated as fixed. Package versions below those boundaries that are not the exact reviewed baseline are unsupported and make the scanner fail closed instead of reporting a clean result. The AptTo fixed status is supported by installed-package regression evidence linked from the platform evidence index.",
                "affected": [{
                    "package": {"ecosystem": "Ubuntu:Pro:20.04:LTS", "name": binary},
                    "versions": [baseline],
                    "ecosystem_specific": {"release": "focal", "architecture": "amd64", "source_package": source},
                    "database_specific": {"fixed_versions": [fixed, UBUNTU_FIXED[source]]},
                } for binary in sorted(package["binaryPackages"])],
                "references": [{"type": "ADVISORY", "url": f"https://ubuntu.com/security/{cve}"}],
                "database_specific": {
                    "ecosystem": "AptTo:focal", "source_package": source,
                    "baseline_version": baseline, "aptto_fixed_version": fixed,
                    "ubuntu_pro_fixed_version": UBUNTU_FIXED[source], "severity": "MEDIUM",
                    "verified_by": "https://github.com/apt-to/platform/actions/runs/40202672075",
                },
            })
    return {"schema_version": "1.6.0", "vulns": advisories}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=PACKAGES)
    parser.add_argument("--output", type=Path, default=OUTPUT)
    args = parser.parse_args()
    config = json.loads(args.config.read_text())
    feed = build_feed(config)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(feed, indent=2, sort_keys=True) + "\n")
    print(f"wrote {len(feed['vulns'])} AptTo advisories to {args.output}")


if __name__ == "__main__":
    main()
