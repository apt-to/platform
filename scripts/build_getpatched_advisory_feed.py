#!/usr/bin/env python3
"""Build the deterministic OSV-format feed for tested GetPatched target backports."""
import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from platform_policy import package_target_policy, target_profile

ROOT = Path(__file__).resolve().parents[1]
PACKAGES = ROOT / "packages.json"
OUTPUT = ROOT / "advisories" / "getpatched-osv.json"
SUMMARIES = {
    "CVE-2025-49794": "libxml2 XPath Schematron use-after-free in Ubuntu Focal packages",
    "CVE-2025-49796": "libxml2 Schematron name-element memory corruption in Ubuntu Focal packages",
    "CVE-2026-4111": "libarchive RAR5 decompression infinite loop in Ubuntu Focal packages",
}


def build_feed(config):
    grouped = {}
    for source, package_record in sorted(config["packages"].items()):
      for target_id in sorted(package_record["targets"]):
        package = package_target_policy(config, source, target_id)
        profile = target_profile(config, target_id)
        baseline = package["baselineVersion"]
        fixed = package["packageVersion"]
        vendor_fixed = package.get("vendorFixedVersions", [])
        for cve in sorted(package["targetCves"]):
            if cve not in SUMMARIES:
                raise ValueError(f"no reviewed advisory summary for {cve}")
            advisory = grouped.setdefault(cve, {
                "schema_version": "1.6.0", "id": cve, "modified": "2026-10-28T16:09:38Z",
                "summary": SUMMARIES[cve],
                "details": "GetPatched records exact affected package versions and exact reviewed fixes per distribution, release, and architecture. A new target or fixed package version is accepted only after its own build and regression evidence.",
                "affected": [], "references": [],
                "database_specific": {"severity": "MEDIUM", "verification_status": "rebranded-package-build-pending"},
            })
            advisory["affected"].extend({
                "package": {"ecosystem": profile["packageEcosystem"], "name": binary},
                "versions": [baseline],
                "ecosystem_specific": {
                    "distribution": profile["distribution"], "release": profile["codename"],
                    "architecture": profile["architecture"], "target_id": target_id, "source_package": source,
                },
                "database_specific": {
                    "target_id": target_id, "source_package": source,
                    "getpatched_fixed_version": fixed, "vendor_fixed_versions": vendor_fixed,
                    "fixed_versions": [fixed, *vendor_fixed],
                },
            } for binary in sorted(package["binaryPackages"]))
            reference = {"type": "ADVISORY", "url": package["advisory"]}
            if reference not in advisory["references"]:
                advisory["references"].append(reference)
    return {"schema_version": "1.6.0", "vulns": [grouped[key] for key in sorted(grouped)]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=PACKAGES)
    parser.add_argument("--output", type=Path, default=OUTPUT)
    args = parser.parse_args()
    config = json.loads(args.config.read_text())
    feed = build_feed(config)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(feed, indent=2, sort_keys=True) + "\n")
    print(f"wrote {len(feed['vulns'])} GetPatched advisories to {args.output}")


if __name__ == "__main__":
    main()
