#!/usr/bin/env python3
"""Build the deterministic OSV-format feed for tested GetPatched target backports."""
import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from platform_policy import package_ecosystem, package_target_policy, target_profile

ROOT = Path(__file__).resolve().parents[1]
PACKAGES = ROOT / "packages.json"
OUTPUT = ROOT / "advisories" / "getpatched-osv.json"
SUMMARIES = {
    "CVE-2025-49794": "libxml2 XPath Schematron use-after-free in Ubuntu Focal packages",
    "CVE-2025-49796": "libxml2 Schematron name-element memory corruption in Ubuntu Focal packages",
    "CVE-2026-4111": "libarchive RAR5 decompression infinite loop in Ubuntu Focal packages",
    "CVE-2025-65018": "libpng simplified API buffer overflow when converting interlaced 16-bit images to 8-bit output",
    "CVE-2026-22695": "libpng simplified API heap buffer over-read for padded or negative row strides",
    "CVE-2026-22801": "libpng simplified write API row-stride integer truncation",
    "CVE-2026-53584": "libgit2 submodule path traversal can write outside a repository worktree",
    "CVE-2026-53585": "libgit2 delta object size header can trigger excessive memory allocation",
    "CVE-2026-53586": "libgit2 HTTP redirect authentication can disclose credentials to another host",
    "CVE-2025-61144": "tiffcrop out-of-bounds read while producing level-2 debug output",
    "CVE-2025-52885": "Poppler structure-tree use-after-free on duplicate parent-tree keys",
}


def build_feed(config, verified_candidates=frozenset()):
    grouped = {}
    for source, package_record in sorted(config["packages"].items()):
      for target_id in sorted(package_record["targets"]):
        package = package_target_policy(config, source, target_id)
        profile = target_profile(config, target_id)
        baseline = package["baselineVersion"]
        fixed = package["packageVersion"]
        vendor_fixed = package.get("vendorFixedVersions", [])
        candidate_status = package.get("candidateStatus", "unverified")
        candidate_preverified = candidate_status.startswith("development-verified")
        candidate_verified = candidate_preverified or (source, target_id) in verified_candidates
        if not candidate_verified:
            continue
        if (source, target_id) in verified_candidates and not candidate_preverified:
            candidate_status = "development-verified-production-release-pending"
        for cve in sorted(package["targetCves"]):
            if cve not in SUMMARIES:
                raise ValueError(f"no reviewed advisory summary for {cve}")
            advisory = grouped.setdefault(cve, {
                "schema_version": "1.6.0", "id": cve, "modified": "2026-10-30T05:38:23Z",
                "summary": SUMMARIES[cve],
                "details": "GetPatched records exact affected package versions and exact reviewed fixes per distribution, release, and architecture. A new target or fixed package version is accepted only after its own build and regression evidence.",
                "affected": [], "references": [],
                "database_specific": {"severity": "MEDIUM", "verification_status": "rebranded-package-build-pending"},
            })
            advisory["affected"].extend({
                "package": {"ecosystem": package_ecosystem(config, source, target_id), "name": binary},
                "versions": [baseline],
                "ecosystem_specific": {
                    "distribution": profile["distribution"], "release": profile["codename"],
                    "architecture": profile["architecture"], "target_id": target_id, "source_package": source,
                },
                "database_specific": {
                    "target_id": target_id, "source_package": source,
                    "candidate_version": fixed, "candidate_status": candidate_status,
                    "getpatched_fixed_version": fixed if candidate_verified else None,
                    "vendor_fixed_versions": vendor_fixed,
                    "fixed_versions": [fixed, *vendor_fixed] if candidate_verified else vendor_fixed,
                },
            } for binary in sorted(package["advisoryPackages"]))
            reference = {"type": "ADVISORY", "url": package.get("advisories", {}).get(cve, package["advisory"])}
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
