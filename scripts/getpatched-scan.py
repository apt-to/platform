#!/usr/bin/env python3
"""Scan installed dpkg package records against the GetPatched OSV-compatible feed."""
import argparse
import hashlib
import json
from email.parser import Parser
from pathlib import Path
import re
import sys
from build_getpatched_advisory_feed import PACKAGES, build_feed
from debian_versions import debian_version_compare, debian_version_parts
from platform_policy import package_target_policy, target_profile

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_FEED = ROOT / "advisories" / "getpatched-osv.json"
MAX_STATUS_BYTES = 16 * 1024 * 1024
MAX_FEED_BYTES = 4 * 1024 * 1024


def parse_status(path):
    path = Path(path)
    if path.stat().st_size > MAX_STATUS_BYTES:
        raise ValueError("dpkg status inventory exceeds the 16 MiB scanner limit")
    text = path.read_text()
    # Parser returns one message. Split dpkg's RFC822-style control records explicitly.
    packages = {}
    for stanza in re.split(r"\n\s*\n", text.strip()):
        if not stanza.strip():
            continue
        record = Parser().parsestr(stanza)
        package = record.get("Package")
        if not package:
            continue
        architecture = record.get("Architecture")
        identity = (package, architecture)
        if identity in packages:
            raise ValueError(f"duplicate dpkg status record for {package}:{architecture}")
        packages[identity] = {
            "version": record.get("Version"),
            "architecture": record.get("Architecture"),
            "status": record.get("Status", ""),
        }
    return packages


def load_feed(path):
    path = Path(path)
    if path.stat().st_size > MAX_FEED_BYTES:
        raise ValueError("OSV feed exceeds the 4 MiB scanner limit")
    feed = json.loads(path.read_text())
    if feed.get("schema_version") != "1.6.0" or not isinstance(feed.get("vulns"), list):
        raise ValueError("advisory feed is not a supported OSV schema database")
    seen = set()
    config = json.loads(PACKAGES.read_text())
    for advisory in feed["vulns"]:
        advisory_id = advisory.get("id")
        if not isinstance(advisory_id, str) or not advisory_id.startswith("CVE-") or advisory_id in seen:
            raise ValueError("advisory IDs must be unique CVE identifiers")
        seen.add(advisory_id)
        if not isinstance(advisory.get("affected"), list) or not advisory["affected"]:
            raise ValueError(f"{advisory_id} has no affected package records")
        for affected in advisory["affected"]:
            package = affected.get("package", {})
            scope = affected.get("ecosystem_specific", {})
            policy = affected.get("database_specific", {})
            fixed = policy.get("fixed_versions")
            source = scope.get("source_package") if isinstance(scope, dict) else None
            target_id = scope.get("target_id") if isinstance(scope, dict) else None
            if (not isinstance(package.get("ecosystem"), str) or not package["ecosystem"]
                    or not isinstance(package.get("name"), str)
                    or not re.fullmatch(r"[a-z0-9][a-z0-9+.-]+", package["name"])
                    or not isinstance(scope, dict) or not isinstance(scope.get("distribution"), str)
                    or not isinstance(scope.get("release"), str) or not isinstance(scope.get("architecture"), str)
                    or not isinstance(target_id, str) or policy.get("target_id") != target_id
                    or not isinstance(source, str) or not isinstance(fixed, list) or not fixed
                    or not isinstance(affected.get("versions"), list) or not affected["versions"] or affected.get("ranges")):
                raise ValueError(f"{advisory_id} has an invalid target-specific affected package entry")
            try:
                profile = target_profile(config, target_id)
                expected = package_target_policy(config, source, target_id)
            except (KeyError, ValueError) as error:
                raise ValueError(f"{advisory_id} names an unconfigured package target: {error}") from error
            vendor_fixed = expected.get("vendorFixedVersions", [])
            if (package["ecosystem"] != profile["packageEcosystem"]
                    or scope["distribution"] != profile["distribution"] or scope["release"] != profile["codename"]
                    or scope["architecture"] != profile["architecture"]
                    or policy.get("source_package") != source
                    or policy.get("getpatched_fixed_version") != expected["packageVersion"]
                    or policy.get("vendor_fixed_versions") != vendor_fixed
                    or fixed != [expected["packageVersion"], *vendor_fixed]
                    or affected["versions"] != [expected["baselineVersion"]]):
                raise ValueError("advisory feed does not match the reviewed GetPatched package policy")
            for version in [*affected["versions"], *fixed]:
                debian_version_parts(version)
            if any(debian_version_compare(fixed_version, affected_version) <= 0
                   for fixed_version in fixed for affected_version in affected["versions"]):
                raise ValueError(f"{advisory_id} fixed versions must sort after every reviewed affected version")
    if feed != build_feed(config):
        raise ValueError("advisory feed does not match the reviewed GetPatched package policy")
    return feed


def scan(status_path, feed_path, release, architecture, image_id=None, target_id=None):
    feed = load_feed(feed_path)
    candidates = {
        affected.get("ecosystem_specific", {}).get("target_id")
        for advisory in feed["vulns"] for affected in advisory["affected"]
        if affected.get("ecosystem_specific", {}).get("release") == release
        and affected.get("ecosystem_specific", {}).get("architecture") == architecture
    }
    if not candidates:
        raise ValueError(f"advisory feed has no coverage for {release}/{architecture}")
    if target_id is None:
        if len(candidates) != 1:
            raise ValueError(f"select --target-id when {release}/{architecture} maps to multiple targets")
        target_id = next(iter(candidates))
    if target_id not in candidates:
        raise ValueError(f"advisory feed has no coverage for {release}/{architecture}")
    installed = parse_status(status_path)
    findings = []
    scanned = {}
    for advisory in feed["vulns"]:
        for affected in advisory["affected"]:
            package = affected["package"]["name"]
            record = installed.get((package, architecture))
            if not record or record["status"].split()[-1:] != ["installed"]:
                continue
            scope = affected["ecosystem_specific"]
            if scope["target_id"] != target_id or scope["release"] != release or scope["architecture"] != architecture:
                continue
            if not record["version"]:
                raise ValueError(f"installed package {package} has no version")
            scanned[package] = record["version"]
            package_policy = affected["database_specific"]
            fixed_versions = package_policy["fixed_versions"]
            affected_versions = affected["versions"]
            version = record["version"]
            getpatched_fixed = package_policy["getpatched_fixed_version"]
            vendor_fixed = package_policy["vendor_fixed_versions"]
            if any(debian_version_compare(version, candidate) == 0 for candidate in affected_versions):
                findings.append({
                    "id": advisory["id"], "package": package, "version": version,
                    "affected_versions": affected_versions,
                    "fixed_versions": fixed_versions, "severity": advisory["database_specific"]["severity"],
                    "summary": advisory["summary"], "references": [ref["url"] for ref in advisory.get("references", [])],
                })
            elif ("+getpatched" in version and debian_version_compare(version, getpatched_fixed) != 0):
                raise ValueError(
                    f"installed package {package} version {version} is not an exact reviewed affected or GetPatched fixed "
                    f"version for {advisory['id']}; update the advisory feed before treating it as clean"
                )
            elif (debian_version_compare(version, getpatched_fixed) != 0 and
                  not any(debian_version_compare(version, candidate) >= 0 for candidate in vendor_fixed)):
                raise ValueError(
                    f"installed package {package} version {version} is not an exact reviewed affected or GetPatched fixed "
                    f"version, or a configured vendor fixed version or later, for {advisory['id']}; update the advisory feed "
                    "before treating it as clean"
                )
    findings.sort(key=lambda item: (item["package"], item["id"]))
    return {
        "schemaVersion": 1, "scanner": "getpatched-dpkg-osv/1", "targetId": target_id, "release": release, "architecture": architecture,
        "imageId": image_id,
        "advisoryFeed": str(feed_path), "advisoryFeedSha256": hashlib.sha256(Path(feed_path).read_bytes()).hexdigest(),
        "packagePolicySha256": hashlib.sha256(PACKAGES.read_bytes()).hexdigest(),
        "statusFileSha256": hashlib.sha256(Path(status_path).read_bytes()).hexdigest(),
        "scannedPackageVersions": dict(sorted(scanned.items())), "findings": findings,
        "findingsById": sorted({item["id"] for item in findings}),
        "summary": {"scannedPackages": len(scanned), "vulnerablePackages": len({item["package"] for item in findings}), "findingCount": len(findings)},
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--feed", type=Path, default=DEFAULT_FEED)
    parser.add_argument("--status-file", type=Path, default=Path("/var/lib/dpkg/status"))
    parser.add_argument("--release", default="focal", help="target distribution release codename")
    parser.add_argument("--architecture", default="amd64", help="target dpkg architecture")
    parser.add_argument("--target-id", help="exact configured distribution/release/architecture target")
    parser.add_argument("--image-id", help="container image digest or local image ID being scanned")
    args = parser.parse_args()
    try:
        report = scan(args.status_file, args.feed, args.release, args.architecture, args.image_id, args.target_id)
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
        print("GetPatched scan failed: " + str(error), file=sys.stderr)
        return 2
    print(json.dumps(report, indent=2))
    return 1 if report["findings"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
