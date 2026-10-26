#!/usr/bin/env python3
"""Scan installed dpkg package records against the AptTo OSV-compatible feed."""
import argparse
import hashlib
import json
from email.parser import Parser
from pathlib import Path
import re
import sys
from build_aptto_advisory_feed import PACKAGES, build_feed

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_FEED = ROOT / "advisories" / "aptto-osv.json"
MAX_STATUS_BYTES = 16 * 1024 * 1024
MAX_FEED_BYTES = 4 * 1024 * 1024


def debian_version_parts(value):
    if not isinstance(value, str) or not value or len(value) > 256 or any(ch.isspace() for ch in value):
        raise ValueError("invalid Debian package version")
    epoch = "0"
    version = value
    if ":" in version:
        epoch, version = version.split(":", 1)
        if not epoch.isdigit():
            raise ValueError("invalid Debian version epoch")
    if "-" in version:
        upstream, revision = version.rsplit("-", 1)
    else:
        upstream, revision = version, "0"
    if not upstream or not revision:
        raise ValueError("invalid Debian version components")
    return int(epoch), upstream, revision


def verrevcmp(left, right):
    i = j = 0

    def order(char):
        if char == "~":
            return -1
        if not char:
            return 0
        if char.isalpha():
            return ord(char)
        return ord(char) + 256

    while i < len(left) or j < len(right):
        while (i < len(left) and not left[i].isdigit()) or (j < len(right) and not right[j].isdigit()):
            a = left[i] if i < len(left) and not left[i].isdigit() else ""
            b = right[j] if j < len(right) and not right[j].isdigit() else ""
            if order(a) != order(b):
                return -1 if order(a) < order(b) else 1
            if a:
                i += 1
            if b:
                j += 1
        while i < len(left) and left[i] == "0":
            i += 1
        while j < len(right) and right[j] == "0":
            j += 1
        first_difference = 0
        while i < len(left) and j < len(right) and left[i].isdigit() and right[j].isdigit():
            if first_difference == 0:
                first_difference = ord(left[i]) - ord(right[j])
            i += 1
            j += 1
        if i < len(left) and left[i].isdigit():
            return 1
        if j < len(right) and right[j].isdigit():
            return -1
        if first_difference:
            return -1 if first_difference < 0 else 1
    return 0


def debian_version_compare(left, right):
    left_epoch, left_upstream, left_revision = debian_version_parts(left)
    right_epoch, right_upstream, right_revision = debian_version_parts(right)
    if left_epoch != right_epoch:
        return -1 if left_epoch < right_epoch else 1
    upstream = verrevcmp(left_upstream, right_upstream)
    return upstream or verrevcmp(left_revision, right_revision)


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
            fixed = affected.get("database_specific", {}).get("fixed_versions")
            if (package.get("ecosystem") != "Ubuntu:Pro:20.04:LTS" or not isinstance(package.get("name"), str) or
                    not re.fullmatch(r"[a-z0-9][a-z0-9+.-]+", package["name"]) or
                    not isinstance(scope, dict) or not isinstance(scope.get("release"), str) or
                    not isinstance(scope.get("architecture"), str) or
                    not isinstance(fixed, list) or not fixed or not isinstance(affected.get("versions"), list) or
                    not affected["versions"] or affected.get("ranges")):
                raise ValueError(f"{advisory_id} has an invalid AptTo package or fixed-version entry")
            for version in [*affected["versions"], *fixed]:
                debian_version_parts(version)
            if any(any(debian_version_compare(fixed_version, affected_version) <= 0 for fixed_version in fixed)
                   for affected_version in affected["versions"]):
                raise ValueError(f"{advisory_id} fixed versions must sort after every reviewed affected version")
    config = json.loads(PACKAGES.read_text())
    if feed != build_feed(config):
        raise ValueError("advisory feed does not match the reviewed AptTo package policy")
    return feed


def scan(status_path, feed_path, release, architecture, image_id=None):
    feed = load_feed(feed_path)
    if not any(affected.get("ecosystem_specific", {}).get("release") == release and
               affected.get("ecosystem_specific", {}).get("architecture") == architecture
               for advisory in feed["vulns"] for affected in advisory["affected"]):
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
            if scope["release"] != release or scope["architecture"] != architecture:
                continue
            if not record["version"]:
                raise ValueError(f"installed package {package} has no version")
            scanned[package] = record["version"]
            fixed_versions = affected["database_specific"]["fixed_versions"]
            affected_versions = affected["versions"]
            version = record["version"]
            if any(debian_version_compare(version, candidate) == 0 for candidate in affected_versions):
                findings.append({
                    "id": advisory["id"], "package": package, "version": version,
                    "affected_versions": affected_versions,
                    "fixed_versions": fixed_versions, "severity": advisory["database_specific"]["severity"],
                    "summary": advisory["summary"], "references": [ref["url"] for ref in advisory.get("references", [])],
                })
            elif not any(debian_version_compare(version, fixed_version) >= 0 for fixed_version in fixed_versions):
                raise ValueError(
                    f"installed package {package} version {version} is outside the reviewed affected/fixed "
                    f"version boundaries for {advisory['id']}; update the advisory feed before treating it as clean"
                )
    findings.sort(key=lambda item: (item["package"], item["id"]))
    return {
        "schemaVersion": 1, "scanner": "aptto-dpkg-osv/1", "release": release, "architecture": architecture,
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
    parser.add_argument("--release", default="focal", help="target Ubuntu release codename")
    parser.add_argument("--architecture", default="amd64", help="target dpkg architecture")
    parser.add_argument("--image-id", help="container image digest or local image ID being scanned")
    args = parser.parse_args()
    try:
        report = scan(args.status_file, args.feed, args.release, args.architecture, args.image_id)
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
        print("AptTo scan failed: " + str(error), file=sys.stderr)
        return 2
    print(json.dumps(report, indent=2))
    return 1 if report["findings"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
