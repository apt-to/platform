#!/usr/bin/env python3
"""Compare raw Trivy and distribution OSV reference evidence without suppressing findings."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from platform_policy import package_target_policy, scanner_config, target_profile


def load(path):
    return json.loads(Path(path).read_text())


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def osv_targets(path, package, ecosystem, version, targets, *, required):
    wrapper = load(path)
    request = wrapper.get("request", {})
    wanted = {"package": {"name": package, "ecosystem": ecosystem}, "version": version}
    if request != wanted:
        raise ValueError(f"OSV request identity mismatch in {path}")
    response = wrapper.get("response")
    if not isinstance(response, dict) or set(response) - {"vulns", "next_page_token"}:
        raise ValueError(f"OSV response malformed in {path}")
    if "next_page_token" in response:
        raise ValueError(f"OSV response is paginated and incomplete in {path}")
    # OSV uses protobuf JSON encoding and may omit an empty repeated `vulns`
    # field entirely. A successful `{}` response therefore means no matches.
    records = response.get("vulns", [])
    if not isinstance(records, list):
        raise ValueError(f"OSV response missing vulnerability list in {path}")
    hits = {}
    for target in targets:
        matches = [v for v in records if target in (v.get("upstream", []) + v.get("aliases", []) + [v.get("id", "")])]
        if not matches and required:
            raise ValueError(f"{target} absent from Canonical OSV query for {version}")
        hits[target] = [v.get("id") for v in matches]
    return hits, sorted(v.get("id", "") for v in records)


def missing_osv_targets(hits):
    return sorted(target for target, matches in hits.items() if not matches)


def trivy_findings(path):
    report = load(path)
    vulnerabilities = []
    identified = []
    for section in report.get("Results", []):
        identified.extend(section.get("Packages", []))
        vulnerabilities.extend(section.get("Vulnerabilities", []))
    return report, vulnerabilities, identified


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path, help="JSON file containing evidence paths and identities")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        data = load(args.input)
        required = ("source", "targetId", "baselineVersion", "patchedVersion", "targetCves", "beforeTrivy", "afterTrivy", "beforeOsv", "afterOsv", "baselineRegression", "patchedRegression", "buildProvenance", "binaryManifest", "packagePolicy", "databaseSha256", "sourceCommit", "beforeScanMetadata", "afterScanMetadata", "scanImages", "aptToFeed", "beforeAptToScan", "afterAptToScan", "beforeAptToStatus", "afterAptToStatus")
        missing = [key for key in required if key not in data]
        if missing:
            raise ValueError("required evidence fields missing: " + ", ".join(missing))
        config = load(ROOT / "packages.json")
        profile = target_profile(config, data["targetId"])
        package = package_target_policy(config, data["source"], data["targetId"])
        scanner = scanner_config(config)
        targets = data["targetCves"]
        if targets != package["targetCves"]:
            raise ValueError("target CVE list differs from reviewed platform configuration")
        if data["baselineVersion"] != package["baselineVersion"] or data["patchedVersion"] != package["packageVersion"]:
            raise ValueError("package version identity does not match the configured backport")
        policy = load(data["packagePolicy"])
        provenance = load(data["buildProvenance"])
        manifest = load(data["binaryManifest"])
        baseline = load(data["baselineRegression"])
        patched = load(data["patchedRegression"])
        if (policy.get("source") != data["source"] or policy.get("targetId") != data["targetId"] or policy.get("targetCves") != targets
                or policy.get("baseVersion") != data["baselineVersion"]
                or policy.get("version") != data["patchedVersion"]
                or policy.get("releaseSerial") != package["releaseSerial"]):
            raise ValueError("Debian release policy identity mismatch")
        if (provenance.get("source") != data["source"] or provenance.get("targetId") != data["targetId"]
                or provenance.get("version") != data["patchedVersion"]
                or provenance.get("releaseSerial") != package["releaseSerial"]
                or provenance.get("sourceCommit") != data["sourceCommit"]
                or provenance.get("publication") != "none; binary outputs remained inside the disposable container"):
            raise ValueError("build provenance does not identify this unpublished source build")
        if baseline.get("phase") != "baseline" or baseline.get("source") != data["source"] or baseline.get("targetId") != data["targetId"] or baseline.get("installedVersion") != data["baselineVersion"] or not baseline.get("passed"):
            raise ValueError("vulnerable baseline regression evidence is missing or failed")
        if patched.get("phase") != "patched" or patched.get("source") != data["source"] or patched.get("targetId") != data["targetId"] or patched.get("installedVersion") != data["patchedVersion"] or not patched.get("passed"):
            raise ValueError("installed patched regression evidence is missing or failed")
        baseline_cves = {check.get("cve") for check in baseline.get("checks", []) if check.get("passed")}
        patched_cves = {check.get("cve") for check in patched.get("checks", []) if check.get("passed")}
        if not set(targets).issubset(baseline_cves) or not set(targets).issubset(patched_cves):
            raise ValueError("a configured target CVE lacks passing baseline or installed patched regression evidence")
        expected_binary_names = package["binaryPackages"]
        if (manifest.get("source") != data["source"] or manifest.get("targetId") != data["targetId"]
                or manifest.get("sourceVersion") != data["baselineVersion"]
                or manifest.get("version") != data["patchedVersion"]
                or manifest.get("architecture") != profile["architecture"]):
            raise ValueError("binary manifest does not identify this package target and version")
        manifest_packages = manifest.get("packages", [])
        for binary in expected_binary_names:
            candidates = [p for p in manifest_packages if p.get("control", "").startswith("Package: " + binary + "\n")]
            if len(candidates) != 1 or not re.fullmatch(r"[0-9a-f]{64}", candidates[0].get("sha256", "")) or data["patchedVersion"] not in candidates[0].get("name", ""):
                raise ValueError("binary manifest lacks exact version and SHA-256 for " + binary)
        if not re.fullmatch(r"[0-9a-f]{64}", data["databaseSha256"]):
            raise ValueError("invalid pinned scanner database digest")
        # The distribution OSV query is an unmodified public-vendor reference.
        # Keep its result separate from installed regressions and the exact-version GetPatched scan.
        before_osv, baseline_records = osv_targets(data["beforeOsv"], data["source"], profile["advisoryEcosystem"], data["baselineVersion"], targets, required=False)
        # OSV may omit a downstream +getpatched version or keep the vendor CVE
        # classification. Preserve either response without treating it as a fix.
        after_osv, patched_records = osv_targets(data["afterOsv"], data["source"], profile["advisoryEcosystem"], data["patchedVersion"], targets, required=False)
        before_raw, before_vulns, before_pkgs = trivy_findings(data["beforeTrivy"])
        after_raw, after_vulns, after_pkgs = trivy_findings(data["afterTrivy"])
        scan_images = load(data["scanImages"])
        expected_ids = {"before": scan_images.get("baselineImageId"), "after": scan_images.get("patchedImageId")}
        scan_metadata = {}
        for phase, report_path, packages_in_report in (("before", data["beforeTrivy"], before_pkgs), ("after", data["afterTrivy"], after_pkgs)):
            sidecar = load(data[phase + "ScanMetadata"])
            if sidecar.get("phase") != phase or sidecar.get("scannerImage") != scanner["image"] or sidecar.get("imageId") != expected_ids[phase] or sidecar.get("databaseSha256") != data["databaseSha256"] or sidecar.get("reportSha256") != sha256(report_path):
                raise ValueError(f"{phase} Trivy scan metadata does not bind the exact image, scanner, DB and raw report")
            for binary in package["binaryPackages"]:
                matches = [p for p in packages_in_report if p.get("Name") == binary]
                expected_version = data["baselineVersion"] if phase == "before" else data["patchedVersion"]
                if len(matches) != 1 or matches[0].get("ID") != binary + "@" + expected_version:
                    raise ValueError(f"{phase} Trivy report does not identify {binary} at the expected version")
            scan_metadata[phase] = {"imageId": sidecar["imageId"], "databaseSha256": sidecar["databaseSha256"], "reportSha256": sidecar["reportSha256"]}
        getpatched_feed = load(data["aptToFeed"])
        if getpatched_feed.get("schema_version") != "1.6.0" or not isinstance(getpatched_feed.get("vulns"), list):
            raise ValueError("GetPatched advisory feed is not OSV-format")
        feed_ids = {item.get("id") for item in getpatched_feed["vulns"]}
        if not set(targets).issubset(feed_ids):
            raise ValueError("GetPatched advisory feed is missing configured target CVEs")
        getpatched_scans = {}
        expected_advisory_names = package["advisoryPackages"]
        for phase in ("before", "after"):
            scan = load(data[phase + "AptToScan"])
            expected_version = data["baselineVersion"] if phase == "before" else data["patchedVersion"]
            package_versions = scan.get("scannedPackageVersions")
            if (scan.get("scanner") != "getpatched-dpkg-osv/1" or scan.get("targetId") != data["targetId"] or
                    scan.get("release") != profile["codename"] or scan.get("architecture") != profile["architecture"] or scan.get("imageId") != expected_ids[phase] or
                    scan.get("advisoryFeedSha256") != sha256(data["aptToFeed"]) or
                    scan.get("packagePolicySha256") != sha256(Path(__file__).resolve().parents[1] / "packages.json") or
                    scan.get("statusFileSha256") != sha256(data[phase + "AptToStatus"]) or
                    not isinstance(package_versions, dict) or
                    any(package_versions.get(name) != expected_version for name in expected_advisory_names)):
                raise ValueError(f"{phase} GetPatched scan does not bind the expected feed, image, package identities and versions")
            findings = scan.get("findings")
            if not isinstance(findings, list):
                raise ValueError(f"{phase} GetPatched scan findings are malformed")
            if any(not isinstance(item, dict) or not isinstance(item.get("id"), str) or not isinstance(item.get("package"), str) for item in findings):
                raise ValueError(f"{phase} GetPatched scan findings are malformed")
            findings_by_id = {item["id"] for item in findings}
            summary_ids = scan.get("findingsById")
            if not isinstance(summary_ids, list) or set(summary_ids) != findings_by_id:
                raise ValueError(f"{phase} GetPatched scan finding summary disagrees with its detailed findings")
            finding_pairs = {(item.get("id"), item.get("package")) for item in findings}
            expected_pairs = {(cve, binary) for cve in targets for binary in expected_advisory_names}
            if phase == "before" and (not set(targets).issubset(findings_by_id) or not expected_pairs.issubset(finding_pairs)):
                raise ValueError("before GetPatched scan did not detect every configured target CVE for every vulnerable binary package")
            if phase == "after" and findings_by_id & set(targets):
                raise ValueError(f"{phase} GetPatched scan does not prove the expected target advisory state")
            getpatched_scans[phase] = {
                "imageId": scan["imageId"], "reportSha256": sha256(data[phase + "AptToScan"]),
                "statusSha256": scan["statusFileSha256"],
                "targetFindingIds": sorted(findings_by_id & set(targets)),
                "unrelatedFindingIds": sorted(findings_by_id - set(targets)),
            }
        all_vulns = before_vulns + after_vulns
        before_target_hits = {v.get("VulnerabilityID") for v in before_vulns if v.get("VulnerabilityID") in targets}
        after_target_hits = {v.get("VulnerabilityID") for v in after_vulns if v.get("VulnerabilityID") in targets}
        unrelated = sorted({v.get("VulnerabilityID", "") for v in all_vulns if v.get("VulnerabilityID") not in targets})
        integrated_findings = [{
            "id": target,
            "baseline": "public distribution OSV target record recorded when present; vulnerable baseline regression reproduced",
            "patched": "resolved by GetPatched backport; exact installed version and target regression passed",
            "vendorFeedAfter": "Distribution OSV may continue to classify +getpatched builds within the vendor affected range; see unmodified raw response",
            "evidence": {"baselineOsvSha256": sha256(data["beforeOsv"]), "patchedOsvSha256": sha256(data["afterOsv"]), "baselineRegression": str(data["baselineRegression"]), "patchedRegression": str(data["patchedRegression"]), "sourceCommit": data["sourceCommit"]},
        } for target in targets]
        report = {
            "schemaVersion": 1, "source": data["source"], "targetId": data["targetId"], "distribution": profile["distribution"], "release": profile["codename"], "architecture": profile["architecture"],
            "baselineVersion": data["baselineVersion"], "patchedVersion": data["patchedVersion"], "sourceCommit": data["sourceCommit"],
            "scanner": {"image": scanner["image"], "databaseReference": scanner["databaseReference"], "databaseSha256": data["databaseSha256"], "before": scan_metadata["before"], "after": scan_metadata["after"]},
            "canonicalOsv": {"ecosystem": profile["advisoryEcosystem"], "before": {"responseSha256": sha256(data["beforeOsv"]), "targetRecords": before_osv, "missingTargetIds": missing_osv_targets(before_osv), "allRecordIds": baseline_records}, "after": {"responseSha256": sha256(data["afterOsv"]), "targetRecords": after_osv, "missingTargetIds": missing_osv_targets(after_osv), "allRecordIds": patched_records}},
            "trivy": {"before": {"sha256": sha256(data["beforeTrivy"]), "packageCount": len(before_pkgs), "findingCount": len(before_vulns), "targetFindings": [v for v in before_vulns if v.get("VulnerabilityID") in targets]}, "after": {"sha256": sha256(data["afterTrivy"]), "packageCount": len(after_pkgs), "findingCount": len(after_vulns), "targetFindings": [v for v in after_vulns if v.get("VulnerabilityID") in targets]}, "unrelatedFindings": unrelated},
            "aptToAdvisoryIntegration": {"source": "GetPatched OSV-format feed scan of installed dpkg status plus distribution OSV vendor-reference queries and installed regression evidence", "scanner": "getpatched-dpkg-osv/1", "feedSha256": sha256(data["aptToFeed"]), "before": getpatched_scans["before"], "after": getpatched_scans["after"], "baselineTargetFindingIds": getpatched_scans["before"]["targetFindingIds"], "patchedTargetFindingIds": getpatched_scans["after"]["targetFindingIds"], "unrelatedFindingIds": sorted(set(getpatched_scans["before"]["unrelatedFindingIds"]) | set(getpatched_scans["after"]["unrelatedFindingIds"])), "rawTrivyBaselineTargetFindingIds": sorted(before_target_hits), "rawTrivyPatchedTargetFindingIds": sorted(after_target_hits), "findings": integrated_findings, "claim": "custom GetPatched advisory scan; raw vendor Trivy findings, including any target findings, remain separately preserved and do not determine backport eligibility"},
            "regression": {"baseline": str(data["baselineRegression"]), "patched": str(data["patchedRegression"]), "targetCves": targets},
            "assessment": {"vendorPublishedVersionStatus": {"targetRecords": before_osv, "missingTargetIds": missing_osv_targets(before_osv), "interpretation": "public distribution OSV response preserved as vendor-reference evidence; target-record absence is not interpreted as clean or affected status"}, "aptToStatus": "backport regression and exact installed-package scan verified for configured target CVEs", "rawTrivyTargetFindingsAfter": sorted(after_target_hits), "unrelatedTrivyFindingsPreserved": True},
            "passed": True,
        }
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + "\n")
        print(data["source"] + ": audit passed; raw Trivy findings preserved, target regressions verified")
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
        print("advisory audit failed: " + str(error), file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
