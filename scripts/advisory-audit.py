#!/usr/bin/env python3
"""Compare raw Trivy and Canonical OSV evidence without suppressing findings."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys


def load(path):
    return json.loads(Path(path).read_text())


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def osv_targets(path, package, ecosystem, version, targets):
    wrapper = load(path)
    request = wrapper.get("request", {})
    wanted = {"package": {"name": package, "ecosystem": ecosystem}, "version": version}
    if request != wanted:
        raise ValueError(f"OSV request identity mismatch in {path}")
    records = wrapper.get("response", {}).get("vulns")
    if not isinstance(records, list):
        raise ValueError(f"OSV response missing vulnerability list in {path}")
    hits = {}
    for target in targets:
        matches = [v for v in records if target in (v.get("upstream", []) + v.get("aliases", []) + [v.get("id", "")])]
        if not matches:
            raise ValueError(f"{target} absent from Canonical OSV query for {version}")
        hits[target] = [v.get("id") for v in matches]
    return hits, sorted(v.get("id", "") for v in records)


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
        required = ("source", "baselineVersion", "patchedVersion", "targetCves", "beforeTrivy", "afterTrivy", "beforeOsv", "afterOsv", "baselineRegression", "patchedRegression", "buildProvenance", "binaryManifest", "packagePolicy", "databaseSha256", "sourceCommit", "beforeScanMetadata", "afterScanMetadata", "scanImages")
        missing = [key for key in required if key not in data]
        if missing:
            raise ValueError("required evidence fields missing: " + ", ".join(missing))
        config = load(Path(__file__).resolve().parents[1] / "packages.json")
        package = config["packages"][data["source"]]
        targets = data["targetCves"]
        if targets != package["targetCves"]:
            raise ValueError("target CVE list differs from reviewed platform configuration")
        if data["baselineVersion"] != package["baselineVersion"] or data["patchedVersion"] != package["baselineVersion"] + "+aptto1":
            raise ValueError("package version identity does not match the configured backport")
        policy = load(data["packagePolicy"])
        provenance = load(data["buildProvenance"])
        manifest = load(data["binaryManifest"])
        baseline = load(data["baselineRegression"])
        patched = load(data["patchedRegression"])
        if policy.get("source") != data["source"] or policy.get("targetCves") != targets or policy.get("baseVersion") != data["baselineVersion"] or policy.get("version") != data["patchedVersion"]:
            raise ValueError("Debian release policy identity mismatch")
        if provenance.get("source") != data["source"] or provenance.get("version") != data["patchedVersion"] or provenance.get("sourceCommit") != data["sourceCommit"] or provenance.get("publication") != "none; binary outputs remained inside the disposable container":
            raise ValueError("build provenance does not identify this unpublished source build")
        if baseline.get("phase") != "baseline" or baseline.get("source") != data["source"] or baseline.get("installedVersion") != data["baselineVersion"] or not baseline.get("passed"):
            raise ValueError("vulnerable baseline regression evidence is missing or failed")
        if patched.get("phase") != "patched" or patched.get("source") != data["source"] or patched.get("installedVersion") != data["patchedVersion"] or not patched.get("passed"):
            raise ValueError("installed patched regression evidence is missing or failed")
        baseline_cves = {check.get("cve") for check in baseline.get("checks", []) if check.get("passed")}
        patched_cves = {check.get("cve") for check in patched.get("checks", []) if check.get("passed")}
        if not set(targets).issubset(baseline_cves) or not set(targets).issubset(patched_cves):
            raise ValueError("a configured target CVE lacks passing baseline or installed patched regression evidence")
        expected_binary_names = package["binaryPackages"]
        manifest_packages = manifest.get("packages", [])
        for binary in expected_binary_names:
            candidates = [p for p in manifest_packages if p.get("control", "").startswith("Package: " + binary + "\n")]
            if len(candidates) != 1 or not re.fullmatch(r"[0-9a-f]{64}", candidates[0].get("sha256", "")) or data["patchedVersion"] not in candidates[0].get("name", ""):
                raise ValueError("binary manifest lacks exact version and SHA-256 for " + binary)
        if not re.fullmatch(r"[0-9a-f]{64}", data["databaseSha256"]):
            raise ValueError("invalid pinned scanner database digest")
        before_osv, baseline_records = osv_targets(data["beforeOsv"], data["source"], config["advisoryEcosystem"], data["baselineVersion"], targets)
        after_osv, patched_records = osv_targets(data["afterOsv"], data["source"], config["advisoryEcosystem"], data["patchedVersion"], targets)
        before_raw, before_vulns, before_pkgs = trivy_findings(data["beforeTrivy"])
        after_raw, after_vulns, after_pkgs = trivy_findings(data["afterTrivy"])
        scan_images = load(data["scanImages"])
        expected_ids = {"before": scan_images.get("baselineImageId"), "after": scan_images.get("patchedImageId")}
        scan_metadata = {}
        for phase, report_path, packages_in_report in (("before", data["beforeTrivy"], before_pkgs), ("after", data["afterTrivy"], after_pkgs)):
            sidecar = load(data[phase + "ScanMetadata"])
            if sidecar.get("phase") != phase or sidecar.get("scannerImage") != config["scannerImage"] or sidecar.get("imageId") != expected_ids[phase] or sidecar.get("databaseSha256") != data["databaseSha256"] or sidecar.get("reportSha256") != sha256(report_path):
                raise ValueError(f"{phase} Trivy scan metadata does not bind the exact image, scanner, DB and raw report")
            versions = {p.get("Name"): p.get("Version") for p in packages_in_report}
            for binary in package["binaryPackages"]:
                if versions.get(binary) != (data["baselineVersion"] if phase == "before" else data["patchedVersion"]):
                    raise ValueError(f"{phase} Trivy report does not identify {binary} at the expected version")
            scan_metadata[phase] = {"imageId": sidecar["imageId"], "databaseSha256": sidecar["databaseSha256"], "reportSha256": sidecar["reportSha256"]}
        all_vulns = before_vulns + after_vulns
        before_target_hits = {v.get("VulnerabilityID") for v in before_vulns if v.get("VulnerabilityID") in targets}
        after_target_hits = {v.get("VulnerabilityID") for v in after_vulns if v.get("VulnerabilityID") in targets}
        if after_target_hits:
            raise ValueError("raw Trivy still reports configured target CVEs on the patched image; investigate before claiming remediation")
        unrelated = sorted({v.get("VulnerabilityID", "") for v in all_vulns if v.get("VulnerabilityID") not in targets})
        integrated_findings = [{
            "id": target,
            "baseline": "affected; Canonical OSV matched exact Ubuntu version and vulnerable baseline regression reproduced",
            "patched": "resolved by AptTo backport; exact installed version and target regression passed",
            "vendorFeedAfter": "Ubuntu OSV may continue to classify +aptto builds within the Ubuntu vendor affected range; see unmodified raw response",
            "evidence": {"baselineOsvSha256": sha256(data["beforeOsv"]), "patchedOsvSha256": sha256(data["afterOsv"]), "baselineRegression": str(data["baselineRegression"]), "patchedRegression": str(data["patchedRegression"]), "sourceCommit": data["sourceCommit"]},
        } for target in targets]
        report = {
            "schemaVersion": 1, "source": data["source"], "release": config["release"], "architecture": config["architecture"],
            "baselineVersion": data["baselineVersion"], "patchedVersion": data["patchedVersion"], "sourceCommit": data["sourceCommit"],
            "scanner": {"image": config["scannerImage"], "databaseReference": config["scannerDatabaseReference"], "databaseSha256": data["databaseSha256"], "before": scan_metadata["before"], "after": scan_metadata["after"]},
            "canonicalOsv": {"ecosystem": config["advisoryEcosystem"], "before": {"responseSha256": sha256(data["beforeOsv"]), "targetRecords": before_osv, "allRecordIds": baseline_records}, "after": {"responseSha256": sha256(data["afterOsv"]), "targetRecords": after_osv, "allRecordIds": patched_records}},
            "trivy": {"before": {"sha256": sha256(data["beforeTrivy"]), "packageCount": len(before_pkgs), "findingCount": len(before_vulns), "targetFindings": [v for v in before_vulns if v.get("VulnerabilityID") in targets]}, "after": {"sha256": sha256(data["afterTrivy"]), "packageCount": len(after_pkgs), "findingCount": len(after_vulns), "targetFindings": [v for v in after_vulns if v.get("VulnerabilityID") in targets]}, "unrelatedFindings": unrelated},
            "aptToAdvisoryIntegration": {"source": "Canonical Ubuntu OSV exact-version queries plus verified installed regression evidence", "baselineTargetFindingIds": sorted(before_target_hits), "patchedTargetFindingIds": sorted(after_target_hits), "findings": integrated_findings, "claim": "custom AptTo advisory scan; raw vendor Trivy reports remain separately preserved"},
            "regression": {"baseline": str(data["baselineRegression"]), "patched": str(data["patchedRegression"]), "targetCves": targets},
            "assessment": {"ubuntuPublishedVersionStatus": "affected per Canonical OSV version query; preserved as vendor status", "aptToStatus": "backport regression verified for configured target CVEs; upstream vendor OSV still describes Ubuntu package versions", "unrelatedTrivyFindingsPreserved": True},
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
