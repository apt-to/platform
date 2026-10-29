"""Public CLI contract tests for the advisory audit."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
AUDIT = ROOT / "scripts/advisory-audit.py"


class AdvisoryAuditContract(unittest.TestCase):
    def invoke(self, fixture, output):
        return subprocess.run(
            [sys.executable, str(AUDIT), "--input", str(fixture), "--output", str(output)],
            capture_output=True, text=True, check=False,
        )

    def test_audit_requires_real_raw_reports_osv_and_installed_test_evidence(self):
        with tempfile.TemporaryDirectory(prefix="getpatched-audit-test-") as directory:
            root = Path(directory)
            fixture = root / "input.json"
            fixture.write_text(json.dumps({"source": "libarchive"}))
            result = self.invoke(fixture, root / "report.json")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("required evidence", result.stderr.lower())

    def test_raw_reports_are_hash_bound_and_not_rewritten(self):
        with tempfile.TemporaryDirectory(prefix="getpatched-audit-test-") as directory:
            root = Path(directory)
            before = root / "before.json"
            after = root / "after.json"
            before_data = {"Results": [{"Packages": [{"Name": "libarchive13", "Version": "3.4.0", "Release": "2ubuntu1.5", "ID": "libarchive13@3.4.0-2ubuntu1.5"}, {"Name": "libarchive-tools", "Version": "3.4.0", "Release": "2ubuntu1.5", "ID": "libarchive-tools@3.4.0-2ubuntu1.5"}], "Vulnerabilities": [{"VulnerabilityID": "CVE-UNRELATED", "PkgName": "libarchive13"}]}]}
            after_data = {"Results": [{"Packages": [{"Name": "libarchive13", "Version": "3.4.0", "Release": "2ubuntu1.5+getpatched1", "ID": "libarchive13@3.4.0-2ubuntu1.5+getpatched1"}, {"Name": "libarchive-tools", "Version": "3.4.0", "Release": "2ubuntu1.5+getpatched1", "ID": "libarchive-tools@3.4.0-2ubuntu1.5+getpatched1"}], "Vulnerabilities": [{"VulnerabilityID": "CVE-UNRELATED", "PkgName": "libarchive13"}, {"VulnerabilityID": "CVE-2026-4111", "PkgName": "libarchive13"}]}]}
            before.write_text(json.dumps(before_data))
            after.write_text(json.dumps(after_data))
            osv_before = root / "osv-before.json"
            osv_after = root / "osv-after.json"
            request_before = {"package": {"name": "libarchive", "ecosystem": "Ubuntu:20.04:LTS"}, "version": "3.4.0-2ubuntu1.5"}
            request_after = {"package": {"name": "libarchive", "ecosystem": "Ubuntu:20.04:LTS"}, "version": "3.4.0-2ubuntu1.5+getpatched1"}
            record = {"id": "UBUNTU-CVE-2026-4111", "upstream": ["CVE-2026-4111"]}
            osv_before.write_text(json.dumps({"request": request_before, "endpoint": "https://api.osv.dev/v1/query", "response": {}}))
            osv_after.write_text(json.dumps({"request": request_after, "endpoint": "https://api.osv.dev/v1/query", "response": {"vulns": [record]}}))
            image_ids = {"baselineImageId": "sha256:baseline", "patchedImageId": "sha256:patched"}
            image_path = root / "images.json"
            image_path.write_text(json.dumps(image_ids))
            getpatched_feed = ROOT / "advisories" / "getpatched-osv.json"
            getpatched_scan_paths = {}
            for phase, version, image_id, ids in (
                ("before", "3.4.0-2ubuntu1.5", image_ids["baselineImageId"], ["CVE-2026-4111"]),
                ("after", "3.4.0-2ubuntu1.5+getpatched1", image_ids["patchedImageId"], []),
            ):
                status_path = root / (phase + "-getpatched-status")
                status_path.write_text("verified status inventory " + phase)
                scan_path = root / (phase + "-getpatched-scan.json")
                scan_path.write_text(json.dumps({
                    "scanner": "getpatched-dpkg-osv/1", "targetId": "ubuntu-focal-amd64", "release": "focal", "architecture": "amd64", "imageId": image_id,
                    "advisoryFeedSha256": hashlib.sha256(getpatched_feed.read_bytes()).hexdigest(),
                    "packagePolicySha256": hashlib.sha256((ROOT / "packages.json").read_bytes()).hexdigest(),
                    "statusFileSha256": hashlib.sha256(status_path.read_bytes()).hexdigest(),
                    "scannedPackageVersions": {"libarchive13": version, "libarchive-tools": version},
                    "findingsById": ids + (["CVE-UNRELATED"] if phase == "before" else []),
                    "findings": [{"id": cve, "package": name} for cve in ids + (["CVE-UNRELATED"] if phase == "before" else []) for name in ("libarchive13", "libarchive-tools")],
                }))
                getpatched_scan_paths[phase] = (scan_path, status_path)
            package_policy = root / "release-policy.json"
            package_policy.write_text(json.dumps({
                "source": "libarchive",
                "targetId": "ubuntu-focal-amd64",
                "targetCves": ["CVE-2026-4111"],
                "baseVersion": "3.4.0-2ubuntu1.5",
                "version": "3.4.0-2ubuntu1.5+getpatched1",
                "releaseSerial": 1,
            }))
            sidecars = {}
            for phase, report_path in (("before", before), ("after", after)):
                sidecar_path = root / (phase + "-scan.json")
                sidecar_path.write_text(json.dumps({"phase": phase, "scannerImage": "aquasec/trivy:0.70.0@sha256:85e87be1a96459c38a4eea47dc64eb2d342bb14cd4b4cef96adcf6ff03378b7c", "imageId": image_ids["baselineImageId" if phase == "before" else "patchedImageId"], "databaseSha256": "05a1fa5372e54059b6a7c1fc41afb812fafd9bd56a8e0ab6aa20d7f3f154ff31", "reportSha256": hashlib.sha256(report_path.read_bytes()).hexdigest()}))
                sidecars[phase] = str(sidecar_path)
            historical_evidence = ROOT / "evidence/build-401896-libarchive"
            evidence_paths = {}
            for name in ("baseline-regression.json", "patched-regression.json", "build-provenance.json", "binary-manifest.json"):
                evidence_path = root / name
                evidence = json.loads((historical_evidence / name).read_text().replace("+aptto1", "+getpatched1"))
                evidence["targetId"] = "ubuntu-focal-amd64"
                if name in ("baseline-regression.json", "patched-regression.json"):
                    evidence.update(distribution="Ubuntu", release="focal", architecture="amd64")
                elif name == "binary-manifest.json":
                    evidence.update(source="libarchive", sourceVersion="3.4.0-2ubuntu1.5",
                                    version="3.4.0-2ubuntu1.5+getpatched1", architecture="amd64")
                evidence_path.write_text(json.dumps(evidence))
                evidence_paths[name] = str(evidence_path)
            build_provenance = json.loads(Path(evidence_paths["build-provenance.json"]).read_text())
            build_provenance["releaseSerial"] = 1
            Path(evidence_paths["build-provenance.json"]).write_text(json.dumps(build_provenance))
            input_data = {
                "source": "libarchive",
                "targetId": "ubuntu-focal-amd64",
                "baselineVersion": "3.4.0-2ubuntu1.5",
                "patchedVersion": "3.4.0-2ubuntu1.5+getpatched1",
                "targetCves": ["CVE-2026-4111"],
                "beforeTrivy": str(before), "afterTrivy": str(after),
                "beforeOsv": str(osv_before), "afterOsv": str(osv_after),
                "baselineRegression": evidence_paths["baseline-regression.json"],
                "patchedRegression": evidence_paths["patched-regression.json"],
                "buildProvenance": evidence_paths["build-provenance.json"],
                "binaryManifest": evidence_paths["binary-manifest.json"],
                "packagePolicy": str(package_policy),
                "databaseSha256": "05a1fa5372e54059b6a7c1fc41afb812fafd9bd56a8e0ab6aa20d7f3f154ff31",
                "sourceCommit": "cad024301c68bb6cf2e4261d350095aaf050703f",
                "beforeScanMetadata": sidecars["before"], "afterScanMetadata": sidecars["after"], "scanImages": str(image_path),
                "aptToFeed": str(getpatched_feed),
                "beforeAptToScan": str(getpatched_scan_paths["before"][0]), "afterAptToScan": str(getpatched_scan_paths["after"][0]),
                "beforeAptToStatus": str(getpatched_scan_paths["before"][1]), "afterAptToStatus": str(getpatched_scan_paths["after"][1]),
            }
            fixture = root / "input.json"
            fixture.write_text(json.dumps(input_data))
            original_before = hashlib.sha256(before.read_bytes()).hexdigest()
            original_after = hashlib.sha256(after.read_bytes()).hexdigest()
            result = self.invoke(fixture, root / "report.json")
            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads((root / "report.json").read_text())
            self.assertTrue(report["passed"])
            self.assertEqual(report["trivy"]["before"]["sha256"], original_before)
            self.assertEqual(report["trivy"]["after"]["sha256"], original_after)
            self.assertIn("CVE-UNRELATED", report["trivy"]["unrelatedFindings"])
            self.assertEqual(report["aptToAdvisoryIntegration"]["baselineTargetFindingIds"], ["CVE-2026-4111"])
            self.assertEqual(report["aptToAdvisoryIntegration"]["patchedTargetFindingIds"], [])
            self.assertEqual(report["aptToAdvisoryIntegration"]["unrelatedFindingIds"], ["CVE-UNRELATED"])
            self.assertEqual(report["aptToAdvisoryIntegration"]["rawTrivyBaselineTargetFindingIds"], [])
            self.assertEqual(report["aptToAdvisoryIntegration"]["rawTrivyPatchedTargetFindingIds"], ["CVE-2026-4111"])
            self.assertEqual(report["assessment"]["rawTrivyTargetFindingsAfter"], ["CVE-2026-4111"])
            self.assertEqual(report["aptToAdvisoryIntegration"]["findings"][0]["patched"], "resolved by GetPatched backport; exact installed version and target regression passed")
            self.assertEqual(report["canonicalOsv"]["after"]["missingTargetIds"], [])
            self.assertEqual(report["canonicalOsv"]["before"]["missingTargetIds"], ["CVE-2026-4111"])
            self.assertIn("absence is not interpreted", report["assessment"]["vendorPublishedVersionStatus"]["interpretation"])
            self.assertEqual(report["assessment"]["vendorPublishedVersionStatus"]["missingTargetIds"], ["CVE-2026-4111"])
            self.assertEqual(hashlib.sha256(before.read_bytes()).hexdigest(), original_before)
            self.assertEqual(hashlib.sha256(after.read_bytes()).hexdigest(), original_after)
            contradictory = json.loads(getpatched_scan_paths["after"][0].read_text())
            contradictory["findings"] = [{"id": "CVE-2026-4111", "package": "libarchive13"}]
            contradictory["findingsById"] = []
            getpatched_scan_paths["after"][0].write_text(json.dumps(contradictory))
            inconsistent = self.invoke(fixture, root / "inconsistent.json")
            self.assertNotEqual(inconsistent.returncode, 0)
            self.assertIn("summary disagrees", inconsistent.stderr)
            after_metadata_path = Path(sidecars["after"])
            after_metadata = json.loads(after_metadata_path.read_text())
            after_metadata["databaseSha256"] = "0" * 64
            after_metadata_path.write_text(json.dumps(after_metadata))
            mismatch = self.invoke(fixture, root / "mismatch.json")
            self.assertNotEqual(mismatch.returncode, 0)
            self.assertIn("scan metadata", mismatch.stderr.lower())

    def test_vendor_osv_absence_on_patched_version_is_preserved_but_not_treated_as_scan_evidence(self):
        with tempfile.TemporaryDirectory(prefix="getpatched-audit-osv-absence-") as directory:
            root = Path(directory)
            # Reuse the complete audited fixture assembled above by keeping this
            # case narrow: exercise the public helper against a genuine OSV query
            # wrapper whose successful response has no target records.
            from importlib.util import module_from_spec, spec_from_file_location
            spec = spec_from_file_location("advisory_audit", AUDIT)
            module = module_from_spec(spec)
            spec.loader.exec_module(module)
            response = root / "osv.json"
            response.write_text(json.dumps({
                "request": {"package": {"name": "libarchive", "ecosystem": "Ubuntu:20.04:LTS"}, "version": "3.4.0-2ubuntu1.5+getpatched1"},
                "endpoint": "https://api.osv.dev/v1/query", "response": {},
            }))
            hits, records = module.osv_targets(response, "libarchive", "Ubuntu:20.04:LTS", "3.4.0-2ubuntu1.5+getpatched1", ["CVE-2026-4111"], required=False)
            self.assertEqual(hits, {"CVE-2026-4111": []})
            self.assertEqual(records, [])
            self.assertEqual(module.osv_targets(response, "libarchive", "Ubuntu:20.04:LTS", "3.4.0-2ubuntu1.5+getpatched1", ["CVE-2026-4111"], required=False), ({"CVE-2026-4111": []}, []))

    def test_absent_public_baseline_record_is_preserved_as_optional_vendor_evidence(self):
        with tempfile.TemporaryDirectory(prefix="getpatched-audit-public-baseline-") as directory:
            root = Path(directory)
            response = root / "osv.json"
            response.write_text(json.dumps({
                "request": {"package": {"name": "libarchive", "ecosystem": "Ubuntu:20.04:LTS"}, "version": "3.4.0-2ubuntu1.5"},
                "endpoint": "https://api.osv.dev/v1/query", "response": {"vulns": []},
            }))
            module = __import__("importlib.util", fromlist=["spec_from_file_location"])
            spec = module.spec_from_file_location("advisory_audit", AUDIT)
            audit = module.module_from_spec(spec)
            spec.loader.exec_module(audit)
            hits, records = audit.osv_targets(response, "libarchive", "Ubuntu:20.04:LTS", "3.4.0-2ubuntu1.5", ["CVE-2026-4111"], required=False)
            self.assertEqual(hits, {"CVE-2026-4111": []})
            self.assertEqual(records, [])
            for token in ("more", ""):
                response.write_text(json.dumps({
                    "request": {"package": {"name": "libarchive", "ecosystem": "Ubuntu:20.04:LTS"}, "version": "3.4.0-2ubuntu1.5"},
                    "endpoint": "https://api.osv.dev/v1/query", "response": {"next_page_token": token},
                }))
                with self.assertRaisesRegex(ValueError, "paginated and incomplete"):
                    audit.osv_targets(response, "libarchive", "Ubuntu:20.04:LTS", "3.4.0-2ubuntu1.5", ["CVE-2026-4111"], required=False)


if __name__ == "__main__":
    unittest.main()
