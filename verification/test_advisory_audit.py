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
        with tempfile.TemporaryDirectory(prefix="aptto-audit-test-") as directory:
            root = Path(directory)
            fixture = root / "input.json"
            fixture.write_text(json.dumps({"source": "libarchive"}))
            result = self.invoke(fixture, root / "report.json")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("required evidence", result.stderr.lower())

    def test_raw_reports_are_hash_bound_and_not_rewritten(self):
        with tempfile.TemporaryDirectory(prefix="aptto-audit-test-") as directory:
            root = Path(directory)
            before = root / "before.json"
            after = root / "after.json"
            before_data = {"Results": [{"Packages": [{"Name": "libarchive13", "Version": "3.4.0", "Release": "2ubuntu1.5", "ID": "libarchive13@3.4.0-2ubuntu1.5"}, {"Name": "libarchive-tools", "Version": "3.4.0", "Release": "2ubuntu1.5", "ID": "libarchive-tools@3.4.0-2ubuntu1.5"}], "Vulnerabilities": [{"VulnerabilityID": "CVE-UNRELATED", "PkgName": "libarchive13"}]}]}
            after_data = {"Results": [{"Packages": [{"Name": "libarchive13", "Version": "3.4.0", "Release": "2ubuntu1.5+aptto1", "ID": "libarchive13@3.4.0-2ubuntu1.5+aptto1"}, {"Name": "libarchive-tools", "Version": "3.4.0", "Release": "2ubuntu1.5+aptto1", "ID": "libarchive-tools@3.4.0-2ubuntu1.5+aptto1"}], "Vulnerabilities": [{"VulnerabilityID": "CVE-UNRELATED", "PkgName": "libarchive13"}]}]}
            before.write_text(json.dumps(before_data))
            after.write_text(json.dumps(after_data))
            osv_before = root / "osv-before.json"
            osv_after = root / "osv-after.json"
            request_before = {"package": {"name": "libarchive", "ecosystem": "Ubuntu:Pro:20.04:LTS"}, "version": "3.4.0-2ubuntu1.5"}
            request_after = {"package": {"name": "libarchive", "ecosystem": "Ubuntu:Pro:20.04:LTS"}, "version": "3.4.0-2ubuntu1.5+aptto1"}
            record = {"id": "UBUNTU-CVE-2026-4111", "upstream": ["CVE-2026-4111"]}
            for path, request_body in ((osv_before, request_before), (osv_after, request_after)):
                path.write_text(json.dumps({"request": request_body, "endpoint": "https://api.osv.dev/v1/query", "response": {"vulns": [record]}}))
            image_ids = {"baselineImageId": "sha256:baseline", "patchedImageId": "sha256:patched"}
            image_path = root / "images.json"
            image_path.write_text(json.dumps(image_ids))
            sidecars = {}
            for phase, report_path in (("before", before), ("after", after)):
                sidecar_path = root / (phase + "-scan.json")
                sidecar_path.write_text(json.dumps({"phase": phase, "scannerImage": "aquasec/trivy:0.70.0@sha256:85e87be1a96459c38a4eea47dc64eb2d342bb14cd4b4cef96adcf6ff03378b7c", "imageId": image_ids["baselineImageId" if phase == "before" else "patchedImageId"], "databaseSha256": "05a1fa5372e54059b6a7c1fc41afb812fafd9bd56a8e0ab6aa20d7f3f154ff31", "reportSha256": hashlib.sha256(report_path.read_bytes()).hexdigest()}))
                sidecars[phase] = str(sidecar_path)
            input_data = {
                "source": "libarchive",
                "baselineVersion": "3.4.0-2ubuntu1.5",
                "patchedVersion": "3.4.0-2ubuntu1.5+aptto1",
                "targetCves": ["CVE-2026-4111"],
                "beforeTrivy": str(before), "afterTrivy": str(after),
                "beforeOsv": str(osv_before), "afterOsv": str(osv_after),
                "baselineRegression": str(ROOT / "evidence/build-401896-libarchive/baseline-regression.json"),
                "patchedRegression": str(ROOT / "evidence/build-401896-libarchive/patched-regression.json"),
                "buildProvenance": str(ROOT / "evidence/build-401896-libarchive/build-provenance.json"),
                "binaryManifest": str(ROOT / "evidence/build-401896-libarchive/binary-manifest.json"),
                "packagePolicy": str(ROOT.parent / "packaging-libarchive/debian/aptto/release-policy.json"),
                "databaseSha256": "05a1fa5372e54059b6a7c1fc41afb812fafd9bd56a8e0ab6aa20d7f3f154ff31",
                "sourceCommit": "cad024301c68bb6cf2e4261d350095aaf050703f",
                "beforeScanMetadata": sidecars["before"], "afterScanMetadata": sidecars["after"], "scanImages": str(image_path),
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
            self.assertEqual(report["aptToAdvisoryIntegration"]["baselineTargetFindingIds"], [])
            self.assertEqual(report["aptToAdvisoryIntegration"]["patchedTargetFindingIds"], [])
            self.assertEqual(report["aptToAdvisoryIntegration"]["findings"][0]["patched"], "resolved by AptTo backport; exact installed version and target regression passed")
            self.assertEqual(hashlib.sha256(before.read_bytes()).hexdigest(), original_before)
            self.assertEqual(hashlib.sha256(after.read_bytes()).hexdigest(), original_after)
            after_metadata_path = Path(sidecars["after"])
            after_metadata = json.loads(after_metadata_path.read_text())
            after_metadata["databaseSha256"] = "0" * 64
            after_metadata_path.write_text(json.dumps(after_metadata))
            mismatch = self.invoke(fixture, root / "mismatch.json")
            self.assertNotEqual(mismatch.returncode, 0)
            self.assertIn("scan metadata", mismatch.stderr.lower())


if __name__ == "__main__":
    unittest.main()
