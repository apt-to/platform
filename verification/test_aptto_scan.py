"""End-to-end contract for AptTo's OSV-compatible dpkg advisory scanner."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCANNER = ROOT / "scripts" / "aptto-scan.py"
FEED = ROOT / "advisories" / "aptto-osv.json"


class AptToScannerContract(unittest.TestCase):
    def scan_packages(self, entries):
        status = "\n\n".join(
            f"Package: {name}\nStatus: install ok installed\nVersion: {version}\nArchitecture: amd64"
            for name, version in entries.items()
        ) + "\n"
        return self.scan(status)

    def scan(self, status_text, feed=FEED, architecture="amd64"):
        with tempfile.TemporaryDirectory(prefix="aptto-scan-test-") as directory:
            status = Path(directory) / "status"
            status.write_text(status_text)
            return subprocess.run(
                [sys.executable, str(SCANNER), "--feed", str(feed), "--status-file", str(status), "--architecture", architecture],
                capture_output=True, text=True, check=False,
            )

    def test_baselines_are_found_and_tested_backports_are_clean(self):
        baseline = self.scan("""Package: libxml2
Status: install ok installed
Version: 2.9.10+dfsg-5ubuntu0.20.04.10
Architecture: amd64

Package: libxml2-utils
Status: install ok installed
Version: 2.9.10+dfsg-5ubuntu0.20.04.10
Architecture: amd64

Package: libarchive13
Status: install ok installed
Version: 3.4.0-2ubuntu1.5
Architecture: amd64

Package: libarchive-tools
Status: install ok installed
Version: 3.4.0-2ubuntu1.5
Architecture: amd64
""")
        self.assertEqual(baseline.returncode, 1, baseline.stderr)
        before = json.loads(baseline.stdout)
        self.assertEqual(set(before["findingsById"]), {"CVE-2025-49794", "CVE-2025-49796", "CVE-2026-4111"})
        self.assertEqual(before["summary"]["vulnerablePackages"], 4)
        self.assertEqual({(item["id"], item["package"]) for item in before["findings"]}, {
            (cve, package) for cve, packages in (
                ("CVE-2025-49794", {"libxml2", "libxml2-utils"}),
                ("CVE-2025-49796", {"libxml2", "libxml2-utils"}),
                ("CVE-2026-4111", {"libarchive13", "libarchive-tools"}),
            ) for package in packages
        })

        patched = self.scan("""Package: libxml2
Status: install ok installed
Version: 2.9.10+dfsg-5ubuntu0.20.04.10+aptto1
Architecture: amd64

Package: libxml2-utils
Status: install ok installed
Version: 2.9.10+dfsg-5ubuntu0.20.04.10+aptto1
Architecture: amd64

Package: libarchive13
Status: install ok installed
Version: 3.4.0-2ubuntu1.5+aptto1
Architecture: amd64

Package: libarchive-tools
Status: install ok installed
Version: 3.4.0-2ubuntu1.5+aptto1
Architecture: amd64
""")
        self.assertEqual(patched.returncode, 0, patched.stderr)
        after = json.loads(patched.stdout)
        self.assertEqual(after["findings"], [])
        self.assertEqual(after["summary"]["scannedPackages"], 4)
        self.assertEqual(after["summary"]["vulnerablePackages"], 0)
        self.assertEqual(after["scanner"], "aptto-dpkg-osv/1")

    def test_uninstalled_and_wrong_architecture_packages_are_not_reported(self):
        result = self.scan("""Package: libarchive13
Status: deinstall ok config-files
Version: 3.4.0-2ubuntu1.5
Architecture: amd64

Package: libarchive-tools
Status: install ok installed
Version: 3.4.0-2ubuntu1.5
Architecture: arm64
""")
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["findings"], [])
        self.assertEqual(report["summary"]["scannedPackages"], 0)

    def test_scan_rejects_architectures_without_advisory_coverage(self):
        result = self.scan("""Package: libarchive13
Status: install ok installed
Version: 3.4.0-2ubuntu1.5
Architecture: arm64
""", architecture="arm64")
        self.assertEqual(result.returncode, 2)
        self.assertIn("no coverage for focal/arm64", result.stderr)

    def test_same_package_can_be_installed_for_multiple_architectures(self):
        result = self.scan("""Package: libxml2
Status: install ok installed
Version: 2.9.10+dfsg-5ubuntu0.20.04.10
Architecture: amd64

Package: libxml2
Status: install ok installed
Version: 2.9.10+dfsg-5ubuntu0.20.04.10
Architecture: i386
""")
        self.assertEqual(result.returncode, 1, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["scannedPackageVersions"], {"libxml2": "2.9.10+dfsg-5ubuntu0.20.04.10"})
        self.assertEqual(set(report["findingsById"]), {"CVE-2025-49794", "CVE-2025-49796"})

    def test_aptto_revisions_and_canonical_esm_fixed_versions_are_clean(self):
        result = self.scan_packages({
            "libxml2": "2.9.10+dfsg-5ubuntu0.20.04.10+aptto2",
            "libxml2-utils": "2.9.10+dfsg-5ubuntu0.20.04.10+esm1",
            "libarchive13": "3.4.0-2ubuntu1.5+aptto2",
            "libarchive-tools": "3.4.0-2ubuntu1.5+esm1",
        })
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["findings"], [])
        self.assertEqual(report["summary"]["scannedPackages"], 4)

    def test_only_the_reviewed_baseline_version_is_asserted_affected(self):
        result = self.scan_packages({
            "libarchive13": "3.4.0-2ubuntu1.5",
            "libarchive-tools": "3.4.0-2ubuntu1.4",
        })
        self.assertEqual(result.returncode, 1, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual([(item["package"], item["id"]) for item in report["findings"]], [("libarchive13", "CVE-2026-4111")])

    def test_unreviewed_older_versions_are_not_inferred_vulnerable(self):
        result = self.scan_packages({
            "libarchive13": "3.4.0-2ubuntu1.4",
            "libarchive-tools": "3.4.0-2ubuntu1.3",
        })
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["findings"], [])

    def test_feed_generation_is_reproducible_and_has_exact_binary_identities(self):
        with tempfile.TemporaryDirectory(prefix="aptto-feed-test-") as directory:
            output = Path(directory) / "feed.json"
            subprocess.run([sys.executable, str(ROOT / "scripts" / "build_aptto_advisory_feed.py"), "--output", str(output)], check=True, capture_output=True, text=True)
            generated = json.loads(output.read_text())
        committed = json.loads(FEED.read_text())
        self.assertEqual(generated, committed)
        self.assertEqual({item["id"] for item in committed["vulns"]}, {"CVE-2025-49794", "CVE-2025-49796", "CVE-2026-4111"})
        self.assertTrue(all(affected["package"]["ecosystem"] == "Ubuntu:Pro:20.04:LTS"
                            for item in committed["vulns"] for affected in item["affected"]))
        self.assertTrue(all("ranges" not in affected for item in committed["vulns"] for affected in item["affected"]))

    def test_scanner_rejects_feed_that_disagrees_with_reviewed_package_policy(self):
        with tempfile.TemporaryDirectory(prefix="aptto-feed-tamper-") as directory:
            tampered = Path(directory) / "tampered.json"
            document = json.loads(FEED.read_text())
            document["vulns"][0]["affected"][0]["database_specific"]["fixed_versions"][0] += "0"
            tampered.write_text(json.dumps(document))
            # Invoke the public CLI with the tampered feed and a real dpkg-status stanza.
            result = self.scan("Package: libarchive13\nStatus: install ok installed\nVersion: 3.4.0-2ubuntu1.5\nArchitecture: amd64\n", tampered)
        self.assertEqual(result.returncode, 2)
        self.assertIn("does not match the reviewed AptTo package policy", result.stderr)


if __name__ == "__main__":
    unittest.main()
