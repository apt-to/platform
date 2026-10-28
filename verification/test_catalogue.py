import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
import importlib.util

sys.path.insert(0, str(ROOT / "scripts"))
_SCAN_SPEC = importlib.util.spec_from_file_location("getpatched_scan", ROOT / "scripts/getpatched-scan.py")
_SCAN = importlib.util.module_from_spec(_SCAN_SPEC)
_SCAN_SPEC.loader.exec_module(_SCAN)
debian_version_compare = _SCAN.debian_version_compare


class PublicCatalogueContract(unittest.TestCase):
    def test_catalogue_matches_release_policy_without_claiming_public_downloads(self):
        platform = json.loads((ROOT / "packages.json").read_text())
        catalogue = json.loads((ROOT / "site/catalogue.json").read_text())
        entries = {item["source"]: item for item in catalogue["packages"]}
        self.assertEqual(set(entries), set(platform["packages"]))
        self.assertEqual(catalogue["target"]["suite"], platform["release"])
        self.assertEqual(catalogue["target"]["architecture"], platform["architecture"])
        for source, policy in platform["packages"].items():
            entry = entries[source]
            self.assertEqual(entry["version"], policy["baselineVersion"] + "+getpatched1")
            old_version = policy["baselineVersion"] + "+aptto1"
            self.assertLess(debian_version_compare(old_version, entry["version"]), 0)
            self.assertEqual(entry["cves"], policy["targetCves"])
            self.assertEqual(entry["delayHours"], policy["sponsorDelayHours"])
            self.assertEqual(entry["access"], "sponsor" if policy["sponsorDelayHours"] else "public")
            self.assertEqual(entry["status"], "esm-compatibility-pending")
            self.assertIsNone(entry["verification"])
            self.assertTrue(entry["verificationUrl"].startswith("https://github.com/getpatched/platform/actions/runs/"))
            self.assertTrue(entry["sourceUrl"].startswith(f"https://github.com/getpatched/packaging-{source}/tree/"))
            self.assertTrue(entry["patchUrl"].startswith(f"https://github.com/getpatched/packaging-{source}/blob/"))
            self.assertEqual(entry["testsUrl"], f"https://github.com/getpatched/packaging-{source}/tree/getpatched/focal/debian/tests")
            self.assertEqual(entry["releasesUrl"], f"https://github.com/getpatched/packaging-{source}/releases")
            self.assertEqual(entry["releaseStatus"], "No production release")

        page = (ROOT / "site/index.html").read_text()
        self.assertIn("The protected signing key passed a disposable repository self-test", page)
        self.assertIn("authentic Ubuntu Pro ESM compatibility", page)
        self.assertIn("package publication and downloads remain disabled until all release gates pass", page)
        self.assertIn("synthetic ESM candidates and do not prove compatibility with real Ubuntu Pro packages", page)
        self.assertIn("Each row links to its source, patch, regression tests and release history", page)
        self.assertIn("Any sponsor delay starts at sponsor publication", page)
        self.assertIn("The hosted checks use synthetic ESM candidates and do not prove compatibility with real Ubuntu Pro packages", page)
        self.assertIn("temporary signed APT client smoke test", page)
        app = (ROOT / "site/catalogue.js").read_text()
        self.assertIn("Hosted builds, regressions and signed-client checks passed", app)
        self.assertIn("item.verificationUrl", app)
        for label in ("Source", "Patch", "Tests", "Releases"):
            self.assertIn(f">{label} ↗</a>", app)
        for field in ("patchUrl", "testsUrl", "releasesUrl", "releaseStatus"):
            self.assertIn(f"item.{field}", app)
        self.assertIn("Public ${escapeHtml(item.delayHours)} hours after sponsor release", app)
        self.assertNotIn("Public 168 hours after sponsor release", app)
        self.assertIn("open the public package source repositories on GitHub", page)
        self.assertNotIn("browse the public package repositories directly", page)
        self.assertIn('all: packages.length', app)
        self.assertIn('sponsor: packages.filter((item) => item.access === "sponsor").length', app)
        self.assertIn('public: packages.filter((item) => item.access === "public").length', app)
        self.assertNotIn('"02"', page)
        self.assertNotIn('"01"', page)


if __name__ == "__main__":
    unittest.main()
