import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class PublicCatalogueContract(unittest.TestCase):
    def test_catalogue_matches_release_policy_without_claiming_public_downloads(self):
        platform = json.loads((ROOT / "packages.json").read_text())
        catalogue = json.loads((ROOT / "site/catalogue.json").read_text())
        entries = {item["source"]: item for item in catalogue["packages"]}
        verification_runs = {
            "libxml2": "https://github.com/getpatched/platform/actions/runs/40640693660",
            "libarchive": "https://github.com/getpatched/platform/actions/runs/40640691922",
        }
        self.assertEqual(set(entries), set(platform["packages"]))
        self.assertEqual(catalogue["target"]["suite"], platform["release"])
        self.assertEqual(catalogue["target"]["architecture"], platform["architecture"])
        for source, policy in platform["packages"].items():
            entry = entries[source]
            self.assertEqual(entry["version"], policy["baselineVersion"] + "+aptto1")
            self.assertEqual(entry["cves"], policy["targetCves"])
            self.assertEqual(entry["delayHours"], policy["sponsorDelayHours"])
            self.assertEqual(entry["access"], "sponsor" if policy["sponsorDelayHours"] else "public")
            self.assertEqual(entry["status"], "development-checks-passed")
            self.assertEqual(entry["verification"], verification_runs[source])
            self.assertTrue(entry["sourceUrl"].startswith(f"https://github.com/getpatched/packaging-{source}/tree/"))
            self.assertTrue(entry["patchUrl"].startswith(f"https://github.com/getpatched/packaging-{source}/blob/"))
            self.assertEqual(entry["testsUrl"], f"https://github.com/getpatched/packaging-{source}/tree/aptto/focal/debian/tests")
            self.assertEqual(entry["releasesUrl"], f"https://github.com/getpatched/packaging-{source}/releases")
            self.assertEqual(entry["releaseStatus"], "No production release")

        page = (ROOT / "site/index.html").read_text()
        self.assertIn("Production signing and package downloads are not available yet; repository metadata will appear after a signed release passes the publication gates", page)
        self.assertIn("No download action is shown until the signed repository is live", page)
        self.assertIn("Each row links to its source, patch, regression tests and release history", page)
        self.assertIn("Any sponsor delay starts at sponsor publication", page)
        self.assertIn("Development checks do not complete release verification", page)
        self.assertIn("temporary signed APT client smoke test", page)
        app = (ROOT / "site/catalogue.js").read_text()
        self.assertIn("Hosted build and regressions", app)
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
