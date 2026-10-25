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
            "libxml2": "https://github.com/apt-to/platform/actions/runs/40206413305",
            "libarchive": "https://github.com/apt-to/platform/actions/runs/40206415448",
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
            self.assertTrue(entry["sourceUrl"].startswith(f"https://github.com/apt-to/packaging-{source}/tree/"))

        page = (ROOT / "site/index.html").read_text()
        self.assertIn("Production signing, package downloads and apt.to repository endpoints are not live yet", page)
        self.assertIn("No download action is shown until the production signed repository is live", page)
        self.assertIn("These checks do not complete release verification", page)
        self.assertIn("temporary signed APT client smoke test", page)
        app = (ROOT / "site/catalogue.js").read_text()
        self.assertIn("Hosted build and regressions", app)
        self.assertIn("open the public package source repositories on GitHub", page)
        self.assertNotIn("browse the public package repositories directly", page)
        self.assertIn('all: packages.length', app)
        self.assertIn('sponsor: packages.filter((item) => item.access === "sponsor").length', app)
        self.assertIn('public: packages.filter((item) => item.access === "public").length', app)
        self.assertNotIn('"02"', page)
        self.assertNotIn('"01"', page)


if __name__ == "__main__":
    unittest.main()
