import json
import sys
import unittest
from copy import deepcopy
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
import importlib.util

sys.path.insert(0, str(ROOT / "scripts"))
from platform_policy import apt_source_list, target_profile, target_source_branch
_SCAN_SPEC = importlib.util.spec_from_file_location("getpatched_scan", ROOT / "scripts/getpatched-scan.py")
_SCAN = importlib.util.module_from_spec(_SCAN_SPEC)
_SCAN_SPEC.loader.exec_module(_SCAN)
debian_version_compare = _SCAN.debian_version_compare


class PublicCatalogueContract(unittest.TestCase):
    def test_ubuntu_snapshot_source_list_emits_one_suite_per_apt_line(self):
        platform = json.loads((ROOT / "packages.json").read_text())
        profile = target_profile(platform, "ubuntu-focal-amd64")
        self.assertEqual(target_source_branch(platform, "ubuntu-focal-amd64"), "getpatched/focal")
        lines = apt_source_list(profile).splitlines()
        self.assertEqual(len(lines), 6)
        for suite in ("focal", "focal-updates", "focal-security"):
            for kind in ("deb", "deb-src"):
                self.assertIn(
                    f"{kind} [arch=amd64] https://snapshot.ubuntu.com/ubuntu/20261025T000000Z/ {suite} main universe restricted multiverse",
                    lines,
                )

    def test_debian_arm64_target_profile_generates_architecture_scoped_sources_without_enabling_publication(self):
        platform = deepcopy(json.loads((ROOT / "packages.json").read_text()))
        target_id = "debian-bookworm-arm64"
        platform["targets"][target_id] = {
            "distribution": "Debian", "releaseVersion": "12", "codename": "bookworm",
            "architecture": "arm64", "sourceBranch": "getpatched/bookworm",
            "advisoryEcosystem": "Debian:12", "packageEcosystem": "Debian",
            "build": {"runner": "ubuntu-24.04-arm", "containerPlatform": "linux/arm64"},
            "repository": {"enabled": False}, "archiveSnapshot": "20261025T000000Z",
            "baseImage": "debian:12@sha256:" + "a" * 64,
            "aptSources": [{"type": "both", "uri": "https://snapshot.debian.org/archive/debian/20261025T000000Z/",
                            "suites": ["bookworm", "bookworm-updates", "bookworm-security"], "components": ["main"]}],
        }
        profile = target_profile(platform, target_id)
        self.assertFalse(profile["repository"]["enabled"])
        self.assertIn("[arch=arm64] https://snapshot.debian.org/archive/debian/20261025T000000Z/", apt_source_list(profile))

    def test_target_recipe_branch_rejects_untrusted_ref_syntax(self):
        platform = deepcopy(json.loads((ROOT / "packages.json").read_text()))
        platform["targets"]["ubuntu-focal-amd64"]["sourceBranch"] = "getpatched/../main"
        with self.assertRaisesRegex(ValueError, "valid getpatched/\\* source branch"):
            target_profile(platform, "ubuntu-focal-amd64")

    def test_catalogue_matches_release_policy_without_claiming_public_downloads(self):
        platform = json.loads((ROOT / "packages.json").read_text())
        catalogue = json.loads((ROOT / "site/catalogue.json").read_text())
        entries = {item["source"]: item for item in catalogue["packages"]}
        self.assertEqual(set(entries), set(platform["packages"]))
        self.assertEqual(catalogue["schemaVersion"], 3)
        self.assertEqual(set(catalogue["targets"]), set(platform["targets"]))
        for target_id, target in platform["targets"].items():
            profile = target_profile(platform, target_id)
            self.assertEqual(catalogue["targets"][target_id]["codename"], profile["codename"])
            self.assertEqual(catalogue["targets"][target_id]["architecture"], profile["architecture"])
        for source, package in platform["packages"].items():
            self.assertEqual(set(entries[source]["targets"]), set(package["targets"]))
            for target_id, policy in package["targets"].items():
                entry = entries[source]["targets"][target_id]
                access = policy["releaseAccess"]
                self.assertEqual(entry["version"], policy["packageVersion"])
                old_version = policy["baselineVersion"]
                self.assertLess(debian_version_compare(old_version, entry["version"]), 0)
                self.assertEqual(entry["cves"], policy["targetCves"])
                self.assertEqual(entry["delayHours"], access["sponsorDelayHours"])
                self.assertEqual(entry["access"], "sponsor" if access["sponsorDelayHours"] else "public")
                self.assertEqual(entry["sponsorEligibility"], access["sponsorEligibility"])
                if access["sponsorDelayHours"] == 168:
                    self.assertEqual(access["sponsorEligibility"], "any-active-individual-github-sponsorship-tier")
                self.assertEqual(entry["publicContributionSpdx"], "MIT")
                self.assertEqual(access["earlyUse"], ["private", "commercial"])
                self.assertFalse(access["earlyRedistributionAllowed"])
                self.assertEqual(access["publicLicenseScope"], "getpatched-authored-contributions-only")
                self.assertEqual(entry["earlyUse"], access["earlyUse"])
                self.assertEqual(entry["earlyRedistributionAllowed"], access["earlyRedistributionAllowed"])
                self.assertEqual(entry["earlyBinaryLicenseId"], access["earlyBinaryLicenseId"])
                self.assertEqual(entry["publicLicenseScope"], access["publicLicenseScope"])
                self.assertEqual(entry["earlyRedistributionAllowed"], False)
                self.assertEqual(entry["status"], "development-verified-production-release-pending")
                expected_run = {
                    "libxml2": "40899705050",
                    "libarchive": "40899709850",
                }[source]
                self.assertEqual(entry["verification"], f"https://github.com/getpatched/platform/actions/runs/{expected_run}")
                self.assertEqual(entry["ubuntuProEsmCompatibility"], "not-tested-out-of-scope")
                self.assertNotIn("verificationUrl", entry)
                self.assertTrue(entry["sourceUrl"].startswith(f"https://github.com/getpatched/packaging-{source}/tree/"))
                self.assertTrue(entry["patchUrl"].startswith(f"https://github.com/getpatched/packaging-{source}/blob/"))
                self.assertEqual(entry["testsUrl"], f"https://github.com/getpatched/packaging-{source}/tree/getpatched/focal/tests")
                self.assertEqual(entry["releasesUrl"], f"https://github.com/getpatched/packaging-{source}/releases")
                self.assertEqual(entry["releaseStatus"], "No production release")

        page = (ROOT / "site/index.html").read_text()
        self.assertIn("Hosted verification passed.", page)
        self.assertIn("Both Focal packages have fresh hosted builds", page)
        self.assertIn("Sponsor sign-in and production repository access setup remain incomplete", page)
        self.assertIn("no production package release has been published", page)
        self.assertIn("Live package publication and downloads remain disabled until GitHub sponsor sign-in and production access setup are complete", page)
        self.assertIn("Hosted verification has passed for both pilot builds", page)
        self.assertIn("Ubuntu Pro/ESM compatibility is not tested or supported", page)
        self.assertIn("Each row links to its source, patch, regression tests and release history", page)
        self.assertIn("Any sponsor delay starts only after sponsor publication", page)
        self.assertIn("temporary signed APT client smoke test", page)
        app = (ROOT / "site/catalogue.js").read_text()
        self.assertIn("Hosted build, CVE scans, installed regressions and signed-client checks required", app)
        self.assertIn("Hosted verification passed", app)
        self.assertNotIn("item.verificationUrl", app)
        for label in ("Source", "Patch", "Tests", "Releases"):
            self.assertIn(f">{label} ↗</a>", app)
        for field in ("patchUrl", "testsUrl", "releasesUrl", "releaseStatus"):
            self.assertIn(f"item.{field}", app)
        self.assertIn("Any active individual GitHub Sponsors tier, no minimum · public ${escapeHtml(item.delayHours)} hours later", app)
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
