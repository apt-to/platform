import json
import sys
import unittest
from copy import deepcopy
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
import importlib.util

sys.path.insert(0, str(ROOT / "scripts"))
from platform_policy import apt_source_list, package_target_policy, target_profile, target_source_branch
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

    def test_all_distribution_snapshot_sources_require_https(self):
        platform = json.loads((ROOT / "packages.json").read_text())
        for target_id in platform["targets"]:
            sources = apt_source_list(target_profile(platform, target_id))
            self.assertNotIn("http://", sources, target_id)
            self.assertIn("https://", sources, target_id)
        for filename in ("packaging.Containerfile", "baseline.Containerfile", "patched-scan.Containerfile"):
            containerfile = (ROOT / "build" / filename).read_text()
            self.assertIn("# syntax=docker/dockerfile:1.7", containerfile)
            self.assertIn("RUN --mount=type=secret,id=runner-ca", containerfile)
            self.assertIn("/etc/ssl/certs/ca-certificates.crt", containerfile)
            self.assertIn("chmod 0644 /etc/ssl/certs/ca-certificates.crt", containerfile)
            self.assertIn('Acquire::https::CAInfo "/etc/ssl/certs/ca-certificates.crt"', containerfile)
        build_script = (ROOT / "scripts/build-package.py").read_text()
        self.assertIn("ca_secret_args, ca_bundle_sha256, ca_bundle_source = runner_ca_bundle()", build_script)
        self.assertIn("*ca_secret_args", build_script)
        self.assertIn('"runnerCaBundleSha256": ca_bundle_sha256', build_script)

        baseline_script = (ROOT / "scripts/run-baseline.py").read_text()
        self.assertIn("*ca_secret_args", baseline_script)
        self.assertIn('"runnerCaBundleSource": ca_bundle_source', baseline_script)
        self.assertIn('"runnerCaBundleSha256": ca_bundle_sha256', baseline_script)

        client_script = (ROOT / "scripts/test-apt-repository.py").read_text()
        self.assertIn("*ca_secret_args", client_script)
        self.assertIn('"runnerCaBundleSource": ca_bundle_source', client_script)
        self.assertIn('"runnerCaBundleSha256": ca_bundle_sha256', client_script)
        self.assertIn('Acquire::https::CAInfo "/etc/ssl/certs/ca-certificates.crt"', client_script)
        self.assertIn("chmod 0644 /etc/ssl/certs/ca-certificates.crt", client_script)

        untrusted_debian = json.loads(json.dumps(platform))
        untrusted_debian["targets"]["debian-trixie-amd64"]["aptSources"][0]["uri"] = (
            "http://mirror.example.invalid/debian/20261030T000000Z/"
        )
        with self.assertRaises(ValueError):
            target_profile(untrusted_debian, "debian-trixie-amd64")

        insecure_ubuntu = json.loads(json.dumps(platform))
        insecure_ubuntu["targets"]["ubuntu-focal-amd64"]["aptSources"][0]["uri"] = (
            "http://snapshot.ubuntu.com/ubuntu/20261025T000000Z/"
        )
        with self.assertRaises(ValueError):
            target_profile(insecure_ubuntu, "ubuntu-focal-amd64")

    def test_target_recipe_branch_rejects_untrusted_ref_syntax(self):
        platform = deepcopy(json.loads((ROOT / "packages.json").read_text()))
        platform["targets"]["ubuntu-focal-amd64"]["sourceBranch"] = "getpatched/../main"
        with self.assertRaisesRegex(ValueError, "valid getpatched/\\* source branch"):
            target_profile(platform, "ubuntu-focal-amd64")

    def test_package_ecosystem_override_must_match_target_distribution_and_release(self):
        platform = deepcopy(json.loads((ROOT / "packages.json").read_text()))
        target = "ubuntu-focal-amd64"
        policy = platform["packages"]["libpng1.6"]["targets"][target]
        policy["packageEcosystem"] = "Ubuntu:20.04:LTS"
        self.assertEqual(package_target_policy(platform, "libpng1.6", target)["packageEcosystem"], "Ubuntu:20.04:LTS")

        policy["packageEcosystem"] = "Ubuntu:22.04:LTS"
        with self.assertRaisesRegex(ValueError, "valid package ecosystem"):
            package_target_policy(platform, "libpng1.6", target)

    def test_libpng_followup_assessment_records_nonaffected_baseline_and_scan_policy(self):
        platform = deepcopy(json.loads((ROOT / "packages.json").read_text()))
        target_id = "ubuntu-focal-amd64"
        policy = platform["packages"]["libpng1.6"]["targets"][target_id]
        assessment = policy["followUpAssessments"]["CVE-2026-22695"]
        self.assertEqual(assessment["baselineApplicability"], "not-affected")
        self.assertEqual(assessment["candidateDisposition"], "fixed-in-backport")
        self.assertEqual(assessment["introducedBy"], "218612ddd6b17944e21eda56caf8b4bf7779d1ea")
        self.assertEqual(assessment["fixedBy"], "e4f7ad4ea2a471776c81dda4846b7691925d9786")
        self.assertIn("scanner absence alone is not remediation evidence", assessment["scannerTreatment"])
        self.assertEqual(package_target_policy(platform, "libpng1.6", target_id)["followUpAssessments"],
                         policy["followUpAssessments"])
        policy["followUpAssessments"]["CVE-2026-22695"]["fixedBy"] = "not-a-commit"
        with self.assertRaisesRegex(ValueError, "invalid follow-up CVE assessment"):
            package_target_policy(platform, "libpng1.6", target_id)

        policy["followUpAssessments"] = {}
        policy["packageEcosystem"] = "Untrusted:Canary"
        with self.assertRaisesRegex(ValueError, "valid package ecosystem"):
            package_target_policy(platform, "libpng1.6", target_id)

    def test_catalogue_matches_release_policy_without_claiming_public_downloads(self):
        platform = json.loads((ROOT / "packages.json").read_text())
        catalogue = json.loads((ROOT / "site/catalogue.json").read_text())
        entries = {item["source"]: item for item in catalogue["packages"]}
        expected_catalogue = {
            source for source, record in platform["packages"].items()
            if all(target.get("candidateStatus") != "unverified-development-candidate"
                   for target in record["targets"].values())
        }
        self.assertEqual(set(entries), expected_catalogue)
        self.assertEqual(expected_catalogue, {"libxml2", "libarchive", "libgit2", "poppler", "tiff"})
        self.assertIn("libpng1.6", set(platform["packages"]) - set(entries))
        self.assertNotIn("libgit2", set(platform["packages"]) - set(entries))
        self.assertNotIn("poppler", set(platform["packages"]) - set(entries))
        self.assertEqual(catalogue["schemaVersion"], 3)
        self.assertEqual(set(catalogue["targets"]), set(platform["targets"]))
        for target_id, target in platform["targets"].items():
            profile = target_profile(platform, target_id)
            self.assertEqual(catalogue["targets"][target_id]["codename"], profile["codename"])
            self.assertEqual(catalogue["targets"][target_id]["architecture"], profile["architecture"])
        for source, entry_package in entries.items():
            package = platform["packages"][source]
            self.assertEqual(set(entry_package["targets"]), set(package["targets"]))
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
                    "libxml2": {"ubuntu-focal-amd64": "40899705050"},
                    "libarchive": {"ubuntu-focal-amd64": "40899709850"},
                    "libgit2": {"ubuntu-focal-amd64": "41144391227"},
                    "poppler": {"ubuntu-focal-amd64": "41149614570"},
                    "tiff": {
                        "ubuntu-focal-amd64": "41154300127",
                        "debian-bookworm-amd64": "41154301399",
                        "debian-trixie-amd64": "41154300175",
                    },
                }[source][target_id]
                self.assertEqual(entry["verification"], f"https://github.com/getpatched/platform/actions/runs/{expected_run}")
                self.assertEqual(
                    entry["ubuntuProEsmCompatibility"],
                    policy.get("ubuntuProEsmCompatibility", "not-tested-out-of-scope"),
                )
                self.assertNotIn("verificationUrl", entry)
                self.assertTrue(entry["sourceUrl"].startswith(f"https://github.com/getpatched/packaging-{source}/tree/"))
                self.assertTrue(entry["patchUrl"].startswith(f"https://github.com/getpatched/packaging-{source}/blob/"))
                expected_branch = {
                    "libxml2": {"ubuntu-focal-amd64": "getpatched/focal"},
                    "libarchive": {"ubuntu-focal-amd64": "getpatched/focal"},
                    "libgit2": {"ubuntu-focal-amd64": "getpatched/focal"},
                    "poppler": {"ubuntu-focal-amd64": "getpatched/focal"},
                    "tiff": {
                        "ubuntu-focal-amd64": "getpatched/focal",
                        "debian-bookworm-amd64": "getpatched/debian-bookworm",
                        "debian-trixie-amd64": "getpatched/debian-trixie",
                    },
                }[source][target_id]
                self.assertEqual(entry["testsUrl"], f"https://github.com/getpatched/packaging-{source}/tree/{expected_branch}/tests")
                self.assertEqual(entry["releasesUrl"], f"https://github.com/getpatched/packaging-{source}/releases")
                self.assertEqual(entry["releaseStatus"], "No production release")

        page = (ROOT / "site/index.html").read_text()
        self.assertIn("Hosted verification passed.", page)
        self.assertIn("Five package projects have hosted builds across Ubuntu Focal, Debian Bookworm and Debian Trixie", page)
        self.assertIn("Production repository access setup remains incomplete", page)
        self.assertIn("no production package release has been published", page)
        self.assertIn("Live package publication and downloads remain disabled until GitHub sponsor sign-in and production access setup are complete", page)
        self.assertIn("Hosted verification is complete for all five package projects' configured targets", page)
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
