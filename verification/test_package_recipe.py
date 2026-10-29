"""Contract tests for pinned package recipes and their source downloads."""
from io import BytesIO
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location("package_recipe", ROOT / "scripts/package_recipe.py")
RECIPE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RECIPE)
MATERIALIZER_SPEC = importlib.util.spec_from_file_location("materialize_package", ROOT / "verification/materialize-package.py")
MATERIALIZER = importlib.util.module_from_spec(MATERIALIZER_SPEC)
MATERIALIZER_SPEC.loader.exec_module(MATERIALIZER)
PLATFORM_CONFIG = json.loads((ROOT / "packages.json").read_text())


def digest(data):
    return hashlib.sha256(data).hexdigest()


class PackageRecipeContract(unittest.TestCase):
    def test_patch_applicability_supports_target_scoped_exact_and_debian_version_ranges(self):
        exact = {"target": "ubuntu-focal-amd64", "sourceVersion": "1.0-2"}
        self.assertTrue(RECIPE.patch_applies_to_version(exact, "ubuntu-focal-amd64", "1.0-2"))
        self.assertFalse(RECIPE.patch_applies_to_version(exact, "ubuntu-focal-arm64", "1.0-2"))
        self.assertFalse(RECIPE.patch_applies_to_version(exact, "ubuntu-focal-amd64", "1.0-3"))
        ranged = {"target": "debian-bookworm-arm64", "sourceVersionRange": {
            "minimum": "1.0-1", "minimumInclusive": True,
            "maximum": "1.0-3", "maximumInclusive": False,
        }}
        self.assertTrue(RECIPE.patch_applies_to_version(ranged, "debian-bookworm-arm64", "1.0-1"))
        self.assertTrue(RECIPE.patch_applies_to_version(ranged, "debian-bookworm-arm64", "1.0-2"))
        self.assertFalse(RECIPE.patch_applies_to_version(ranged, "debian-bookworm-arm64", "1.0-3"))
        self.assertFalse(RECIPE.patch_applies_to_version(ranged, "ubuntu-focal-amd64", "1.0-2"))

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="getpatched-recipe-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "patches").mkdir()
        (self.root / "tests/fixtures").mkdir(parents=True)
        (self.root / "LICENSES").mkdir()
        self.patch_bytes = b"diff --git a/libarchive/fix.c b/libarchive/fix.c\n"
        self.build_patch_bytes = b"diff --git a/libarchive/test.c b/libarchive/test.c\n"
        self.fixture_bytes = b"bounded regression input\n"
        self.reference_bytes = b"upstream-style regression source\n"
        (self.root / "patches/fix.patch").write_bytes(self.patch_bytes)
        (self.root / "patches/build-test.patch").write_bytes(self.build_patch_bytes)
        (self.root / "tests/fixtures/input.bin").write_bytes(self.fixture_bytes)
        (self.root / "tests/fixtures/reference.c").write_bytes(self.reference_bytes)
        (self.root / "LICENSES/ubuntu-source-copyright").write_text("Copyright notice\n")
        (self.root / "LICENSE").write_text("MIT-authored materials only\n")
        (self.root / "LICENSES/GETPATCHED-EARLY-ACCESS.md").write_text("Early binary terms\n")
        (self.root / "README.md").write_text("Recipe test\n")

        central = PLATFORM_CONFIG["packages"]["libarchive"]["targets"]["ubuntu-focal-amd64"]
        source_version = central["baselineVersion"]
        descriptor_bytes = b"pinned descriptor fixture\n"
        orig_bytes = b"pinned original source fixture\n"
        debian_bytes = b"pinned Debian source fixture\n"
        self.source_bytes = {
            "https://launchpad.net/source/libarchive.dsc": descriptor_bytes,
            "https://launchpad.net/source/libarchive.orig.tar.gz": orig_bytes,
            "https://launchpad.net/source/libarchive.debian.tar.xz": debian_bytes,
        }
        self.manifest = {
            "schemaVersion": 2,
            "project": {"name": "GetPatched", "repository": "getpatched/packaging-libarchive"},
            "package": {
                "source": "libarchive",
                "copyrightFile": "LICENSES/ubuntu-source-copyright",
            },
            "targets": [{
                "id": "ubuntu-focal-amd64",
                "base": {"distribution": "Ubuntu", "release": "20.04", "codename": "focal", "sourcePocket": "updates", "architecture": "amd64"},
                "source": {
                    "format": "3.0 (quilt)",
                    "version": source_version,
                    "publication": "https://api.launchpad.net/source/libarchive",
                    "publishedAt": "2025-04-23T19:22:36+00:00",
                    "descriptor": {
                        "name": f"libarchive_{source_version}.dsc",
                        "url": "https://launchpad.net/source/libarchive.dsc",
                        "sha256": digest(descriptor_bytes),
                        "bytes": len(descriptor_bytes),
                    },
                    "files": [
                        {"name": "libarchive_3.4.0.orig.tar.gz", "role": "upstream-source", "url": "https://launchpad.net/source/libarchive.orig.tar.gz", "sha256": digest(orig_bytes), "bytes": len(orig_bytes)},
                        {"name": f"libarchive_{source_version}.debian.tar.xz", "role": "ubuntu-packaging", "url": "https://launchpad.net/source/libarchive.debian.tar.xz", "sha256": digest(debian_bytes), "bytes": len(debian_bytes)},
                    ],
                    "signatureVerification": {"verified": False, "note": "fixture"},
                },
                "supportedSourceVersions": [source_version],
                "packageVersion": source_version + "+getpatched1",
                "releaseSerial": 1,
                "changelog": {"distribution": "focal", "urgency": "medium", "maintainer": "GetPatched <packages@getpatched.dev>", "date": "Thu, 29 Oct 2026 00:00:00 +0000"},
                "binaryPackages": central["binaryPackages"],
                "patches": ["cve-2026-4111"],
                "buildPatches": ["test-zstd-size-tolerance"],
                "releaseAccess": {"policy": "public-after-checks", "sponsorDelayHours": 0,
                                  "sponsorEligibility": None, "earlyBinaryLicenseId": None,
                                  "publicContributionSpdx": "MIT"},
            }],
            "patchMetadata": "patches/metadata.json",
            "regressionTests": {"fixturesDirectory": "tests/fixtures", "runner": "getpatched/platform:verification/regression.py"},
            "licensing": {
                "publicContributionsSpdx": "MIT",
                "publicContributionsLicenseFile": "LICENSE",
                "earlyBinaryLicenseId": "LicenseRef-GetPatched-Early-Binary-1.0",
                "earlyBinaryTermsFile": "LICENSES/GETPATCHED-EARLY-ACCESS.md",
                "upstreamCopyrightFile": "LICENSES/ubuntu-source-copyright",
                "upstreamLicenses": "preserve",
            },
        }
        self.target = self.manifest["targets"][0]
        self.target["schemaVersion"] = 1
        (self.root / "targets/ubuntu").mkdir(parents=True)
        self.manifest["schemaVersion"] = 3
        self.manifest["targets"] = [{"id": self.target["id"], "file": "targets/ubuntu/focal-amd64.json"}]
        self.metadata = {"schemaVersion": 2, "patches": [{
            "id": "cve-2026-4111",
            "kind": "security",
            "file": "fix.patch",
            "sha256": digest(self.patch_bytes),
            "title": "Reject oversized RAR5 filter blocks",
            "cves": central["targetCves"],
            "upstream": {"repository": "https://github.com/libarchive/libarchive", "commit": "a" * 40, "url": "https://github.com/libarchive/libarchive/commit/" + "a" * 40},
            "appliesTo": [{"target": "ubuntu-focal-amd64", "sourceVersion": source_version}],
            "dep3": {"origin": "upstream", "forwarded": "not-needed", "lastUpdate": "2026-10-29"},
            "referenceFiles": [{"path": "tests/fixtures/reference.c", "sha256": digest(self.reference_bytes), "purpose": "review context"}],
            "tests": [{"id": "fixture-regression", "runner": "getpatched/platform:verification/regression.py", "fixtures": [{"path": "tests/fixtures/input.bin", "sha256": digest(self.fixture_bytes)}]}],
        }, {
            "id": "test-zstd-size-tolerance",
            "kind": "build-compatibility",
            "file": "build-test.patch",
            "sha256": digest(self.build_patch_bytes),
            "title": "Allow a two-byte Zstandard output variation in a tiny-input test",
            "cves": [],
            "appliesTo": [{"target": "ubuntu-focal-amd64", "sourceVersion": source_version}],
            "tests": [{"id": "upstream-test-suite", "runner": "debian/rules check", "expectation": "All upstream tests complete with the bounded output-size exception."}],
        }]}
        self._write_json(self.root / "targets/ubuntu/focal-amd64.json", self.target)
        self._write_json(self.root / "package-manifest.json", self.manifest)
        self._write_json(self.root / "patches/metadata.json", self.metadata)

    @staticmethod
    def _write_json(path, data):
        path.write_text(json.dumps(data, indent=2) + "\n")

    def test_exact_focal_target_and_patch_set_validate(self):
        recipe = RECIPE.load_recipe(self.root, PLATFORM_CONFIG)
        self.assertEqual(recipe["policy"]["source"], "libarchive")
        self.assertEqual(recipe["policy"]["version"], "3.4.0-2ubuntu1.5+getpatched1")
        self.assertEqual(recipe["policy"]["patches"], ["cve-2026-4111"])
        self.assertEqual(recipe["policy"]["buildPatches"], ["test-zstd-size-tolerance"])

    def test_build_compatibility_patch_cannot_claim_cves(self):
        self.metadata["patches"][1]["cves"] = ["CVE-2026-4111"]
        self._write_json(self.root / "patches/metadata.json", self.metadata)
        with self.assertRaisesRegex(RuntimeError, "Build patch .* list no CVEs"):
            RECIPE.load_recipe(self.root, PLATFORM_CONFIG)

    def test_build_compatibility_patch_requires_versioned_patch_metadata(self):
        self.metadata["schemaVersion"] = 1
        self._write_json(self.root / "patches/metadata.json", self.metadata)
        with self.assertRaisesRegex(RuntimeError, "Build-compatibility patches require patch metadata schemaVersion 2"):
            RECIPE.load_recipe(self.root, PLATFORM_CONFIG)

    def test_patch_and_fixture_checksums_are_enforced(self):
        (self.root / "patches/fix.patch").write_bytes(self.patch_bytes + b"changed")
        with self.assertRaisesRegex(RuntimeError, "SHA-256 mismatch"):
            RECIPE.load_recipe(self.root, PLATFORM_CONFIG)
        (self.root / "patches/fix.patch").write_bytes(self.patch_bytes)
        (self.root / "tests/fixtures/input.bin").write_bytes(self.fixture_bytes + b"changed")
        with self.assertRaisesRegex(RuntimeError, "SHA-256 mismatch"):
            RECIPE.load_recipe(self.root, PLATFORM_CONFIG)

    def test_source_version_must_match_the_public_candidate_exactly(self):
        self.target["source"]["version"] += "1"
        self._write_json(self.root / "targets/ubuntu/focal-amd64.json", self.target)
        with self.assertRaisesRegex(RuntimeError, "exact source version"):
            RECIPE.load_recipe(self.root, PLATFORM_CONFIG)

    def test_target_cves_must_match_the_reviewed_platform_policy(self):
        self.metadata["patches"][0]["cves"] = ["CVE-OTHER"]
        self._write_json(self.root / "patches/metadata.json", self.metadata)
        with self.assertRaisesRegex(RuntimeError, "target CVE policy"):
            RECIPE.load_recipe(self.root, PLATFORM_CONFIG)

    def test_security_patch_requires_full_upstream_commit_provenance(self):
        self.metadata["patches"][0]["upstream"]["commit"] = "short"
        self._write_json(self.root / "patches/metadata.json", self.metadata)
        with self.assertRaisesRegex(RuntimeError, "full commit"):
            RECIPE.load_recipe(self.root, PLATFORM_CONFIG)

    def test_source_archive_downloads_are_size_and_hash_pinned(self):
        recipe = RECIPE.load_recipe(self.root, PLATFORM_CONFIG)
        with tempfile.TemporaryDirectory(prefix="getpatched-source-download-test-") as directory:
            def open_pinned(request, timeout):
                return BytesIO(self.source_bytes[request.full_url])

            with patch.object(RECIPE.urllib.request, "urlopen", side_effect=open_pinned):
                downloaded = RECIPE.download_source_assets(recipe, directory)
            self.assertEqual(len(downloaded), 3)
            for name, content in ((recipe["descriptor"]["name"], self.source_bytes[recipe["descriptor"]["url"]]),
                                  *((item["name"], self.source_bytes[item["url"]]) for item in recipe["sourceFiles"])):
                self.assertEqual((Path(directory) / name).read_bytes(), content)

    def test_source_archive_download_rejects_changed_bytes(self):
        recipe = RECIPE.load_recipe(self.root, PLATFORM_CONFIG)
        with tempfile.TemporaryDirectory(prefix="getpatched-source-download-test-") as directory:
            with patch.object(RECIPE.urllib.request, "urlopen", return_value=BytesIO(b"wrong")):
                with self.assertRaisesRegex(RuntimeError, "size or SHA-256 mismatch"):
                    RECIPE.download_source_assets(recipe, directory)

    def test_materializer_preserves_vendor_series_and_emits_recipe_metadata(self):
        source = self.root / "extracted-source"
        (source / "debian/source").mkdir(parents=True)
        (source / "debian/patches").mkdir()
        (source / "debian/tests/fixtures").mkdir(parents=True)
        (source / "debian/source/format").write_text("3.0 (quilt)\n")
        (source / "debian/patches/series").write_text("# Ubuntu patches\nvendor.patch -p1\n")
        (source / "debian/changelog").write_text(
            "libarchive (3.4.0-2ubuntu1.5) focal; urgency=medium\n\n"
            "  * Existing Ubuntu changelog entry.\n\n"
            " -- Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>  Wed, 23 Apr 2025 19:22:36 +0000\n"
        )
        recipe = RECIPE.load_recipe(self.root, PLATFORM_CONFIG)
        policy_path = self.root / "policy.json"
        policy_path.write_text(json.dumps(recipe["policy"]))
        provenance_path = self.root / "provenance.json"
        provenance_path.write_text(json.dumps({"source": "libarchive", "recipeCommit": "a" * 40}))
        source_provenance_path = self.root / "output-source-provenance.json"
        arguments = [
            "materialize-package.py", "--recipe", str(self.root), "--source", str(source),
            "--target", "ubuntu-focal-amd64", "--policy", str(policy_path),
            "--provenance", str(provenance_path), "--source-provenance", str(source_provenance_path),
        ]
        with patch("sys.argv", arguments):
            MATERIALIZER.main()

        series = (source / "debian/patches/series").read_text()
        self.assertEqual(series, "# Ubuntu patches\nvendor.patch -p1\nfix.patch\nbuild-test.patch\n")
        self.assertEqual((source / "debian/patches/fix.patch").read_bytes(), self.patch_bytes)
        self.assertEqual((source / "debian/patches/build-test.patch").read_bytes(), self.build_patch_bytes)
        self.assertEqual((source / "debian/tests/fixtures/input.bin").read_bytes(), self.fixture_bytes)
        self.assertEqual((source / "debian/tests/fixtures/reference.c").read_bytes(), self.reference_bytes)
        self.assertTrue((source / "debian/getpatched/package-manifest.json").is_file())
        self.assertTrue((source / "debian/getpatched/patches.json").is_file())
        self.assertTrue((source / "debian/getpatched/release-policy.json").is_file())
        self.assertEqual(json.loads(source_provenance_path.read_text())["recipeCommit"], "a" * 40)
        changelog = (source / "debian/changelog").read_text()
        self.assertTrue(changelog.startswith("libarchive (3.4.0-2ubuntu1.5+getpatched1) focal; urgency=medium\n"))
        self.assertIn("CVE-2026-4111", changelog)
        self.assertIn("test-only build compatibility patch", changelog)
        self.assertIn("Existing Ubuntu changelog entry.", changelog)


if __name__ == "__main__":
    unittest.main()
