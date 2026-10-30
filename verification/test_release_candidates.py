import importlib.util
import json
from pathlib import Path
import re
import tempfile
import unittest
import sys


SCRIPT = Path(__file__).resolve().parents[1] / "scripts/build-package.py"
SPEC = importlib.util.spec_from_file_location("getpatched_build_package", SCRIPT)
BUILD_PACKAGE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BUILD_PACKAGE)
ROOT = SCRIPT.parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from platform_policy import package_target_policy, target_profile

TARGET_ID = "ubuntu-focal-amd64"
CONFIG = json.loads((ROOT / "packages.json").read_text())


def source_policy(source):
    package = package_target_policy(CONFIG, source, TARGET_ID)
    profile = target_profile(CONFIG, TARGET_ID)
    return {
        "source": source, "targetId": TARGET_ID,
        "baseVersion": package["baselineVersion"], "version": package["packageVersion"],
        "releaseSerial": package["releaseSerial"], "targetCve": package["targetCve"],
        "targetCves": package["targetCves"],
        "ubuntuProEsmCompatibility": package.get("ubuntuProEsmCompatibility", "not-applicable"),
        "sponsorDelayHours": package["releaseAccess"]["sponsorDelayHours"],
        "binaryPackages": package["binaryPackages"], "architecture": profile["architecture"],
        "release": profile["codename"], "distribution": profile["distribution"],
        "releaseVersion": profile["releaseVersion"],
    }


class ReleaseCandidateOutput(unittest.TestCase):
    def test_latest_public_focal_candidates_are_eligible_after_verification(self):
        self.assertEqual(set(CONFIG["packages"]), {"libxml2", "libarchive", "libpng1.6", "libgit2", "tiff", "poppler"})
        workflow = (ROOT / ".github/workflows/package-verification.yml").read_text()
        options = re.search(r"options: \[([^]]+)\]", workflow).group(1)
        runnable_candidates = {"libxml2", "libarchive", "libpng1.6", "libgit2", "tiff", "poppler"}
        self.assertEqual(set(item.strip() for item in options.split(",")), runnable_candidates)
        self.assertTrue(runnable_candidates.issubset(CONFIG["packages"]))
        baseline_cli = (ROOT / "scripts/run-baseline.py").read_text()
        self.assertIn('"libgit2"', baseline_cli)
        for source, package_record in CONFIG["packages"].items():
            package = package_record["targets"][TARGET_ID]
            if source in ("libxml2", "libarchive"):
                self.assertEqual(package["ubuntuProEsmCompatibility"], "not-tested-out-of-scope")
            else:
                self.assertNotIn("ubuntuProEsmCompatibility", package)
            policy = source_policy(source)
            validated_source, expected, profile = BUILD_PACKAGE.validate_release_policy(policy, CONFIG)
            self.assertEqual(validated_source, source)
            self.assertEqual(expected["baselineVersion"], package["baselineVersion"])
            self.assertEqual(expected["packageVersion"], package["packageVersion"])
            self.assertEqual(expected["targetCves"], package["targetCves"])
            self.assertEqual(profile["codename"], "focal")
            with self.assertRaisesRegex(RuntimeError, "verification checks pass"):
                BUILD_PACKAGE.release_eligibility(policy)
            eligibility = BUILD_PACKAGE.release_eligibility(policy, verification_checks_passed=True, publication_enabled=False)
            self.assertFalse(eligibility["releaseEligible"])
            self.assertEqual(eligibility["reason"], "repository publication is disabled for this target")
            eligibility = BUILD_PACKAGE.release_eligibility(policy, verification_checks_passed=True, publication_enabled=True)
            self.assertTrue(eligibility["releaseEligible"])
            self.assertTrue(eligibility["verificationChecksPassed"])
            self.assertEqual(eligibility["supportScope"], TARGET_ID)
            self.assertEqual(eligibility["targetId"], TARGET_ID)
            self.assertEqual(eligibility["ubuntuProEsmCompatibility"], package.get("ubuntuProEsmCompatibility", "not-applicable"))
            self.assertIsNone(eligibility["reason"])

    def test_package_identity_and_sponsor_policy_must_match_project_policy(self):
        for source in CONFIG["packages"]:
            policy = source_policy(source)
            mismatched = {**policy, "baseVersion": "unexpected"}
            with self.assertRaisesRegex(RuntimeError, "Packaging policy disagrees with project configuration"):
                BUILD_PACKAGE.validate_release_policy(mismatched, CONFIG)

    def test_candidate_export_follows_signed_client_verification_without_esm_gate(self):
        source = (SCRIPT.parents[0] / "build-package.py").read_text()
        verify_at = source.index('"--trust-image", scanner["image"], "--apt-sources-b64", build_sources')
        eligibility_at = source.index('"release-eligibility.json"')
        persist_at = source.rindex("persist_release_candidates(selected, binary_manifest")
        self.assertLess(verify_at, eligibility_at)
        self.assertLess(eligibility_at, persist_at)
        self.assertNotIn("require_release_compatibility", source)
        self.assertIn('verification_checks_passed=True, publication_enabled=profile["repository"]["enabled"]', source)

    def test_private_staging_requires_explicit_release_eligibility(self):
        workflow = (SCRIPT.parents[1] / ".github/workflows/private-staging.yml").read_text()
        self.assertIn('test -s "$RUNNER_TEMP/candidate/release-eligibility.json"', workflow)
        self.assertIn('eligibility.get("releaseEligible") is not True', workflow)
        self.assertIn('eligibility.get("targetId") != target', workflow)
        self.assertIn('eligibility.get("supportScope") != target', workflow)
        self.assertIn('eligibility.get("verificationChecksPassed") is not True', workflow)
        self.assertIn('expected_esm = "not-tested-out-of-scope" if target == "ubuntu-focal-amd64" else "not-applicable"', workflow)

    def test_only_verified_selected_binaries_are_persisted_with_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            build = root / "build"
            output = root / "output"
            build.mkdir()
            output.mkdir()
            source = output / "source"
            source.mkdir()
            binary = build / "libarchive13_3.4.0-2ubuntu1.5+getpatched1_amd64.deb"
            binary.write_bytes(b"verified package bytes")
            source_files = {
                "libarchive_3.4.0-2ubuntu1.5+getpatched1.dsc": b"source descriptor",
                "libarchive_3.4.0.orig.tar.gz": b"upstream source",
                "libarchive_3.4.0.orig.tar.gz.asc": b"upstream source signature",
                "libarchive_3.4.0-2ubuntu1.5+getpatched1.debian.tar.xz": b"debian source",
            }
            for name, content in source_files.items():
                (source / name).write_bytes(content)
            digest = BUILD_PACKAGE.sha256(binary)
            manifest = {"source": "libarchive", "targetId": TARGET_ID, "version": "3.4.0-2ubuntu1.5+getpatched1", "architecture": "amd64", "packages": [{
                "name": binary.name,
                "sha256": digest,
                "control": "Package: libarchive13\nVersion: 3.4.0-2ubuntu1.5+getpatched1\nArchitecture: amd64\nDepends: libc6\n",
            }]}

            profile = target_profile(CONFIG, TARGET_ID)
            BUILD_PACKAGE.persist_release_candidates(
                [binary], manifest, output, "libarchive", "3.4.0-2ubuntu1.5+getpatched1", "a" * 40, TARGET_ID, profile,
            )

            saved = output / "binary" / binary.name
            self.assertEqual(saved.read_bytes(), binary.read_bytes())
            report = json.loads((output / "release-candidates.json").read_text())
            self.assertEqual(report["publication"], "not published; runner-local candidates for a protected staging job")
            self.assertEqual(report["sourceCommit"], "a" * 40)
            self.assertEqual(report["targetId"], TARGET_ID)
            self.assertEqual(report["sourceFiles"], [{
                "name": name,
                "bytes": len(content),
                "sha256": BUILD_PACKAGE.sha256(source / name),
            } for name, content in sorted(source_files.items())])
            self.assertEqual(report["packages"], [{
                "name": binary.name,
                "package": "libarchive13",
                "version": "3.4.0-2ubuntu1.5+getpatched1",
                "architecture": "amd64",
                "bytes": len(b"verified package bytes"),
                "sha256": digest,
            }])

    def test_candidate_copy_is_rejected_when_it_differs_from_build_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            build = root / "build"
            output = root / "output"
            build.mkdir()
            output.mkdir()
            source = output / "source"
            source.mkdir()
            (source / "libxml2_2.9.10+getpatched1.dsc").write_bytes(b"descriptor")
            binary = build / "libxml2_2.9.10+getpatched1_amd64.deb"
            binary.write_bytes(b"tampered package")
            manifest = {"source": "libxml2", "targetId": TARGET_ID, "version": "2.9.10+getpatched1", "architecture": "amd64", "packages": [{
                "name": binary.name,
                "sha256": "0" * 64,
                "control": "Package: libxml2\nVersion: 2.9.10+getpatched1\nArchitecture: amd64\n",
            }]}
            with self.assertRaisesRegex(RuntimeError, "verified binary manifest"):
                BUILD_PACKAGE.persist_release_candidates(
                    [binary], manifest, output, "libxml2", "2.9.10+getpatched1", "b" * 40, TARGET_ID, target_profile(CONFIG, TARGET_ID),
                )


if __name__ == "__main__":
    unittest.main()
