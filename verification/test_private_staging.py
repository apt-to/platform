import importlib.util
import json
from pathlib import Path
import re
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "compare-release-candidates.py"
SPEC = importlib.util.spec_from_file_location("compare_release_candidates", SCRIPT)
COMPARE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(COMPARE)
STAGE_SPEC = importlib.util.spec_from_file_location("stage_release", ROOT / "scripts" / "stage-release.py")
STAGE = importlib.util.module_from_spec(STAGE_SPEC)
STAGE_SPEC.loader.exec_module(STAGE)


class PrivateStagingManifest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.expected = {
            "source": "libarchive", "sourceVersion": "3.4.0-2ubuntu1.5+aptto1+getpatched1",
            "sourceCommit": "a" * 40, "distribution": "focal", "architecture": "amd64",
            "publication": "runner local output", "packages": [{
                "name": "libarchive13_3.4.0-2ubuntu1.5+aptto1+getpatched1_amd64.deb",
                "package": "libarchive13", "version": "3.4.0-2ubuntu1.5+aptto1+getpatched1",
                "architecture": "amd64", "bytes": 123, "sha256": "b" * 64,
            }],
            "sourceFiles": [{
                "name": "libarchive_3.4.0-2ubuntu1.5+aptto1+getpatched1.dsc", "bytes": 456, "sha256": "c" * 64,
            }],
        }
        self.expected_path = self.root / "expected.json"
        self.expected_path.write_text(json.dumps(self.expected))
        self.rebuilt_path = self.root / "rebuilt.json"
        self.rebuilt_path.write_text(json.dumps({**self.expected, "publication": "rebuilt"}))

    def test_matching_candidate_identity_and_hashes_pass(self):
        self.assertEqual(COMPARE.canonical(self.expected_path), COMPARE.canonical(self.rebuilt_path))

    def test_binary_hash_mismatch_is_rejected(self):
        altered = {**self.expected, "packages": [{**self.expected["packages"][0], "sha256": "c" * 64}]}
        self.rebuilt_path.write_text(json.dumps(altered))
        self.assertNotEqual(COMPARE.canonical(self.expected_path), COMPARE.canonical(self.rebuilt_path))

    def test_source_commit_or_candidate_name_mismatch_is_rejected(self):
        for field, value in (("sourceCommit", "d" * 40), ("sourceVersion", "3.4.0-2ubuntu1.5+getpatched2")):
            altered = {**self.expected, field: value}
            self.rebuilt_path.write_text(json.dumps(altered))
            self.assertNotEqual(COMPARE.canonical(self.expected_path), COMPARE.canonical(self.rebuilt_path))

    def test_source_package_hash_mismatch_is_rejected(self):
        altered = {**self.expected, "sourceFiles": [{**self.expected["sourceFiles"][0], "sha256": "d" * 64}]}
        self.rebuilt_path.write_text(json.dumps(altered))
        self.assertNotEqual(COMPARE.canonical(self.expected_path), COMPARE.canonical(self.rebuilt_path))

    def test_staging_downloads_the_complete_source_artifact_into_the_manifest_source_directory(self):
        producer = (ROOT / ".github/workflows/package-verification.yml").read_text()
        staging = (ROOT / ".github/workflows/private-staging.yml").read_text()
        self.assertIn('name: source-${{ matrix.package }}-${{ github.run_id }}-${{ github.run_attempt }}', producer)
        self.assertIn('gh run download "$RUN_ID" --repo getpatched/platform --name "source-${package}-${RUN_ID}-${RUN_ATTEMPT}" --dir "$RUNNER_TEMP/candidate/source"', staging)
        self.assertIn('SOURCE_DIRECTORY: ${{ runner.temp }}/candidate/source', staging)
        self.assertIn('GETPATCHED_RELEASE_ENDPOINT: https://repo.getpatched.dev', staging)
        self.assertRegex(
            staging,
            r"rebuild-and-stage:\n\s+if: >-\n\s+vars\.GETPATCHED_REPOSITORY_ENABLED == 'true' &&",
        )

    def test_release_endpoint_is_pinned_to_repository_hostname(self):
        self.assertEqual(STAGE.validate_endpoint("https://repo.getpatched.dev/"), "https://repo.getpatched.dev")
        for endpoint in ("http://repo.getpatched.dev", "https://getpatched.dev", "https://attacker.example", "https://repo.getpatched.dev/path"):
            with self.subTest(endpoint=endpoint), self.assertRaisesRegex(ValueError, "repo.getpatched.dev gateway"):
                STAGE.validate_endpoint(endpoint)

    def test_debian_source_filename_allowlist_accepts_normal_underscored_names(self):
        self.assertRegex("libarchive_3.4.0-2ubuntu1.5+aptto1+getpatched1.dsc", r"^[A-Za-z0-9][A-Za-z0-9_.+~-]*$")
        self.assertNotRegex("../libarchive_3.4.0.dsc", r"^[A-Za-z0-9][A-Za-z0-9_.+~-]*$")


if __name__ == "__main__":
    unittest.main()
