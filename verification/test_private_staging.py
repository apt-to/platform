import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "compare-release-candidates.py"
SPEC = importlib.util.spec_from_file_location("compare_release_candidates", SCRIPT)
COMPARE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(COMPARE)


class PrivateStagingManifest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.expected = {
            "source": "libarchive", "sourceVersion": "3.4.0-2ubuntu1.5+aptto1",
            "sourceCommit": "a" * 40, "distribution": "focal", "architecture": "amd64",
            "publication": "runner local output", "packages": [{
                "name": "libarchive13_3.4.0-2ubuntu1.5+aptto1_amd64.deb",
                "package": "libarchive13", "version": "3.4.0-2ubuntu1.5+aptto1",
                "architecture": "amd64", "bytes": 123, "sha256": "b" * 64,
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
        for field, value in (("sourceCommit", "d" * 40), ("sourceVersion", "3.4.0-2ubuntu1.5+aptto2")):
            altered = {**self.expected, field: value}
            self.rebuilt_path.write_text(json.dumps(altered))
            self.assertNotEqual(COMPARE.canonical(self.expected_path), COMPARE.canonical(self.rebuilt_path))


if __name__ == "__main__":
    unittest.main()
