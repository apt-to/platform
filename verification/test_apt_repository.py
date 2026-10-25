import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("generate_apt_index", ROOT / "scripts" / "generate-apt-index.py")
GENERATOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GENERATOR)


class AptRepositoryIndex(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.dist = Path(self.temp.name) / "dists/focal"
        index = self.dist / "main/binary-amd64/Packages.gz"
        index.parent.mkdir(parents=True)
        index.write_bytes(b"fake compressed index bytes")
        digest = hashlib.sha256(index.read_bytes()).hexdigest()
        self.release = self.dist / "Release"
        self.release.write_text(
            "Origin: AptTo\nLabel: apt.to\nSuite: focal\nCodename: focal\n"
            "Architectures: amd64\nComponents: main\nSHA256:\n"
            f" {digest} {index.stat().st_size} main/binary-amd64/Packages.gz\n"
            f" {'0' * 64} 123 Release\n"
        )

    def test_release_has_only_verified_index_checksums_and_hash_paths(self):
        entries = GENERATOR.rewrite_release_checksums(self.release, self.dist)
        GENERATOR.write_by_hash(self.dist, entries)
        self.assertIn("Acquire-By-Hash: yes\n", self.release.read_text())
        self.assertNotIn(" Release\n", self.release.read_text())
        self.assertEqual(set(entries), {"main/binary-amd64/Packages.gz"})
        original = self.dist / "main/binary-amd64/Packages.gz"
        by_hash = original.parent / "by-hash/SHA256" / entries["main/binary-amd64/Packages.gz"][0]
        self.assertEqual(by_hash.read_bytes(), original.read_bytes())

    def test_bad_index_digest_is_rejected_before_signing(self):
        self.release.write_text(self.release.read_text().replace(hashlib.sha256(b"fake compressed index bytes").hexdigest(), "0" * 64))
        with self.assertRaisesRegex(ValueError, "checksum mismatch"):
            GENERATOR.rewrite_release_checksums(self.release, self.dist)

    def test_release_path_traversal_is_rejected(self):
        self.release.write_text(self.release.read_text().replace("main/binary-amd64/Packages.gz", "../../outside"))
        with self.assertRaisesRegex(ValueError, "escapes"):
            GENERATOR.rewrite_release_checksums(self.release, self.dist)

    def test_generation_refuses_to_mix_with_an_existing_suite_snapshot(self):
        repo = Path(self.temp.name) / "repo"
        (repo / "pool").mkdir(parents=True)
        (repo / "pool/package.deb").write_bytes(b"binary")
        (repo / "pool/package.dsc").write_bytes(b"source")
        old_suite = repo / "dists/focal"
        old_suite.mkdir(parents=True)
        (old_suite / "InRelease").write_bytes(b"prior signature")
        with self.assertRaisesRegex(ValueError, "fresh immutable repository snapshot"):
            GENERATOR.generate(repo, "focal", "amd64", "main", "AptTo")


if __name__ == "__main__":
    unittest.main()
