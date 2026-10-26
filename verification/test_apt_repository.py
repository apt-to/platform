import hashlib
import importlib.util
import os
from pathlib import Path
import subprocess
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

    def test_release_path_containment_works_without_path_is_relative_to(self):
        self.assertTrue(hasattr(Path, "relative_to"))
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

    def test_signing_creates_verifiable_inrelease_and_detached_signature(self):
        dist = Path(self.temp.name) / "signed/dists/focal"
        dist.mkdir(parents=True)
        (dist / "Release").write_text("Origin: AptTo\nArchitectures: amd64\n")
        key_home = Path(self.temp.name) / "signer"
        key_home.mkdir(mode=0o700)
        env = {**os.environ, "GNUPGHOME": str(key_home)}
        subprocess.run(["gpg", "--batch", "--pinentry-mode", "loopback", "--passphrase", "",
                        "--quick-generate-key", "AptTo Test <test@apt.to>", "ed25519", "sign", "0"],
                       check=True, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        listing = subprocess.run(["gpg", "--batch", "--with-colons", "--list-secret-keys"], check=True,
                                 capture_output=True, text=True, env=env).stdout
        fingerprint = next(line.split(":")[9] for line in listing.splitlines() if line.startswith("fpr:"))
        public_key = GENERATOR.sign_release(dist, key_home, fingerprint)
        GENERATOR.sign_release(dist, key_home, fingerprint)
        self.assertEqual(list(Path(self.temp.name).glob("aptto-gpg-verify-*")), [])
        self.assertTrue(public_key.is_file())
        self.assertTrue((dist / "InRelease").is_file())
        self.assertTrue((dist / "Release.gpg").is_file())
        (dist / "Release").write_text("Origin: Tampered\nArchitectures: amd64\n")
        verify_home = Path(self.temp.name) / "tamper-check"
        verify_home.mkdir(mode=0o700)
        verify_env = {**env, "GNUPGHOME": str(verify_home)}
        subprocess.run(["gpg", "--batch", "--import", str(public_key)], check=True, env=verify_env,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        checked = subprocess.run(["gpg", "--batch", "--verify", str(dist / "Release.gpg"), str(dist / "Release")],
                                 env=verify_env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.assertNotEqual(checked.returncode, 0)


if __name__ == "__main__":
    unittest.main()
