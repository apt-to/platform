import hashlib
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "publish-apt-snapshot.py"
SPEC = importlib.util.spec_from_file_location("publish_apt_snapshot", SCRIPT)
PUBLISH = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PUBLISH)
GENERATOR_SPEC = importlib.util.spec_from_file_location("generate_apt_index", ROOT / "scripts" / "generate-apt-index.py")
GENERATOR = importlib.util.module_from_spec(GENERATOR_SPEC)
GENERATOR_SPEC.loader.exec_module(GENERATOR)
SIGNER_SPEC = importlib.util.spec_from_file_location("sign_and_publish_apt_snapshot", ROOT / "scripts" / "sign-and-publish-apt-snapshot.py")
SIGNER = importlib.util.module_from_spec(SIGNER_SPEC)
SIGNER_SPEC.loader.exec_module(SIGNER)
ROLLBACK_SPEC = importlib.util.spec_from_file_location("rollback_apt_snapshot", ROOT / "scripts" / "rollback-apt-snapshot.py")
ROLLBACK = importlib.util.module_from_spec(ROLLBACK_SPEC)
ROLLBACK_SPEC.loader.exec_module(ROLLBACK)
RETENTION_SPEC = importlib.util.spec_from_file_location("retain_apt_snapshots", ROOT / "scripts" / "retain-apt-snapshots.py")
RETENTION = importlib.util.module_from_spec(RETENTION_SPEC)
RETENTION_SPEC.loader.exec_module(RETENTION)


class AptSnapshotPublisher(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repository = Path(self.temp.name)
        self.dist = self.repository / "dists/focal"
        for relative in PUBLISH.REQUIRED:
            target = self.repository / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(("fixture:" + relative).encode())

    def test_manifest_hashes_all_declared_repository_files(self):
        root, files = PUBLISH.snapshot_files(self.repository)
        self.assertEqual(root, self.repository.resolve())
        self.assertEqual({item["path"] for item in files}, PUBLISH.REQUIRED)
        for item in files:
            content = (root / item["path"]).read_bytes()
            self.assertEqual(item["size"], len(content))
            self.assertEqual(item["sha256"], hashlib.sha256(content).hexdigest())

    def test_signer_uses_exact_builder_ids_for_each_channel(self):
        ids = {"public": "focal-20261025T120000-r123-public", "early": "focal-20261025T120000-r123-early"}
        self.assertEqual(SIGNER.validate_snapshot_ids(ids), ids)
        with self.assertRaisesRegex(ValueError, "does not match its builder channel"):
            SIGNER.validate_snapshot_ids({"public": ids["early"], "early": ids["public"]})
        self.assertEqual(SIGNER.validate_snapshot_ids({"public": ids["public"]}), {"public": ids["public"]})
        with self.assertRaisesRegex(ValueError, "at least one valid channel"):
            SIGNER.validate_snapshot_ids({})

    def test_rollback_only_activates_a_matching_retained_snapshot_without_uploading_bytes(self):
        snapshot_id = "focal-20261025T120000-r123-public"
        with patch.object(ROLLBACK.PUBLISH, "call", return_value=(201, {"id": snapshot_id, "channel": "public", "active": True, "cleanup_pending": False})) as call:
            result = ROLLBACK.rollback("https://repo.apt.to", "public", snapshot_id)
        self.assertEqual(result, {"id": snapshot_id, "channel": "public", "active": True, "cleanup_pending": False})
        call.assert_called_once_with(
            f"https://repo.apt.to/internal/repository-snapshots/public/{snapshot_id}/activate", "POST", body={}
        )

    def test_rollback_rejects_wrong_channel_snapshot_and_noncanonical_endpoint(self):
        with self.assertRaisesRegex(ValueError, "selected channel"):
            ROLLBACK.rollback("https://repo.apt.to", "early", "focal-20261025T120000-r123-public")
        with self.assertRaisesRegex(ValueError, "configured HTTPS"):
            ROLLBACK.rollback("https://attacker.example", "public", "focal-20261025T120000-r123-public")

    def test_retention_uses_only_the_canonical_gateway_and_requires_confirmed_channel_counts(self):
        counts = {"retained_snapshots": 6, "deleted_snapshots": 1, "pending_snapshots": 0,
                  "retained_builds": 0, "deleted_builds": 2, "pending_builds": 0, "deleted_objects": 20}
        result = {"channels": {"public": counts, "early": counts}, "rollback_snapshots_kept_per_channel": 5}
        with patch.object(RETENTION.PUBLISH, "call", return_value=(200, result)) as call:
            self.assertEqual(RETENTION.retain("https://repo.apt.to", ["public", "early"]), result)
        call.assert_called_once_with("https://repo.apt.to/internal/repository-snapshots/retention", "POST", body={"channels": ["public", "early"]})
        with self.assertRaisesRegex(ValueError, "configured HTTPS"):
            RETENTION.retain("https://attacker.example", ["public"])
        with self.assertRaisesRegex(ValueError, "unique public"):
            RETENTION.retain("https://repo.apt.to", ["public", "public"])
        with patch.object(RETENTION.PUBLISH, "call", return_value=(200, {"channels": {"public": counts}, "rollback_snapshots_kept_per_channel": 99})):
            with self.assertRaisesRegex(RuntimeError, "unexpected rollback retention policy"):
                RETENTION.retain("https://repo.apt.to", ["public"])

    def test_snapshot_files_reject_symlinked_index_files(self):
        target = self.dist / "main/binary-amd64/Packages.gz"
        target.unlink()
        outside = self.repository / "outside-index"
        outside.write_bytes(b"not a repository index")
        target.symlink_to(outside)
        with self.assertRaisesRegex(ValueError, "symbolic link"):
            PUBLISH.snapshot_files(self.repository)

    def test_release_hash_mismatch_is_rejected_before_signature_checks(self):
        content = b"Packages index\n"
        index = self.dist / "main/binary-amd64/Packages"
        index.parent.mkdir(parents=True, exist_ok=True)
        index.write_bytes(content)
        self.dist.mkdir(parents=True, exist_ok=True)
        self.dist.joinpath("Release").write_text(f"Architectures: amd64\nSHA256:\n {'0' * 64} {len(content)} main/binary-amd64/Packages\n")
        with self.assertRaisesRegex(ValueError, "SHA256 does not match"):
            PUBLISH.verify_release(self.repository, "0" * 40)

    def test_real_signatures_verify_only_with_configured_primary_key_fingerprint(self):
        packages = self.dist / "main/binary-amd64/Packages"
        packages.parent.mkdir(parents=True, exist_ok=True)
        content = b"Package: aptto-test\nVersion: 1.0\nArchitecture: amd64\n"
        packages.write_bytes(content)
        digest = hashlib.sha256(content).hexdigest()
        (self.dist / "Release").write_text(
            "Origin: AptTo\nSuite: focal\nArchitectures: amd64\nComponents: main\nSHA256:\n"
            f" {digest} {len(content)} main/binary-amd64/Packages\n"
        )
        signer = self.repository / "signer"
        signer.mkdir(mode=0o700)
        env = {**os.environ, "GNUPGHOME": str(signer)}
        generated = subprocess.run(
            ["gpg", "--batch", "--pinentry-mode", "loopback", "--passphrase", "", "--quick-generate-key", "AptTo Test <test@apt.to>", "ed25519", "sign", "0"],
            env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True,
        )
        if generated.returncode:
            raise RuntimeError(f"temporary GPG key generation failed: {generated.stderr[-2000:]}")
        listed = subprocess.run(["gpg", "--batch", "--with-colons", "--list-secret-keys"], check=True, capture_output=True, text=True, env=env).stdout
        fingerprint = next(line.split(":")[9] for line in listed.splitlines() if line.startswith("fpr:"))
        GENERATOR.sign_release(self.dist, signer, fingerprint)
        PUBLISH.verify_release(self.repository, fingerprint)
        with self.assertRaisesRegex(ValueError, "does not match the configured primary-key fingerprint"):
            PUBLISH.verify_release(self.repository, "0" * 40)

    def test_release_verification_requires_a_full_fingerprint(self):
        with self.assertRaisesRegex(ValueError, "configured 40- or 64-character"):
            PUBLISH.verify_release(self.repository, "short")

    def test_publication_requires_the_pinned_github_environment_and_workflow(self):
        values = {
            "GITHUB_ACTIONS": "true", "GITHUB_EVENT_NAME": "workflow_dispatch",
            "GITHUB_REPOSITORY": "apt-to/platform", "GITHUB_REF": "refs/heads/main",
            "GITHUB_WORKFLOW_REF": "apt-to/platform/.github/workflows/repository-snapshot.yml@refs/heads/main",
            "ACTIONS_ID_TOKEN_REQUEST_URL": "https://pipelines.actions.githubusercontent.com/token", "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "test-only",
        }
        with patch.dict(os.environ, values, clear=True):
            PUBLISH.validate_identity()
        with patch.dict(os.environ, {**values, "GITHUB_EVENT_NAME": "workflow_run"}, clear=True):
            PUBLISH.validate_identity()
        with patch.dict(os.environ, {**values, "GITHUB_REF": "refs/heads/feature"}, clear=True):
            with self.assertRaisesRegex(RuntimeError, "restricted"):
                PUBLISH.validate_identity()
        with patch.dict(os.environ, {**values, "GITHUB_WORKFLOW_REF": "apt-to/platform/.github/workflows/private-staging.yml@refs/heads/main"}, clear=True):
            with self.assertRaisesRegex(RuntimeError, "protected AptTo workflow"):
                PUBLISH.validate_identity()

    def test_publication_rejects_non_aptto_hosts_before_requesting_an_oidc_token(self):
        with self.assertRaisesRegex(ValueError, "HTTPS repo.apt.to gateway"):
            PUBLISH.publish("https://attacker.example", "public", "snapshot-001", ["pilot"], self.repository, "0" * 40)


if __name__ == "__main__":
    unittest.main()
