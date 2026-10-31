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
        ids = [
            {"suite": "focal", "architecture": "amd64", "channel": "public", "snapshot_build": "focal-20261025T120000-r123-public"},
            {"suite": "focal", "architecture": "amd64", "channel": "early", "snapshot_build": "focal-20261025T120000-r123-early"},
            {"suite": "jammy", "architecture": "amd64", "channel": "public", "snapshot_build": "jammy-amd64-20261025T120000-r125-public"},
            {"suite": "bookworm", "architecture": "amd64", "channel": "public", "snapshot_build": "bookworm-amd64-20261025T120000-r124-public"},
        ]
        self.assertEqual(SIGNER.validate_snapshot_ids(ids), ids)
        with self.assertRaisesRegex(ValueError, "does not match its target and channel"):
            SIGNER.validate_snapshot_ids([{"suite": "bookworm", "architecture": "amd64", "channel": "public", "snapshot_build": ids[0]["snapshot_build"]}])
        with self.assertRaisesRegex(ValueError, "non-empty list"):
            SIGNER.validate_snapshot_ids([])

    def test_bookworm_snapshot_manifest_uses_suite_specific_indexes_and_paths(self):
        root = Path(self.temp.name) / "bookworm-repo"
        for relative in PUBLISH.required_files("bookworm", "amd64"):
            target = root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(("fixture:" + relative).encode())
        _, files = PUBLISH.snapshot_files(root, "bookworm", "amd64")
        self.assertEqual({item["path"] for item in files}, PUBLISH.required_files("bookworm", "amd64"))
        with self.assertRaisesRegex(ValueError, "not enabled"):
            PUBLISH.snapshot_files(root, "bookworm", "arm64")

    def test_bookworm_publication_registers_target_identity_and_signed_file_manifest(self):
        root = Path(self.temp.name) / "bookworm-publish"
        for relative in PUBLISH.required_files("bookworm", "amd64"):
            target = root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(("fixture:" + relative).encode())
        snapshot_id = "bookworm-amd64-20261025T120000-r123-public"
        with patch.object(PUBLISH, "verify_release"), patch.object(PUBLISH, "call", return_value=(201, {})) as call:
            PUBLISH.publish("https://repo.getpatched.dev", "public", snapshot_id, ["tiff-bookworm"], root, "0" * 40,
                            "bookworm", "amd64")
        registration = call.call_args_list[0]
        self.assertEqual(registration.args[:2], ("https://repo.getpatched.dev/internal/repository-snapshots/public", "POST"))
        self.assertEqual(registration.kwargs["body"]["suite"], "bookworm")
        self.assertEqual(registration.kwargs["body"]["architecture"], "amd64")
        self.assertTrue(all(item["path"].startswith("dists/bookworm/") or item["path"] == "getpatched-archive-keyring.gpg"
                            for item in registration.kwargs["body"]["files"]))

    def test_jammy_publication_registers_target_identity_and_signed_file_manifest(self):
        root = Path(self.temp.name) / "jammy-publish"
        for relative in PUBLISH.required_files("jammy", "amd64"):
            target = root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(("fixture:" + relative).encode())
        snapshot_id = "jammy-amd64-20261025T120000-r125-public"
        with patch.object(PUBLISH, "verify_release"), patch.object(PUBLISH, "call", return_value=(201, {})) as call:
            PUBLISH.publish("https://repo.getpatched.dev", "public", snapshot_id, ["libgit2-jammy"], root, "0" * 40,
                            "jammy", "amd64")
        registration = call.call_args_list[0]
        self.assertEqual(registration.kwargs["body"]["suite"], "jammy")
        self.assertEqual(registration.kwargs["body"]["architecture"], "amd64")
        self.assertTrue(all(item["path"].startswith("dists/jammy/") or item["path"] == "getpatched-archive-keyring.gpg"
                            for item in registration.kwargs["body"]["files"]))

    def test_rollback_only_activates_a_matching_retained_snapshot_without_uploading_bytes(self):
        snapshot_id = "focal-20261025T120000-r123-public"
        with patch.object(ROLLBACK.PUBLISH, "call", return_value=(201, {"id": snapshot_id, "channel": "public", "active": True, "cleanup_pending": False})) as call:
            result = ROLLBACK.rollback("https://repo.getpatched.dev", "public", snapshot_id)
        self.assertEqual(result, {"id": snapshot_id, "channel": "public", "active": True, "cleanup_pending": False})
        call.assert_called_once_with(
            f"https://repo.getpatched.dev/internal/repository-snapshots/public/{snapshot_id}/activate", "POST", body={}
        )

    def test_rollback_accepts_jammy_snapshot_for_jammy_target(self):
        snapshot_id = "jammy-amd64-20261025T120000-r125-public"
        result_body = {"id": snapshot_id, "channel": "public", "active": True, "cleanup_pending": False}
        with patch.object(ROLLBACK.PUBLISH, "call", return_value=(201, result_body)):
            result = ROLLBACK.rollback("https://repo.getpatched.dev", "public", snapshot_id, "ubuntu-jammy-amd64")
        self.assertEqual(result["id"], snapshot_id)

    def test_rollback_accepts_target_specific_debian_snapshot(self):
        snapshot_id = "bookworm-amd64-20261025T120000-r123-public"
        with patch.object(ROLLBACK.PUBLISH, "call", return_value=(201, {"id": snapshot_id, "channel": "public", "active": True})):
            result = ROLLBACK.rollback("https://repo.getpatched.dev", "public", snapshot_id, "debian-bookworm-amd64")
        self.assertEqual(result["id"], snapshot_id)

    def test_rollback_requires_snapshot_id_to_match_selected_target(self):
        with self.assertRaisesRegex(ValueError, "selected target and channel"):
            ROLLBACK.rollback("https://repo.getpatched.dev", "public", "bookworm-amd64-20261025T120000-r123-public", "debian-trixie-amd64")

    def test_rollback_rejects_wrong_channel_snapshot_and_noncanonical_endpoint(self):
        with self.assertRaisesRegex(ValueError, "selected target and channel"):
            ROLLBACK.rollback("https://repo.getpatched.dev", "early", "focal-20261025T120000-r123-public")
        with self.assertRaisesRegex(ValueError, "configured HTTPS"):
            ROLLBACK.rollback("https://attacker.example", "public", "focal-20261025T120000-r123-public")

    def test_retention_uses_only_the_canonical_gateway_and_requires_confirmed_channel_counts(self):
        counts = {"retained_snapshots": 6, "deleted_snapshots": 1, "pending_snapshots": 0,
                  "retained_builds": 0, "deleted_builds": 2, "pending_builds": 0, "deleted_objects": 20}
        result = {"channels": {"public": counts, "early": counts}, "rollback_snapshots_kept_per_channel": 5}
        with patch.object(RETENTION.PUBLISH, "call", return_value=(200, result)) as call:
            self.assertEqual(RETENTION.retain("https://repo.getpatched.dev", ["public", "early"]), result)
        call.assert_called_once_with("https://repo.getpatched.dev/internal/repository-snapshots/retention", "POST", body={"channels": ["public", "early"]})
        with self.assertRaisesRegex(ValueError, "configured HTTPS"):
            RETENTION.retain("https://attacker.example", ["public"])
        with self.assertRaisesRegex(ValueError, "unique public"):
            RETENTION.retain("https://repo.getpatched.dev", ["public", "public"])
        with patch.object(RETENTION.PUBLISH, "call", return_value=(200, {"channels": {"public": counts}, "rollback_snapshots_kept_per_channel": 99})):
            with self.assertRaisesRegex(RuntimeError, "unexpected rollback retention policy"):
                RETENTION.retain("https://repo.getpatched.dev", ["public"])

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
        content = b"Package: getpatched-test\nVersion: 1.0\nArchitecture: amd64\n"
        packages.write_bytes(content)
        digest = hashlib.sha256(content).hexdigest()
        (self.dist / "Release").write_text(
            "Origin: GetPatched\nSuite: focal\nArchitectures: amd64\nComponents: main\nSHA256:\n"
            f" {digest} {len(content)} main/binary-amd64/Packages\n"
        )
        signer = self.repository / "signer"
        signer.mkdir(mode=0o700)
        env = {**os.environ, "GNUPGHOME": str(signer)}
        generated = subprocess.run(
            ["gpg", "--batch", "--pinentry-mode", "loopback", "--passphrase", "", "--quick-generate-key", "GetPatched Test <test@getpatched.dev>", "ed25519", "sign", "0"],
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

        original_run = PUBLISH.subprocess.run
        other_fingerprint = "1" * 40
        def substituted_signer(command, **kwargs):
            if "--with-colons" in command and "--list-keys" in command:
                result = original_run(command, **kwargs)
                return subprocess.CompletedProcess(command, 0, stdout=result.stdout + f"pub:u:255:22:OTHER::::::\nfpr:::::::::{other_fingerprint}:\n", stderr=result.stderr)
            if "--decrypt" in command or "--verify" in command:
                result = original_run(command, **kwargs)
                status = result.stderr.decode("utf-8", errors="replace")
                status += f"\n[GNUPG:] VALIDSIG {other_fingerprint} 2026-10-25 1792957274 0 4 0 1 8 01 {other_fingerprint}\n"
                return subprocess.CompletedProcess(command, result.returncode, stdout=result.stdout, stderr=status.encode())
            return original_run(command, **kwargs)
        with patch.object(PUBLISH.subprocess, "run", side_effect=substituted_signer):
            with self.assertRaisesRegex(ValueError, "signature is not valid under the published archive key"):
                PUBLISH.verify_release(self.repository, fingerprint)

    def test_release_verification_requires_a_full_fingerprint(self):
        with self.assertRaisesRegex(ValueError, "configured 40- or 64-character"):
            PUBLISH.verify_release(self.repository, "short")

    def test_publication_requires_the_pinned_github_environment_and_workflow(self):
        values = {
            "GITHUB_ACTIONS": "true", "GITHUB_EVENT_NAME": "workflow_dispatch",
            "GITHUB_REPOSITORY": "getpatched/platform", "GITHUB_REF": "refs/heads/main",
            "GITHUB_WORKFLOW_REF": "getpatched/platform/.github/workflows/repository-snapshot.yml@refs/heads/main",
            "ACTIONS_ID_TOKEN_REQUEST_URL": "https://pipelines.actions.githubusercontent.com/token", "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "test-only",
        }
        with patch.dict(os.environ, values, clear=True):
            PUBLISH.validate_identity()
        with patch.dict(os.environ, {**values, "GITHUB_EVENT_NAME": "workflow_run"}, clear=True):
            PUBLISH.validate_identity()
        with patch.dict(os.environ, {**values, "GITHUB_REF": "refs/heads/feature"}, clear=True):
            with self.assertRaisesRegex(RuntimeError, "restricted"):
                PUBLISH.validate_identity()
        with patch.dict(os.environ, {**values, "GITHUB_WORKFLOW_REF": "getpatched/platform/.github/workflows/private-staging.yml@refs/heads/main"}, clear=True):
            with self.assertRaisesRegex(RuntimeError, "protected GetPatched workflow"):
                PUBLISH.validate_identity()

    def test_publication_rejects_non_getpatched_hosts_before_requesting_an_oidc_token(self):
        with self.assertRaisesRegex(ValueError, "HTTPS repo.getpatched.dev gateway"):
            PUBLISH.publish("https://attacker.example", "public", "snapshot-001", ["pilot"], self.repository, "0" * 40)


if __name__ == "__main__":
    unittest.main()
