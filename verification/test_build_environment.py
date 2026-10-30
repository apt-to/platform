import hashlib
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from build_environment import runner_ca_bundle


class RunnerCaBundleTests(unittest.TestCase):
    def test_returns_buildkit_secret_reference_and_digest(self):
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory) / "ca-certificates.crt"
            bundle.write_bytes(
                b"-----BEGIN CERTIFICATE-----\nYWJj\n-----END CERTIFICATE-----\n"
            )
            expected_digest = hashlib.sha256(bundle.read_bytes()).hexdigest()
            with patch.dict(os.environ, {"GETPATCHED_CA_BUNDLE": str(bundle)}):
                arguments, digest, source = runner_ca_bundle()
        self.assertEqual(arguments, ["--secret", "id=runner-ca,src=" + str(bundle.resolve())])
        self.assertEqual(digest, expected_digest)
        self.assertEqual(source, "explicit-override")

    def test_rejects_missing_or_empty_bundle(self):
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory) / "empty.crt"
            bundle.touch()
            with patch.dict(os.environ, {"GETPATCHED_CA_BUNDLE": str(bundle)}):
                with self.assertRaisesRegex(RuntimeError, "non-empty Linux CA bundle"):
                    runner_ca_bundle()

    def test_rejects_non_certificate_and_private_key_material(self):
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory) / "invalid.crt"
            for contents, message in (
                (b"not a certificate\n", "PEM-encoded certificates"),
                (b"-----BEGIN PRIVATE KEY-----\nZm9v\n-----END PRIVATE KEY-----\n", "private key"),
            ):
                bundle.write_bytes(contents)
                with patch.dict(os.environ, {"GETPATCHED_CA_BUNDLE": str(bundle)}):
                    with self.assertRaisesRegex(RuntimeError, message):
                        runner_ca_bundle()

