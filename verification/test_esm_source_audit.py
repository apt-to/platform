import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from importlib.util import module_from_spec, spec_from_file_location


ROOT = Path(__file__).resolve().parents[1]
SPEC = spec_from_file_location("getpatched_esm_source_audit", ROOT / "scripts/inspect-esm-source.py")
AUDIT = module_from_spec(SPEC)
SPEC.loader.exec_module(AUDIT)


def make_dsc(source, version, files):
    checksums = "\n".join(
        f" {hashlib.sha256(content).hexdigest()} {len(content)} {name}"
        for name, content in sorted(files.items())
    )
    return (
        "Format: 3.0 (quilt)\n"
        f"Source: {source}\n"
        f"Version: {version}\n"
        "Checksums-Sha256:\n"
        f"{checksums}\n"
    )


class EsmSourceAudit(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "source"
        self.source.mkdir()
        self.policy = {"packages": {"libxml2": {
            "futureEsmVersion": "2.9.10+dfsg-5ubuntu0.20.04.10+esm6",
        }}}
        self.files = {
            "libxml2_2.9.10+dfsg.orig.tar.xz": b"upstream source fixture",
            "libxml2_2.9.10+dfsg-5ubuntu0.20.04.10+esm6.debian.tar.xz": b"debian source fixture",
        }
        for name, content in self.files.items():
            (self.source / name).write_bytes(content)
        (self.source / "libxml2_2.9.10+dfsg-5ubuntu0.20.04.10+esm6.dsc").write_text(
            make_dsc("libxml2", self.policy["packages"]["libxml2"]["futureEsmVersion"], self.files)
        )

    def test_hashes_every_source_member_and_records_version_drift(self):
        self.policy["packages"]["libxml2"]["futureEsmVersion"] += "+getpatched0"
        report = AUDIT.inspect("libxml2", self.source, self.policy)
        self.assertFalse(report["matchesPolicyEsmVersion"])
        self.assertEqual(report["sourceVersion"], "2.9.10+dfsg-5ubuntu0.20.04.10+esm6")
        self.assertEqual({item["name"] for item in report["sourceFiles"]}, set(self.files))
        self.assertFalse(report["sourceContentsPublished"])

    def test_source_member_hash_mismatch_is_rejected(self):
        (self.source / next(iter(self.files))).write_bytes(b"tampered")
        with self.assertRaisesRegex(ValueError, "does not match"):
            AUDIT.inspect("libxml2", self.source, self.policy)

    def test_unlisted_downloads_and_path_traversal_are_rejected(self):
        (self.source / "unexpected.txt").write_text("extra")
        with self.assertRaisesRegex(ValueError, "outside the verified"):
            AUDIT.inspect("libxml2", self.source, self.policy)
        (self.source / "unexpected.txt").unlink()
        descriptor = self.source / "libxml2_2.9.10+dfsg-5ubuntu0.20.04.10+esm6.dsc"
        descriptor.write_text("""Format: 3.0 (quilt)
Source: libxml2
Version: 2.9.10+dfsg-5ubuntu0.20.04.10+esm6
Checksums-Sha256:
 0000000000000000000000000000000000000000000000000000000000000000 1 ../escape.tar.xz
""")
        with self.assertRaisesRegex(ValueError, "unsafe or malformed"):
            AUDIT.inspect("libxml2", self.source, self.policy)

    def test_source_identity_and_download_size_are_bounded(self):
        with self.assertRaisesRegex(ValueError, "reviewed pilot policy"):
            AUDIT.inspect("openssl", self.source, self.policy)
        descriptor = self.source / "libxml2_2.9.10+dfsg-5ubuntu0.20.04.10+esm6.dsc"
        with patch.object(AUDIT, "MAX_SOURCE_BYTES", descriptor.stat().st_size + 10):
            with self.assertRaisesRegex(ValueError, "exceeds the pilot size bound"):
                AUDIT.inspect("libxml2", self.source, self.policy)

    def test_workflow_uses_protected_environment_and_never_uploads_source_or_client_logs(self):
        workflow = (ROOT / ".github/workflows/esm-source-audit.yml").read_text()
        self.assertIn("if: github.ref == 'refs/heads/main'", workflow)
        self.assertIn("name: getpatched-esm", workflow)
        self.assertIn("UBUNTU_PRO_TOKEN: ${{ secrets.UBUNTU_PRO_TOKEN }}", workflow)
        self.assertIn('sudo pro attach "$UBUNTU_PRO_TOKEN" --no-auto-enable', workflow)
        self.assertIn("focal-infra-security focal-infra-updates", workflow)
        self.assertIn("path: build/esm-source-report.json", workflow)
        self.assertNotIn("path: $RUNNER_TEMP/esm-source", workflow)
        self.assertNotIn("path: $RUNNER_TEMP/pro-", workflow)
        self.assertIn("sudo pro detach --assume-yes", workflow)
        self.assertIn("if: always()", workflow)


if __name__ == "__main__":
    unittest.main()
