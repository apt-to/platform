import importlib.util
import hashlib
from pathlib import Path
import subprocess
import sys
import tempfile
from unittest.mock import patch
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("build_apt_snapshot", ROOT / "scripts" / "build-apt-snapshot.py")
BUILD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BUILD)


def release_record(state="public"):
    return {
        "id": "libarchive-3-4-0-getpatched1", "state": state,
        "repository": "getpatched/packaging-libarchive", "tag": "getpatched/3.4.0-2ubuntu1.5+getpatched1",
        "source_commit": "a" * 40,
        "required_assets": [{"name": "libarchive13_amd64.deb", "sha256": "b" * 64}],
        "source_assets": [{"name": "libarchive_3.4.0.dsc", "sha256": "c" * 64}],
    }


class SnapshotAssemblyContract(unittest.TestCase):
    def test_snapshot_targets_are_suite_scoped_and_arm64_stays_disabled(self):
        for suite in ("focal", "bookworm", "trixie"):
            BUILD.validate_snapshot_target(suite, "amd64")
        for suite, architecture in (("bookworm", "arm64"), ("trixie", "arm64"), ("sid", "amd64")):
            with self.subTest(suite=suite, architecture=architecture), self.assertRaisesRegex(ValueError, "not enabled"):
                BUILD.validate_snapshot_target(suite, architecture)
        self.assertEqual(BUILD.snapshot_id_prefix("focal", "amd64"), "focal-")
        self.assertEqual(BUILD.snapshot_id_prefix("bookworm", "amd64"), "bookworm-amd64-")

    def test_cli_exposes_debian_suites_as_supported_targets(self):
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts/build-apt-snapshot.py"), "--help"],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("{focal,bookworm,trixie}", result.stdout)

    def test_active_snapshot_identity_is_bound_to_suite_and_architecture(self):
        releases = [release_record()]
        focal = {"id": "focal-20261025T120000-r123-public", "release_ids": [releases[0]["id"]], "healthy": True}
        bookworm = {"id": "bookworm-amd64-20261025T120000-r123-public", "release_ids": [releases[0]["id"]], "healthy": True}
        self.assertTrue(BUILD.snapshot_inventory_matches(releases, focal))
        self.assertTrue(BUILD.snapshot_inventory_matches(releases, bookworm, "bookworm", "amd64"))
        self.assertFalse(BUILD.snapshot_inventory_matches(releases, focal, "bookworm", "amd64"))

    def test_index_manifest_reads_only_requested_suite(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            focal = repository / "dists/focal/Release"
            bookworm = repository / "dists/bookworm/Release"
            focal.parent.mkdir(parents=True)
            bookworm.parent.mkdir(parents=True)
            focal.write_text("focal")
            bookworm.write_text("bookworm")
            manifest = BUILD.index_manifest(repository, "bookworm")
        self.assertEqual([item["path"] for item in manifest], ["dists/bookworm/Release"])

    def test_valid_public_and_sponsor_release_records_are_accepted(self):
        BUILD.validate_release(release_record())
        BUILD.validate_release(release_record("sponsor-period"))

    def test_inventory_rejects_other_repositories_and_unsafe_asset_names(self):
        invalid = release_record()
        invalid["repository"] = "attacker/packaging-libarchive"
        with self.assertRaisesRegex(ValueError, "invalid pilot package record"):
            BUILD.validate_release(invalid)
        invalid = release_record()
        invalid["source_assets"][0]["name"] = "../outside.dsc"
        with self.assertRaisesRegex(ValueError, "invalid source_assets entry"):
            BUILD.validate_release(invalid)

    def test_inventory_accepts_selected_public_batch_recipe_repositories(self):
        for package in ("libpng1.6", "libgit2", "tiff", "poppler"):
            release = release_record()
            release["repository"] = f"getpatched/packaging-{package}"
            BUILD.validate_release(release)

    def test_inventory_requires_binary_and_complete_source_descriptor(self):
        invalid = release_record()
        invalid["required_assets"] = [{"name": "debug.txt", "sha256": "b" * 64}]
        with self.assertRaisesRegex(ValueError, "no binary package"):
            BUILD.validate_release(invalid)
        invalid = release_record()
        invalid["source_assets"] = [{"name": "libarchive.orig.tar.xz", "sha256": "c" * 64}]
        with self.assertRaisesRegex(ValueError, "no Debian source descriptor"):
            BUILD.validate_release(invalid)

    def test_public_channel_excludes_sponsor_period_candidate(self):
        releases = [release_record(), release_record("sponsor-period")]
        selected = [release for release in releases if release["state"] == "public"]
        self.assertEqual([release["id"] for release in selected], ["libarchive-3-4-0-getpatched1"])

    def test_early_channel_includes_public_and_sponsor_period_candidates(self):
        releases = [release_record(), release_record("sponsor-period")]
        selected = [release for release in releases if release["state"] in {"public", "sponsor-period"}]
        self.assertEqual(len(selected), 2)

    def test_snapshot_noop_requires_a_healthy_active_snapshot_with_the_exact_release_set(self):
        releases = [release_record()]
        active = {"id": "focal-20261025T120000-r123-public", "release_ids": [releases[0]["id"]], "healthy": True}
        self.assertTrue(BUILD.snapshot_inventory_matches(releases, active))
        self.assertFalse(BUILD.snapshot_inventory_matches(releases, {**active, "healthy": False}))
        self.assertFalse(BUILD.snapshot_inventory_matches(releases, {**active, "release_ids": ["another-release"]}))
        self.assertFalse(BUILD.snapshot_inventory_matches(releases, {**active, "id": "untrusted"}))
        self.assertFalse(BUILD.snapshot_inventory_matches(releases, None))

    def test_unchanged_channel_skips_download_index_generation_and_staging(self):
        releases = [release_record()]
        active = {"id": "focal-20261025T120000-r123-public", "release_ids": [releases[0]["id"]], "healthy": True}
        with patch.object(BUILD, "fetch_inventory", return_value={"releases": releases, "active_snapshot": active}):
            with tempfile.TemporaryDirectory() as temporary:
                result = BUILD.assemble_channel("https://repo.getpatched.dev", "public", Path(temporary))
                self.assertEqual(result["unchanged"], True)
                self.assertIsNone(result["snapshot_build"])
                self.assertFalse((Path(temporary) / "public").exists())

    def test_empty_target_inventory_is_a_noop_and_does_not_publish_empty_indexes(self):
        with patch.object(BUILD, "fetch_inventory", return_value={"releases": [], "active_snapshot": None}), tempfile.TemporaryDirectory() as temporary:
            result = BUILD.assemble_channel("https://repo.getpatched.dev", "public", Path(temporary), suite="bookworm")
        self.assertTrue(result["unchanged"])
        self.assertEqual(result["release_count"], 0)
        self.assertIsNone(result["snapshot_build"])

    def test_empty_inventory_with_active_snapshot_fails_closed(self):
        active = {"id": "bookworm-amd64-20261025T120000-r123-public", "release_ids": ["withdrawn"], "healthy": True}
        with patch.object(BUILD, "fetch_inventory", return_value={"releases": [], "active_snapshot": active}), tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(RuntimeError, "active snapshot still exists"):
                BUILD.assemble_channel("https://repo.getpatched.dev", "public", Path(temporary), suite="bookworm")

    def test_changed_channel_result_marks_snapshot_as_changed(self):
        releases = [release_record()]
        with patch.object(BUILD, "fetch_inventory", return_value={"releases": releases, "active_snapshot": None}), \
             patch.object(BUILD, "download_asset"), \
             patch.object(BUILD.GENERATOR, "generate", return_value={"indexes": ["Packages"]}), \
             patch.object(BUILD, "register_unsigned_build", return_value=7), \
             patch.dict(BUILD.os.environ, {"GITHUB_RUN_ID": "123"}), tempfile.TemporaryDirectory() as temporary:
            result = BUILD.assemble_channel("https://repo.getpatched.dev", "public", Path(temporary))
        self.assertIs(result["unchanged"], False)
        self.assertIsNotNone(result["snapshot_build"])

    def test_reuses_identical_source_tarball_shared_by_multiple_release_revisions(self):
        first = release_record()
        second = release_record()
        second["id"] = "libarchive-3-4-0-getpatched2"
        second["tag"] = "getpatched/3.4.0-2ubuntu1.5+getpatched2"
        descriptor = {"name": "libarchive_3.4.0.dsc", "sha256": "c" * 64}
        shared = {"name": "libarchive_3.4.0.orig.tar.xz", "sha256": hashlib.sha256(b"shared upstream source").hexdigest()}
        first["source_assets"] = [descriptor, shared]
        second["source_assets"] = [{"name": "libarchive_3.4.0+getpatched2.dsc", "sha256": "e" * 64}, shared]
        release_records = [first, second]
        source_downloads = []

        def download(_endpoint, _channel, _release, asset, target, **_kwargs):
            if asset["name"].endswith((".dsc", ".orig.tar.xz")):
                if asset["name"].endswith(".orig.tar.xz"):
                    source_downloads.append(asset["name"])
                    target.write_bytes(b"shared upstream source")
                else:
                    target.write_bytes(asset["name"].encode())
            else:
                target.write_bytes(asset["name"].encode())

        with patch.object(BUILD, "fetch_inventory", return_value={"releases": release_records, "active_snapshot": None}), \
             patch.object(BUILD, "download_asset", side_effect=download), \
             patch.object(BUILD.GENERATOR, "generate", return_value={"indexes": ["Packages"]}), \
             patch.object(BUILD, "register_unsigned_build", return_value=7), \
             patch.dict(BUILD.os.environ, {"GITHUB_RUN_ID": "123"}), tempfile.TemporaryDirectory() as temporary:
            result = BUILD.assemble_channel("https://repo.getpatched.dev", "public", Path(temporary))

        self.assertFalse(result["unchanged"])
        self.assertEqual(source_downloads, ["libarchive_3.4.0.orig.tar.xz"])

    def test_public_download_follows_github_release_redirects_but_private_download_does_not(self):
        class Response:
            headers = {"Content-Length": "8"}
            def __init__(self): self.body = b"asset123"
            def __enter__(self): return self
            def __exit__(self, *_): return None
            def read(self, _size):
                body, self.body = self.body, b""
                return body
        class Opener:
            def __init__(self, handler=None): self.handler = handler
            def open(self, _request, timeout): self.timeout = timeout; return Response()
        release = {"id": "libarchive-getpatched1", "repository": "getpatched/packaging-libarchive"}
        asset = {"name": "libarchive.dsc", "sha256": __import__("hashlib").sha256(b"asset123").hexdigest()}
        with patch.object(BUILD, "public_asset_url", return_value="https://github.com/getpatched/packaging-libarchive/releases/download/tag/libarchive.dsc"), \
             patch.object(BUILD.urllib.request, "build_opener", side_effect=lambda *handlers: Opener(handlers)), \
             patch.object(BUILD, "request_headers", return_value={"Authorization": "Bearer test"}), tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "public.dsc"
            BUILD.download_asset("https://repo.getpatched.dev", "public", release, asset, target)
            self.assertEqual(target.read_bytes(), b"asset123")
            target = Path(temporary) / "private.deb"
            BUILD.download_asset("https://repo.getpatched.dev", "early", release, {**asset, "name": "pkg.deb"}, target, private_binary=True)
            self.assertEqual(target.read_bytes(), b"asset123")


if __name__ == "__main__":
    unittest.main()
