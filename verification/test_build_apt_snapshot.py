import importlib.util
from pathlib import Path
import tempfile
from unittest.mock import patch
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("build_apt_snapshot", ROOT / "scripts" / "build-apt-snapshot.py")
BUILD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BUILD)


def release_record(state="public"):
    return {
        "id": "libarchive-3-4-0-aptto1", "state": state,
        "repository": "apt-to/packaging-libarchive", "tag": "aptto/3.4.0-2ubuntu1.5+aptto1",
        "source_commit": "a" * 40,
        "required_assets": [{"name": "libarchive13_amd64.deb", "sha256": "b" * 64}],
        "source_assets": [{"name": "libarchive_3.4.0.dsc", "sha256": "c" * 64}],
    }


class SnapshotAssemblyContract(unittest.TestCase):
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
        self.assertEqual([release["id"] for release in selected], ["libarchive-3-4-0-aptto1"])

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
                result = BUILD.assemble_channel("https://repo.apt.to", "public", Path(temporary))
                self.assertEqual(result["unchanged"], True)
                self.assertIsNone(result["snapshot_build"])
                self.assertFalse((Path(temporary) / "public").exists())


if __name__ == "__main__":
    unittest.main()
