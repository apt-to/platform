"""Behavioral tests for release publication timing."""
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from release_state import is_public_due, mark_public_promoted, mark_public_published, mark_sponsor_published


class PublicationClock(unittest.TestCase):
    def test_gated_release_becomes_due_at_the_exact_utc_boundary(self):
        public_after = datetime(2026, 11, 1, 12, 0, tzinfo=timezone.utc)
        self.assertFalse(is_public_due(public_after, public_after - timedelta(microseconds=1)))
        self.assertTrue(is_public_due(public_after, public_after))
        self.assertTrue(is_public_due(public_after, public_after + timedelta(microseconds=1)))

    def test_sponsor_clock_starts_only_after_complete_verified_publication(self):
        published_at = datetime(2026, 10, 25, 14, 0, tzinfo=timezone.utc)
        first = {"name": "libxml2_2.9.10_amd64.deb", "sha256": "a" * 64}
        second = {"name": "libxml2_utils_2.9.10_amd64.deb", "sha256": "b" * 64}
        release = {
            "source": "libxml2",
            "version": "2.9.10+dfsg-5ubuntu0.20.04.10+aptto1+getpatched1",
            "sponsor_delay_hours": 168,
            "state": "prepared",
            "required_assets": [first, second],
            "release_checks_passed": True,
            "sponsor_publication_complete": False,
        }

        with self.assertRaisesRegex(ValueError, "publication is not complete"):
            mark_sponsor_published(release, [first, second], published_at)

        release["sponsor_publication_complete"] = True
        with self.assertRaisesRegex(ValueError, "complete asset set"):
            mark_sponsor_published(release, [first], published_at)

        shortened = {**release, "sponsor_delay_hours": 167, "sponsor_publication_complete": True}
        with self.assertRaisesRegex(ValueError, "exactly 168 integer hours"):
            mark_sponsor_published(shortened, [first, second], published_at)

        published = mark_sponsor_published(release, [first, second], published_at)
        self.assertEqual(published["state"], "sponsor-period")
        self.assertEqual(published["sponsor_published_at"], "2026-10-25T14:00:00Z")
        self.assertEqual(published["public_after"], "2026-11-01T14:00:00Z")
        self.assertEqual(release["state"], "prepared")
        duplicate = mark_sponsor_published(published, [first, second], published_at + timedelta(days=1))
        self.assertEqual(duplicate, published)
        changed = [first, {**second, "sha256": "c" * 64}]
        with self.assertRaisesRegex(ValueError, "immutable"):
            mark_sponsor_published(published, changed, published_at + timedelta(days=1))

    def test_zero_delay_release_is_public_after_checks_and_asset_readback(self):
        published_at = datetime(2026, 10, 25, 14, 0, tzinfo=timezone.utc)
        asset = {"name": "libarchive13_3.4.0_amd64.deb", "sha256": "c" * 64}
        release = {
            "source": "libarchive",
            "version": "3.4.0-2ubuntu1.5+aptto1+getpatched1",
            "sponsor_delay_hours": 0,
            "state": "prepared",
            "required_assets": [asset],
            "release_checks_passed": True,
            "public_publication_complete": False,
        }

        with self.assertRaisesRegex(ValueError, "publication is not complete"):
            mark_public_published(release, [asset], published_at)

        release["public_publication_complete"] = True
        malformed_policy = {**release, "sponsor_delay_hours": False}
        with self.assertRaisesRegex(ValueError, "zero-hour integer"):
            mark_public_published(malformed_policy, [asset], published_at)

        published = mark_public_published(release, [asset], published_at)
        self.assertEqual(published["state"], "public")
        self.assertEqual(published["public_published_at"], "2026-10-25T14:00:00Z")
        self.assertNotIn("public_after", published)

    def test_gated_release_promotion_waits_for_deadline_and_preserves_hashes(self):
        published_at = datetime(2026, 10, 25, 14, 0, tzinfo=timezone.utc)
        assets = [{"name": "libxml2_amd64.deb", "sha256": "d" * 64}]
        prepared = {
            "source": "libxml2",
            "version": "2.9.10+dfsg-5ubuntu0.20.04.10+aptto1+getpatched1",
            "sponsor_delay_hours": 168,
            "state": "prepared",
            "required_assets": assets,
            "release_checks_passed": True,
            "sponsor_publication_complete": True,
        }
        sponsor_release = mark_sponsor_published(prepared, assets, published_at)
        deadline = datetime.fromisoformat(sponsor_release["public_after"].replace("Z", "+00:00"))

        with self.assertRaisesRegex(ValueError, "168-hour deadline"):
            mark_public_promoted(
                sponsor_release,
                assets,
                deadline - timedelta(microseconds=1),
                public_publication_complete=True,
            )

        with self.assertRaisesRegex(ValueError, "not complete"):
            mark_public_promoted(
                sponsor_release,
                assets,
                deadline,
                public_publication_complete=False,
            )

        promoted = mark_public_promoted(
            sponsor_release,
            assets,
            deadline,
            public_publication_complete=True,
        )
        self.assertEqual(promoted["state"], "public")
        self.assertEqual(promoted["verified_assets"], sponsor_release["verified_assets"])
        self.assertEqual(promoted["public_published_at"], "2026-11-01T14:00:00Z")
        duplicate = mark_public_promoted(
            promoted,
            assets,
            deadline + timedelta(days=1),
            public_publication_complete=True,
        )
        self.assertEqual(duplicate, promoted)
        changed = [{**assets[0], "sha256": "e" * 64}]
        with self.assertRaisesRegex(ValueError, "immutable"):
            mark_public_promoted(
                promoted,
                changed,
                deadline + timedelta(days=1),
                public_publication_complete=True,
            )


if __name__ == "__main__":
    unittest.main()
