from __future__ import annotations

import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

from bridge.outreach import CampaignSpec, OutreachError, OutreachStore


class OutreachStoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Path(self.tmp.name) / "outreach.sqlite3"
        self.store = OutreachStore(self.db)

    def tearDown(self):
        self.tmp.cleanup()

    @staticmethod
    def epoch(y, m, d, hh=12, mm=0, tz="UTC"):
        return int(datetime(y, m, d, hh, mm, tzinfo=ZoneInfo(tz)).timestamp())

    def create(self, campaign="c1", recipients=None, **kwargs):
        recipients = recipients or ["user:1", "user:2"]
        spec = CampaignSpec(
            campaign_id=campaign,
            message_text=kwargs.pop("message_text", "Hello"),
            daily_limit=kwargs.pop("daily_limit", 20),
            interval_seconds=kwargs.pop("interval_seconds", 0),
            timezone_name=kwargs.pop("timezone_name", "UTC"),
            window_start=kwargs.pop("window_start", "00:00"),
            window_end=kwargs.pop("window_end", "00:00"),
        )
        self.assertFalse(kwargs)
        return self.store.create_campaign(spec, recipients, created_at=self.epoch(2026,10,25))

    def test_duplicate_input_removed(self):
        result = self.create(recipients=["user:1","user:1","user:2"])
        self.assertEqual(result["recipients"], 2)
        self.assertEqual(result["duplicates_removed"], 1)

    def test_interval_between_successful_sends(self):
        now = self.epoch(2026,10,25,10)
        self.create(interval_seconds=600)
        first = self.store.claim_next("c1", now=now)
        self.assertEqual(first.recipient, "user:1")
        self.store.mark_sent("c1","user:1",sent_at=now)
        self.assertIsNone(self.store.claim_next("c1", now=now+599))
        self.assertEqual(self.store.claim_next("c1", now=now+600).recipient, "user:2")

    def test_daily_limit_resets_next_local_day(self):
        now = self.epoch(2026,10,25,10,tz="Europe/Warsaw")
        self.create(daily_limit=1, timezone_name="Europe/Warsaw")
        first = self.store.claim_next("c1", now=now)
        self.store.mark_sent("c1",first.recipient,sent_at=now)
        self.assertIsNone(self.store.claim_next("c1", now=now+3600))
        tomorrow = self.epoch(2026,10,26,10,tz="Europe/Warsaw")
        self.assertEqual(self.store.claim_next("c1", now=tomorrow).recipient, "user:2")

    def test_same_message_same_recipient_is_global_duplicate(self):
        now = self.epoch(2026,10,25,10)
        self.create(campaign="c1", recipients=["user:1"], message_text="Same")
        first = self.store.claim_next("c1", now=now)
        self.store.mark_sent("c1", first.recipient, sent_at=now)
        self.create(campaign="c2", recipients=["user:1","user:2"], message_text="Same")
        second = self.store.claim_next("c2", now=now+1)
        self.assertEqual(second.recipient, "user:2")
        self.assertEqual(self.store.status("c2", now=now+1)["counts"]["skipped_duplicate"], 1)

    def test_pause_and_resume(self):
        now = self.epoch(2026,10,25,10)
        self.create()
        self.store.pause("c1")
        self.assertIsNone(self.store.claim_next("c1", now=now))
        self.store.resume("c1")
        self.assertEqual(self.store.claim_next("c1", now=now).recipient, "user:1")

    def test_retry_survives_restart(self):
        now = self.epoch(2026,10,25,10)
        self.create(recipients=["user:1"])
        first = self.store.claim_next("c1", now=now, lease_seconds=60)
        self.store.mark_failed("c1", first.recipient, error="FloodWait", retry_after_seconds=120, now=now)
        restarted = OutreachStore(self.db)
        self.assertIsNone(restarted.claim_next("c1", now=now+119, lease_seconds=60))
        self.assertEqual(restarted.claim_next("c1", now=now+120, lease_seconds=60).recipient, "user:1")

    def test_expired_inflight_lease_recovers_after_restart(self):
        now = self.epoch(2026,10,25,10)
        self.create(recipients=["user:1"])
        self.store.claim_next("c1", now=now, lease_seconds=60)
        restarted = OutreachStore(self.db)
        self.assertEqual(restarted.claim_next("c1", now=now+61, lease_seconds=60).recipient, "user:1")

    def test_local_send_window(self):
        self.create(recipients=["user:1"], timezone_name="Europe/Warsaw", window_start="09:00", window_end="18:00")
        before = self.epoch(2026,10,25,8,59,tz="Europe/Warsaw")
        inside = self.epoch(2026,10,25,9,0,tz="Europe/Warsaw")
        self.assertIsNone(self.store.preview_next("c1", now=before))
        self.assertEqual(self.store.preview_next("c1", now=inside).recipient, "user:1")

    def test_duplicate_campaign_rejected(self):
        self.create()
        with self.assertRaises(OutreachError):
            self.create()


if __name__ == "__main__":
    unittest.main()
