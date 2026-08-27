from __future__ import annotations

import unittest
from datetime import datetime, timezone

from bridge.errors import BridgeError
from bridge.final5_global_search_r10 import GlobalSearchR10Backend
from bridge.validation import DateRange


class Final5Task3GlobalSearchR10Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.client_calls = 0

        def client_factory():
            self.client_calls += 1
            raise AssertionError("empty global query must fail before creating a Telegram client")

        self.backend = GlobalSearchR10Backend(client_factory=client_factory)

    def assert_empty_global_rejected(self, *, sender: str | None, dates: DateRange) -> None:
        with self.assertRaises(BridgeError) as ctx:
            self.backend.search(
                chat=None,
                sender=sender,
                text="   ",
                dates=dates,
                limit=10,
                cursor=None,
                scan_limit=100,
            )
        self.assertEqual(ctx.exception.code, "telegram_global_empty_query_unsupported")
        self.assertEqual(ctx.exception.status, 400)
        self.assertEqual(ctx.exception.details, {"retryable": False})
        self.assertEqual(self.client_calls, 0)

    def test_empty_global_query_fails_before_rpc(self) -> None:
        self.assert_empty_global_rejected(sender=None, dates=DateRange(start=None, end=None))

    def test_sender_only_global_query_fails_truthfully_before_rpc(self) -> None:
        self.assert_empty_global_rejected(sender="target", dates=DateRange(start=None, end=None))

    def test_date_only_global_query_fails_truthfully_before_rpc(self) -> None:
        self.assert_empty_global_rejected(
            sender=None,
            dates=DateRange(start=datetime(2026, 8, 1, tzinfo=timezone.utc), end=datetime(2026, 8, 27, tzinfo=timezone.utc)),
        )


if __name__ == "__main__":
    unittest.main()
