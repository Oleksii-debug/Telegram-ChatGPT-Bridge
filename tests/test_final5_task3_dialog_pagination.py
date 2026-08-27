from __future__ import annotations

import unittest
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from bridge.backend import TelethonReadConfig
from bridge.errors import BridgeError
from bridge.models import decode_cursor
from ops.final5_task3_dialog_pagination import DeepDialogTelethonReadBackend


@dataclass
class User:
    id: int
    first_name: str
    username: str | None = None


@dataclass
class FakeMessage:
    id: int
    date: datetime


@dataclass
class FakeDialog:
    id: int
    entity: User
    message: FakeMessage
    unread_count: int = 0
    pinned: bool = False


class FakeClient:
    def __init__(self, dialogs):
        self.dialogs = list(dialogs)
        self.calls = []

    def is_user_authorized(self):
        return True

    def iter_dialogs(
        self,
        limit,
        offset_date=None,
        offset_id=0,
        offset_peer=None,
        ignore_pinned=False,
    ):
        self.calls.append(
            {
                "limit": limit,
                "offset_date": offset_date,
                "offset_id": offset_id,
                "offset_peer": offset_peer,
                "ignore_pinned": ignore_pinned,
            }
        )
        start = 0
        if offset_peer is not None:
            for index, dialog in enumerate(self.dialogs):
                if dialog.id == offset_peer and dialog.message.id == offset_id:
                    start = index + 1
                    break
            else:
                return []
        return self.dialogs[start : start + limit]

    def get_input_entity(self, peer_id):
        return peer_id


class PinnedAwareFakeClient(FakeClient):
    """Approximate Telegram's exclude-pinned continuation contract."""

    def iter_dialogs(
        self,
        limit,
        offset_date=None,
        offset_id=0,
        offset_peer=None,
        ignore_pinned=False,
    ):
        self.calls.append(
            {
                "limit": limit,
                "offset_date": offset_date,
                "offset_id": offset_id,
                "offset_peer": offset_peer,
                "ignore_pinned": ignore_pinned,
            }
        )
        rows = [dialog for dialog in self.dialogs if not (ignore_pinned and dialog.pinned)]
        if offset_peer is None:
            return rows[:limit]
        for index, dialog in enumerate(rows):
            if dialog.id == offset_peer and dialog.message.id == offset_id:
                return rows[index + 1 : index + 1 + limit]
        # A pinned offset is not in an exclude-pinned result set. Telegram may
        # continue with unpinned rows, but it cannot return other pinned rows.
        return rows[:limit]


class DialogPaginationTests(unittest.TestCase):
    def make_dialogs(self, count=13):
        now = datetime(2026, 8, 27, 12, 0, tzinfo=timezone.utc)
        dialogs = []
        for index in range(count):
            number = index + 1
            dialogs.append(
                FakeDialog(
                    id=-1000000000000 - number,
                    entity=User(number, f"Dialog {number}", f"user{number}"),
                    message=FakeMessage(10_000 - number, now - timedelta(minutes=index)),
                    unread_count=1 if number % 2 else 0,
                    pinned=number == 1,
                )
            )
        return dialogs

    def backend(self, client):
        return DeepDialogTelethonReadBackend(
            client_factory=lambda: client,
            config=TelethonReadConfig(dialog_scan_limit=4, search_scan_limit=20),
        )

    def test_traverses_beyond_one_bounded_prefix_without_duplicates(self):
        client = FakeClient(self.make_dialogs())
        backend = self.backend(client)
        cursor = None
        seen = []
        for _ in range(20):
            page = backend.list_dialogs(limit=2, cursor=cursor, query="", unread_only=False)
            seen.extend(item.id for item in page.items)
            cursor = page.next_cursor
            if cursor is None:
                break
        self.assertEqual(seen, [str(i) for i in range(1, 14)])
        self.assertEqual(len(seen), len(set(seen)))
        self.assertGreater(len(client.calls), 1)
        self.assertTrue(any(call["offset_peer"] is not None for call in client.calls[1:]))

    def test_sparse_filter_can_advance_with_short_or_empty_pages(self):
        dialogs = self.make_dialogs(15)
        for index, dialog in enumerate(dialogs):
            dialog.entity.first_name = "needle" if index in {0, 7, 14} else "other"
        client = FakeClient(dialogs)
        backend = self.backend(client)
        cursor = None
        found = []
        empty_with_cursor = False
        for _ in range(20):
            page = backend.list_dialogs(limit=2, cursor=cursor, query="needle", unread_only=False)
            found.extend(item.id for item in page.items)
            if not page.items and page.next_cursor is not None:
                empty_with_cursor = True
            cursor = page.next_cursor
            if cursor is None:
                break
        self.assertEqual(found, ["1", "8", "15"])
        self.assertTrue(empty_with_cursor)

    def test_cursor_contains_no_peer_access_hash(self):
        client = FakeClient(self.make_dialogs())
        page = self.backend(client).list_dialogs(limit=2, cursor=None, query="", unread_only=False)
        decoded = decode_cursor(page.next_cursor)
        self.assertEqual(set(decoded), {"v", "scope", "sig", "offset", "after"})
        self.assertEqual(decoded["v"], 4)
        self.assertIsNone(decoded["offset"])
        self.assertIsInstance(decoded["after"], int)
        self.assertNotIn("access_hash", str(decoded).casefold())

    def test_native_pinned_order_is_preserved(self):
        dialogs = self.make_dialogs(4)
        dialogs[0].message.date = datetime(2020, 1, 1, tzinfo=timezone.utc)
        client = FakeClient(dialogs)
        page = self.backend(client).list_dialogs(limit=2, cursor=None, query="", unread_only=False)
        self.assertTrue(page.items[0].pinned)
        self.assertEqual(page.items[0].id, "1")

    def test_small_page_does_not_skip_remaining_pinned_dialogs(self):
        dialogs = self.make_dialogs(8)
        for index, dialog in enumerate(dialogs):
            dialog.pinned = index < 3
        client = PinnedAwareFakeClient(dialogs)
        backend = self.backend(client)
        cursor = None
        seen = []
        for _ in range(20):
            page = backend.list_dialogs(limit=1, cursor=cursor, query="", unread_only=False)
            seen.extend(item.id for item in page.items)
            cursor = page.next_cursor
            if cursor is None:
                break
        self.assertEqual(seen, [str(i) for i in range(1, 9)])

    def test_first_window_replay_survives_newer_insert_without_duplicate(self):
        dialogs = self.make_dialogs(8)
        client = PinnedAwareFakeClient(dialogs)
        backend = self.backend(client)
        first = backend.list_dialogs(limit=1, cursor=None, query="", unread_only=False)
        inserted = self.make_dialogs(1)[0]
        inserted.id = -1000000000999
        inserted.entity.id = 999
        inserted.entity.first_name = "Inserted"
        inserted.message.id = 99_999
        inserted.message.date += timedelta(minutes=5)
        inserted.pinned = True
        client.dialogs.insert(0, inserted)
        second = backend.list_dialogs(limit=1, cursor=first.next_cursor, query="", unread_only=False)
        self.assertEqual([item.id for item in first.items], ["1"])
        self.assertEqual([item.id for item in second.items], ["2"])

    def test_full_window_ending_in_pinned_prefix_fails_closed(self):
        dialogs = self.make_dialogs(8)
        for dialog in dialogs[:5]:
            dialog.pinned = True
        client = PinnedAwareFakeClient(dialogs)
        backend = self.backend(client)
        cursor = None
        with self.assertRaises(BridgeError) as captured:
            for _ in range(10):
                page = backend.list_dialogs(limit=1, cursor=cursor, query="", unread_only=False)
                cursor = page.next_cursor
                if cursor is None:
                    self.fail("unsafe pinned prefix ended without a fail-closed error")
        self.assertEqual(captured.exception.code, "telegram_dialog_scan_limit_too_small")


if __name__ == "__main__":
    unittest.main()
