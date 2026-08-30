from __future__ import annotations

import unittest
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from bridge.backend import TelethonReadBackend, TelethonReadConfig
from bridge.dialog_pagination import install_dialog_pagination
from bridge.errors import BridgeError
from bridge.models import decode_cursor


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
        return rows[:limit]


class DialogPaginationCurrentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        install_dialog_pagination()

    def make_dialogs(self, count=13):
        now = datetime(2026, 8, 27, 12, 0, tzinfo=timezone.utc)
        rows = []
        for index in range(count):
            number = index + 1
            rows.append(
                FakeDialog(
                    id=-1000000000000 - number,
                    entity=User(number, f"Dialog {number}", f"user{number}"),
                    message=FakeMessage(10_000 - number, now - timedelta(minutes=index)),
                    unread_count=1 if number % 2 else 0,
                    pinned=number == 1,
                )
            )
        return rows

    def backend(self, client):
        return TelethonReadBackend(
            client_factory=lambda: client,
            config=TelethonReadConfig(dialog_scan_limit=4, search_scan_limit=20),
        )

    def test_runtime_class_traverses_beyond_bounded_prefix_without_duplicates(self):
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
        self.assertTrue(any(call["offset_peer"] is not None for call in client.calls[1:]))

    def test_sparse_filter_advances_through_empty_visible_pages(self):
        dialogs = self.make_dialogs(15)
        for index, dialog in enumerate(dialogs):
            dialog.entity.first_name = "needle" if index in {0, 7, 14} else "other"
        backend = self.backend(FakeClient(dialogs))
        cursor = None
        found = []
        empty_with_cursor = False
        for _ in range(20):
            page = backend.list_dialogs(limit=2, cursor=cursor, query="needle", unread_only=False)
            found.extend(item.id for item in page.items)
            empty_with_cursor |= not page.items and page.next_cursor is not None
            cursor = page.next_cursor
            if cursor is None:
                break
        self.assertEqual(found, ["1", "8", "15"])
        self.assertTrue(empty_with_cursor)

    def test_cursor_has_no_access_hash(self):
        page = self.backend(FakeClient(self.make_dialogs())).list_dialogs(
            limit=2, cursor=None, query="", unread_only=False
        )
        decoded = decode_cursor(page.next_cursor)
        self.assertEqual(set(decoded), {"v", "scope", "sig", "offset", "after"})
        self.assertEqual(decoded["v"], 4)
        self.assertNotIn("access_hash", str(decoded).casefold())

    def test_small_api_page_does_not_skip_remaining_pinned_dialogs(self):
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

    def test_pinned_prefix_that_exceeds_scan_bound_fails_closed(self):
        dialogs = self.make_dialogs(8)
        for dialog in dialogs[:5]:
            dialog.pinned = True
        backend = self.backend(PinnedAwareFakeClient(dialogs))
        cursor = None
        with self.assertRaises(BridgeError) as captured:
            for _ in range(10):
                page = backend.list_dialogs(limit=1, cursor=cursor, query="", unread_only=False)
                cursor = page.next_cursor
                if cursor is None:
                    self.fail("unsafe pinned prefix ended without fail-closed error")
        self.assertEqual(captured.exception.code, "telegram_dialog_scan_limit_too_small")


if __name__ == "__main__":
    unittest.main()
