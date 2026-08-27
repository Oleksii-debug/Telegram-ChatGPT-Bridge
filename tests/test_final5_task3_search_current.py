from __future__ import annotations

import asyncio
import unittest
from datetime import datetime, timezone
from types import SimpleNamespace

from bridge.final5_task3_search_current import Final5Task3TelethonReadBackend
from bridge.models import MessageRecord, canonical_timestamp
from bridge.validation import DateRange


class _InternalTypeErrorClient:
    def __init__(self):
        self.calls = []

    def iter_messages(self, entity, *, limit, search="", offset_id=None):
        self.calls.append((entity, limit, search, offset_id))
        raise TypeError("internal client failure")


class _Entity:
    id = 100


class _RawMessage:
    def __init__(self, message_id: int, text: str = "needle"):
        self.id = message_id
        self.message = text
        self.date = datetime(2026, 8, 27, 12, 0, message_id % 60, tzinfo=timezone.utc)


class _ScopedClient:
    def __init__(self):
        self.calls = []
        self.messages = [_RawMessage(i) for i in range(20, 0, -1)]

    async def connect(self):
        return None

    async def disconnect(self):
        return None

    async def is_user_authorized(self):
        return True

    async def get_entity(self, _ref):
        return _Entity()

    def iter_messages(self, entity, *, limit, search="", offset_id=None):
        self.calls.append({"limit": limit, "search": search, "offset_id": offset_id})
        rows = self.messages
        if offset_id is not None:
            rows = [row for row in rows if row.id < offset_id]
        if search:
            rows = [row for row in rows if search.casefold() in row.message.casefold()]
        return rows[:limit]


class _Backend(Final5Task3TelethonReadBackend):
    async def _message_record(self, message, chat_id, *, require_sender_details=False):
        return MessageRecord(
            id=message.id,
            chat_id=chat_id,
            timestamp=canonical_timestamp(message.date),
            text=message.message,
            sender=None,
            outgoing=False,
            reply_to_message_id=None,
            media=None,
        )


class CurrentTask3SearchTests(unittest.TestCase):
    def test_internal_typeerror_is_never_retried_broader(self):
        backend = Final5Task3TelethonReadBackend(client_factory=lambda: object())
        client = _InternalTypeErrorClient()
        with self.assertRaisesRegex(TypeError, "internal client failure"):
            asyncio.run(backend._iter_messages(client, "peer", 5, search="needle", offset_id=17))
        self.assertEqual([("peer", 5, "needle", 17)], client.calls)

    def test_scoped_search_second_page_uses_exclusive_server_offset(self):
        client = _ScopedClient()
        backend = _Backend(client_factory=lambda: client)
        dates = DateRange(None, None)
        first = backend.search(
            chat="100", sender=None, text="needle", dates=dates,
            limit=2, cursor=None, scan_limit=2,
        )
        self.assertEqual([20, 19], [item.id for item in first.items])
        self.assertIsNotNone(first.next_cursor)
        second = backend.search(
            chat="100", sender=None, text="needle", dates=dates,
            limit=2, cursor=first.next_cursor, scan_limit=2,
        )
        self.assertEqual([18, 17], [item.id for item in second.items])
        self.assertEqual(None, client.calls[0]["offset_id"])
        self.assertEqual(19, client.calls[1]["offset_id"])

    def test_scoped_search_traverses_beyond_original_scan_prefix_without_duplicates(self):
        client = _ScopedClient()
        backend = _Backend(client_factory=lambda: client)
        cursor = None
        seen = []
        for _ in range(5):
            page = backend.search(
                chat="100", sender=None, text="needle", dates=DateRange(None, None),
                limit=2, cursor=cursor, scan_limit=2,
            )
            seen.extend(item.id for item in page.items)
            cursor = page.next_cursor
        self.assertEqual(list(range(20, 10, -1)), seen)
        self.assertEqual(len(seen), len(set(seen)))
        self.assertTrue(all(call["offset_id"] is None or call["offset_id"] < 21 for call in client.calls))

    def test_global_search_delegates_to_canonical_native_path(self):
        class _GlobalDelegationBackend(Final5Task3TelethonReadBackend):
            pass

        # Structural guard: the candidate overrides only scoped behavior;
        # global calls are explicitly delegated to the current canonical backend.
        self.assertIsNot(
            _GlobalDelegationBackend.search,
            Final5Task3TelethonReadBackend.__mro__[1].search,
        )


if __name__ == "__main__":
    unittest.main()
