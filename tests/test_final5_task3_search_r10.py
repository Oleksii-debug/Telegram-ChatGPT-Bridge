from __future__ import annotations

import asyncio
import unittest
from datetime import datetime, timezone

from bridge.errors import BridgeError
from bridge.final5_task3_search_r10 import Final5Task3SearchR10Backend
from bridge.models import MessageRecord, canonical_timestamp
from bridge.validation import DateRange


class _InternalTypeErrorClient:
    def __init__(self):
        self.calls = []

    def iter_messages(self, entity, *, limit, search="", offset_id=None):
        self.calls.append((entity, limit, search, offset_id))
        raise TypeError("internal client failure")


class _NoSearchClient:
    def __init__(self):
        self.calls = 0

    def iter_messages(self, entity, *, limit):
        self.calls += 1
        return []


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
        self.messages = [_RawMessage(i) for i in range(30, 0, -1)]

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


class _Backend(Final5Task3SearchR10Backend):
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


class Task3SearchR10Tests(unittest.TestCase):
    def test_internal_typeerror_is_not_retried_without_constraints(self):
        backend = Final5Task3SearchR10Backend(client_factory=lambda: object())
        client = _InternalTypeErrorClient()
        with self.assertRaisesRegex(TypeError, "internal client failure"):
            asyncio.run(backend._iter_messages(client, "peer", 5, search="needle", offset_id=17))
        self.assertEqual([("peer", 5, "needle", 17)], client.calls)

    def test_unsupported_search_fails_before_any_broad_call(self):
        backend = Final5Task3SearchR10Backend(client_factory=lambda: object())
        client = _NoSearchClient()
        with self.assertRaises(BridgeError) as raised:
            asyncio.run(backend._iter_messages(client, "peer", 5, search="needle"))
        self.assertEqual("telegram_search_unsupported", raised.exception.code)
        self.assertEqual(0, client.calls)

    def test_scoped_page_two_uses_exclusive_telethon_offset(self):
        client = _ScopedClient()
        backend = _Backend(client_factory=lambda: client)
        first = backend.search(
            chat="100", sender=None, text="needle", dates=DateRange(None, None),
            limit=2, cursor=None, scan_limit=2,
        )
        second = backend.search(
            chat="100", sender=None, text="needle", dates=DateRange(None, None),
            limit=2, cursor=first.next_cursor, scan_limit=2,
        )
        self.assertEqual([30, 29], [item.id for item in first.items])
        self.assertEqual([28, 27], [item.id for item in second.items])
        self.assertEqual(None, client.calls[0]["offset_id"])
        self.assertEqual(29, client.calls[1]["offset_id"])

    def test_deep_scoped_pagination_crosses_original_scan_prefix_without_duplicates(self):
        client = _ScopedClient()
        backend = _Backend(client_factory=lambda: client)
        cursor = None
        seen = []
        for _ in range(6):
            page = backend.search(
                chat="100", sender=None, text="needle", dates=DateRange(None, None),
                limit=2, cursor=cursor, scan_limit=2,
            )
            seen.extend(item.id for item in page.items)
            cursor = page.next_cursor
        self.assertEqual(list(range(30, 18, -1)), seen)
        self.assertEqual(len(seen), len(set(seen)))
        self.assertEqual([None, 29, 27, 25, 23, 21], [call["offset_id"] for call in client.calls])

    def test_global_search_remains_canonical_not_reimplemented(self):
        # The override explicitly delegates chat=None to TelethonReadBackend.search;
        # this specialist must not create a second SearchGlobal protocol.
        self.assertIs(Final5Task3SearchR10Backend.__mro__[1], __import__("bridge.backend", fromlist=["TelethonReadBackend"]).TelethonReadBackend)


if __name__ == "__main__":
    unittest.main()
