from __future__ import annotations

import asyncio
import unittest
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from types import SimpleNamespace

from bridge.backend import TelethonReadBackend, TelethonReadConfig, _GlobalSearchContinuation
from bridge.errors import BridgeError
from bridge.models import EntityRef, MessageRecord
from bridge.validation import DateRange


class Swarm10NativeGlobalContinuationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.backend = TelethonReadBackend(client_factory=lambda: object())

    def test_cursor_roundtrip_is_scope_and_signature_bound(self) -> None:
        state = _GlobalSearchContinuation(55, "channel", 777, 9)
        token = self.backend._encode_global_cursor("sig", state)
        self.assertEqual(self.backend._decode_global_cursor(token, "sig"), state)
        with self.assertRaises(BridgeError):
            self.backend._decode_global_cursor(token, "other")

    def test_global_peer_and_rate_fallback_are_stable(self) -> None:
        message = SimpleNamespace(
            peer_id=SimpleNamespace(channel_id=42),
            date=datetime(2026, 8, 27, 8, 0, tzinfo=timezone.utc),
        )
        self.assertEqual(self.backend._global_peer_parts(message), ("channel", 42))
        self.assertEqual(
            self.backend._next_global_offset_rate(SimpleNamespace(), message),
            int(message.date.timestamp()),
        )
        self.assertEqual(
            self.backend._next_global_offset_rate(SimpleNamespace(next_rate=77), message),
            77,
        )

    def test_filtered_empty_page_keeps_native_cursor(self) -> None:
        other = EntityRef(id="1", kind="user", display_name="Other", username="other")
        target = EntityRef(id="2", kind="user", display_name="Target", username="target")
        target_entity = type("User", (), {"id": 2, "username": "target", "first_name": "Target", "last_name": ""})()
        first = SimpleNamespace(
            id=10,
            chat_id=100,
            record=MessageRecord(
                id=10,
                chat_id="100",
                timestamp="2026-08-27T05:00:00Z",
                text="needle",
                sender=other,
            ),
        )
        second = SimpleNamespace(
            id=9,
            chat_id=200,
            record=MessageRecord(
                id=9,
                chat_id="200",
                timestamp="2026-08-27T04:59:00Z",
                text="needle",
                sender=target,
            ),
        )

        class FakeClient:
            async def get_entity(self, value):
                if value == "target":
                    return target_entity
                raise ValueError("not found")

        class FakeBackend(TelethonReadBackend):
            @asynccontextmanager
            async def _client_session(self):
                yield FakeClient()

            async def _search_global_chunk(self, client, *, query, limit, state, max_date):
                del client, query, limit, max_date
                if state is None:
                    return [first], _GlobalSearchContinuation(10, "user", 100, 7)
                if state.offset_id == 10:
                    return [second], _GlobalSearchContinuation(9, "channel", 200, 6)
                return [], None

            async def _message_record(self, message, chat_id, *, require_sender_details=False):
                del chat_id, require_sender_details
                return message.record

        backend = FakeBackend(client_factory=lambda: object())
        dates = DateRange(None, None)
        first_page = backend.search(
            chat=None,
            sender="@target",
            text="needle",
            dates=dates,
            limit=1,
            cursor=None,
            scan_limit=1,
        )
        self.assertEqual(first_page.items, ())
        self.assertIsNotNone(first_page.next_cursor)

        second_page = backend.search(
            chat=None,
            sender="@target",
            text="needle",
            dates=dates,
            limit=1,
            cursor=first_page.next_cursor,
            scan_limit=1,
        )
        self.assertEqual([item.id for item in second_page.items], [9])


class _Channel:
    def __init__(self, entity_id: int) -> None:
        self.id = entity_id
        self.title = f"Chat {entity_id}"


class _Message:
    def __init__(self, message_id: int, chat_id: int, stamp: str) -> None:
        self.id = message_id
        self.chat_id = chat_id
        self.date = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
        self.message = f"message {message_id}"
        self.sender_id = None
        self.out = False
        self.reply_to = None
        self.media = None
        self.file = None


class _DialogClient:
    def __init__(self) -> None:
        self.entities = [_Channel(100), _Channel(200)]
        self.messages = {
            100: [_Message(5, 100, "2026-08-27T05:00:00Z"), _Message(4, 100, "2026-08-27T04:00:00Z")],
            200: [_Message(8, 200, "2026-08-27T04:30:00Z"), _Message(7, 200, "2026-08-27T03:00:00Z")],
        }

    async def connect(self) -> None:
        return None

    async def is_user_authorized(self) -> bool:
        return True

    async def disconnect(self) -> None:
        return None

    def iter_dialogs(self, limit: int):
        return [
            SimpleNamespace(entity=entity, message=self.messages[entity.id][0])
            for entity in self.entities[:limit]
        ]

    def iter_messages(
        self,
        entity,
        limit: int,
        *,
        from_user=None,
        offset_id: int | None = None,
        offset_date: datetime | None = None,
    ):
        del from_user
        rows = list(self.messages[entity.id])
        if offset_date is not None:
            rows = [row for row in rows if row.date < offset_date]
        if offset_id is not None:
            rows = [row for row in rows if row.id < offset_id]
        return rows[:limit]


class Swarm10GlobalFilterMergeTests(unittest.TestCase):
    def _backend(self, client: _DialogClient) -> TelethonReadBackend:
        return TelethonReadBackend(
            client_factory=lambda: client,
            config=TelethonReadConfig(
                request_timeout_seconds=2,
                dialog_scan_limit=10,
                search_scan_limit=20,
            ),
        )

    def test_empty_text_uses_cross_dialog_merge_and_boundary_cursor(self) -> None:
        backend = self._backend(_DialogClient())
        dates = DateRange(None, None)
        first = backend.search(
            chat=None,
            sender=None,
            text="",
            dates=dates,
            limit=2,
            cursor=None,
            scan_limit=10,
        )
        self.assertEqual([(item.chat_id, item.id) for item in first.items], [("100", 5), ("200", 8)])
        self.assertIsNotNone(first.next_cursor)

        second = backend.search(
            chat=None,
            sender=None,
            text="",
            dates=dates,
            limit=2,
            cursor=first.next_cursor,
            scan_limit=10,
        )
        self.assertEqual([(item.chat_id, item.id) for item in second.items], [("100", 4), ("200", 7)])

    def test_filter_merge_fails_closed_when_budget_cannot_seed_all_dialogs(self) -> None:
        backend = self._backend(_DialogClient())
        with self.assertRaises(BridgeError) as captured:
            backend.search(
                chat=None,
                sender=None,
                text="",
                dates=DateRange(None, None),
                limit=1,
                cursor=None,
                scan_limit=1,
            )
        self.assertEqual(captured.exception.code, "global_search_scan_limit_too_small")


class _ScopedSearchEntity:
    id = 300


class _ScopedSearchMessage:
    def __init__(self, message_id: int, text: str = "needle") -> None:
        self.id = message_id
        self.message = text
        self.date = datetime(2026, 8, 27, 12, 0, message_id, tzinfo=timezone.utc)


class _ScopedSearchClient:
    def __init__(self, *, target_ids: set[int] | None = None) -> None:
        self.calls: list[dict[str, object]] = []
        self.messages = [_ScopedSearchMessage(message_id) for message_id in range(20, 0, -1)]
        self.target_ids = set(target_ids or ())

    async def connect(self) -> None:
        return None

    async def is_user_authorized(self) -> bool:
        return True

    async def disconnect(self) -> None:
        return None

    async def get_entity(self, _ref: object) -> _ScopedSearchEntity:
        return _ScopedSearchEntity()

    def iter_messages(
        self,
        entity: object,
        *,
        limit: int,
        search: str = "",
        offset_id: int | None = None,
    ) -> list[_ScopedSearchMessage]:
        self.calls.append(
            {
                "entity": entity,
                "limit": limit,
                "search": search,
                "offset_id": offset_id,
            }
        )
        rows = self.messages
        if offset_id is not None:
            rows = [row for row in rows if row.id < offset_id]
        if search:
            rows = [row for row in rows if search.casefold() in row.message.casefold()]
        return rows[:limit]


class _IgnoresScopedSearchOffset(_ScopedSearchClient):
    def iter_messages(
        self,
        entity: object,
        *,
        limit: int,
        search: str = "",
        offset_id: int | None = None,
    ) -> list[_ScopedSearchMessage]:
        self.calls.append(
            {
                "entity": entity,
                "limit": limit,
                "search": search,
                "offset_id": offset_id,
            }
        )
        rows = self.messages
        if search:
            rows = [row for row in rows if search.casefold() in row.message.casefold()]
        return rows[:limit]


class _ScopedSearchBackend(TelethonReadBackend):
    async def _message_record(
        self,
        message: _ScopedSearchMessage,
        chat_id: str,
        *,
        require_sender_details: bool = False,
    ) -> MessageRecord:
        del require_sender_details
        if message.id in self.client_factory().target_ids:
            sender = EntityRef(id="42", kind="user", display_name="Target", username="target")
        else:
            sender = EntityRef(id="7", kind="user", display_name="Other", username="other")
        return MessageRecord(
            id=message.id,
            chat_id=chat_id,
            timestamp=message.date.isoformat().replace("+00:00", "Z"),
            text=message.message,
            sender=sender,
            outgoing=False,
            reply_to_message_id=None,
            media=None,
        )


class Swarm10ScopedSearchContinuationTests(unittest.TestCase):
    @staticmethod
    def _backend(client: _ScopedSearchClient) -> _ScopedSearchBackend:
        return _ScopedSearchBackend(
            client_factory=lambda: client,
            config=TelethonReadConfig(request_timeout_seconds=2, search_scan_limit=20),
        )

    def test_second_page_uses_exclusive_server_offset(self) -> None:
        client = _ScopedSearchClient()
        backend = self._backend(client)
        first = backend.search(
            chat="300",
            sender=None,
            text="needle",
            dates=DateRange(None, None),
            limit=2,
            cursor=None,
            scan_limit=2,
        )
        second = backend.search(
            chat="300",
            sender=None,
            text="needle",
            dates=DateRange(None, None),
            limit=2,
            cursor=first.next_cursor,
            scan_limit=2,
        )
        self.assertEqual([20, 19], [item.id for item in first.items])
        self.assertEqual([18, 17], [item.id for item in second.items])
        self.assertEqual([None, 19], [call["offset_id"] for call in client.calls])

    def test_cursor_traverses_beyond_the_original_bounded_prefix_without_duplicates(self) -> None:
        client = _ScopedSearchClient()
        backend = self._backend(client)
        cursor = None
        seen: list[int] = []
        for _ in range(5):
            page = backend.search(
                chat="300",
                sender=None,
                text="needle",
                dates=DateRange(None, None),
                limit=2,
                cursor=cursor,
                scan_limit=2,
            )
            seen.extend(item.id for item in page.items)
            cursor = page.next_cursor
        self.assertEqual(list(range(20, 10, -1)), seen)
        self.assertEqual(len(seen), len(set(seen)))
        self.assertEqual([None, 19, 17, 15, 13], [call["offset_id"] for call in client.calls])

    def test_empty_sparse_pages_keep_advancing_until_sender_match(self) -> None:
        client = _ScopedSearchClient(target_ids={16})
        backend = self._backend(client)
        cursor = None
        pages: list[list[int]] = []
        for _ in range(3):
            page = backend.search(
                chat="300",
                sender="@target",
                text="",
                dates=DateRange(None, None),
                limit=1,
                cursor=cursor,
                scan_limit=2,
            )
            pages.append([item.id for item in page.items])
            self.assertIsNotNone(page.next_cursor)
            cursor = page.next_cursor
        self.assertEqual([[], [], [16]], pages)
        self.assertEqual([None, 19, 17], [call["offset_id"] for call in client.calls])

    def test_nonadvancing_explicit_offset_fails_closed(self) -> None:
        client = _IgnoresScopedSearchOffset()
        backend = self._backend(client)
        first = backend.search(
            chat="300",
            sender=None,
            text="needle",
            dates=DateRange(None, None),
            limit=2,
            cursor=None,
            scan_limit=2,
        )
        with self.assertRaises(BridgeError) as captured:
            backend.search(
                chat="300",
                sender=None,
                text="needle",
                dates=DateRange(None, None),
                limit=2,
                cursor=first.next_cursor,
                scan_limit=2,
            )
        self.assertEqual(captured.exception.code, "telegram_search_continuation_not_advanced")
        self.assertEqual([None, 19], [call["offset_id"] for call in client.calls])


class _RaisesInsideConstrainedCall:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def iter_messages(
        self,
        entity: object,
        *,
        limit: int,
        search: str = "",
        offset_id: int | None = None,
    ) -> list[object]:
        self.calls.append({"entity": entity, "limit": limit, "search": search, "offset_id": offset_id})
        raise TypeError("simulated TypeError inside client call")


class _LegacyNoSearchSupport:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def iter_messages(self, entity: object, *, limit: int) -> list[object]:
        self.calls.append({"entity": entity, "limit": limit})
        return ["legacy"]


class _LegacyNoOffsetSupport:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def iter_messages(self, entity: object, *, limit: int, search: str = "") -> list[object]:
        self.calls.append({"entity": entity, "limit": limit, "search": search})
        return ["legacy"]


class _SupportedConstraints:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def iter_messages(
        self,
        entity: object,
        *,
        limit: int,
        search: str = "",
        offset_id: int | None = None,
    ) -> list[object]:
        self.calls.append({"entity": entity, "limit": limit, "search": search, "offset_id": offset_id})
        return ["ok"]


class Swarm10FailClosedIterMessagesTests(unittest.TestCase):
    def setUp(self) -> None:
        self.backend = TelethonReadBackend(client_factory=lambda: object())

    def test_internal_typeerror_does_not_retry_without_constraints(self) -> None:
        client = _RaisesInsideConstrainedCall()
        with self.assertRaisesRegex(TypeError, "inside client call"):
            asyncio.run(self.backend._iter_messages(client, "peer", 25, search="needle", offset_id=77))
        self.assertEqual(
            client.calls,
            [{"entity": "peer", "limit": 25, "search": "needle", "offset_id": 77}],
        )

    def test_legacy_client_without_search_parameter_is_called_only_once(self) -> None:
        client = _LegacyNoSearchSupport()
        result = asyncio.run(self.backend._iter_messages(client, "peer", 25, search="needle"))
        self.assertEqual(result, ["legacy"])
        self.assertEqual(client.calls, [{"entity": "peer", "limit": 25}])

    def test_legacy_client_without_offset_parameter_is_called_only_once(self) -> None:
        client = _LegacyNoOffsetSupport()
        result = asyncio.run(self.backend._iter_messages(client, "peer", 25, search="needle", offset_id=77))
        self.assertEqual(result, ["legacy"])
        self.assertEqual(client.calls, [{"entity": "peer", "limit": 25, "search": "needle"}])

    def test_supported_constraints_are_forwarded_exactly_once(self) -> None:
        client = _SupportedConstraints()
        result = asyncio.run(self.backend._iter_messages(client, "peer", 25, search="needle", offset_id=77))
        self.assertEqual(result, ["ok"])
        self.assertEqual(
            client.calls,
            [{"entity": "peer", "limit": 25, "search": "needle", "offset_id": 77}],
        )


if __name__ == "__main__":
    unittest.main()
