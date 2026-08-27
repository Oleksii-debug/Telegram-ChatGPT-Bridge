from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone

from bridge.backend import TelethonReadConfig
from bridge.errors import BridgeError
from bridge.final5_search_backend import Final5TelethonReadBackend
from bridge.validation import DateRange


class User:
    def __init__(self, user_id: int, username: str | None, first_name: str, last_name: str = "") -> None:
        self.id = user_id
        self.username = username
        self.first_name = first_name
        self.last_name = last_name


class Chat:
    def __init__(self, chat_id: int, title: str = "chat") -> None:
        self.id = chat_id
        self.title = title


class Message:
    def __init__(self, message_id: int, chat_id: int, sender: User, *, text: str = "hello", minutes: int = 0) -> None:
        self.id = message_id
        self.chat_id = chat_id
        self.sender_id = sender.id
        self.date = datetime(2026, 8, 26, 18, 0, tzinfo=timezone.utc) - timedelta(minutes=minutes)
        self.message = text
        self.out = False
        self.reply_to = None
        self.media = None
        self.file = None
        self._sender = sender

    async def get_sender(self) -> User:
        return self._sender


class StrictTelethonClient:
    """Fake that enforces the relevant Telethon 1.44 public contract."""

    def __init__(self, *, entities=None, dialogs=(), messages=()) -> None:  # type: ignore[no-untyped-def]
        self.entities = dict(entities or {})
        self.dialogs = list(dialogs)
        self.messages = list(messages)
        self.calls: list[dict[str, object]] = []
        self.disconnected = False

    async def connect(self) -> None:
        return None

    async def is_user_authorized(self) -> bool:
        return True

    async def disconnect(self) -> None:
        self.disconnected = True

    async def get_entity(self, target):  # type: ignore[no-untyped-def]
        if target in self.entities:
            return self.entities[target]
        raise ValueError("not found")

    def iter_dialogs(self, limit: int):
        return self.dialogs[:limit]

    def iter_messages(
        self,
        entity,
        limit: int,
        *,
        search: str = "",
        filter=None,
        from_user=None,
        offset_id: int | None = None,
    ):  # type: ignore[no-untyped-def]
        if entity is None and not search and filter is None and from_user is None:
            raise ValueError("global search requires search/filter/from_user")
        self.calls.append(
            {
                "entity": entity,
                "limit": limit,
                "search": search,
                "filter": filter,
                "from_user": from_user,
                "offset_id": offset_id,
            }
        )
        rows = list(self.messages)
        if entity is not None:
            rows = [row for row in rows if row.chat_id == entity.id]
        if offset_id is not None:
            rows = [row for row in rows if row.id < offset_id]
        if from_user is not None:
            rows = [row for row in rows if row.sender_id == from_user.id]
        if search:
            folded = search.casefold()
            rows = [row for row in rows if folded in row.message.casefold()]
        return rows[:limit]


class NoConstraintClient(StrictTelethonClient):
    def iter_messages(self, entity, limit: int, *, search: str = ""):  # type: ignore[no-untyped-def]
        if entity is None and not search:
            raise ValueError("global search requires constraint")
        return []


class NoOffsetClient(StrictTelethonClient):
    def iter_messages(self, entity, limit: int, *, search: str = "", filter=None, from_user=None):  # type: ignore[no-untyped-def]
        if entity is None and not search and filter is None and from_user is None:
            raise ValueError("global search requires constraint")
        return self.messages[:limit]


class TestBackend(Final5TelethonReadBackend):
    _FILTER_SENTINEL = object()

    @staticmethod
    def _global_empty_filter():
        return TestBackend._FILTER_SENTINEL


class Final5Task3SearchTests(unittest.TestCase):
    def _backend(self, client) -> TestBackend:  # type: ignore[no-untyped-def]
        return TestBackend(
            client_factory=lambda: client,
            config=TelethonReadConfig(
                request_timeout_seconds=2,
                dialog_scan_limit=20,
                search_scan_limit=100,
                flood_wait_cap_seconds=10,
            ),
        )

    def _search(
        self,
        backend: TestBackend,
        *,
        chat: str | None = None,
        sender: str | None = None,
        text: str = "",
        dates: DateRange | None = None,
        limit: int = 2,
        cursor: str | None = None,
        scan_limit: int = 3,
    ):
        return backend.search(
            chat=chat,
            sender=sender,
            text=text,
            dates=dates or DateRange(None, None),
            limit=limit,
            cursor=cursor,
            scan_limit=scan_limit,
        )

    def test_global_sender_only_uses_from_user_constraint(self):
        sender = User(42, "reader", "Reader")
        client = StrictTelethonClient(
            entities={"reader": sender},
            messages=[Message(9, 100, sender)],
        )
        page = self._search(self._backend(client), sender="@reader")

        self.assertEqual([item.id for item in page.items], [9])
        self.assertIs(client.calls[0]["from_user"], sender)
        self.assertIsNone(client.calls[0]["filter"])
        self.assertEqual(client.calls[0]["search"], "")
        self.assertTrue(client.disconnected)

    def test_global_date_only_uses_empty_filter_constraint(self):
        sender = User(1, "one", "One")
        client = StrictTelethonClient(messages=[Message(9, 100, sender)])
        dates = DateRange(
            datetime(2026, 8, 26, 17, 0, tzinfo=timezone.utc),
            datetime(2026, 8, 26, 19, 0, tzinfo=timezone.utc),
        )
        page = self._search(self._backend(client), dates=dates)

        self.assertEqual([item.id for item in page.items], [9])
        self.assertIs(client.calls[0]["filter"], TestBackend._FILTER_SENTINEL)
        self.assertIsNone(client.calls[0]["from_user"])
        self.assertEqual(client.calls[0]["search"], "")

    def test_global_empty_query_is_still_legally_constrained(self):
        sender = User(1, "one", "One")
        client = StrictTelethonClient(messages=[Message(9, 100, sender)])
        page = self._search(self._backend(client))

        self.assertEqual([item.id for item in page.items], [9])
        self.assertIs(client.calls[0]["filter"], TestBackend._FILTER_SENTINEL)

    def test_global_constraint_support_fails_closed_instead_of_broad_retry(self):
        client = NoConstraintClient()
        with self.assertRaises(BridgeError) as captured:
            self._search(self._backend(client))
        self.assertEqual(captured.exception.code, "telegram_global_search_unsupported")
        self.assertEqual(captured.exception.status, 503)
        self.assertTrue(client.disconnected)

    def test_scoped_second_page_uses_exclusive_server_offset(self):
        sender = User(1, "one", "One")
        chat = Chat(100)
        messages = [Message(mid, 100, sender, text="needle", minutes=10 - mid) for mid in range(10, 4, -1)]
        client = StrictTelethonClient(entities={"room": chat}, messages=messages)
        backend = self._backend(client)

        first = self._search(backend, chat="room", text="needle", limit=2, scan_limit=3)
        self.assertEqual([item.id for item in first.items], [10, 9])
        self.assertIsNotNone(first.next_cursor)

        second = self._search(
            backend,
            chat="room",
            text="needle",
            limit=2,
            scan_limit=3,
            cursor=first.next_cursor,
        )
        self.assertEqual([item.id for item in second.items], [8, 7])
        self.assertEqual(client.calls[0]["offset_id"], None)
        self.assertEqual(client.calls[1]["offset_id"], 9)
        self.assertNotEqual([item.id for item in first.items], [item.id for item in second.items])

    def test_scoped_sparse_filter_continues_from_last_scanned_raw_message(self):
        wanted = User(1, "wanted", "Wanted")
        other = User(2, "other", "Other")
        chat = Chat(100)
        messages = [
            Message(10, 100, wanted),
            Message(9, 100, other),
            Message(8, 100, other),
            Message(7, 100, wanted),
            Message(6, 100, wanted),
        ]
        client = StrictTelethonClient(entities={"room": chat}, messages=messages)
        backend = self._backend(client)

        first = self._search(backend, chat="room", sender="wanted", limit=2, scan_limit=3)
        self.assertEqual([item.id for item in first.items], [10])
        self.assertIsNotNone(first.next_cursor)

        second = self._search(
            backend,
            chat="room",
            sender="wanted",
            limit=2,
            scan_limit=3,
            cursor=first.next_cursor,
        )
        self.assertEqual([item.id for item in second.items], [7, 6])
        self.assertEqual(client.calls[1]["offset_id"], 8)

    def test_scoped_legacy_client_does_not_claim_server_continuation(self):
        sender = User(1, "one", "One")
        chat = Chat(100)
        client = NoOffsetClient(entities={"room": chat}, messages=[Message(10, 100, sender)])
        first = self._search(self._backend(client), chat="room", limit=1, scan_limit=1)
        self.assertEqual([item.id for item in first.items], [10])
        self.assertIsNone(first.next_cursor)


if __name__ == "__main__":
    unittest.main()
