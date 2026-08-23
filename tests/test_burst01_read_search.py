from __future__ import annotations

import unittest
from datetime import datetime, timezone
from types import SimpleNamespace

from bridge.backend import TelethonReadBackend, TelethonReadConfig
from bridge.errors import BridgeError
from bridge.read_search_correctness import GlobalSenderTelethonReadBackend
from bridge.validation import DateRange


class User:
    def __init__(self, user_id: int, username: str | None, first_name: str, last_name: str = "") -> None:
        self.id = user_id
        self.username = username
        self.first_name = first_name
        self.last_name = last_name


class _Message:
    def __init__(self, message_id: int, chat_id: int, sender: User, text: str = "hello") -> None:
        self.id = message_id
        self.chat_id = chat_id
        self.sender_id = sender.id
        self.date = datetime(2026, 8, 23, 12, 0, tzinfo=timezone.utc)
        self.message = text
        self.out = False
        self.reply_to = None
        self.media = None
        self.file = None
        self._sender = sender

    async def get_sender(self) -> User:
        return self._sender


class _MetadataFailureMessage(_Message):
    async def get_sender(self) -> User:
        class FloodWaitError(Exception):
            seconds = 9

        raise FloodWaitError("synthetic optional sender metadata failure")


class _StrictGlobalClient:
    def __init__(self, *, dialogs=(), direct_entities=None, messages=()) -> None:  # type: ignore[no-untyped-def]
        self.dialogs = list(dialogs)
        self.direct_entities = dict(direct_entities or {})
        self.messages = list(messages)
        self.calls: list[dict[str, object]] = []
        self.connected = False
        self.disconnected = False

    async def connect(self) -> None:
        self.connected = True

    async def is_user_authorized(self) -> bool:
        return True

    async def disconnect(self) -> None:
        self.disconnected = True

    async def get_entity(self, target):  # type: ignore[no-untyped-def]
        if target in self.direct_entities:
            return self.direct_entities[target]
        raise ValueError("not found")

    def iter_dialogs(self, limit: int):
        return self.dialogs[:limit]

    def iter_messages(
        self,
        entity,
        limit: int,
        *,
        search: str = "",
        from_user=None,
        offset_id: int = 0,
    ):  # type: ignore[no-untyped-def]
        del offset_id
        if entity is None and not search and from_user is None:
            raise ValueError("global search requires search/filter/from_user")
        self.calls.append(
            {
                "entity": entity,
                "limit": limit,
                "search": search,
                "from_user": from_user,
            }
        )
        rows = self.messages
        if from_user is not None:
            rows = [row for row in rows if row.sender_id == from_user.id]
        if search:
            folded = search.casefold()
            rows = [row for row in rows if folded in row.message.casefold()]
        return rows[:limit]


class _NoFromUserClient(_StrictGlobalClient):
    def iter_messages(self, entity, limit: int, *, search: str = ""):  # type: ignore[no-untyped-def]
        if entity is None and not search:
            raise ValueError("global search requires search/filter/from_user")
        return []


class _ScopedMinimalClient(_StrictGlobalClient):
    def iter_messages(self, entity, limit: int):  # type: ignore[no-untyped-def]
        self.calls.append({"entity": entity, "limit": limit})
        return self.messages[:limit]


class Burst01GlobalSenderSearchTests(unittest.TestCase):
    def _backend(self, client) -> GlobalSenderTelethonReadBackend:  # type: ignore[no-untyped-def]
        return GlobalSenderTelethonReadBackend(
            client_factory=lambda: client,
            config=TelethonReadConfig(
                request_timeout_seconds=2,
                dialog_scan_limit=20,
                search_scan_limit=100,
            ),
        )

    def _search(self, backend: TelethonReadBackend, sender: str, *, chat: str | None = None, text: str = ""):
        return backend.search(
            chat=chat,
            sender=sender,
            text=text,
            dates=DateRange(None, None),
            limit=10,
            cursor=None,
            scan_limit=10,
        )

    def test_sender_only_global_username_uses_telethon_from_user(self):
        sender = User(42, "reader", "Reader")
        message = _Message(7, 1001, sender)
        client = _StrictGlobalClient(direct_entities={"reader": sender}, messages=[message])
        page = self._search(self._backend(client), "@reader")

        self.assertEqual([item.id for item in page.items], [7])
        self.assertEqual(len(client.calls), 1)
        self.assertIs(client.calls[0]["from_user"], sender)
        self.assertEqual(client.calls[0]["search"], "")
        self.assertEqual(page.items[0].sender.id, "42")
        self.assertEqual(page.items[0].sender.username, "reader")
        self.assertTrue(client.disconnected)

    def test_resolved_sender_survives_optional_message_sender_metadata_failure(self):
        sender = User(42, "reader", "Reader")
        message = _MetadataFailureMessage(71, 1001, sender)
        client = _StrictGlobalClient(direct_entities={"reader": sender}, messages=[message])
        page = self._search(self._backend(client), "@reader")

        self.assertEqual([item.id for item in page.items], [71])
        self.assertEqual(page.items[0].sender.id, "42")
        self.assertEqual(page.items[0].sender.display_name, "Reader")
        self.assertTrue(client.disconnected)

    def test_global_sender_with_text_preserves_existing_server_search_path(self):
        sender = User(42, "reader", "Reader")
        message = _Message(8, 1001, sender, text="Привіт світе")
        client = _StrictGlobalClient(messages=[message])
        page = self._search(self._backend(client), "reader", text="Привіт")

        self.assertEqual([item.id for item in page.items], [8])
        self.assertIsNone(client.calls[0]["from_user"])
        self.assertEqual(client.calls[0]["search"], "Привіт")

    def test_display_name_falls_back_to_unique_bounded_dialog_match(self):
        sender = User(77, "ivan77", "Іван", "Петренко")
        dialog = SimpleNamespace(entity=sender, message=None, unread_count=0, pinned=False)
        message = _Message(9, 1002, sender)
        client = _StrictGlobalClient(dialogs=[dialog], messages=[message])
        page = self._search(self._backend(client), "іван петренко")

        self.assertEqual([item.id for item in page.items], [9])
        self.assertIs(client.calls[0]["from_user"], sender)
        self.assertEqual(page.items[0].sender.display_name, "Іван Петренко")

    def test_partial_display_name_must_be_unique(self):
        first = User(1, "ivan_one", "Іван", "Петренко")
        second = User(2, "ivan_two", "Іван", "Петренко")
        dialogs = [
            SimpleNamespace(entity=first, message=None, unread_count=0, pinned=False),
            SimpleNamespace(entity=second, message=None, unread_count=0, pinned=False),
        ]
        client = _StrictGlobalClient(dialogs=dialogs)

        with self.assertRaises(BridgeError) as captured:
            self._search(self._backend(client), "Іван")
        self.assertEqual(captured.exception.code, "sender_ambiguous")
        self.assertEqual(captured.exception.status, 400)
        self.assertEqual(client.calls, [])
        self.assertTrue(client.disconnected)

    def test_missing_sender_is_controlled_not_false_empty(self):
        client = _StrictGlobalClient()
        with self.assertRaises(BridgeError) as captured:
            self._search(self._backend(client), "Невідомий Користувач")
        self.assertEqual(captured.exception.code, "sender_not_found")
        self.assertEqual(captured.exception.status, 404)
        self.assertEqual(client.calls, [])

    def test_global_sender_does_not_silently_drop_constraint_on_incompatible_client(self):
        sender = User(42, "reader", "Reader")
        client = _NoFromUserClient(direct_entities={"reader": sender})
        with self.assertRaises(BridgeError) as captured:
            self._search(self._backend(client), "@reader")
        self.assertEqual(captured.exception.code, "telegram_global_sender_unsupported")
        self.assertEqual(captured.exception.status, 503)

    def test_chat_scoped_sender_search_keeps_minimal_fake_compatibility(self):
        sender = User(42, "reader", "Reader")
        chat = SimpleNamespace(id=1001)
        message = _Message(10, 1001, sender)
        client = _ScopedMinimalClient(direct_entities={"chatname": chat}, messages=[message])
        page = self._search(self._backend(client), "reader", chat="chatname")
        self.assertEqual([item.id for item in page.items], [10])
        self.assertEqual(len(client.calls), 1)


if __name__ == "__main__":
    unittest.main()
