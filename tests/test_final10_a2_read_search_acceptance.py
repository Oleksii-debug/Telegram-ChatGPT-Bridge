from __future__ import annotations

import unittest
from datetime import datetime, timezone

from bridge.backend import TelethonReadBackend, TelethonReadConfig
from bridge.dialog_pagination import install_dialog_pagination
from bridge.errors import BridgeError
from bridge.typed_dialog_identity import install_typed_dialog_identity, marked_dialog_id
from bridge.validation import DateRange


class User:
    def __init__(self, peer_id: int, first_name: str, username: str | None = None) -> None:
        self.id = peer_id
        self.first_name = first_name
        self.last_name = ""
        self.username = username


class Chat:
    def __init__(self, peer_id: int, title: str) -> None:
        self.id = peer_id
        self.title = title
        self.username = None


class Channel:
    def __init__(self, peer_id: int, title: str) -> None:
        self.id = peer_id
        self.title = title
        self.username = None


class _DialogMessage:
    def __init__(self, message_id: int, stamp: datetime) -> None:
        self.id = message_id
        self.date = stamp


class _Dialog:
    def __init__(self, entity, message_id: int, stamp: datetime, *, pinned: bool = False) -> None:
        self.entity = entity
        self.id = int(marked_dialog_id(entity, TelethonReadBackend._entity_kind(entity)))
        self.message = _DialogMessage(message_id, stamp)
        self.unread_count = 1
        self.pinned = pinned


class _Message:
    def __init__(self, message_id: int, chat_id: int, stamp: datetime, text: str, sender: User) -> None:
        self.id = message_id
        self.chat_id = chat_id
        self.date = stamp
        self.message = text
        self.sender_id = sender.id
        self._sender = sender
        self.reply_to = None
        self.media = None
        self.file = None
        self.out = False

    async def get_sender(self):
        return self._sender


class _ReadOnlyClient:
    def __init__(self) -> None:
        self.sender = User(501, "Олена", "olena")
        self.group = Chat(11, "Pinned group")
        self.user = User(22, "Recent user", "recent")
        self.channel = Channel(77, "Канал пошуку")
        self.other_group = Chat(88, "Older group")
        self.dialogs = [
            _Dialog(self.group, 101, datetime(2026, 8, 30, 9, 4, tzinfo=timezone.utc), pinned=True),
            _Dialog(self.user, 100, datetime(2026, 8, 30, 9, 3, tzinfo=timezone.utc)),
            _Dialog(self.channel, 99, datetime(2026, 8, 30, 9, 2, tzinfo=timezone.utc)),
            _Dialog(self.other_group, 98, datetime(2026, 8, 30, 9, 1, tzinfo=timezone.utc)),
        ]
        self.channel_marked = int(marked_dialog_id(self.channel, "channel"))
        self.messages = {
            self.channel_marked: [
                _Message(30, self.channel_marked, datetime(2026, 8, 29, 10, 0, tzinfo=timezone.utc), "Їжак 🦔 e\u0301", self.sender),
                _Message(29, self.channel_marked, datetime(2026, 8, 29, 9, 0, tzinfo=timezone.utc), "їЖАК друга згадка", self.sender),
                _Message(28, self.channel_marked, datetime(2026, 8, 29, 8, 0, tzinfo=timezone.utc), "інший текст", self.sender),
            ]
        }
        self.entity_requests: list[object] = []
        self.dialog_calls: list[dict[str, object]] = []

    async def connect(self) -> None:
        return None

    async def disconnect(self) -> None:
        return None

    async def is_user_authorized(self) -> bool:
        return True

    def get_input_entity(self, peer_id):
        return peer_id

    def iter_dialogs(
        self,
        limit: int,
        offset_date=None,
        offset_id: int = 0,
        offset_peer=None,
        ignore_pinned: bool = False,
    ):
        self.dialog_calls.append(
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
        return []

    async def get_entity(self, target):
        self.entity_requests.append(target)
        if target == self.channel_marked:
            return self.channel
        if target == "olena":
            return self.sender
        if target == -self.group.id:
            return self.group
        if target == self.user.id:
            return self.user
        if target == -self.other_group.id:
            return self.other_group
        raise ValueError("unknown synthetic peer")

    def iter_messages(
        self,
        entity,
        *,
        limit: int,
        search: str = "",
        offset_id: int | None = None,
        from_user=None,
        offset_date=None,
    ):
        del search, from_user
        marked = int(marked_dialog_id(entity, TelethonReadBackend._entity_kind(entity)))
        rows = list(self.messages.get(marked, ()))
        if offset_id is not None:
            rows = [row for row in rows if row.id < offset_id]
        if offset_date is not None:
            rows = [row for row in rows if row.date < offset_date]
        return rows[:limit]


class Final10A2ReadSearchAcceptanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        # Production runtime installs both patches before constructing the app.
        install_dialog_pagination()
        install_typed_dialog_identity()

    @staticmethod
    def _backend(client: _ReadOnlyClient) -> TelethonReadBackend:
        return TelethonReadBackend(
            client_factory=lambda: client,
            config=TelethonReadConfig(dialog_scan_limit=2, search_scan_limit=20),
        )

    def test_deep_dialog_typed_peer_history_and_scoped_search_survive_restart(self) -> None:
        client = _ReadOnlyClient()
        cursor = None
        channel_ref = None
        seen_dialog_ids: list[str] = []

        # Reconstruct the backend between pages to model service/process restart.
        for _ in range(8):
            page = self._backend(client).list_dialogs(limit=1, cursor=cursor, query="", unread_only=False)
            seen_dialog_ids.extend(item.id for item in page.items)
            if page.items and page.items[0].kind == "channel":
                channel_ref = page.items[0].id
                break
            cursor = page.next_cursor
            self.assertIsNotNone(cursor)

        self.assertEqual(channel_ref, "-1000000000077")
        self.assertEqual(len(seen_dialog_ids), len(set(seen_dialog_ids)))
        self.assertTrue(any(call["offset_peer"] is not None for call in client.dialog_calls))

        first_history = self._backend(client).history(chat=channel_ref, limit=1, cursor=None)
        self.assertEqual([item.id for item in first_history.items], [30])
        self.assertEqual(first_history.items[0].text, "Їжак 🦔 e\u0301")
        self.assertIsNotNone(first_history.next_cursor)

        second_history = self._backend(client).history(
            chat=channel_ref,
            limit=1,
            cursor=first_history.next_cursor,
        )
        self.assertEqual([item.id for item in second_history.items], [29])
        self.assertIn(client.channel_marked, client.entity_requests)

        dates = DateRange(
            datetime(2026, 8, 29, 8, 30, tzinfo=timezone.utc),
            datetime(2026, 8, 29, 10, 30, tzinfo=timezone.utc),
        )
        first_search = self._backend(client).search(
            chat=channel_ref,
            sender="@olena",
            text="їжак",
            dates=dates,
            limit=1,
            cursor=None,
            scan_limit=10,
        )
        self.assertEqual([item.id for item in first_search.items], [30])
        self.assertEqual(first_search.items[0].sender.id, "501")
        self.assertEqual(first_search.items[0].sender.username, "olena")
        self.assertIsNotNone(first_search.next_cursor)

        second_search = self._backend(client).search(
            chat=channel_ref,
            sender="@olena",
            text="ЇЖАК",
            dates=dates,
            limit=1,
            cursor=first_search.next_cursor,
            scan_limit=10,
        )
        self.assertEqual([item.id for item in second_search.items], [29])
        self.assertNotEqual(first_search.items[0].id, second_search.items[0].id)

    def test_cursor_cannot_be_reused_for_a_different_scoped_search(self) -> None:
        client = _ReadOnlyClient()
        channel_ref = str(client.channel_marked)
        dates = DateRange(None, None)
        first = self._backend(client).search(
            chat=channel_ref,
            sender="@olena",
            text="їжак",
            dates=dates,
            limit=1,
            cursor=None,
            scan_limit=10,
        )
        self.assertIsNotNone(first.next_cursor)

        with self.assertRaises(BridgeError) as captured:
            self._backend(client).search(
                chat=channel_ref,
                sender="@olena",
                text="інший",
                dates=dates,
                limit=1,
                cursor=first.next_cursor,
                scan_limit=10,
            )
        self.assertEqual(captured.exception.code, "invalid_cursor")


if __name__ == "__main__":
    unittest.main()
