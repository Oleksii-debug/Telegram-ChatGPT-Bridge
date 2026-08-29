from __future__ import annotations

import unittest
from datetime import datetime, timezone

from bridge.backend import TelethonReadBackend
from bridge.typed_dialog_identity import install_typed_dialog_identity, marked_dialog_id


class User:
    def __init__(self, peer_id: int):
        self.id = peer_id
        self.first_name = "User"
        self.last_name = ""
        self.username = None


class Chat:
    def __init__(self, peer_id: int):
        self.id = peer_id
        self.title = "Group"
        self.username = None


class Channel:
    def __init__(self, peer_id: int):
        self.id = peer_id
        self.title = "Channel"
        self.username = None


class _DialogMessage:
    id = 99
    date = datetime(2026, 8, 30, 0, 0, tzinfo=timezone.utc)


class _Dialog:
    def __init__(self, entity):
        self.entity = entity
        self.message = _DialogMessage()
        self.unread_count = 0
        self.pinned = False


class _HistoryMessage:
    def __init__(self, peer_id: int):
        self.id = 7
        self.chat_id = peer_id
        self.date = datetime(2026, 8, 29, 23, 59, tzinfo=timezone.utc)
        self.message = "hello"
        self.sender_id = None
        self.reply_to = None
        self.media = None
        self.file = None
        self.out = False


class _Client:
    def __init__(self, dialog):
        self.dialog = dialog
        self.entity_requests: list[int] = []

    async def connect(self):
        return None

    async def disconnect(self):
        return None

    async def is_user_authorized(self):
        return True

    def iter_dialogs(self, *, limit):
        return [self.dialog][:limit]

    async def get_entity(self, target):
        self.entity_requests.append(target)
        entity = self.dialog.entity
        expected = int(marked_dialog_id(entity, TelethonReadBackend._entity_kind(entity)))
        if target != expected:
            raise ValueError("wrong peer identity")
        return entity

    def iter_messages(self, entity, *, limit, search="", offset_id=None):
        del search, offset_id
        return [_HistoryMessage(int(marked_dialog_id(entity, TelethonReadBackend._entity_kind(entity))))][:limit]


class Final10B3TypedDialogIdentityTests(unittest.TestCase):
    def setUp(self):
        self._original_descriptor = TelethonReadBackend.__dict__["_dialog_record"]
        install_typed_dialog_identity()

    def tearDown(self):
        TelethonReadBackend._dialog_record = self._original_descriptor

    def test_dialog_ids_preserve_telegram_peer_type(self):
        self.assertEqual("42", marked_dialog_id(User(42), "user"))
        self.assertEqual("-42", marked_dialog_id(Chat(42), "group"))
        self.assertEqual("-1000000000042", marked_dialog_id(Channel(42), "channel"))

    def test_channel_dialog_id_roundtrips_into_history_resolution(self):
        client = _Client(_Dialog(Channel(77)))
        backend = TelethonReadBackend(client_factory=lambda: client)

        dialogs = backend.list_dialogs(limit=1, cursor=None, query="", unread_only=False)
        self.assertEqual(1, len(dialogs.items))
        self.assertEqual("channel", dialogs.items[0].kind)
        self.assertEqual("-1000000000077", dialogs.items[0].id)

        history = backend.history(chat=dialogs.items[0].id, limit=1, cursor=None)
        self.assertEqual([-1000000000077], client.entity_requests)
        self.assertEqual(1, len(history.items))

    def test_group_dialog_id_roundtrips_into_history_resolution(self):
        client = _Client(_Dialog(Chat(88)))
        backend = TelethonReadBackend(client_factory=lambda: client)

        dialogs = backend.list_dialogs(limit=1, cursor=None, query="", unread_only=False)
        self.assertEqual("-88", dialogs.items[0].id)
        backend.history(chat=dialogs.items[0].id, limit=1, cursor=None)
        self.assertEqual([-88], client.entity_requests)


if __name__ == "__main__":
    unittest.main()
