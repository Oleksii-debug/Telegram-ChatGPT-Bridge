from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone

from bridge.backend import TelethonReadBackend, TelethonReadConfig
from bridge.errors import BridgeError
from bridge.validation import DateRange


class User:
    def __init__(self, user_id: int = 7, *, name: str = "Олексій", username: str = "reader") -> None:
        self.id = user_id
        self.first_name = name
        self.last_name = ""
        self.username = username


class Chat:
    def __init__(self, chat_id: int = 1) -> None:
        self.id = chat_id
        self.title = f"Chat {chat_id}"


class Msg:
    def __init__(self, message_id: int, *, text: str | None = None, sender_id: int = 7) -> None:
        self.id = message_id
        self.message = text if text is not None else f"message-{message_id}"
        self.date = datetime(2026, 8, 23, 12, 0, tzinfo=timezone.utc) + timedelta(minutes=message_id)
        self.chat_id = 1
        self.sender_id = sender_id
        self._sender = User(sender_id)
        self.out = False
        self.reply_to = None
        self.media = None
        self.file = None
        self.document = None
        self.photo = None
        self.voice = None
        self.video_note = None
        self.video = None
        self.audio = None
        self.sticker = None

    async def get_sender(self):
        return self._sender


class ExplicitOffsetClient:
    """Telethon-like fake with an explicit offset_id keyword contract."""

    def __init__(self) -> None:
        self.messages = [Msg(index) for index in range(7, 0, -1)]
        self.calls: list[tuple[int, int, str]] = []
        self.disconnected = 0

    async def connect(self):
        return None

    async def is_user_authorized(self):
        return True

    async def disconnect(self):
        self.disconnected += 1

    def get_entity(self, target):
        return Chat(int(target))

    def iter_messages(self, entity, limit: int, *, offset_id: int = 0, search: str = ""):
        del entity
        self.calls.append((limit, offset_id, search))
        rows = self.messages
        if offset_id:
            rows = [message for message in rows if message.id < offset_id]
        return rows[:limit]


class HistoryServerOffsetTests(unittest.TestCase):
    def test_history_traverses_beyond_old_scan_ceiling_with_exclusive_offset(self):
        client = ExplicitOffsetClient()
        backend = TelethonReadBackend(
            client_factory=lambda: client,
            # Deliberately tiny: old behavior could never reach IDs 3..1.
            config=TelethonReadConfig(request_timeout_seconds=2, search_scan_limit=3),
        )

        cursor = None
        seen: list[int] = []
        while True:
            page = backend.history(chat="1", limit=2, cursor=cursor)
            seen.extend(message.id for message in page.items)
            cursor = page.next_cursor
            if cursor is None:
                break

        self.assertEqual(seen, [7, 6, 5, 4, 3, 2, 1])
        self.assertEqual(client.calls, [(3, 0, ""), (3, 6, ""), (3, 4, ""), (3, 2, "")])
        self.assertEqual(client.disconnected, 4)

    def test_newer_insert_between_pages_does_not_shift_server_offset(self):
        client = ExplicitOffsetClient()
        backend = TelethonReadBackend(client_factory=lambda: client)
        first = backend.history(chat="1", limit=2, cursor=None)
        client.messages.insert(0, Msg(8))
        second = backend.history(chat="1", limit=2, cursor=first.next_cursor)
        self.assertEqual([message.id for message in first.items], [7, 6])
        self.assertEqual([message.id for message in second.items], [5, 4])
        self.assertEqual(client.calls[1][1], 6)


class SenderResolutionClient(ExplicitOffsetClient):
    def __init__(self, message: Msg) -> None:
        super().__init__()
        self.messages = [message]


class SenderResolutionTests(unittest.TestCase):
    def test_name_filter_propagates_floodwait_instead_of_false_empty_result(self):
        class FloodWaitError(Exception):
            seconds = 17

        message = Msg(1)

        async def broken_sender():
            raise FloodWaitError("PRIVATE")

        message.get_sender = broken_sender
        backend = TelethonReadBackend(
            client_factory=lambda: SenderResolutionClient(message),
            config=TelethonReadConfig(flood_wait_cap_seconds=10),
        )
        with self.assertRaises(BridgeError) as captured:
            backend.search(
                chat="1",
                sender="Олексій",
                text="",
                dates=DateRange(None, None),
                limit=10,
                cursor=None,
                scan_limit=10,
            )
        self.assertEqual(captured.exception.code, "telegram_flood_wait")
        self.assertEqual(captured.exception.status, 429)
        self.assertEqual(captured.exception.retry_after_seconds, 10)
        self.assertNotIn("PRIVATE", captured.exception.message)

    def test_stable_numeric_sender_filter_survives_optional_name_lookup_failure(self):
        message = Msg(1, sender_id=7)

        async def broken_sender():
            raise RuntimeError("PRIVATE")

        message.get_sender = broken_sender
        backend = TelethonReadBackend(client_factory=lambda: SenderResolutionClient(message))
        result = backend.search(
            chat="1",
            sender="7",
            text="",
            dates=DateRange(None, None),
            limit=10,
            cursor=None,
            scan_limit=10,
        )
        self.assertEqual([item.id for item in result.items], [1])
        self.assertEqual(result.items[0].sender.id, "7")
        self.assertIsNone(result.items[0].sender.display_name)

    def test_at_username_filter_is_normalized_without_mutating_result_identity(self):
        message = Msg(1)
        backend = TelethonReadBackend(client_factory=lambda: SenderResolutionClient(message))
        result = backend.search(
            chat="1",
            sender="@READER",
            text="",
            dates=DateRange(None, None),
            limit=10,
            cursor=None,
            scan_limit=10,
        )
        self.assertEqual([item.id for item in result.items], [1])
        self.assertEqual(result.items[0].sender.username, "reader")
        self.assertEqual(result.items[0].sender.id, "7")


class ServerSearchHintTests(unittest.TestCase):
    def test_server_search_hint_is_nfkc_normalized_then_local_match_is_caseless(self):
        message = Msg(1, text="ЙЖАК")
        client = SenderResolutionClient(message)
        backend = TelethonReadBackend(client_factory=lambda: client)
        result = backend.search(
            chat="1",
            sender=None,
            text="и\u0306жак",
            dates=DateRange(None, None),
            limit=10,
            cursor=None,
            scan_limit=10,
        )
        self.assertEqual([item.id for item in result.items], [1])
        self.assertEqual(client.calls[0][2], "йжак")
        self.assertEqual(result.items[0].text, "ЙЖАК")


if __name__ == "__main__":
    unittest.main()
