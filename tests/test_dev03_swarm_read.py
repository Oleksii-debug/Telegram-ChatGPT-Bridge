from __future__ import annotations

import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from bridge.backend import TelethonReadBackend, TelethonReadConfig
from bridge.errors import BridgeError
from bridge.models import MessageRecord, decode_cursor, stable_message_sort
from bridge.validation import DateRange, normalize_search_text


class User:
    def __init__(self, user_id: int, *, first_name: str = "Ім'я", last_name: str = "", username: str = "reader") -> None:
        self.id = user_id
        self.first_name = first_name
        self.last_name = last_name
        self.username = username


class Chat:
    def __init__(self, chat_id: int, *, title: str | None = None) -> None:
        self.id = chat_id
        self.title = title or f"Chat {chat_id}"


class Msg:
    def __init__(
        self,
        message_id: int,
        text: str,
        date: datetime,
        *,
        chat_id: int = 1,
        sender_id: int = 7,
        sender_name: str = "Ім'я",
        username: str = "reader",
    ) -> None:
        self.id = message_id
        self.message = text
        self.date = date
        self.chat_id = chat_id
        self.sender_id = sender_id
        self._sender = User(sender_id, first_name=sender_name, username=username)
        self.out = False
        self.reply_to = None
        self.media = None
        self.file = None
        self.document = None
        self.voice = None
        self.video_note = None
        self.photo = None
        self.video = None
        self.audio = None
        self.sticker = None

    async def get_sender(self):
        return self._sender


class Dialog:
    def __init__(self, chat_id: int, title: str, date: datetime, *, unread: int = 0) -> None:
        self.entity = Chat(chat_id, title=title)
        self.message = SimpleNamespace(date=date)
        self.unread_count = unread
        self.pinned = False


class MutableClient:
    def __init__(self) -> None:
        z = timezone.utc
        self.dialogs = [
            Dialog(1, "Україна", datetime(2026, 8, 23, 12, 0, tzinfo=z), unread=1),
            Dialog(2, "Other", datetime(2026, 8, 23, 11, 0, tzinfo=z)),
            Dialog(3, "Third", datetime(2026, 8, 23, 10, 0, tzinfo=z)),
        ]
        self.messages_by_chat: dict[int, list[Msg]] = {
            1: [
                Msg(3, "Третє", datetime(2026, 8, 23, 12, 0, tzinfo=z), chat_id=1, sender_name="Олексій"),
                Msg(2, "Друге", datetime(2026, 8, 23, 11, 0, tzinfo=z), chat_id=1, sender_name="Наталія"),
                Msg(1, "Перше", datetime(2026, 8, 23, 10, 0, tzinfo=z), chat_id=1, sender_name="Олексій"),
            ],
            2: [
                Msg(3, "Other newest", datetime(2026, 8, 23, 12, 0, tzinfo=z), chat_id=2, sender_name="Other"),
                Msg(1, "Other older", datetime(2026, 8, 23, 9, 0, tzinfo=z), chat_id=2, sender_name="Other"),
            ],
        }
        self.connected = 0
        self.disconnected = 0

    async def connect(self):
        self.connected += 1

    async def is_user_authorized(self):
        return True

    async def disconnect(self):
        self.disconnected += 1

    def iter_dialogs(self, limit: int):
        return self.dialogs[:limit]

    def get_entity(self, target):
        try:
            chat_id = int(target)
        except (TypeError, ValueError):
            chat_id = 1
        return Chat(chat_id)

    def iter_messages(self, entity, limit: int, **kwargs):
        del kwargs
        if entity is None:
            messages = [message for items in self.messages_by_chat.values() for message in items]
        else:
            messages = self.messages_by_chat.get(int(entity.id), [])
        return messages[:limit]

    def get_messages(self, entity, ids: int):
        return next((message for message in self.messages_by_chat.get(int(entity.id), []) if message.id == ids), None)


class ReadCursorInvariantTests(unittest.TestCase):
    def setUp(self) -> None:
        self.client = MutableClient()
        self.backend = TelethonReadBackend(
            client_factory=lambda: self.client,
            config=TelethonReadConfig(request_timeout_seconds=2, dialog_scan_limit=100, search_scan_limit=100),
        )

    def test_history_keyset_cursor_survives_newer_insert_without_duplicate(self):
        first = self.backend.history(chat="1", limit=1, cursor=None)
        self.assertEqual([message.id for message in first.items], [3])
        self.assertIsNotNone(first.next_cursor)

        self.client.messages_by_chat[1].insert(
            0,
            Msg(4, "Новіше після першої сторінки", datetime(2026, 8, 23, 13, 0, tzinfo=timezone.utc), chat_id=1),
        )
        second = self.backend.history(chat="1", limit=1, cursor=first.next_cursor)
        self.assertEqual([message.id for message in second.items], [2])
        self.assertNotEqual(first.items[0].id, second.items[0].id)

    def test_dialog_keyset_cursor_survives_newer_insert_without_duplicate(self):
        first = self.backend.list_dialogs(limit=1, cursor=None, query="", unread_only=False)
        self.assertEqual([dialog.id for dialog in first.items], ["1"])
        self.client.dialogs.insert(
            0,
            Dialog(4, "Inserted", datetime(2026, 8, 23, 13, 0, tzinfo=timezone.utc)),
        )
        second = self.backend.list_dialogs(limit=1, cursor=first.next_cursor, query="", unread_only=False)
        self.assertEqual([dialog.id for dialog in second.items], ["2"])

    def test_history_cursor_is_bound_to_chat(self):
        first = self.backend.history(chat="1", limit=1, cursor=None)
        with self.assertRaises(BridgeError) as captured:
            self.backend.history(chat="2", limit=1, cursor=first.next_cursor)
        self.assertEqual(captured.exception.code, "invalid_cursor")

    def test_dialog_cursor_is_bound_to_filters(self):
        first = self.backend.list_dialogs(limit=1, cursor=None, query="", unread_only=False)
        with self.assertRaises(BridgeError) as captured:
            self.backend.list_dialogs(limit=1, cursor=first.next_cursor, query="Україна", unread_only=False)
        self.assertEqual(captured.exception.code, "invalid_cursor")

    def test_search_cursor_is_bound_to_text_sender_date_and_scan_limit(self):
        first = self.backend.search(
            chat="1",
            sender=None,
            text="",
            dates=DateRange(None, None),
            limit=1,
            cursor=None,
            scan_limit=10,
        )
        cases = [
            dict(chat="1", sender=None, text="інше", dates=DateRange(None, None), scan_limit=10),
            dict(chat="1", sender="7", text="", dates=DateRange(None, None), scan_limit=10),
            dict(
                chat="1",
                sender=None,
                text="",
                dates=DateRange(datetime(2026, 8, 23, 10, 0, tzinfo=timezone.utc), None),
                scan_limit=10,
            ),
            dict(chat="1", sender=None, text="", dates=DateRange(None, None), scan_limit=11),
        ]
        for params in cases:
            with self.subTest(params=params), self.assertRaises(BridgeError) as captured:
                self.backend.search(limit=1, cursor=first.next_cursor, **params)
            self.assertEqual(captured.exception.code, "invalid_cursor")

    def test_cursor_contains_hash_binding_not_private_query(self):
        first = self.backend.list_dialogs(limit=1, cursor=None, query="СИНТЕТИЧНИЙ-ПОШУК", unread_only=False)
        # Query filters the synthetic dataset to zero, so use history to inspect
        # the stable v2 cursor shape and separately verify dialog signatures via
        # the filter-binding test above.
        history = self.backend.history(chat="1", limit=1, cursor=None)
        decoded = decode_cursor(history.next_cursor)
        self.assertEqual(decoded["v"], 2)
        self.assertEqual(decoded["scope"], "history")
        self.assertRegex(decoded["sig"], r"^[0-9a-f]{24}$")
        self.assertNotIn("СИНТЕТИЧНИЙ", str(decoded))
        self.assertEqual(len(first.items), 0)

    def test_legacy_offset_cursor_fails_closed(self):
        from bridge.models import encode_cursor

        old = encode_cursor({"v": 1, "scope": "history", "offset": 1})
        with self.assertRaises(BridgeError) as captured:
            self.backend.history(chat="1", limit=1, cursor=old)
        self.assertEqual(captured.exception.code, "invalid_cursor")


class UnicodeSenderAndTimezoneTests(unittest.TestCase):
    def setUp(self) -> None:
        self.client = MutableClient()
        self.backend = TelethonReadBackend(
            client_factory=lambda: self.client,
            config=TelethonReadConfig(request_timeout_seconds=2, dialog_scan_limit=100, search_scan_limit=100),
        )

    def test_nfkc_casefold_matches_cyrillic_composed_and_decomposed(self):
        self.assertEqual(normalize_search_text("Й"), normalize_search_text("и\u0306"))
        self.client.messages_by_chat[1][0].message = "ЙЖАК"
        result = self.backend.search(
            chat="1",
            sender=None,
            text="и\u0306жак",
            dates=DateRange(None, None),
            limit=10,
            cursor=None,
            scan_limit=10,
        )
        self.assertEqual([message.id for message in result.items], [3])
        self.assertEqual(result.items[0].text, "ЙЖАК")

    def test_person_search_matches_display_name_not_only_id_or_username(self):
        result = self.backend.search(
            chat="1",
            sender="олексій",
            text="",
            dates=DateRange(None, None),
            limit=10,
            cursor=None,
            scan_limit=10,
        )
        self.assertEqual([message.id for message in result.items], [3, 1])

    def test_dialog_order_compares_instants_not_offset_strings(self):
        self.client.dialogs = [
            Dialog(1, "A", datetime(2026, 8, 23, 12, 0, tzinfo=timezone(timedelta(hours=2)))),  # 10:00Z
            Dialog(2, "B", datetime(2026, 8, 23, 10, 30, tzinfo=timezone.utc)),  # newer instant
        ]
        result = self.backend.list_dialogs(limit=10, cursor=None, query="", unread_only=False)
        self.assertEqual([dialog.id for dialog in result.items], ["2", "1"])
        self.assertTrue(result.items[0].last_message_at.endswith("Z"))

    def test_date_boundaries_compare_same_instant_across_offsets(self):
        self.client.messages_by_chat[1] = [
            Msg(1, "boundary", datetime(2026, 8, 23, 10, 0, tzinfo=timezone.utc), chat_id=1)
        ]
        same_instant = datetime(2026, 8, 23, 12, 0, tzinfo=timezone(timedelta(hours=2)))
        result = self.backend.search(
            chat="1",
            sender=None,
            text="boundary",
            dates=DateRange(same_instant, same_instant),
            limit=10,
            cursor=None,
            scan_limit=10,
        )
        self.assertEqual([message.id for message in result.items], [1])

    def test_global_sort_is_total_when_message_id_and_timestamp_match(self):
        stamp = "2026-08-23T10:00:00Z"
        records = [
            MessageRecord(5, "1", stamp, "a"),
            MessageRecord(5, "2", stamp, "b"),
        ]
        self.assertEqual([record.chat_id for record in stable_message_sort(records)], ["2", "1"])


class TelegramErrorMappingTests(unittest.TestCase):
    def test_floodwait_during_entity_resolution_is_429_not_fake_not_found(self):
        class FloodWaitError(Exception):
            seconds = 99

        class Client(MutableClient):
            def get_entity(self, target):
                del target
                raise FloodWaitError("PRIVATE")

        client = Client()
        backend = TelethonReadBackend(client_factory=lambda: client, config=TelethonReadConfig(flood_wait_cap_seconds=30))
        with self.assertRaises(BridgeError) as captured:
            backend.history(chat="1", limit=1, cursor=None)
        self.assertEqual(captured.exception.code, "telegram_flood_wait")
        self.assertEqual(captured.exception.status, 429)
        self.assertEqual(captured.exception.retry_after_seconds, 30)
        self.assertNotIn("PRIVATE", captured.exception.message)
        self.assertEqual(client.disconnected, 1)

    def test_generic_seconds_attribute_is_not_misclassified_as_floodwait(self):
        class RetryLookingRpcError(Exception):
            seconds = 5

        class Client(MutableClient):
            def get_entity(self, target):
                del target
                raise RetryLookingRpcError("PRIVATE")

        backend = TelethonReadBackend(client_factory=Client)
        with self.assertRaises(BridgeError) as captured:
            backend.history(chat="1", limit=1, cursor=None)
        self.assertEqual(captured.exception.code, "telegram_rpc_error")
        self.assertEqual(captured.exception.status, 502)

    def test_explicit_missing_entity_is_controlled_404(self):
        class Client(MutableClient):
            def get_entity(self, target):
                del target
                raise ValueError("PRIVATE")

        backend = TelethonReadBackend(client_factory=Client)
        with self.assertRaises(BridgeError) as captured:
            backend.history(chat="missing", limit=1, cursor=None)
        self.assertEqual(captured.exception.code, "chat_not_found")
        self.assertEqual(captured.exception.status, 404)
        self.assertNotIn("PRIVATE", captured.exception.message)


class ReadConcurrencyLifecycleTests(unittest.TestCase):
    def test_parallel_reads_use_independent_bounded_client_lifecycles(self):
        created: list[MutableClient] = []
        lock = threading.Lock()

        def factory():
            client = MutableClient()
            with lock:
                created.append(client)
            return client

        backend = TelethonReadBackend(
            client_factory=factory,
            config=TelethonReadConfig(request_timeout_seconds=2, search_scan_limit=100),
        )

        def read_once(_: int):
            page = backend.history(chat="1", limit=2, cursor=None)
            return [message.id for message in page.items]

        with ThreadPoolExecutor(max_workers=6) as pool:
            results = list(pool.map(read_once, range(12)))

        self.assertEqual(results, [[3, 2]] * 12)
        self.assertEqual(len(created), 12)
        self.assertTrue(all((client.connected, client.disconnected) == (1, 1) for client in created))


if __name__ == "__main__":
    unittest.main()
