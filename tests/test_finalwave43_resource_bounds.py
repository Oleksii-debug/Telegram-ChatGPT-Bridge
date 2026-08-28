from __future__ import annotations

import json
import threading
import unittest
from datetime import datetime, timedelta, timezone

from bridge.archive import ArchiveLimits
from bridge.audit import AuditLog
from bridge.backend import TelethonReadBackend, TelethonReadConfig
from bridge.downloads import DownloadLimits, DownloadManager
from bridge.errors import BridgeError
from bridge.models import encode_cursor
from bridge.storage import DownloadItem, FileRecord
from bridge.validation import DateRange


class _CountingFiles:
    def __init__(self, records: dict[str, FileRecord] | None = None) -> None:
        self.records = dict(records or {})
        self.get_calls = 0
        self.deleted: list[str] = []

    def get(self, file_ref: str) -> FileRecord | None:
        self.get_calls += 1
        return self.records.get(file_ref)

    def delete(self, file_ref: str) -> bool:
        self.deleted.append(file_ref)
        self.records.pop(file_ref, None)
        return True


class _Entity:
    def __init__(self, value: int) -> None:
        self.id = value
        self.title = f"Dialog {value}"
        self.username = None


class _DialogMessage:
    def __init__(self, date: datetime) -> None:
        self.date = date


class _Dialog:
    def __init__(self, value: int, date: datetime) -> None:
        self.entity = _Entity(value)
        self.message = _DialogMessage(date)
        self.unread_count = 0
        self.pinned = False


class _Message:
    def __init__(self, value: int, date: datetime, *, sender_counter: list[int] | None = None) -> None:
        self.id = value
        self.date = date
        self.message = f"message {value}"
        self.chat_id = 1
        self.sender_id = value
        self.out = False
        self.reply_to = None
        self.media = None
        self.file = None
        self._sender_counter = sender_counter

    async def get_sender(self):
        if self._sender_counter is not None:
            self._sender_counter[0] += 1
        sender = _Entity(self.sender_id)
        sender.first_name = f"Person {self.sender_id}"
        sender.last_name = ""
        return sender


class _ReadClient:
    def __init__(self, dialogs: list[_Dialog], messages: list[_Message]) -> None:
        self.dialogs = dialogs
        self.messages = messages
        self.dialog_limits: list[int] = []
        self.message_limits: list[int] = []

    async def connect(self) -> None:
        return None

    async def disconnect(self) -> None:
        return None

    async def is_user_authorized(self) -> bool:
        return True

    def iter_dialogs(self, *, limit: int):
        self.dialog_limits.append(limit)
        return self.dialogs[:limit]

    def iter_messages(self, entity, *, limit: int, search: str = ""):
        del entity, search
        self.message_limits.append(limit)
        return self.messages[:limit]

    async def get_entity(self, target):
        del target
        return _Entity(1)



def _record(ref: str, size: int = 1) -> FileRecord:
    return FileRecord(
        file_ref=ref,
        path=f"/private/{ref}",
        name=f"{ref}.bin",
        mime_type="application/octet-stream",
        size=size,
        sha256="a" * 64,
        created_at=1,
    )



def _item(index: int) -> DownloadItem:
    return DownloadItem(
        item_id=f"item-{index}",
        chat="1",
        message_id=index + 1,
        source_file_ref=f"tg_{index}_0123456789abcdef0123",
        name=f"file-{index}.bin",
        mime_type="application/octet-stream",
    )


class Finalwave43AuditBoundsTests(unittest.TestCase):
    def test_1k_5k_10k_event_workloads_keep_constant_recent_window(self) -> None:
        for count in (1_000, 5_000, 10_000):
            with self.subTest(count=count):
                log = AuditLog(memory_event_limit=128)
                for index in range(count):
                    log.write("request", request_id=str(index), status=200)
                events = log.events
                self.assertEqual(len(events), 128)
                self.assertEqual(events[0]["request_id"], str(count - 128))
                self.assertEqual(events[-1]["request_id"], str(count - 1))
                self.assertLessEqual(len(json.dumps(events)), 64 * 1024)

    def test_event_snapshot_is_json_compatible_and_cannot_expand_internal_cache(self) -> None:
        log = AuditLog(memory_event_limit=2)
        log.write("request", status=200, message_body="synthetic-private-value")
        snapshot = log.events
        snapshot.append({"event": "external-mutation"})
        self.assertEqual(len(log.events), 1)
        self.assertNotIn("message_body", log.events[0])
        json.dumps(log.events)

    def test_concurrent_in_memory_writes_remain_bounded(self) -> None:
        log = AuditLog(memory_event_limit=256)

        def writer(start: int) -> None:
            for value in range(start, start + 2_500):
                log.write("request", request_id=str(value), status=200)

        threads = [threading.Thread(target=writer, args=(index * 2_500,)) for index in range(4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(len(log.events), 256)


class Finalwave43BulkAccountingTests(unittest.TestCase):
    @staticmethod
    def _manager(files: _CountingFiles, *, max_bulk_bytes: int = 20_000) -> DownloadManager:
        manager = object.__new__(DownloadManager)
        manager.files = files
        manager.limits = DownloadLimits(max_single_bytes=1, max_bulk_files=500, max_bulk_bytes=max_bulk_bytes)
        return manager

    def test_1k_5k_10k_accept_primitive_does_not_rescan_prior_files(self) -> None:
        for count in (1_000, 5_000, 10_000):
            with self.subTest(count=count):
                files = _CountingFiles()
                manager = self._manager(files, max_bulk_bytes=count + 1)
                payload = {"results": {}, "failures": {}}
                current_total = 0
                for index in range(count):
                    current_total = manager._accept_result(
                        payload,
                        _item(index),
                        _record(f"new-{index}"),
                        current_total=current_total,
                    )
                self.assertEqual(current_total, count)
                self.assertEqual(files.get_calls, 0)
                self.assertEqual(len(payload["results"]), count)

    def test_restart_baseline_is_validated_once_then_accounting_is_constant_per_accept(self) -> None:
        existing = {f"old-{index}": _record(f"old-{index}") for index in range(200)}
        files = _CountingFiles(existing)
        manager = self._manager(files)
        payload = {
            "results": {f"old-item-{index}": f"old-{index}" for index in range(200)},
            "failures": {},
        }
        records = manager._complete_files(payload)
        current_total = sum(record.size for record in records)
        self.assertEqual(files.get_calls, 200)
        for index in range(200, 500):
            current_total = manager._accept_result(
                payload,
                _item(index),
                _record(f"new-{index}"),
                current_total=current_total,
            )
        self.assertEqual(files.get_calls, 200)
        self.assertEqual(current_total, 500)

    def test_overflow_removes_only_new_record_and_preserves_checkpoint_results(self) -> None:
        files = _CountingFiles()
        manager = self._manager(files, max_bulk_bytes=5)
        payload = {"results": {"prior": "prior-ref"}, "failures": {}}
        record = _record("overflow", 1)
        with self.assertRaises(BridgeError) as raised:
            manager._accept_result(payload, _item(9), record, current_total=5)
        self.assertEqual(raised.exception.code, "bulk_size_limit")
        self.assertEqual(files.deleted, ["overflow"])
        self.assertEqual(payload["results"], {"prior": "prior-ref"})


class Finalwave43ReadRescanCharacterizationTests(unittest.TestCase):
    @staticmethod
    def _fixture(count: int = 10_000) -> tuple[TelethonReadBackend, _ReadClient]:
        base = datetime(2026, 1, 1, tzinfo=timezone.utc)
        dialogs = [_Dialog(index + 1, base - timedelta(seconds=index)) for index in range(count)]
        messages = [_Message(count - index, base - timedelta(seconds=index)) for index in range(count)]
        client = _ReadClient(dialogs, messages)
        backend = TelethonReadBackend(
            client_factory=lambda: client,
            config=TelethonReadConfig(dialog_scan_limit=2_000, search_scan_limit=5_000),
        )
        return backend, client

    def test_dialog_cursor_second_page_rescans_same_bounded_prefix(self) -> None:
        backend, client = self._fixture()
        first = backend.list_dialogs(limit=100, cursor=None, query="", unread_only=False)
        self.assertIsNotNone(first.next_cursor)
        backend.list_dialogs(limit=100, cursor=first.next_cursor, query="", unread_only=False)
        self.assertEqual(client.dialog_limits, [2_000, 2_000])

    def test_search_cursor_second_page_rescans_same_bounded_prefix(self) -> None:
        backend, client = self._fixture()
        dates = DateRange(None, None)
        first = backend.search(
            chat=None,
            sender=None,
            text="message",
            dates=dates,
            limit=100,
            cursor=None,
            scan_limit=5_000,
        )
        self.assertIsNotNone(first.next_cursor)
        backend.search(
            chat=None,
            sender=None,
            text="message",
            dates=dates,
            limit=100,
            cursor=first.next_cursor,
            scan_limit=5_000,
        )
        self.assertEqual(client.message_limits, [5_000, 5_000])

    def test_sender_name_filter_resolves_sender_metadata_once_per_scanned_message(self) -> None:
        base = datetime(2026, 1, 1, tzinfo=timezone.utc)
        counter = [0]
        messages = [_Message(1_000 - index, base - timedelta(seconds=index), sender_counter=counter) for index in range(1_000)]
        client = _ReadClient([], messages)
        backend = TelethonReadBackend(
            client_factory=lambda: client,
            config=TelethonReadConfig(search_scan_limit=1_000),
        )
        backend.search(
            chat=None,
            sender="Person",
            text="message",
            dates=DateRange(None, None),
            limit=10,
            cursor=None,
            scan_limit=1_000,
        )
        self.assertEqual(counter[0], 1_000)


class Finalwave43StaticBoundTests(unittest.TestCase):
    def test_large_bulk_and_zip_member_counts_fail_closed_before_work(self) -> None:
        with self.assertRaises(ValueError):
            DownloadLimits(max_bulk_files=501)
        with self.assertRaises(ValueError):
            ArchiveLimits(max_members=501)

    def test_read_scan_configuration_has_hard_caps(self) -> None:
        with self.assertRaises(ValueError):
            TelethonReadConfig(dialog_scan_limit=20_001)
        with self.assertRaises(ValueError):
            TelethonReadConfig(search_scan_limit=50_001)

    def test_cursor_state_size_stays_small_across_1k_5k_10k_boundaries(self) -> None:
        lengths = []
        for value in (1_000, 5_000, 10_000):
            cursor = encode_cursor(
                {
                    "v": 2,
                    "scope": "search",
                    "sig": "a" * 24,
                    "boundary": ["2026-01-01T00:00:00Z", value, "1"],
                }
            )
            lengths.append(len(cursor.encode("ascii")))
        self.assertLess(max(lengths), 256)
        self.assertLessEqual(max(lengths) - min(lengths), 4)


if __name__ == "__main__":
    unittest.main()
