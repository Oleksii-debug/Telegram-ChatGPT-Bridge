from __future__ import annotations

import unittest

from bridge.audit import AuditLog
from bridge.downloads import DownloadLimits, DownloadManager
from bridge.errors import BridgeError
from bridge.storage import DownloadItem, FileRecord


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


def _record(ref: str, size: int) -> FileRecord:
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
        chat="123",
        message_id=index + 1,
        source_file_ref=f"tg_{index}_0123456789abcdef0123",
        name=f"file-{index}.bin",
        mime_type="application/octet-stream",
    )


class AuditMemoryBoundTests(unittest.TestCase):
    def test_event_cache_retains_only_the_configured_recent_window(self) -> None:
        audit = AuditLog(memory_event_limit=64)
        for index in range(5000):
            audit.write("request", request_id=str(index), status=200)

        self.assertEqual(len(audit.events), 64)
        self.assertEqual(audit.events[0]["request_id"], str(5000 - 64))
        self.assertEqual(audit.events[-1]["request_id"], "4999")

    def test_event_cache_limit_is_strictly_bounded(self) -> None:
        for value in (0, -1, True, AuditLog.MAX_MEMORY_EVENT_LIMIT + 1):
            with self.subTest(value=value), self.assertRaises(ValueError):
                AuditLog(memory_event_limit=value)


class BulkDownloadAccountingTests(unittest.TestCase):
    @staticmethod
    def _manager(files: _CountingFiles, *, max_bulk_bytes: int = 500) -> DownloadManager:
        manager = object.__new__(DownloadManager)
        manager.files = files
        manager.limits = DownloadLimits(
            max_single_bytes=100,
            max_bulk_files=100,
            max_bulk_bytes=max_bulk_bytes,
        )
        return manager

    def test_accepting_results_does_not_revalidate_all_prior_files(self) -> None:
        old = _record("old", 50)
        files = _CountingFiles({"old": old})
        manager = self._manager(files)
        payload = {"results": {"old-item": "old"}, "failures": {}}

        existing = manager._complete_files(payload)
        current_total = sum(record.size for record in existing)
        self.assertEqual(files.get_calls, 1)

        for index in range(50):
            record = _record(f"new-{index}", 5)
            current_total = manager._accept_result(
                payload,
                _item(index),
                record,
                current_total=current_total,
            )

        self.assertEqual(current_total, 300)
        self.assertEqual(files.get_calls, 1)
        self.assertEqual(len(payload["results"]), 51)

    def test_running_total_matches_sum_for_varied_sequences(self) -> None:
        sequences = ([1], [3, 5, 7, 11], [5] * 100, [100, 100, 100, 100, 100])
        for sizes in sequences:
            with self.subTest(sizes=sizes[:5], count=len(sizes)):
                files = _CountingFiles()
                manager = self._manager(files)
                payload = {"results": {}, "failures": {}}
                current_total = 0
                for index, size in enumerate(sizes):
                    current_total = manager._accept_result(
                        payload,
                        _item(index),
                        _record(f"r-{index}", size),
                        current_total=current_total,
                    )
                self.assertEqual(current_total, sum(sizes))

    def test_running_total_rejects_overflow_and_deletes_new_record(self) -> None:
        files = _CountingFiles()
        manager = self._manager(files)
        payload = {"results": {}, "failures": {}}
        record = _record("too-much", 60)

        with self.assertRaises(BridgeError) as raised:
            manager._accept_result(payload, _item(1), record, current_total=450)

        self.assertEqual(raised.exception.code, "bulk_size_limit")
        self.assertEqual(files.deleted, ["too-much"])
        self.assertEqual(payload["results"], {})


if __name__ == "__main__":
    unittest.main()
