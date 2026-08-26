from __future__ import annotations

import asyncio
import sqlite3
import tempfile
import time
import unittest
import zipfile
from pathlib import Path

from bridge.archive import ArchiveBuilder, ArchiveLimits
from bridge.backend import TelethonReadBackend, TelethonReadConfig
from bridge.errors import BridgeError
from bridge.storage import FileRecordStore
from ops.telegram_write_adapter import (
    DeterministicFakeTelegramClient,
    TelegramContractError,
    TelegramRuntimeConfig,
    TelegramWriteAdapter,
)
from ops.write_safety import PersistentWriteStore


class ArchiveLivenessTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.store = FileRecordStore(root / "state" / "files.db", root / "files")
        self.output = root / "archive-work"

    def add_file(self, name: str, data: bytes) -> object:
        path = self.store.root / f"source-{len(list(self.store.root.iterdir()))}.bin"
        path.write_bytes(data)
        return self.store.add(path, name=name)

    def assert_no_archive_artifacts(self) -> None:
        self.assertEqual(list(self.output.glob("*.part")), [])
        self.assertEqual(list(self.store.root.glob("*.zip")), [])

    def test_archive_deadline_is_bounded_and_fails_before_effect(self) -> None:
        source = self.add_file("payload.bin", b"abc")
        ticks = iter((0.0, 0.0, 2.0))
        builder = ArchiveBuilder(
            files=self.store,
            output_dir=self.output,
            limits=ArchiveLimits(max_build_seconds=1.0),
            monotonic=lambda: next(ticks, 2.0),
        )
        with self.assertRaises(BridgeError) as cm:
            builder.build([source.file_ref])
        self.assertEqual(cm.exception.code, "archive_timeout")
        self.assertEqual(cm.exception.status, 504)
        self.assertTrue(cm.exception.details.get("retryable"))
        self.assert_no_archive_artifacts()

    def test_archive_cancellation_during_stream_cleans_partial_state(self) -> None:
        source = self.add_file("large.bin", b"x" * (4 * 1024 * 1024))
        calls = 0

        def cancelled() -> bool:
            nonlocal calls
            calls += 1
            return calls >= 8

        builder = ArchiveBuilder(files=self.store, output_dir=self.output)
        with self.assertRaises(BridgeError) as cm:
            builder.build([source.file_ref], cancelled=cancelled)
        self.assertEqual(cm.exception.code, "archive_cancelled")
        self.assertTrue(cm.exception.details.get("retryable"))
        self.assert_no_archive_artifacts()
        self.assertIsNotNone(self.store.get(source.file_ref))

    def test_archive_cancellation_checker_failure_fails_closed(self) -> None:
        source = self.add_file("payload.bin", b"abc")
        builder = ArchiveBuilder(files=self.store, output_dir=self.output)

        def broken_check() -> bool:
            raise RuntimeError("private callback detail must not surface")

        with self.assertRaises(BridgeError) as cm:
            builder.build([source.file_ref], cancelled=broken_check)
        self.assertEqual(cm.exception.code, "archive_cancellation_check_failed")
        self.assertNotIn("private callback", cm.exception.message)
        self.assert_no_archive_artifacts()

    def test_archive_rejects_non_boolean_cancellation_state(self) -> None:
        source = self.add_file("payload.bin", b"abc")
        builder = ArchiveBuilder(files=self.store, output_dir=self.output)
        with self.assertRaises(BridgeError) as cm:
            builder.build([source.file_ref], cancelled=lambda: 1)  # type: ignore[return-value]
        self.assertEqual(cm.exception.code, "archive_cancellation_check_failed")
        self.assert_no_archive_artifacts()

    def test_archive_post_registry_boundary_returns_durable_success(self) -> None:
        source = self.add_file("payload.bin", b"archive-data")
        state = {"cancel": False}
        delegate = self.store

        class BoundaryStore:
            root = delegate.root

            @staticmethod
            def get(file_ref: str):
                return delegate.get(file_ref)

            @staticmethod
            def add(path: Path, *, name: str, mime_type: str = "application/octet-stream"):
                state["cancel"] = True
                return delegate.add(path, name=name, mime_type=mime_type)

        builder = ArchiveBuilder(files=BoundaryStore(), output_dir=self.output)  # type: ignore[arg-type]
        record = builder.build([source.file_ref], cancelled=lambda: state["cancel"])
        self.assertTrue(state["cancel"])
        self.assertIsNotNone(self.store.get(record.file_ref))
        self.assertIsNone(zipfile.ZipFile(record.path).testzip())

    def test_archive_limit_rejects_unbounded_deadlines(self) -> None:
        for value in (0.0, 601.0, True):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    ArchiveLimits(max_build_seconds=value)  # type: ignore[arg-type]


class ExistingBoundaryEvidenceTests(unittest.TestCase):
    def test_hung_read_fake_is_cut_off_by_operation_timeout(self) -> None:
        class HungReadClient:
            disconnected = False

            async def connect(self) -> None:
                return None

            async def is_user_authorized(self) -> bool:
                return True

            async def disconnect(self) -> None:
                self.disconnected = True

            async def iter_dialogs(self, limit: int):
                del limit
                await asyncio.Event().wait()
                if False:
                    yield None

        client = HungReadClient()
        backend = TelethonReadBackend(
            client_factory=lambda: client,
            config=TelethonReadConfig(request_timeout_seconds=1),
        )
        started = time.monotonic()
        with self.assertRaises(BridgeError) as cm:
            backend.list_dialogs(limit=1, cursor=None, query="", unread_only=False)
        elapsed = time.monotonic() - started
        self.assertEqual(cm.exception.code, "telegram_timeout")
        self.assertLess(elapsed, 2.5)
        self.assertTrue(client.disconnected)

    def test_write_pre_effect_timeout_does_not_create_external_write(self) -> None:
        client = DeterministicFakeTelegramClient(operation_delay=0.20)
        adapter = TelegramWriteAdapter(
            TelegramRuntimeConfig(
                application_id_ref=1,
                application_hash_ref="configured-reference",
                session_reference="configured-reference",
                request_timeout_seconds=0.05,
                synthetic_test_mode=True,
            ),
            lambda: client,
        )
        with self.assertRaises(TelegramContractError) as cm:
            asyncio.run(adapter.send_async(100, "bounded"))
        self.assertEqual(cm.exception.code, "telegram_timeout")
        self.assertEqual(client.external_writes, [])
        self.assertEqual(client.disconnect_count, 1)

    def test_sqlite_busy_wait_is_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "writes.db"
            store = PersistentWriteStore(path, busy_timeout_ms=50)
            blocker = sqlite3.connect(str(path), timeout=0.0, isolation_level=None)
            try:
                blocker.execute("BEGIN IMMEDIATE")
                started = time.monotonic()
                with self.assertRaises(sqlite3.OperationalError):
                    with store._connect() as connection:
                        connection.execute("BEGIN IMMEDIATE")
                self.assertLess(time.monotonic() - started, 1.0)
            finally:
                blocker.rollback()
                blocker.close()


if __name__ == "__main__":
    unittest.main()
