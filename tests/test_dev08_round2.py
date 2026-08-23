from __future__ import annotations

import multiprocessing
import os
import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path

from ops.dev08_recovery_extensions import RollbackSafeReliableWriteStoreProxy
from ops.write_safety import PersistentWriteStore, ReconciliationRequired, WriteSafetyError


IDEM = "dev08-round2-idempotency"
TARGET = "@target_user"


def _payload(text: str = "draft") -> dict[str, object]:
    return {"target": TARGET, "text": text}


def _crash_guarded_call(db_path: str, lock_root: str, preview_token: str) -> None:
    store = PersistentWriteStore(Path(db_path), preview_ttl_seconds=1000)
    proxy = RollbackSafeReliableWriteStoreProxy(
        store,
        lock_root=Path(lock_root),
        backward_skew_seconds=0,
    )

    def crash(_: dict[str, object]) -> dict[str, object]:
        os._exit(81)

    proxy.commit(
        preview_token,
        expected_action="SEND",
        idempotency_key=IDEM,
        external_write=crash,
        now=201,
    )


@unittest.skipUnless(os.name == "posix", "HOSTiQ reliability contracts are POSIX-specific")
class RollbackSafeRecoveryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.db = root / "state" / "writes.sqlite3"
        self.store = PersistentWriteStore(self.db, preview_ttl_seconds=1000)
        self.proxy = RollbackSafeReliableWriteStoreProxy(
            self.store,
            backward_skew_seconds=0,
        )
        self.lock_root = self.proxy.commit_guard.lock_root

    def _fork_context(self):  # type: ignore[no-untyped-def]
        try:
            return multiprocessing.get_context("fork")
        except ValueError:
            self.skipTest("fork context unavailable")

    def test_orphaned_calling_recovers_even_when_wall_clock_rolled_back(self) -> None:
        preview = self.proxy.create_preview("SEND", _payload(), now=200)
        child = self._fork_context().Process(
            target=_crash_guarded_call,
            args=(str(self.db), str(self.lock_root), preview.token),
        )
        child.start()
        child.join(5)
        self.assertEqual(child.exitcode, 81)
        self.assertEqual(self.store.transaction_state(IDEM), "CALLING")

        restarted_store = PersistentWriteStore(self.db, preview_ttl_seconds=1000)
        restarted = RollbackSafeReliableWriteStoreProxy(
            restarted_store,
            lock_root=self.lock_root,
            backward_skew_seconds=0,
        )
        report = restarted.recover_on_startup(now=150)
        self.assertEqual(report.calling_recovered, 1)
        self.assertEqual(restarted_store.transaction_state(IDEM), "AMBIGUOUS")
        self.assertEqual(restarted.clock_guard.high_water(), 201)

        calls: list[int] = []
        with self.assertRaises(ReconciliationRequired):
            restarted.commit(
                preview.token,
                expected_action="SEND",
                idempotency_key=IDEM,
                external_write=lambda _: (calls.append(1) or {"id": 2}),
                now=202,
            )
        self.assertEqual(calls, [])

    def test_request_time_remains_fail_closed_after_rollback_safe_recovery(self) -> None:
        self.proxy.create_preview("SEND", _payload("one"), now=300)
        report = self.proxy.recover_on_startup(now=250)
        self.assertEqual(report.markers_scanned, 0)
        self.assertEqual(self.proxy.clock_guard.high_water(), 300)

        with self.assertRaises(WriteSafetyError) as cm:
            self.proxy.create_preview("SEND", _payload("two"), now=250)
        self.assertEqual(cm.exception.code, "write_clock_moved_backward")

    def test_recovery_without_existing_high_water_initializes_clock(self) -> None:
        fresh_root = Path(self.temp.name) / "fresh"
        store = PersistentWriteStore(fresh_root / "writes.sqlite3", preview_ttl_seconds=1000)
        proxy = RollbackSafeReliableWriteStoreProxy(store, backward_skew_seconds=0)
        with store._connect() as con:
            con.execute("DELETE FROM dev08_write_clock")
            con.commit()
        report = proxy.recover_on_startup(now=42)
        self.assertEqual(report.markers_scanned, 0)
        self.assertEqual(proxy.clock_guard.high_water(), 42)

    def test_invalid_recovery_clock_is_rejected(self) -> None:
        with self.assertRaises(WriteSafetyError) as cm:
            self.proxy.recover_on_startup(now=-1)
        self.assertEqual(cm.exception.code, "invalid_write_clock")
        with self.assertRaises(WriteSafetyError) as cm2:
            self.proxy.recover_on_startup(now=True)
        self.assertEqual(cm2.exception.code, "invalid_write_clock")


class Dev04MigrationRaceOracleTests(unittest.TestCase):
    """Cross-lane oracle for the exact read-then-ALTER legacy migration pattern.

    DEV08 does not mutate DEV04 storage code here.  These tests prove why a migration
    lock/transaction is required when multiple Passenger workers may bootstrap the
    same legacy SQLite registry concurrently.
    """

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.db = Path(self.temp.name) / "files.sqlite3"
        with sqlite3.connect(str(self.db)) as con:
            con.execute(
                "CREATE TABLE files ("
                "file_ref TEXT PRIMARY KEY, rel_path TEXT NOT NULL UNIQUE, "
                "name TEXT NOT NULL, mime_type TEXT NOT NULL, size INTEGER NOT NULL, "
                "sha256 TEXT NOT NULL, created_at INTEGER NOT NULL)"
            )
            con.commit()

    def test_unserialized_check_then_alter_has_duplicate_column_race(self) -> None:
        barrier = threading.Barrier(2)
        outcomes: list[str] = []
        errors: list[BaseException] = []

        def worker() -> None:
            try:
                con = sqlite3.connect(str(self.db), timeout=2.0, isolation_level=None)
                try:
                    columns = {str(row[1]) for row in con.execute("PRAGMA table_info(files)")}
                    self.assertNotIn("origin_key", columns)
                    barrier.wait(2)
                    try:
                        con.execute("ALTER TABLE files ADD COLUMN origin_key TEXT")
                        outcomes.append("migrated")
                    except sqlite3.OperationalError as exc:
                        if "duplicate column name" in str(exc).casefold():
                            outcomes.append("duplicate_column")
                        else:
                            raise
                finally:
                    con.close()
            except BaseException as exc:  # pragma: no cover - diagnostic capture
                errors.append(exc)

        first = threading.Thread(target=worker)
        second = threading.Thread(target=worker)
        first.start(); second.start(); first.join(5); second.join(5)
        self.assertEqual(errors, [])
        self.assertEqual(sorted(outcomes), ["duplicate_column", "migrated"])
        with sqlite3.connect(str(self.db)) as con:
            columns = {str(row[1]) for row in con.execute("PRAGMA table_info(files)")}
        self.assertIn("origin_key", columns)

    def test_begin_immediate_serializes_check_and_migration(self) -> None:
        start = threading.Barrier(2)
        outcomes: list[str] = []
        errors: list[BaseException] = []

        def worker() -> None:
            con: sqlite3.Connection | None = None
            try:
                start.wait(2)
                con = sqlite3.connect(str(self.db), timeout=5.0, isolation_level=None)
                con.execute("PRAGMA busy_timeout=5000")
                con.execute("BEGIN IMMEDIATE")
                columns = {str(row[1]) for row in con.execute("PRAGMA table_info(files)")}
                if "origin_key" not in columns:
                    con.execute("ALTER TABLE files ADD COLUMN origin_key TEXT")
                    outcomes.append("migrated")
                else:
                    outcomes.append("already_migrated")
                con.execute("COMMIT")
            except BaseException as exc:  # pragma: no cover - diagnostic capture
                errors.append(exc)
                if con is not None and con.in_transaction:
                    con.execute("ROLLBACK")
            finally:
                if con is not None:
                    con.close()

        first = threading.Thread(target=worker)
        second = threading.Thread(target=worker)
        first.start(); second.start(); first.join(6); second.join(6)
        self.assertEqual(errors, [])
        self.assertEqual(sorted(outcomes), ["already_migrated", "migrated"])


if __name__ == "__main__":
    unittest.main()
