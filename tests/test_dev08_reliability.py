from __future__ import annotations

import multiprocessing
import os
import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path

from bridge.downloads import DownloadManager
from bridge.errors import BridgeError
from bridge.runtime import RuntimeBootstrapError, _SQLiteFixedWindowStore
from bridge.storage import CheckpointStore, DownloadItem, FileRecordStore
from ops.dev08_reliability import ReliableWriteStoreProxy
from ops.telegram_session_lock import SessionLockError, TelegramSessionLock
from ops.write_safety import PersistentWriteStore, ReconciliationRequired, WriteSafetyError


IDEM = "dev08-idempotency-key"
TARGET = "@target_user"
SOURCE_REF = "tg_1_0123456789abcdefabcd"


def _send_payload(text: str = "draft") -> dict[str, object]:
    return {"target": TARGET, "text": text}


def _crash_during_guarded_calling(db_path: str, lock_root: str, preview_token: str) -> None:
    store = PersistentWriteStore(Path(db_path), preview_ttl_seconds=1000)
    proxy = ReliableWriteStoreProxy(
        store,
        lock_root=Path(lock_root),
        backward_skew_seconds=0,
    )

    def crash(_: dict[str, object]) -> dict[str, object]:
        os._exit(77)

    proxy.commit(
        preview_token,
        expected_action="SEND",
        idempotency_key=IDEM,
        external_write=crash,
        now=101,
    )


def _crash_after_durable_commit(db_path: str, lock_root: str, preview_token: str) -> None:
    class ExitAfterCommitStore(PersistentWriteStore):
        def commit(self, *args, **kwargs):  # type: ignore[no-untyped-def]
            result = super().commit(*args, **kwargs)
            os._exit(78)

    store = ExitAfterCommitStore(Path(db_path), preview_ttl_seconds=1000)
    proxy = ReliableWriteStoreProxy(
        store,
        lock_root=Path(lock_root),
        backward_skew_seconds=0,
    )
    proxy.commit(
        preview_token,
        expected_action="SEND",
        idempotency_key=IDEM,
        external_write=lambda _: {"id": 1},
        now=101,
    )


def _crash_holding_session_lock(lock_path: str, marker_path: str) -> None:
    with TelegramSessionLock(Path(lock_path), timeout_seconds=1.0):
        Path(marker_path).write_text("acquired", encoding="utf-8")
        os._exit(79)


class _BlockingBackend:
    def __init__(self) -> None:
        self.calls = 0

    def download_media(self, **kwargs):  # type: ignore[no-untyped-def]
        self.calls += 1
        target = Path(kwargs["destination"])
        target.write_bytes(b"abc")
        return {"path": str(target)}


class _FailOnSaveCheckpointStore(CheckpointStore):
    def __init__(self, db_path: Path) -> None:
        self.save_calls = 0
        self.fail_at: int | None = None
        super().__init__(db_path)

    def save(self, payload):  # type: ignore[no-untyped-def]
        self.save_calls += 1
        if self.fail_at is not None and self.save_calls == self.fail_at:
            raise RuntimeError("fault_injected_checkpoint_save")
        return super().save(payload)


@unittest.skipUnless(os.name == "posix", "HOSTiQ reliability contracts are POSIX-specific")
class GuardedWriteRecoveryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.db = root / "state" / "writes.sqlite3"
        self.store = PersistentWriteStore(self.db, preview_ttl_seconds=1000)
        self.proxy = ReliableWriteStoreProxy(self.store, backward_skew_seconds=0)
        self.lock_root = self.proxy.commit_guard.lock_root

    def preview(self):  # type: ignore[no-untyped-def]
        return self.proxy.create_preview("SEND", _send_payload(), now=100)

    def _fork_context(self):  # type: ignore[no-untyped-def]
        try:
            return multiprocessing.get_context("fork")
        except ValueError:
            self.skipTest("fork context unavailable")

    def test_process_crash_during_external_boundary_recovers_to_ambiguous(self) -> None:
        preview = self.preview()
        ctx = self._fork_context()
        child = ctx.Process(
            target=_crash_during_guarded_calling,
            args=(str(self.db), str(self.lock_root), preview.token),
        )
        child.start()
        child.join(5)
        self.assertEqual(child.exitcode, 77)
        self.assertEqual(self.store.transaction_state(IDEM), "CALLING")

        restarted_store = PersistentWriteStore(self.db, preview_ttl_seconds=1000)
        restarted = ReliableWriteStoreProxy(
            restarted_store,
            lock_root=self.lock_root,
            backward_skew_seconds=0,
        )
        report = restarted.recover_on_startup(now=102)
        self.assertEqual(report.calling_recovered, 1)
        self.assertEqual(report.active_busy, 0)
        self.assertEqual(restarted_store.transaction_state(IDEM), "AMBIGUOUS")
        calls: list[int] = []
        with self.assertRaises(ReconciliationRequired):
            restarted.commit(
                preview.token,
                expected_action="SEND",
                idempotency_key=IDEM,
                external_write=lambda _: (calls.append(1) or {"id": 2}),
                now=103,
            )
        self.assertEqual(calls, [])

    def test_crash_after_durable_commit_keeps_replay_and_clears_marker(self) -> None:
        preview = self.preview()
        ctx = self._fork_context()
        child = ctx.Process(
            target=_crash_after_durable_commit,
            args=(str(self.db), str(self.lock_root), preview.token),
        )
        child.start()
        child.join(5)
        self.assertEqual(child.exitcode, 78)
        self.assertEqual(self.store.transaction_state(IDEM), "COMMITTED")

        restarted = ReliableWriteStoreProxy(
            PersistentWriteStore(self.db, preview_ttl_seconds=1000),
            lock_root=self.lock_root,
            backward_skew_seconds=0,
        )
        report = restarted.recover_on_startup(now=102)
        self.assertEqual(report.calling_recovered, 0)
        self.assertEqual(report.stale_markers_cleared, 1)
        calls: list[int] = []
        result = restarted.commit(
            preview.token,
            expected_action="SEND",
            idempotency_key=IDEM,
            external_write=lambda _: (calls.append(1) or {"id": 2}),
            now=103,
        )
        self.assertTrue(result.idempotent_replay)
        self.assertEqual(result.result, {"id": 1})
        self.assertEqual(calls, [])

    def test_live_guarded_call_is_not_recovered_by_second_worker(self) -> None:
        preview = self.preview()
        entered = threading.Event()
        release = threading.Event()
        calls: list[int] = []
        errors: list[BaseException] = []

        def external(_: dict[str, object]) -> dict[str, object]:
            calls.append(1)
            entered.set()
            release.wait(3)
            return {"id": 1}

        def first_worker() -> None:
            try:
                self.proxy.commit(
                    preview.token,
                    expected_action="SEND",
                    idempotency_key=IDEM,
                    external_write=external,
                    now=101,
                )
            except BaseException as exc:  # pragma: no cover - diagnostic capture
                errors.append(exc)

        thread = threading.Thread(target=first_worker)
        thread.start()
        self.assertTrue(entered.wait(2))
        second = ReliableWriteStoreProxy(
            PersistentWriteStore(self.db, preview_ttl_seconds=1000),
            lock_root=self.lock_root,
            backward_skew_seconds=0,
        )
        try:
            with self.assertRaises(WriteSafetyError) as cm:
                second.commit(
                    preview.token,
                    expected_action="SEND",
                    idempotency_key=IDEM,
                    external_write=lambda _: {"id": 2},
                    now=101,
                )
            self.assertEqual(cm.exception.code, "write_in_progress")
            report = second.recover_on_startup(now=101)
            self.assertEqual(report.calling_recovered, 0)
            self.assertEqual(report.active_busy, 1)
            self.assertEqual(self.store.transaction_state(IDEM), "CALLING")
        finally:
            release.set()
            thread.join(4)
        self.assertEqual(errors, [])
        self.assertEqual(calls, [1])
        self.assertEqual(self.store.transaction_state(IDEM), "COMMITTED")

    def test_committed_replay_is_shared_across_store_instances(self) -> None:
        preview = self.preview()
        calls: list[int] = []
        self.proxy.commit(
            preview.token,
            expected_action="SEND",
            idempotency_key=IDEM,
            external_write=lambda _: (calls.append(1) or {"id": 1}),
            now=101,
        )
        second = ReliableWriteStoreProxy(
            PersistentWriteStore(self.db, preview_ttl_seconds=1000),
            lock_root=self.lock_root,
            backward_skew_seconds=0,
        )
        replay = second.commit(
            preview.token,
            expected_action="SEND",
            idempotency_key=IDEM,
            external_write=lambda _: (calls.append(2) or {"id": 2}),
            now=102,
        )
        self.assertTrue(replay.idempotent_replay)
        self.assertEqual(calls, [1])

    def test_backward_wall_clock_is_rejected_across_restart(self) -> None:
        self.proxy.create_preview("SEND", _send_payload("one"), now=200)
        restarted = ReliableWriteStoreProxy(
            PersistentWriteStore(self.db, preview_ttl_seconds=1000),
            lock_root=self.lock_root,
            backward_skew_seconds=0,
        )
        with self.assertRaises(WriteSafetyError) as cm:
            restarted.create_preview("SEND", _send_payload("two"), now=199)
        self.assertEqual(cm.exception.code, "write_clock_moved_backward")
        self.assertEqual(restarted.clock_guard.high_water(), 200)

    def test_guard_persists_no_plain_idempotency_key(self) -> None:
        preview = self.preview()
        # RESERVED is safe to resume; emulate process loss before CALLING by using the
        # existing store test seam after the guard marker has been initialized.
        self.proxy.commit_guard._arm(self.store._idempotency_hash(IDEM), now=101)
        self.store.simulate_reserved_crash_for_test(
            preview.token,
            expected_action="SEND",
            idempotency_key=IDEM,
            now=101,
        )
        raw = self.db.read_bytes()
        self.assertNotIn(IDEM.encode("utf-8"), raw)
        report = self.proxy.recover_on_startup(now=102)
        self.assertEqual(report.reserved_released, 1)
        self.assertEqual(self.store.transaction_state(IDEM), "RESERVED")


@unittest.skipUnless(os.name == "posix", "HOSTiQ reliability contracts are POSIX-specific")
class SharedRateLimitStateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "state"
        self.db = self.root / "rate.sqlite3"
        self.now = [120]
        self.store1 = _SQLiteFixedWindowStore(self.db, clock=lambda: self.now[0])
        self.store2 = _SQLiteFixedWindowStore(self.db, clock=lambda: self.now[0])

    def take(self, store, namespace="read", actor="actor", operation="op", limit=2):  # type: ignore[no-untyped-def]
        return store.take(
            namespace=namespace,
            actor=actor,
            operation=operation,
            limit=limit,
            window_seconds=60,
        )

    def test_quota_is_shared_across_store_instances(self) -> None:
        self.assertTrue(self.take(self.store1)[0])
        self.assertTrue(self.take(self.store2)[0])
        allowed, remaining, retry = self.take(self.store1)
        self.assertFalse(allowed)
        self.assertEqual(remaining, 0)
        self.assertGreater(retry, 0)

    def test_read_write_namespaces_do_not_consume_each_other(self) -> None:
        self.assertTrue(self.take(self.store1, namespace="read", limit=1)[0])
        self.assertTrue(self.take(self.store2, namespace="write", limit=1)[0])
        self.assertFalse(self.take(self.store1, namespace="read", limit=1)[0])
        self.assertFalse(self.take(self.store2, namespace="write", limit=1)[0])

    def test_backward_clock_fails_closed_across_instances(self) -> None:
        self.assertTrue(self.take(self.store1)[0])
        self.now[0] = 119
        with self.assertRaises(RuntimeBootstrapError) as cm:
            self.take(self.store2)
        self.assertEqual(cm.exception.code, "rate_limit_clock_moved_backward")

    def test_concurrent_limit_one_has_exactly_one_winner(self) -> None:
        barrier = threading.Barrier(2)
        decisions: list[bool] = []
        errors: list[BaseException] = []

        def worker(store) -> None:  # type: ignore[no-untyped-def]
            try:
                barrier.wait(2)
                decisions.append(self.take(store, actor="same", operation="same", limit=1)[0])
            except BaseException as exc:
                errors.append(exc)

        a = threading.Thread(target=worker, args=(self.store1,))
        b = threading.Thread(target=worker, args=(self.store2,))
        a.start(); b.start(); a.join(4); b.join(4)
        self.assertEqual(errors, [])
        self.assertEqual(sorted(decisions), [False, True])


@unittest.skipUnless(os.name == "posix", "HOSTiQ reliability contracts are POSIX-specific")
class SessionAndDownloadLockInteractionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_session_lock_serializes_independent_instances(self) -> None:
        path = self.root / "locks" / "telegram-session.lock"
        first = TelegramSessionLock(path, timeout_seconds=1.0)
        first.acquire()
        try:
            with self.assertRaises(SessionLockError) as cm:
                TelegramSessionLock(path, timeout_seconds=0).acquire()
            self.assertEqual(cm.exception.code, "session_lock_timeout")
        finally:
            first.release()
        with TelegramSessionLock(path, timeout_seconds=0.1):
            pass

    def test_session_lock_is_released_by_process_death(self) -> None:
        try:
            ctx = multiprocessing.get_context("fork")
        except ValueError:
            self.skipTest("fork context unavailable")
        lock_path = self.root / "locks" / "telegram-session.lock"
        marker = self.root / "child-acquired"
        child = ctx.Process(
            target=_crash_holding_session_lock,
            args=(str(lock_path), str(marker)),
        )
        child.start(); child.join(5)
        self.assertEqual(child.exitcode, 79)
        self.assertTrue(marker.exists())
        with TelegramSessionLock(lock_path, timeout_seconds=0.2):
            pass

    def _download_fixture(self):  # type: ignore[no-untyped-def]
        files = FileRecordStore(self.root / "state" / "files.sqlite3", self.root / "files")
        checkpoints = CheckpointStore(self.root / "state" / "downloads.sqlite3")
        backend = _BlockingBackend()
        manager = DownloadManager(
            backend=backend,
            files=files,
            checkpoints=checkpoints,
            staging_dir=self.root / "tmp" / "downloads",
        )
        item = DownloadItem("item1", "1", 1, SOURCE_REF, "a.txt", "text/plain", 3, None)
        return files, checkpoints, backend, manager, item

    def test_same_download_job_is_process_lock_serialized(self) -> None:
        files, checkpoints, backend, first, item = self._download_fixture()
        second = DownloadManager(
            backend=backend,
            files=files,
            checkpoints=checkpoints,
            staging_dir=self.root / "tmp2" / "downloads",
        )
        job = checkpoints.create([item])
        with first._job_lock(job):
            with self.assertRaises(BridgeError) as cm:
                second.resume(job)
        self.assertEqual(cm.exception.code, "job_busy")
        self.assertEqual(backend.calls, 0)

    def test_different_download_jobs_do_not_share_one_global_lock(self) -> None:
        _, checkpoints, _, manager, item = self._download_fixture()
        job1 = checkpoints.create([item])
        item2 = DownloadItem("item2", "1", 2, "tg_2_0123456789abcdefabcd", "b.txt", "text/plain", 3, None)
        job2 = checkpoints.create([item2])
        with manager._job_lock(job1):
            with manager._job_lock(job2):
                pass

    def test_oracle_reproduces_file_registered_before_checkpoint_crash_window(self) -> None:
        """Executable finding: current DEV04 flow can redownload after this crash seam.

        This intentionally records the *current defect* as an oracle, not as closure.
        DEV08 does not silently replace DEV04 download business logic.  A future
        canonical fix should change this expectation to one backend call / one row.
        """
        files = FileRecordStore(self.root / "state" / "files.sqlite3", self.root / "files")
        checkpoints = _FailOnSaveCheckpointStore(self.root / "state" / "downloads.sqlite3")
        backend = _BlockingBackend()
        manager = DownloadManager(
            backend=backend,
            files=files,
            checkpoints=checkpoints,
            staging_dir=self.root / "tmp" / "downloads",
        )
        item = DownloadItem("item1", "1", 1, SOURCE_REF, "a.txt", "text/plain", 3, None)
        job = checkpoints.create([item])  # save call 1
        checkpoints.fail_at = 3  # call 2 = RUNNING; call 3 = after FileRecordStore.add
        with self.assertRaisesRegex(RuntimeError, "fault_injected_checkpoint_save"):
            manager.resume(job)
        self.assertEqual(backend.calls, 1)
        with sqlite3.connect(str(files.db_path)) as con:
            first_rows = int(con.execute("SELECT COUNT(*) FROM files").fetchone()[0])
        self.assertEqual(first_rows, 1)

        # The checkpoint never learned the first file_ref, so current code downloads
        # again and creates a second registered private file.  This is the active
        # cross-DB crash window DEV08 is reporting for DEV04/DEV01 integration.
        result = manager.resume(job)
        self.assertEqual(result["status"], "complete")
        self.assertEqual(backend.calls, 2)
        with sqlite3.connect(str(files.db_path)) as con:
            final_rows = int(con.execute("SELECT COUNT(*) FROM files").fetchone()[0])
        self.assertEqual(final_rows, 2)


if __name__ == "__main__":
    unittest.main()
