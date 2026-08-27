# -*- coding: utf-8 -*-
"""FINALWAVE-39 deterministic Passenger-style multi-process stress oracles.

All tests are local/synthetic.  They exercise shared SQLite/private filesystem
state only; no Telegram credentials, network access, private messages or live
external effects are used.
"""
from __future__ import annotations

import json
import multiprocessing as mp
import os
import sqlite3
import tempfile
import threading
import time
import unittest
from pathlib import Path


def _context():
    return mp.get_context("fork" if "fork" in mp.get_all_start_methods() else "spawn")


def _join_all(testcase: unittest.TestCase, workers, *, timeout: float = 20.0) -> None:
    deadline = time.monotonic() + timeout
    for worker in workers:
        remaining = max(0.1, deadline - time.monotonic())
        worker.join(remaining)
    alive = [worker for worker in workers if worker.is_alive()]
    for worker in alive:
        worker.terminate()
        worker.join(2)
    testcase.assertFalse(alive, f"Passenger stress workers hung: {[worker.pid for worker in alive]}")


def _write_bootstrap_worker(db_path: str, barrier, output) -> None:
    """Force the historical schema-version SELECT/INSERT race deterministically."""
    from ops import write_safety

    real_connect = sqlite3.connect

    class _CursorProxy:
        def __init__(self, cursor):
            self._cursor = cursor

        def fetchone(self):
            row = self._cursor.fetchone()
            # Old canonical code lets every process reach this point before any
            # schema-version INSERT.  The fixed code holds BEGIN IMMEDIATE first,
            # so only the first process can reach the barrier; after its bounded
            # timeout the barrier is broken and following serialized readers pass.
            try:
                barrier.wait(timeout=0.5)
            except threading.BrokenBarrierError:
                pass
            return row

        def __getattr__(self, name):
            return getattr(self._cursor, name)

    class _ConnectionProxy:
        def __init__(self, inner):
            object.__setattr__(self, "_inner", inner)

        def __getattr__(self, name):
            return getattr(self._inner, name)

        def __setattr__(self, name, value):
            if name == "_inner":
                object.__setattr__(self, name, value)
            else:
                setattr(self._inner, name, value)

        def execute(self, sql, *args, **kwargs):
            cursor = self._inner.execute(sql, *args, **kwargs)
            normalized = " ".join(str(sql).lower().split())
            if normalized.startswith("select value from meta where key='schema_version'"):
                return _CursorProxy(cursor)
            return cursor

        def executescript(self, script):
            return self._inner.executescript(script)

        def close(self):
            return self._inner.close()

    def instrumented_connect(*args, **kwargs):
        return _ConnectionProxy(real_connect(*args, **kwargs))

    write_safety.sqlite3.connect = instrumented_connect
    try:
        write_safety.PersistentWriteStore(Path(db_path), busy_timeout_ms=5000)
        output.put(("ok", ""))
    except BaseException as exc:  # record class only; never exception text/private data
        output.put(("error", type(exc).__name__))


def _same_key_commit_worker(db_path: str, token: str, barrier, counter, counter_lock, output) -> None:
    from ops.write_safety import PersistentWriteStore, WriteSafetyError

    store = PersistentWriteStore(Path(db_path), busy_timeout_ms=5000)
    barrier.wait(timeout=10)

    def external_write(_payload):
        with counter_lock:
            counter.value += 1
        time.sleep(0.05)
        return {"id": 1}

    try:
        result = store.commit(
            token,
            expected_action="SEND",
            idempotency_key="shared-idempotency-key",
            external_write=external_write,
            now=101,
        )
        output.put(("ok", bool(result.idempotent_replay)))
    except WriteSafetyError as exc:
        output.put(("safe", exc.code))
    except BaseException as exc:
        output.put(("error", type(exc).__name__))


def _different_key_commit_worker(db_path: str, token: str, key: str, index: int, barrier, counter, counter_lock, output) -> None:
    from ops.write_safety import PersistentWriteStore

    store = PersistentWriteStore(Path(db_path), busy_timeout_ms=5000)
    barrier.wait(timeout=10)

    def external_write(_payload):
        with counter_lock:
            counter.value += 1
        return {"id": index + 1}

    try:
        result = store.commit(
            token,
            expected_action="SEND",
            idempotency_key=key,
            external_write=external_write,
            now=101,
        )
        output.put(("ok", result.state))
    except BaseException as exc:
        output.put(("error", type(exc).__name__))


def _calling_crash_worker(db_path: str, token: str) -> None:
    from ops.write_safety import PersistentWriteStore

    store = PersistentWriteStore(Path(db_path), busy_timeout_ms=5000)
    store.simulate_calling_crash_for_test(
        token,
        expected_action="SEND",
        idempotency_key="crash-idempotency-key",
        now=101,
    )
    os._exit(23)


def _rate_worker(db_path: str, barrier, output) -> None:
    from bridge.runtime import _SQLiteFixedWindowStore

    try:
        barrier.wait(timeout=10)
        store = _SQLiteFixedWindowStore(Path(db_path), clock=lambda: 120.0)
        allowed, remaining, retry = store.take(
            namespace="read",
            actor="same-passenger-actor",
            operation="read-api",
            limit=5,
            window_seconds=60,
        )
        output.put(("ok", allowed, remaining, retry))
    except BaseException as exc:
        output.put(("error", type(exc).__name__, 0, 0))


class _CountingBackend:
    def __init__(self, counter, lock):
        self.counter = counter
        self.lock = lock

    def download_media(self, **kwargs):
        with self.lock:
            self.counter.value += 1
        destination = Path(kwargs["destination"])
        destination.write_bytes(b"abc")
        return {"path": str(destination)}


def _download_worker(root_path: str, job_id: str, barrier, counter, counter_lock, output) -> None:
    from bridge.downloads import DownloadManager
    from bridge.errors import BridgeError
    from bridge.storage import CheckpointStore, FileRecordStore

    root = Path(root_path)
    try:
        files = FileRecordStore(root / "state" / "files.db", root / "files")
        checkpoints = CheckpointStore(root / "state" / "jobs.db")
        manager = DownloadManager(
            backend=_CountingBackend(counter, counter_lock),
            files=files,
            checkpoints=checkpoints,
            staging_dir=root / "tmp" / "downloads",
        )
        barrier.wait(timeout=10)
        result = manager.resume(job_id)
        output.put(("ok", result["status"], len(result.get("files", []))))
    except BridgeError as exc:
        output.put(("safe", exc.code, 0))
    except BaseException as exc:
        output.put(("error", type(exc).__name__, 0))


def _archive_worker(root_path: str, source_ref: str, barrier, output) -> None:
    from bridge.archive import ArchiveBuilder
    from bridge.storage import FileRecordStore

    root = Path(root_path)
    try:
        files = FileRecordStore(root / "state" / "files.db", root / "files")
        builder = ArchiveBuilder(files=files, output_dir=root / "tmp" / "archives")
        barrier.wait(timeout=10)
        record = builder.build([source_ref], archive_name="stress.zip")
        output.put(("ok", record.file_ref, record.sha256))
    except BaseException as exc:
        output.put(("error", type(exc).__name__, ""))


def _audit_worker(audit_path: str, index: int, barrier, output) -> None:
    from bridge.audit import AuditLog

    try:
        audit = AuditLog(Path(audit_path))
        barrier.wait(timeout=10)
        for item in range(10):
            audit.write("stress", request_id=f"p{index}-{item}", count=item)
        output.put("ok")
    except BaseException as exc:
        output.put(type(exc).__name__)


def _session_lock_worker(lock_path: str, barrier, active, peak, stats_lock, output) -> None:
    from ops.telegram_session_lock import TelegramSessionLock

    try:
        barrier.wait(timeout=10)
        with TelegramSessionLock(Path(lock_path), timeout_seconds=5.0, poll_interval_seconds=0.01):
            with stats_lock:
                active.value += 1
                peak.value = max(peak.value, active.value)
            time.sleep(0.01)
            with stats_lock:
                active.value -= 1
        output.put("ok")
    except BaseException as exc:
        output.put(type(exc).__name__)


def _session_lock_crash_holder(lock_path: str, ready) -> None:
    from ops.telegram_session_lock import TelegramSessionLock

    lock = TelegramSessionLock(Path(lock_path), timeout_seconds=2.0, poll_interval_seconds=0.01).acquire()
    ready.set()
    try:
        while True:
            time.sleep(1)
    finally:  # SIGTERM/process loss does not rely on this path; flock is kernel-owned.
        lock.release()


def _file_store_open_worker(db_path: str, root_path: str, barrier, output) -> None:
    from bridge.storage import FileRecordStore

    try:
        barrier.wait(timeout=10)
        FileRecordStore(Path(db_path), Path(root_path))
        output.put("ok")
    except BaseException as exc:
        output.put(type(exc).__name__)


def _checkpoint_store_open_worker(db_path: str, barrier, output) -> None:
    from bridge.storage import CheckpointStore

    try:
        barrier.wait(timeout=10)
        CheckpointStore(Path(db_path))
        output.put("ok")
    except BaseException as exc:
        output.put(type(exc).__name__)


class Finalwave39PassengerConcurrencyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def test_forced_write_schema_bootstrap_race_all_10_workers_succeed(self) -> None:
        ctx = _context()
        db_path = str(self.root / "writes.sqlite3")
        barrier = ctx.Barrier(10)
        output = ctx.Queue()
        workers = [ctx.Process(target=_write_bootstrap_worker, args=(db_path, barrier, output)) for _ in range(10)]
        for worker in workers:
            worker.start()
        _join_all(self, workers, timeout=20)
        results = [output.get(timeout=3) for _ in workers]
        self.assertEqual(results.count(("ok", "")), 10, results)
        self.assertTrue(all(worker.exitcode == 0 for worker in workers), [worker.exitcode for worker in workers])
        with sqlite3.connect(db_path) as connection:
            rows = connection.execute("SELECT key,value FROM meta WHERE key='schema_version'").fetchall()
        self.assertEqual(rows, [("schema_version", "1")])

    def test_unknown_write_schema_still_fails_closed(self) -> None:
        from ops.write_safety import PersistentWriteStore

        path = self.root / "unknown.sqlite3"
        with sqlite3.connect(str(path)) as connection:
            connection.execute("CREATE TABLE meta(key TEXT PRIMARY KEY,value TEXT NOT NULL)")
            connection.execute("INSERT INTO meta(key,value) VALUES('schema_version','999')")
            connection.commit()
        with self.assertRaisesRegex(RuntimeError, "unsupported write-store schema"):
            PersistentWriteStore(path)

    def test_same_idempotency_key_10_processes_never_double_effect(self) -> None:
        from ops.write_safety import PersistentWriteStore

        ctx = _context()
        path = self.root / "same-key.sqlite3"
        parent = PersistentWriteStore(path)
        preview = parent.create_preview("SEND", {"target": "@target_user", "text": "synthetic"}, now=100)
        barrier = ctx.Barrier(10)
        output = ctx.Queue()
        counter = ctx.Value("i", 0)
        counter_lock = ctx.Lock()
        workers = [
            ctx.Process(
                target=_same_key_commit_worker,
                args=(str(path), preview.token, barrier, counter, counter_lock, output),
            )
            for _ in range(10)
        ]
        for worker in workers:
            worker.start()
        _join_all(self, workers, timeout=20)
        results = [output.get(timeout=3) for _ in workers]
        self.assertEqual(counter.value, 1, results)
        self.assertFalse(any(item[0] == "error" for item in results), results)
        self.assertTrue(all(item[0] == "ok" or item == ("safe", "write_in_progress") for item in results), results)
        replay = parent.commit(
            preview.token,
            expected_action="SEND",
            idempotency_key="shared-idempotency-key",
            external_write=lambda _payload: (_ for _ in ()).throw(AssertionError("replay invoked external effect")),
            now=102,
        )
        self.assertTrue(replay.idempotent_replay)
        self.assertEqual(counter.value, 1)

    def test_different_idempotency_keys_10_processes_no_lost_commits(self) -> None:
        from ops.write_safety import PersistentWriteStore

        ctx = _context()
        path = self.root / "different-keys.sqlite3"
        parent = PersistentWriteStore(path)
        previews = [
            parent.create_preview("SEND", {"target": "@target_user", "text": f"synthetic-{index}"}, now=100)
            for index in range(10)
        ]
        barrier = ctx.Barrier(10)
        output = ctx.Queue()
        counter = ctx.Value("i", 0)
        counter_lock = ctx.Lock()
        workers = [
            ctx.Process(
                target=_different_key_commit_worker,
                args=(str(path), previews[index].token, f"different-key-{index:02d}", index, barrier, counter, counter_lock, output),
            )
            for index in range(10)
        ]
        for worker in workers:
            worker.start()
        _join_all(self, workers, timeout=20)
        results = [output.get(timeout=3) for _ in workers]
        self.assertEqual(counter.value, 10, results)
        self.assertEqual(results.count(("ok", "COMMITTED")), 10, results)
        self.assertTrue(all(worker.exitcode == 0 for worker in workers), [worker.exitcode for worker in workers])
        for index in range(10):
            self.assertEqual(parent.transaction_state(f"different-key-{index:02d}"), "COMMITTED")

    def test_calling_process_loss_restart_is_ambiguous_and_never_replayed(self) -> None:
        from ops.write_safety import PersistentWriteStore, ReconciliationRequired

        ctx = _context()
        path = self.root / "calling-crash.sqlite3"
        parent = PersistentWriteStore(path)
        preview = parent.create_preview("SEND", {"target": "@target_user", "text": "synthetic"}, now=100)
        worker = ctx.Process(target=_calling_crash_worker, args=(str(path), preview.token))
        worker.start()
        worker.join(10)
        if worker.is_alive():
            worker.terminate()
            worker.join(2)
            self.fail("CALLING crash worker hung")
        self.assertEqual(worker.exitcode, 23)
        restarted = PersistentWriteStore(path)
        self.assertEqual(restarted.transaction_state("crash-idempotency-key"), "CALLING")
        self.assertEqual(restarted.mark_calling_transaction_ambiguous_on_recovery(now=102), 1)
        self.assertEqual(restarted.transaction_state("crash-idempotency-key"), "AMBIGUOUS")
        calls: list[int] = []
        with self.assertRaises(ReconciliationRequired):
            restarted.commit(
                preview.token,
                expected_action="SEND",
                idempotency_key="crash-idempotency-key",
                external_write=lambda _payload: (calls.append(1) or {"id": 2}),
                now=103,
            )
        self.assertEqual(calls, [])

    def test_shared_rate_limit_10_processes_exactly_honors_limit(self) -> None:
        ctx = _context()
        state = self.root / "rate"
        state.mkdir(mode=0o700)
        db_path = str(state / "rate.sqlite3")
        barrier = ctx.Barrier(10)
        output = ctx.Queue()
        workers = [ctx.Process(target=_rate_worker, args=(db_path, barrier, output)) for _ in range(10)]
        for worker in workers:
            worker.start()
        _join_all(self, workers, timeout=20)
        results = [output.get(timeout=3) for _ in workers]
        self.assertFalse(any(item[0] == "error" for item in results), results)
        self.assertEqual(sum(1 for item in results if item[1] is True), 5, results)
        self.assertEqual(sum(1 for item in results if item[1] is False), 5, results)

    def _download_fixture(self):
        from bridge.storage import CheckpointStore, DownloadItem, FileRecordStore

        state = self.root / "state"
        state.mkdir(mode=0o700, exist_ok=True)
        files = FileRecordStore(state / "files.db", self.root / "files")
        checkpoints = CheckpointStore(state / "jobs.db")
        item = DownloadItem(
            "item-1",
            "1",
            1,
            "tg_1_0123456789abcdefabcd",
            "a.txt",
            "text/plain",
            3,
            None,
        )
        return files, checkpoints, item

    def test_same_download_job_10_processes_downloads_at_most_once(self) -> None:
        ctx = _context()
        _files, checkpoints, item = self._download_fixture()
        job_id = checkpoints.create([item])
        barrier = ctx.Barrier(10)
        output = ctx.Queue()
        counter = ctx.Value("i", 0)
        counter_lock = ctx.Lock()
        workers = [
            ctx.Process(
                target=_download_worker,
                args=(str(self.root), job_id, barrier, counter, counter_lock, output),
            )
            for _ in range(10)
        ]
        for worker in workers:
            worker.start()
        _join_all(self, workers, timeout=25)
        results = [output.get(timeout=3) for _ in workers]
        self.assertEqual(counter.value, 1, results)
        self.assertFalse(any(item[0] == "error" for item in results), results)
        self.assertTrue(all(item[0] == "ok" or item == ("safe", "job_busy", 0) for item in results), results)
        final = checkpoints.load(job_id)
        self.assertEqual(final["status"], "complete")
        self.assertEqual(len(final["results"]), 1)

    def test_different_download_jobs_6_processes_complete_without_starvation(self) -> None:
        ctx = _context()
        _files, checkpoints, item = self._download_fixture()
        jobs = [checkpoints.create([item]) for _ in range(6)]
        barrier = ctx.Barrier(6)
        output = ctx.Queue()
        counter = ctx.Value("i", 0)
        counter_lock = ctx.Lock()
        workers = [
            ctx.Process(
                target=_download_worker,
                args=(str(self.root), job_id, barrier, counter, counter_lock, output),
            )
            for job_id in jobs
        ]
        for worker in workers:
            worker.start()
        _join_all(self, workers, timeout=25)
        results = [output.get(timeout=3) for _ in workers]
        self.assertEqual(counter.value, 6, results)
        self.assertEqual(sum(1 for item in results if item[:2] == ("ok", "complete")), 6, results)
        for job_id in jobs:
            self.assertEqual(checkpoints.load(job_id)["status"], "complete")

    def test_archive_6_processes_same_sources_no_registry_collision(self) -> None:
        from bridge.storage import FileRecordStore

        ctx = _context()
        state = self.root / "state"
        state.mkdir(mode=0o700, exist_ok=True)
        files = FileRecordStore(state / "files.db", self.root / "files")
        source = files.root / "source.txt"
        source.write_bytes(b"archive-source")
        os.chmod(source, 0o600)
        record = files.add(source, name="source.txt", mime_type="text/plain")
        barrier = ctx.Barrier(6)
        output = ctx.Queue()
        workers = [
            ctx.Process(target=_archive_worker, args=(str(self.root), record.file_ref, barrier, output))
            for _ in range(6)
        ]
        for worker in workers:
            worker.start()
        _join_all(self, workers, timeout=25)
        results = [output.get(timeout=3) for _ in workers]
        self.assertFalse(any(item[0] == "error" for item in results), results)
        self.assertEqual(len({item[1] for item in results}), 6, results)
        for item in results:
            self.assertIsNotNone(files.get(item[1]))

    def test_audit_append_10_processes_keeps_every_json_line_intact(self) -> None:
        ctx = _context()
        parent = self.root / "audit"
        parent.mkdir(mode=0o700)
        audit_path = str(parent / "bridge.jsonl")
        barrier = ctx.Barrier(10)
        output = ctx.Queue()
        workers = [ctx.Process(target=_audit_worker, args=(audit_path, index, barrier, output)) for index in range(10)]
        for worker in workers:
            worker.start()
        _join_all(self, workers, timeout=30)
        results = [output.get(timeout=3) for _ in workers]
        self.assertEqual(results.count("ok"), 10, results)
        lines = Path(audit_path).read_text(encoding="ascii").splitlines()
        self.assertEqual(len(lines), 100)
        payloads = [json.loads(line) for line in lines]
        request_ids = {payload["request_id"] for payload in payloads}
        self.assertEqual(len(request_ids), 100)
        self.assertTrue(all(set(payload).issubset({"ts", "event", "request_id", "count"}) for payload in payloads))

    def test_session_lock_10_processes_has_peak_one_holder(self) -> None:
        ctx = _context()
        private = self.root / "private"
        private.mkdir(mode=0o700)
        lock_path = str(private / "telegram-session.lock")
        barrier = ctx.Barrier(10)
        output = ctx.Queue()
        active = ctx.Value("i", 0)
        peak = ctx.Value("i", 0)
        stats_lock = ctx.Lock()
        workers = [
            ctx.Process(target=_session_lock_worker, args=(lock_path, barrier, active, peak, stats_lock, output))
            for _ in range(10)
        ]
        for worker in workers:
            worker.start()
        _join_all(self, workers, timeout=20)
        results = [output.get(timeout=3) for _ in workers]
        self.assertEqual(results.count("ok"), 10, results)
        self.assertEqual(active.value, 0)
        self.assertEqual(peak.value, 1)

    def test_session_lock_process_death_releases_kernel_flock(self) -> None:
        from ops.telegram_session_lock import TelegramSessionLock

        ctx = _context()
        private = self.root / "private"
        private.mkdir(mode=0o700)
        lock_path = str(private / "telegram-session.lock")
        ready = ctx.Event()
        holder = ctx.Process(target=_session_lock_crash_holder, args=(lock_path, ready))
        holder.start()
        self.assertTrue(ready.wait(5), "crash holder never acquired session lock")
        holder.terminate()
        holder.join(5)
        self.assertFalse(holder.is_alive())
        with TelegramSessionLock(Path(lock_path), timeout_seconds=1.0, poll_interval_seconds=0.01):
            pass

    def test_file_registry_legacy_migration_10_processes_serializes(self) -> None:
        ctx = _context()
        state = self.root / "migration-state"
        root = self.root / "migration-files"
        state.mkdir(mode=0o700)
        root.mkdir(mode=0o700)
        db_path = state / "files.sqlite3"
        with sqlite3.connect(str(db_path)) as connection:
            connection.execute(
                "CREATE TABLE files ("
                "file_ref TEXT PRIMARY KEY, rel_path TEXT NOT NULL UNIQUE, name TEXT NOT NULL, "
                "mime_type TEXT NOT NULL, size INTEGER NOT NULL, sha256 TEXT NOT NULL, created_at INTEGER NOT NULL)"
            )
            connection.commit()
        barrier = ctx.Barrier(10)
        output = ctx.Queue()
        workers = [
            ctx.Process(target=_file_store_open_worker, args=(str(db_path), str(root), barrier, output))
            for _ in range(10)
        ]
        for worker in workers:
            worker.start()
        _join_all(self, workers, timeout=20)
        results = [output.get(timeout=3) for _ in workers]
        self.assertEqual(results.count("ok"), 10, results)
        with sqlite3.connect(str(db_path)) as connection:
            columns = [str(row[1]) for row in connection.execute("PRAGMA table_info(files)")]
            indexes = [str(row[1]) for row in connection.execute("PRAGMA index_list(files)")]
        self.assertEqual(columns.count("origin_key"), 1)
        self.assertIn("files_origin_key_unique", indexes)

    def test_checkpoint_store_fresh_bootstrap_10_processes(self) -> None:
        ctx = _context()
        state = self.root / "checkpoint-state"
        state.mkdir(mode=0o700)
        db_path = state / "jobs.sqlite3"
        barrier = ctx.Barrier(10)
        output = ctx.Queue()
        workers = [ctx.Process(target=_checkpoint_store_open_worker, args=(str(db_path), barrier, output)) for _ in range(10)]
        for worker in workers:
            worker.start()
        _join_all(self, workers, timeout=20)
        results = [output.get(timeout=3) for _ in workers]
        self.assertEqual(results.count("ok"), 10, results)
        with sqlite3.connect(str(db_path)) as connection:
            table = connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='download_jobs'"
            ).fetchone()
        self.assertEqual(table, ("download_jobs",))


if __name__ == "__main__":
    unittest.main()
