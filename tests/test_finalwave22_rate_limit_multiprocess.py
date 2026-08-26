"""FINALWAVE-22 adversarial production B8 rate-limit regressions.

These tests are credential-free and exercise the real SQLite-backed runtime
limiter used by Passenger workers. They never contact Telegram or production.
"""
from __future__ import annotations

import multiprocessing
import os
import sqlite3
import stat
import tempfile
import unittest
from pathlib import Path

from bridge.runtime import (
    RuntimeBootstrapError,
    SQLiteWriteRateLimiter,
    _SQLiteFixedWindowStore,
)


class _Clock:
    def __init__(self, value: float):
        self.value = value

    def __call__(self) -> float:
        return self.value


def _process_take(
    database: str,
    now: int,
    actor: str,
    operation: str,
    limit: int,
    window_seconds: int,
    start_event,
    result_queue,
) -> None:
    """One Passenger-like process with its own store/SQLite connection lifecycle."""

    try:
        start_event.wait(10.0)
        store = _SQLiteFixedWindowStore(Path(database), clock=lambda: float(now))
        allowed, remaining, retry_after = store.take(
            namespace="read",
            actor=actor,
            operation=operation,
            limit=limit,
            window_seconds=window_seconds,
        )
        result_queue.put(("ok", allowed, remaining, retry_after))
    except BaseException as exc:  # child diagnostics are stable codes only
        result_queue.put(("error", type(exc).__name__, getattr(exc, "code", "unknown")))


class Finalwave22RateLimitTests(unittest.TestCase):
    @staticmethod
    def _state_root(base: str) -> Path:
        state = Path(base) / "state"
        state.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(state, 0o700)
        return state

    @staticmethod
    def _run_processes(database: Path, specs: list[tuple[int, str, str, int, int]]) -> list[tuple]:
        context = multiprocessing.get_context("spawn")
        start_event = context.Event()
        result_queue = context.Queue()
        processes = [
            context.Process(
                target=_process_take,
                args=(str(database), now, actor, operation, limit, window, start_event, result_queue),
            )
            for now, actor, operation, limit, window in specs
        ]
        for process in processes:
            process.start()
        start_event.set()
        results = [result_queue.get(timeout=20.0) for _ in processes]
        for process in processes:
            process.join(timeout=20.0)
            if process.is_alive():
                process.kill()
                process.join(timeout=5.0)
                raise AssertionError("rate-limit worker did not terminate")
            if process.exitcode != 0:
                raise AssertionError(f"rate-limit worker exit={process.exitcode}")
        result_queue.close()
        result_queue.join_thread()
        return results

    def test_two_processes_same_actor_share_one_persistent_quota(self):
        with tempfile.TemporaryDirectory() as td:
            database = self._state_root(td) / "rate.sqlite3"
            _SQLiteFixedWindowStore(database, clock=lambda: 120.0)
            results = self._run_processes(
                database,
                [(120, "same-actor", "read-api", 1, 60)] * 2,
            )
            self.assertTrue(all(row[0] == "ok" for row in results), results)
            self.assertEqual(1, sum(1 for row in results if row[1] is True))
            self.assertEqual(1, sum(1 for row in results if row[1] is False))
            blocked = [row for row in results if row[1] is False]
            self.assertEqual(60, blocked[0][3])

    def test_ten_processes_same_actor_cannot_oversubscribe_limit(self):
        with tempfile.TemporaryDirectory() as td:
            database = self._state_root(td) / "rate.sqlite3"
            _SQLiteFixedWindowStore(database, clock=lambda: 600.0)
            results = self._run_processes(
                database,
                [(600, "shared-actor", "read-api", 4, 60)] * 10,
            )
            self.assertTrue(all(row[0] == "ok" for row in results), results)
            self.assertEqual(4, sum(1 for row in results if row[1] is True))
            self.assertEqual(6, sum(1 for row in results if row[1] is False))

    def test_ten_processes_different_actors_are_isolated(self):
        with tempfile.TemporaryDirectory() as td:
            database = self._state_root(td) / "rate.sqlite3"
            _SQLiteFixedWindowStore(database, clock=lambda: 900.0)
            specs = [(900, f"actor-{index}", "read-api", 1, 60) for index in range(10)]
            results = self._run_processes(database, specs)
            self.assertTrue(all(row[0] == "ok" and row[1] is True for row in results), results)

    def test_ten_process_fresh_bootstrap_is_race_safe(self):
        with tempfile.TemporaryDirectory() as td:
            database = self._state_root(td) / "rate.sqlite3"
            specs = [(1_200, f"bootstrap-{index}", "read-api", 1, 60) for index in range(10)]
            results = self._run_processes(database, specs)
            self.assertTrue(all(row[0] == "ok" and row[1] is True for row in results), results)
            self.assertTrue(database.is_file())
            self.assertEqual(0o600, stat.S_IMODE(database.stat().st_mode))

    def test_restart_preserves_exhausted_actor_until_epoch_window_rollover(self):
        with tempfile.TemporaryDirectory() as td:
            database = self._state_root(td) / "rate.sqlite3"
            clock = _Clock(119.0)
            first = _SQLiteFixedWindowStore(database, clock=clock)
            self.assertTrue(first.take(
                namespace="read", actor="actor", operation="read-api", limit=1, window_seconds=60
            )[0])
            blocked = _SQLiteFixedWindowStore(database, clock=clock).take(
                namespace="read", actor="actor", operation="read-api", limit=1, window_seconds=60
            )
            self.assertEqual((False, 0, 1), blocked)
            clock.value = 120.0
            after_restart = _SQLiteFixedWindowStore(database, clock=clock).take(
                namespace="read", actor="actor", operation="read-api", limit=1, window_seconds=60
            )
            self.assertEqual((True, 0, 0), after_restart)

    def test_forward_jump_then_backward_clock_fails_closed_across_restart(self):
        with tempfile.TemporaryDirectory() as td:
            database = self._state_root(td) / "rate.sqlite3"
            clock = _Clock(120.0)
            store = _SQLiteFixedWindowStore(database, clock=clock)
            self.assertTrue(store.take(
                namespace="read", actor="actor", operation="read-api", limit=10, window_seconds=60
            )[0])
            clock.value = 3_600.0
            self.assertTrue(store.take(
                namespace="read", actor="actor", operation="read-api", limit=10, window_seconds=60
            )[0])
            clock.value = 3_599.0
            with self.assertRaises(RuntimeBootstrapError) as current:
                store.take(namespace="read", actor="actor", operation="read-api", limit=10, window_seconds=60)
            self.assertEqual("rate_limit_clock_moved_backward", current.exception.code)
            restarted = _SQLiteFixedWindowStore(database, clock=clock)
            with self.assertRaises(RuntimeBootstrapError) as after_restart:
                restarted.take(namespace="read", actor="actor", operation="read-api", limit=10, window_seconds=60)
            self.assertEqual("rate_limit_clock_moved_backward", after_restart.exception.code)

    def test_busy_database_fails_closed_instead_of_bypassing_quota(self):
        with tempfile.TemporaryDirectory() as td:
            database = self._state_root(td) / "rate.sqlite3"
            store = _SQLiteFixedWindowStore(database, clock=lambda: 120.0)
            blocker = sqlite3.connect(str(database), timeout=1.0, isolation_level=None)
            try:
                blocker.execute("BEGIN IMMEDIATE")
                with self.assertRaises(RuntimeBootstrapError) as caught:
                    store.take(namespace="read", actor="actor", operation="read-api", limit=10, window_seconds=60)
                self.assertEqual("rate_limit_database_unavailable", caught.exception.code)
            finally:
                blocker.execute("ROLLBACK")
                blocker.close()

    def test_corrupt_database_fails_closed_on_restart(self):
        with tempfile.TemporaryDirectory() as td:
            database = self._state_root(td) / "rate.sqlite3"
            _SQLiteFixedWindowStore(database, clock=lambda: 120.0)
            for suffix in ("-wal", "-shm"):
                sidecar = Path(str(database) + suffix)
                if sidecar.exists():
                    sidecar.unlink()
            database.write_bytes(b"not-a-sqlite-database")
            os.chmod(database, 0o600)
            with self.assertRaises(RuntimeBootstrapError) as caught:
                _SQLiteFixedWindowStore(database, clock=lambda: 120.0)
            self.assertEqual("rate_limit_database_unavailable", caught.exception.code)

    def test_malicious_sidecar_topology_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            state = self._state_root(td)
            database = state / "rate.sqlite3"
            _SQLiteFixedWindowStore(database, clock=lambda: 120.0)
            target = state / "sidecar-target"
            target.write_bytes(b"")
            os.chmod(target, 0o600)
            wal = Path(str(database) + "-wal")
            if wal.exists():
                wal.unlink()
            wal.symlink_to(target)
            with self.assertRaises(RuntimeBootstrapError):
                _SQLiteFixedWindowStore(database, clock=lambda: 120.0)

    def test_pruning_removes_only_stale_actor_rows(self):
        with tempfile.TemporaryDirectory() as td:
            database = self._state_root(td) / "rate.sqlite3"
            clock = _Clock(0.0)
            store = _SQLiteFixedWindowStore(database, clock=clock)
            store.take(namespace="read", actor="old", operation="read-api", limit=10, window_seconds=60)
            clock.value = 120.0
            store.take(namespace="read", actor="recent", operation="read-api", limit=10, window_seconds=60)
            clock.value = 180.0
            store.take(namespace="read", actor="current", operation="read-api", limit=10, window_seconds=60)
            connection = sqlite3.connect(str(database))
            try:
                rows = connection.execute(
                    "SELECT window_start FROM fixed_window_quota ORDER BY window_start"
                ).fetchall()
            finally:
                connection.close()
            self.assertEqual([(120,), (180,)], rows)

    def test_read_write_namespaces_do_not_consume_each_other(self):
        with tempfile.TemporaryDirectory() as td:
            database = self._state_root(td) / "rate.sqlite3"
            store = _SQLiteFixedWindowStore(database, clock=lambda: 300.0)
            self.assertTrue(store.take(
                namespace="read", actor="actor", operation="same-op", limit=1, window_seconds=60
            )[0])
            self.assertTrue(store.take(
                namespace="write", actor="actor", operation="same-op", limit=1, window_seconds=60
            )[0])
            self.assertFalse(store.take(
                namespace="read", actor="actor", operation="same-op", limit=1, window_seconds=60
            )[0])
            self.assertFalse(store.take(
                namespace="write", actor="actor", operation="same-op", limit=1, window_seconds=60
            )[0])

    def test_write_reset_at_matches_fixed_epoch_window_boundary(self):
        with tempfile.TemporaryDirectory() as td:
            database = self._state_root(td) / "rate.sqlite3"
            clock = _Clock(125.0)
            limiter = SQLiteWriteRateLimiter(
                _SQLiteFixedWindowStore(database, clock=clock),
                limit=2,
                window_seconds=60,
            )
            remaining, reset_at = limiter.consume("a" * 64, "previewTelegramSend")
            self.assertEqual(1, remaining)
            self.assertEqual(180, reset_at)


if __name__ == "__main__":
    unittest.main()
