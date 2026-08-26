# -*- coding: utf-8 -*-
"""Cross-primitive lock-order oracle for FINALWAVE-39.

Synthetic only: the callback represents the Telegram effect boundary but performs
no network I/O and uses no Telegram credentials or private content.
"""
from __future__ import annotations

import multiprocessing as mp
import tempfile
import time
import unittest
from pathlib import Path


def _context():
    return mp.get_context("fork" if "fork" in mp.get_all_start_methods() else "spawn")


def _worker(db_path, token, key, index, lock_path, barrier, active, peak, stats_lock, effects, effects_lock, output):
    from ops.telegram_session_lock import TelegramSessionLock
    from ops.write_safety import PersistentWriteStore

    store = PersistentWriteStore(Path(db_path), busy_timeout_ms=5000)
    try:
        barrier.wait(timeout=10)

        def external_write(_payload):
            with TelegramSessionLock(Path(lock_path), timeout_seconds=5.0, poll_interval_seconds=0.01):
                with stats_lock:
                    active.value += 1
                    peak.value = max(peak.value, active.value)
                try:
                    with effects_lock:
                        effects.value += 1
                    time.sleep(0.03)
                    return {"id": index + 1}
                finally:
                    with stats_lock:
                        active.value -= 1

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


class Finalwave39LockOrderTests(unittest.TestCase):
    def test_six_processes_sqlite_then_session_effect_boundary_has_no_deadlock(self):
        from ops.write_safety import PersistentWriteStore

        ctx = _context()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            private = root / "private"
            private.mkdir(mode=0o700)
            lock_path = private / "telegram-session.lock"
            db_path = root / "writes.sqlite3"
            parent = PersistentWriteStore(db_path)
            previews = [
                parent.create_preview(
                    "SEND",
                    {"target": "@target_user", "text": f"synthetic-{index}"},
                    now=100,
                )
                for index in range(6)
            ]
            barrier = ctx.Barrier(6)
            active = ctx.Value("i", 0)
            peak = ctx.Value("i", 0)
            effects = ctx.Value("i", 0)
            stats_lock = ctx.Lock()
            effects_lock = ctx.Lock()
            output = ctx.Queue()
            workers = [
                ctx.Process(
                    target=_worker,
                    args=(
                        str(db_path),
                        previews[index].token,
                        f"lock-order-key-{index:02d}",
                        index,
                        str(lock_path),
                        barrier,
                        active,
                        peak,
                        stats_lock,
                        effects,
                        effects_lock,
                        output,
                    ),
                )
                for index in range(6)
            ]
            for worker in workers:
                worker.start()

            deadline = time.monotonic() + 20
            for worker in workers:
                worker.join(max(0.1, deadline - time.monotonic()))
            alive = [worker for worker in workers if worker.is_alive()]
            for worker in alive:
                worker.terminate()
                worker.join(2)
            self.assertFalse(alive, "SQLite/session lock-order workers deadlocked")

            results = [output.get(timeout=3) for _ in workers]
            self.assertEqual(results.count(("ok", "COMMITTED")), 6, results)
            self.assertEqual(effects.value, 6, results)
            self.assertEqual(active.value, 0)
            self.assertEqual(peak.value, 1)
            self.assertTrue(all(worker.exitcode == 0 for worker in workers), [worker.exitcode for worker in workers])
            for index in range(6):
                self.assertEqual(parent.transaction_state(f"lock-order-key-{index:02d}"), "COMMITTED")


if __name__ == "__main__":
    unittest.main()
