# -*- coding: utf-8 -*-
"""BURST01-09 diagnostic oracle for Passenger multi-process write-store bootstrap.

This specialist test intentionally characterizes the current unsafe bootstrap
interleaving.  It is not a product PASS and should be inverted/replaced by a
"both workers succeed" regression when the production store bootstrap is fixed.
No Telegram/network/private data is used.
"""
from __future__ import annotations

import multiprocessing as mp
import os
import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path


def _bootstrap_worker(db_path: str, barrier, output) -> None:
    """Run the real PersistentWriteStore while forcing both schema reads to race."""
    from ops import write_safety

    real_connect = sqlite3.connect

    class _CursorProxy:
        def __init__(self, cursor):
            self._cursor = cursor

        def fetchone(self):
            row = self._cursor.fetchone()
            # Current production code reads the version outside a writer
            # transaction.  Force both processes to observe the empty row before
            # either performs INSERT.  A future BEGIN IMMEDIATE-style fix may
            # serialize before this point, in which case timeout simply releases
            # the first worker and the diagnostic will stop reproducing.
            try:
                barrier.wait(timeout=1.0)
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
    except BaseException as exc:  # diagnostic only; record class, never private text
        output.put(("error", type(exc).__name__))


class PassengerWriteStoreBootstrapOracleTests(unittest.TestCase):
    def test_current_schema_bootstrap_select_insert_race_is_reproducible(self) -> None:
        ctx = mp.get_context("fork" if hasattr(os, "fork") else "spawn")
        with tempfile.TemporaryDirectory() as tmp:
            db_path = str(Path(tmp) / "writes.sqlite3")
            barrier = ctx.Barrier(2)
            output = ctx.Queue()
            workers = [ctx.Process(target=_bootstrap_worker, args=(db_path, barrier, output)) for _ in range(2)]
            for worker in workers:
                worker.start()
            for worker in workers:
                worker.join(10)
                self.assertFalse(worker.is_alive(), "bootstrap worker hung")
                self.assertEqual(worker.exitcode, 0)
            results = [output.get(timeout=2) for _ in workers]

        statuses = sorted(item[0] for item in results)
        error_types = {item[1] for item in results if item[0] == "error"}
        self.assertEqual(statuses, ["error", "ok"])
        self.assertIn("IntegrityError", error_types)


if __name__ == "__main__":
    unittest.main()
