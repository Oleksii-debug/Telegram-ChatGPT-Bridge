from __future__ import annotations

import multiprocessing as mp
import sqlite3
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path

from ops.write_safety import PersistentWriteStore, WriteAction


def _cold_start_worker(db_path: str, gate, results, worker_id: int) -> None:
    try:
        gate.wait(10)
        store = PersistentWriteStore(db_path, busy_timeout_ms=5000)
        preview = store.create_preview(
            WriteAction.SEND,
            {"target": f"peer-{worker_id}", "text": "cold-start"},
            now=100 + worker_id,
        )
        results.put(("ok", worker_id, preview.preview_id))
    except BaseException as exc:  # subprocess evidence must report every failure
        results.put(("error", worker_id, type(exc).__name__, str(exc)))


class _Row(dict):
    pass


class _SeedConnection:
    def __init__(self) -> None:
        self.statements: list[str] = []
        self.seeded = False
        self.in_transaction = False

    def execute(self, sql: str, parameters=()):
        normalized = " ".join(sql.split())
        self.statements.append(normalized)
        if normalized == "BEGIN IMMEDIATE":
            self.in_transaction = True
            return self
        if normalized.startswith("SELECT name, type FROM sqlite_master"):
            return self
        if normalized.startswith("CREATE TABLE IF NOT EXISTS meta"):
            return self
        if normalized.startswith("INSERT OR IGNORE INTO meta"):
            self.seeded = True
            return self
        if normalized.startswith("SELECT value FROM meta"):
            return self
        if normalized.startswith("CREATE TABLE IF NOT EXISTS previews"):
            return self
        if normalized.startswith("CREATE TABLE IF NOT EXISTS idempotency"):
            return self
        if normalized.startswith("CREATE INDEX IF NOT EXISTS idx_previews_expires"):
            return self
        if normalized.startswith("CREATE INDEX IF NOT EXISTS idx_idempotency_state"):
            return self
        raise AssertionError(f"unexpected SQL: {normalized}")

    def fetchall(self):
        return []

    def fetchone(self):
        return _Row(value="1") if self.seeded else None

    def commit(self) -> None:
        self.in_transaction = False

    def rollback(self) -> None:
        self.in_transaction = False


class WriteStoreSchemaRaceTests(unittest.TestCase):
    def test_schema_version_seed_is_conflict_safe(self) -> None:
        store = object.__new__(PersistentWriteStore)
        connection = _SeedConnection()

        @contextmanager
        def connect():
            yield connection

        store._connect = connect  # type: ignore[method-assign]
        store._init_schema()

        seed_statements = [s for s in connection.statements if s.startswith("INSERT")]
        self.assertEqual(1, len(seed_statements))
        self.assertIn("INSERT OR IGNORE", seed_statements[0])
        self.assertIn("BEGIN IMMEDIATE", connection.statements)

    def test_existing_incompatible_schema_still_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            db_path = Path(td) / "writes.sqlite3"
            con = sqlite3.connect(db_path)
            try:
                con.execute("CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
                con.execute("INSERT INTO meta(key,value) VALUES('schema_version','999')")
                con.commit()
            finally:
                con.close()
            with self.assertRaisesRegex(RuntimeError, "unsupported write-store schema"):
                PersistentWriteStore(db_path)

    def test_incompatible_schema_is_not_mutated_before_rejection(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            db_path = Path(td) / "writes.sqlite3"
            con = sqlite3.connect(db_path)
            try:
                con.execute("CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
                con.execute("INSERT INTO meta(key,value) VALUES('schema_version','999')")
                con.commit()
                before = con.execute(
                    "SELECT type,name,sql FROM sqlite_master ORDER BY type,name"
                ).fetchall()
            finally:
                con.close()

            with self.assertRaisesRegex(RuntimeError, "unsupported write-store schema"):
                PersistentWriteStore(db_path)

            con = sqlite3.connect(db_path)
            try:
                after = con.execute(
                    "SELECT type,name,sql FROM sqlite_master ORDER BY type,name"
                ).fetchall()
            finally:
                con.close()
            self.assertEqual(before, after, "unsupported DB must not be partially migrated")

    def test_existing_managed_tables_without_schema_metadata_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            db_path = Path(td) / "writes.sqlite3"
            con = sqlite3.connect(db_path)
            try:
                con.execute("CREATE TABLE previews (legacy TEXT)")
                con.commit()
            finally:
                con.close()

            with self.assertRaisesRegex(RuntimeError, "write-store schema metadata missing"):
                PersistentWriteStore(db_path)

            con = sqlite3.connect(db_path)
            try:
                names = {
                    row[0]
                    for row in con.execute(
                        "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
                    )
                }
            finally:
                con.close()
            self.assertEqual({"previews"}, names)

    def test_eight_process_cold_start_shares_one_write_store(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            db_path = str(Path(td) / "writes.sqlite3")
            ctx = mp.get_context("spawn")
            gate = ctx.Event()
            results = ctx.Queue()
            processes = [
                ctx.Process(target=_cold_start_worker, args=(db_path, gate, results, index))
                for index in range(8)
            ]
            for process in processes:
                process.start()
            gate.set()

            observed = [results.get(timeout=20) for _ in processes]
            for process in processes:
                process.join(20)
                self.assertFalse(process.is_alive(), "cold-start worker did not terminate")
                self.assertEqual(0, process.exitcode)

            errors = [item for item in observed if item[0] != "ok"]
            self.assertEqual([], errors)
            self.assertEqual(8, len({item[2] for item in observed}))

            con = sqlite3.connect(db_path)
            try:
                schema = con.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()
                preview_count = con.execute("SELECT COUNT(*) FROM previews").fetchone()[0]
            finally:
                con.close()
            self.assertEqual(("1",), schema)
            self.assertEqual(8, preview_count)


if __name__ == "__main__":
    unittest.main()
