from __future__ import annotations

import multiprocessing
import os
import sqlite3
import stat
import tempfile
import unittest
from pathlib import Path

from ops.secure_write_store import SecurePersistentWriteStore


_PREVIEWS_SQL = """
CREATE TABLE previews (
    preview_id TEXT PRIMARY KEY,
    token_hash TEXT NOT NULL UNIQUE,
    action TEXT NOT NULL,
    request_fingerprint TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    consumed_at INTEGER
)
"""

_IDEMPOTENCY_SQL = """
CREATE TABLE idempotency (
    key_hash TEXT PRIMARY KEY,
    request_fingerprint TEXT NOT NULL,
    preview_id TEXT NOT NULL,
    state TEXT NOT NULL,
    result_json TEXT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    FOREIGN KEY(preview_id) REFERENCES previews(preview_id)
)
"""


def _cold_start_worker(db_path: str) -> bool:
    store = SecurePersistentWriteStore(db_path)
    with sqlite3.connect(db_path) as connection:
        row = connection.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()
    return row == (str(store.SCHEMA_VERSION),)


class SecureWriteSchemaAdoptionTests(unittest.TestCase):
    def setUp(self) -> None:
        if os.name != "posix":
            self.skipTest("secure write store is a POSIX production component")
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.parent = Path(self.tmp.name) / "state"
        self.parent.mkdir(mode=0o700)
        os.chmod(self.parent, 0o700)
        self.db = self.parent / "writes.sqlite3"

    def _prepare(self, statements: list[str]) -> None:
        with sqlite3.connect(self.db) as connection:
            for statement in statements:
                connection.execute(statement)
            connection.commit()
        os.chmod(self.db, 0o600)

    def _managed_schema(self) -> tuple[tuple[str, str], ...]:
        with sqlite3.connect(self.db) as connection:
            rows = connection.execute(
                "SELECT name,sql FROM sqlite_master "
                "WHERE type IN ('table','index') AND name NOT LIKE 'sqlite_%' "
                "ORDER BY type,name"
            ).fetchall()
        return tuple((str(name), str(sql)) for name, sql in rows)

    def test_fresh_database_still_bootstraps_current_schema(self) -> None:
        store = SecurePersistentWriteStore(self.db)
        with sqlite3.connect(self.db) as connection:
            version = connection.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()
            tables = {
                row[0]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )
            }
        self.assertEqual(version, (str(store.SCHEMA_VERSION),))
        self.assertTrue({"meta", "previews", "idempotency"}.issubset(tables))

    def test_compatible_looking_managed_tables_without_meta_are_not_silently_adopted(self) -> None:
        self._prepare(
            [
                _PREVIEWS_SQL,
                _IDEMPOTENCY_SQL,
                "CREATE INDEX idx_previews_expires ON previews(expires_at)",
                "CREATE INDEX idx_idempotency_state ON idempotency(state)",
            ]
        )
        before = self._managed_schema()

        with self.assertRaisesRegex(RuntimeError, "unsupported write-store schema"):
            SecurePersistentWriteStore(self.db)

        self.assertEqual(self._managed_schema(), before)
        with sqlite3.connect(self.db) as connection:
            meta = connection.execute(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='meta'"
            ).fetchone()
        self.assertEqual(meta, (0,))

    def test_meta_without_schema_version_is_not_repaired_by_assumption(self) -> None:
        self._prepare(["CREATE TABLE meta (key TEXT PRIMARY KEY,value TEXT NOT NULL)"])
        before = self._managed_schema()

        with self.assertRaisesRegex(RuntimeError, "unsupported write-store schema"):
            SecurePersistentWriteStore(self.db)

        self.assertEqual(self._managed_schema(), before)
        with sqlite3.connect(self.db) as connection:
            rows = connection.execute("SELECT key,value FROM meta").fetchall()
        self.assertEqual(rows, [])

    def test_unsupported_version_is_rejected_without_creating_managed_tables(self) -> None:
        self._prepare(
            [
                "CREATE TABLE meta (key TEXT PRIMARY KEY,value TEXT NOT NULL)",
                "INSERT INTO meta(key,value) VALUES('schema_version','999')",
            ]
        )
        before = self._managed_schema()

        with self.assertRaisesRegex(RuntimeError, "unsupported write-store schema"):
            SecurePersistentWriteStore(self.db)

        self.assertEqual(self._managed_schema(), before)
        with sqlite3.connect(self.db) as connection:
            row = connection.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()
        self.assertEqual(row, ("999",))

    def test_eight_process_cold_start_remains_single_versioned_schema(self) -> None:
        context = multiprocessing.get_context("spawn")
        with context.Pool(processes=8) as pool:
            results = pool.map(_cold_start_worker, [str(self.db)] * 8)
        self.assertEqual(results, [True] * 8)
        self.assertEqual(stat.S_IMODE(os.lstat(self.db).st_mode), 0o600)
        with sqlite3.connect(self.db) as connection:
            rows = connection.execute("SELECT key,value FROM meta ORDER BY key").fetchall()
        self.assertEqual(rows, [("schema_version", "1")])


if __name__ == "__main__":
    unittest.main()
