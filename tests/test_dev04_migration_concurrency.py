from __future__ import annotations

import multiprocessing
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path

from bridge.storage import FileRecordStore


def _open_store_worker(db_path: str, root_path: str, start_event, result_queue) -> None:
    start_event.wait(10)
    try:
        FileRecordStore(Path(db_path), Path(root_path))
        result_queue.put("ok")
    except BaseException as exc:  # pragma: no cover - result is asserted in parent
        result_queue.put(type(exc).__name__)
        raise


class ConcurrentFileRegistryMigrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        base = Path(self.tmp.name)
        self.db_path = base / "state" / "files.sqlite3"
        self.root = base / "files"
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.root.mkdir(parents=True, exist_ok=True)
        os.chmod(self.db_path.parent, 0o700)
        os.chmod(self.root, 0o700)

    def _create_legacy_schema(self) -> None:
        with sqlite3.connect(str(self.db_path)) as connection:
            connection.execute(
                """
                CREATE TABLE files (
                    file_ref TEXT PRIMARY KEY,
                    rel_path TEXT NOT NULL UNIQUE,
                    name TEXT NOT NULL,
                    mime_type TEXT NOT NULL,
                    size INTEGER NOT NULL,
                    sha256 TEXT NOT NULL,
                    created_at INTEGER NOT NULL
                )
                """
            )
            connection.commit()

    def _run_workers(self, count: int) -> tuple[list[str], list[int | None]]:
        context = multiprocessing.get_context("fork") if "fork" in multiprocessing.get_all_start_methods() else multiprocessing.get_context("spawn")
        start_event = context.Event()
        result_queue = context.Queue()
        workers = [
            context.Process(
                target=_open_store_worker,
                args=(str(self.db_path), str(self.root), start_event, result_queue),
            )
            for _ in range(count)
        ]
        for worker in workers:
            worker.start()
        start_event.set()
        for worker in workers:
            worker.join(15)
        results = [result_queue.get(timeout=3) for _ in workers]
        return results, [worker.exitcode for worker in workers]

    def test_two_workers_serialize_legacy_origin_key_migration(self) -> None:
        self._create_legacy_schema()
        results, exitcodes = self._run_workers(2)

        self.assertEqual(results.count("ok"), 2, results)
        self.assertTrue(all(code == 0 for code in exitcodes), exitcodes)

        with sqlite3.connect(str(self.db_path)) as connection:
            columns = [str(row[1]) for row in connection.execute("PRAGMA table_info(files)")]
            indexes = [str(row[1]) for row in connection.execute("PRAGMA index_list(files)")]
        self.assertEqual(columns.count("origin_key"), 1)
        self.assertIn("files_origin_key_unique", indexes)

    def test_four_workers_share_fresh_file_registry_bootstrap(self) -> None:
        results, exitcodes = self._run_workers(4)

        self.assertEqual(results.count("ok"), 4, results)
        self.assertTrue(all(code == 0 for code in exitcodes), exitcodes)

        with sqlite3.connect(str(self.db_path)) as connection:
            mode = connection.execute("PRAGMA journal_mode").fetchone()
            columns = [str(row[1]) for row in connection.execute("PRAGMA table_info(files)")]
            indexes = [str(row[1]) for row in connection.execute("PRAGMA index_list(files)")]
        self.assertEqual(str(mode[0]).lower(), "wal")
        self.assertEqual(columns.count("origin_key"), 1)
        self.assertIn("files_origin_key_unique", indexes)


if __name__ == "__main__":
    unittest.main()
