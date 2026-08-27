# -*- coding: utf-8 -*-
"""Adjacent FINALWAVE-39 multi-process liveness oracles.

Synthetic shared-state tests only; no network, Telegram credentials or private content.
"""
from __future__ import annotations

import multiprocessing as mp
import os
import tempfile
import time
import unittest
from pathlib import Path


def _context():
    return mp.get_context("fork" if "fork" in mp.get_all_start_methods() else "spawn")


def _join_all(testcase: unittest.TestCase, workers, *, timeout: float = 20.0) -> None:
    deadline = time.monotonic() + timeout
    for worker in workers:
        worker.join(max(0.1, deadline - time.monotonic()))
    alive = [worker for worker in workers if worker.is_alive()]
    for worker in alive:
        worker.terminate()
        worker.join(2)
    testcase.assertFalse(alive, f"workers hung: {[worker.pid for worker in alive]}")


def _distinct_rate_worker(db_path: str, actor: str, barrier, output) -> None:
    from bridge.runtime import _SQLiteFixedWindowStore

    try:
        barrier.wait(timeout=10)
        store = _SQLiteFixedWindowStore(Path(db_path), clock=lambda: 120.0)
        output.put(store.take(
            namespace="read",
            actor=actor,
            operation="read-api",
            limit=1,
            window_seconds=60,
        ))
    except BaseException as exc:
        output.put(("error", type(exc).__name__, 0))


class _Backend:
    def download_media(self, **kwargs):
        destination = Path(kwargs["destination"])
        destination.write_bytes(b"abc")
        return {"path": str(destination)}


def _download_lock_crash_holder(root_path: str, job_id: str, ready) -> None:
    from bridge.downloads import DownloadManager
    from bridge.storage import CheckpointStore, FileRecordStore

    root = Path(root_path)
    files = FileRecordStore(root / "state" / "files.db", root / "files")
    checkpoints = CheckpointStore(root / "state" / "jobs.db")
    manager = DownloadManager(
        backend=_Backend(),
        files=files,
        checkpoints=checkpoints,
        staging_dir=root / "tmp" / "downloads",
    )
    with manager._job_lock(job_id):
        ready.set()
        os._exit(31)


class Finalwave39AdjacentConcurrencyTests(unittest.TestCase):
    def test_ten_distinct_rate_actors_do_not_false_share_quota(self) -> None:
        ctx = _context()
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "state"
            state.mkdir(mode=0o700)
            db_path = str(state / "rate.sqlite3")
            barrier = ctx.Barrier(10)
            output = ctx.Queue()
            workers = [
                ctx.Process(target=_distinct_rate_worker, args=(db_path, f"actor-{index}", barrier, output))
                for index in range(10)
            ]
            for worker in workers:
                worker.start()
            _join_all(self, workers)
            results = [output.get(timeout=3) for _ in workers]
            self.assertFalse(any(item[0] == "error" for item in results), results)
            self.assertEqual(sum(1 for allowed, _remaining, _retry in results if allowed is True), 10, results)
            self.assertTrue(all(worker.exitcode == 0 for worker in workers), [worker.exitcode for worker in workers])

    def test_download_job_lock_owner_process_death_allows_resume(self) -> None:
        from bridge.downloads import DownloadManager
        from bridge.storage import CheckpointStore, DownloadItem, FileRecordStore

        ctx = _context()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = root / "state"
            state.mkdir(mode=0o700)
            files = FileRecordStore(state / "files.db", root / "files")
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
            job_id = checkpoints.create([item])
            ready = ctx.Event()
            holder = ctx.Process(target=_download_lock_crash_holder, args=(str(root), job_id, ready))
            holder.start()
            self.assertTrue(ready.wait(5), "download crash holder never acquired job lock")
            holder.join(5)
            if holder.is_alive():
                holder.terminate()
                holder.join(2)
                self.fail("download crash holder hung")
            self.assertEqual(holder.exitcode, 31)

            restarted_files = FileRecordStore(state / "files.db", root / "files")
            restarted_checkpoints = CheckpointStore(state / "jobs.db")
            manager = DownloadManager(
                backend=_Backend(),
                files=restarted_files,
                checkpoints=restarted_checkpoints,
                staging_dir=root / "tmp" / "downloads",
            )
            result = manager.resume(job_id)
            self.assertEqual(result["status"], "complete")
            self.assertEqual(len(result["files"]), 1)
            self.assertEqual(restarted_checkpoints.load(job_id)["status"], "complete")


if __name__ == "__main__":
    unittest.main()
