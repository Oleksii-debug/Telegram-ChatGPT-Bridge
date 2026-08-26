from __future__ import annotations

import fcntl
import hashlib
import multiprocessing
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from bridge.downloads import DownloadLimits, DownloadManager
from bridge.errors import BridgeError
from bridge.storage import CheckpointStore, DownloadItem, FileRecordStore


class CountingBackend:
    def __init__(self, *, data: bytes = b"abc", outside: Path | None = None) -> None:
        self.data = data
        self.outside = outside
        self.calls = 0

    def download_media(self, **kwargs):
        self.calls += 1
        if self.outside is not None:
            self.outside.write_bytes(self.data)
            return {"path": str(self.outside)}
        target = Path(kwargs["destination"])
        target.write_bytes(self.data)
        return {"path": str(target)}


def _hold_flock(lock_path: str, ready, release) -> None:
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        os.fchmod(fd, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX)
        ready.set()
        release.wait(10)
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)


class FinalWave51DownloadCrashTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.files = FileRecordStore(self.root / "state" / "files.sqlite3", self.root / "files")
        self.checkpoints = CheckpointStore(self.root / "state" / "jobs.sqlite3")
        self.backend = CountingBackend()
        self.staging = self.root / "tmp" / "downloads"
        self.manager = DownloadManager(
            backend=self.backend,
            files=self.files,
            checkpoints=self.checkpoints,
            staging_dir=self.staging,
        )

    @staticmethod
    def item(
        item_id: str = "item1",
        *,
        message_id: int = 1,
        file_ref: str = "tg_1_0123456789abcdefabcd",
        expected_size: int | None = 3,
        expected_sha256: str | None = None,
    ) -> DownloadItem:
        return DownloadItem(
            item_id,
            "1",
            message_id,
            file_ref,
            f"{item_id}.txt",
            "text/plain",
            expected_size,
            expected_sha256,
        )

    @staticmethod
    def owned_stage_name(job_id: str, token: str = "a" * 24, suffix: str = ".txt") -> str:
        return f"{job_id}_{token}{suffix}.part"

    def test_mid_staging_process_loss_is_reconciled_before_redownload(self) -> None:
        item = self.item()
        job_id = self.checkpoints.create([item])
        orphan = self.staging / self.owned_stage_name(job_id)
        orphan.write_bytes(b"partial-private-bytes")

        result = self.manager.resume(job_id)

        self.assertEqual(result["status"], "complete")
        self.assertEqual(self.backend.calls, 1)
        self.assertFalse(orphan.exists())
        self.assertEqual(list(self.staging.iterdir()), [])

    def test_completed_resume_also_reconciles_stale_job_staging(self) -> None:
        item = self.item()
        job_id = self.checkpoints.create([item])
        self.assertEqual(self.manager.resume(job_id)["status"], "complete")
        calls = self.backend.calls
        orphan = self.staging / self.owned_stage_name(job_id, "b" * 24)
        orphan.write_bytes(b"old-partial")

        result = self.manager.resume(job_id)

        self.assertEqual(result["status"], "complete")
        self.assertEqual(self.backend.calls, calls)
        self.assertFalse(orphan.exists())

    def test_staging_recovery_unlinks_owned_symlink_without_touching_target(self) -> None:
        item = self.item()
        job_id = self.checkpoints.create([item])
        outside = self.root / "outside-private.bin"
        outside.write_bytes(b"outside-must-survive")
        orphan = self.staging / self.owned_stage_name(job_id, "c" * 24)
        orphan.symlink_to(outside)

        result = self.manager.resume(job_id)

        self.assertEqual(result["status"], "complete")
        self.assertFalse(orphan.exists())
        self.assertEqual(outside.read_bytes(), b"outside-must-survive")

    def test_staging_recovery_ignores_unowned_leaf(self) -> None:
        item = self.item()
        job_id = self.checkpoints.create([item])
        unrelated = self.staging / f"otherjob_{'d' * 24}.txt.part"
        unrelated.write_bytes(b"unrelated")

        result = self.manager.resume(job_id)

        self.assertEqual(result["status"], "complete")
        self.assertEqual(unrelated.read_bytes(), b"unrelated")

    def test_staging_recovery_special_topology_fails_before_telegram(self) -> None:
        item = self.item()
        job_id = self.checkpoints.create([item])
        unsafe = self.staging / self.owned_stage_name(job_id, "e" * 24)
        unsafe.mkdir()

        with self.assertRaises(BridgeError) as caught:
            self.manager.resume(job_id)

        self.assertEqual(caught.exception.code, "staging_recovery_unsafe")
        self.assertEqual(self.backend.calls, 0)
        self.assertTrue(unsafe.is_dir())

    def test_staging_recovery_disk_error_fails_before_telegram(self) -> None:
        job_id = self.checkpoints.create([self.item()])
        with patch("bridge.downloads.os.scandir", side_effect=OSError("synthetic disk fault")):
            with self.assertRaises(BridgeError) as caught:
                self.manager.resume(job_id)
        self.assertEqual(caught.exception.code, "staging_recovery_unavailable")
        self.assertEqual(caught.exception.status, 503)
        self.assertEqual(self.backend.calls, 0)

    def test_backend_outside_path_is_rejected_without_deletion(self) -> None:
        outside = self.root / "outside.bin"
        backend = CountingBackend(outside=outside)
        manager = DownloadManager(
            backend=backend,
            files=self.files,
            checkpoints=self.checkpoints,
            staging_dir=self.root / "tmp" / "outside-case",
        )

        result = manager.start_bulk([self.item()])

        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["failures"][0]["code"], "unsafe_backend_path")
        self.assertEqual(outside.read_bytes(), b"abc")
        self.assertEqual(backend.calls, 1)

    def test_after_move_before_registry_is_adopted_without_backend_download(self) -> None:
        item = self.item()
        job_id = self.checkpoints.create([item])
        final = self.manager._final_path(item, job_id=job_id)
        final.write_bytes(b"abc")

        result = self.manager.resume(job_id)

        self.assertEqual(result["status"], "complete")
        self.assertEqual(self.backend.calls, 0)
        stored = self.files.get(result["files"][0]["file_ref"])
        self.assertIsNotNone(stored)
        assert stored is not None
        self.assertEqual(stored.origin_key, self.manager._origin_key(job_id, item.item_id))

    def test_after_registry_before_checkpoint_is_recovered_without_duplicate(self) -> None:
        item = self.item()
        job_id = self.checkpoints.create([item])
        final = self.manager._final_path(item, job_id=job_id)
        final.write_bytes(b"abc")
        origin = self.manager._origin_key(job_id, item.item_id)
        registered = self.files.add(final, name=item.name, mime_type=item.mime_type, origin_key=origin)

        result = self.manager.resume(job_id)

        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["files"][0]["file_ref"], registered.file_ref)
        self.assertEqual(self.backend.calls, 0)
        with sqlite3.connect(str(self.files.db_path)) as connection:
            count = connection.execute("SELECT COUNT(*) FROM files WHERE origin_key=?", (origin,)).fetchone()[0]
        self.assertEqual(count, 1)

    def test_checkpoint_write_failure_after_registry_resumes_exactly_once(self) -> None:
        item = self.item()
        job_id = self.checkpoints.create([item])
        real_save = self.checkpoints.save
        save_calls = 0

        def fail_second_save(payload):
            nonlocal save_calls
            save_calls += 1
            if save_calls == 2:
                raise OSError("synthetic checkpoint write failure")
            return real_save(payload)

        with patch.object(self.checkpoints, "save", side_effect=fail_second_save):
            with self.assertRaises(OSError):
                self.manager.resume(job_id)

        self.assertEqual(self.backend.calls, 1)
        resumed = self.manager.resume(job_id)
        self.assertEqual(resumed["status"], "complete")
        self.assertEqual(self.backend.calls, 1)
        origin = self.manager._origin_key(job_id, item.item_id)
        with sqlite3.connect(str(self.files.db_path)) as connection:
            count = connection.execute("SELECT COUNT(*) FROM files WHERE origin_key=?", (origin,)).fetchone()[0]
        self.assertEqual(count, 1)

    def test_missing_registered_leaf_self_heals_with_one_redownload(self) -> None:
        item = self.item()
        job_id = self.checkpoints.create([item])
        final = self.manager._final_path(item, job_id=job_id)
        final.write_bytes(b"abc")
        origin = self.manager._origin_key(job_id, item.item_id)
        stale = self.files.add(final, name=item.name, mime_type=item.mime_type, origin_key=origin)
        Path(stale.path).unlink()

        result = self.manager.resume(job_id)

        self.assertEqual(result["status"], "complete")
        self.assertEqual(self.backend.calls, 1)
        with sqlite3.connect(str(self.files.db_path)) as connection:
            count = connection.execute("SELECT COUNT(*) FROM files WHERE origin_key=?", (origin,)).fetchone()[0]
        self.assertEqual(count, 1)

    def test_corrupt_registered_result_is_never_served_or_redownloaded(self) -> None:
        expected = hashlib.sha256(b"abc").hexdigest()
        item = self.item(expected_sha256=expected)
        job_id = self.checkpoints.create([item])
        final = self.manager._final_path(item, job_id=job_id)
        final.write_bytes(b"abc")
        origin = self.manager._origin_key(job_id, item.item_id)
        registered = self.files.add(final, name=item.name, mime_type=item.mime_type, origin_key=origin)
        final.write_bytes(b"xyz")

        result = self.manager.resume(job_id)

        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["failures"][0]["code"], "checkpoint_result_mismatch")
        self.assertEqual(self.backend.calls, 0)
        self.assertIsNone(self.files.get(registered.file_ref))

    def test_bulk_actual_size_overrun_removes_second_registry_and_does_not_retry(self) -> None:
        manager = DownloadManager(
            backend=self.backend,
            files=self.files,
            checkpoints=self.checkpoints,
            staging_dir=self.root / "tmp" / "bulk-total",
            limits=DownloadLimits(max_single_bytes=4, max_bulk_files=10, max_bulk_bytes=5),
        )
        first = self.item("first", file_ref="tg_1_0123456789abcdefabcd", expected_size=None)
        second = self.item(
            "second",
            message_id=2,
            file_ref="tg_2_0123456789abcdefabcd",
            expected_size=None,
        )

        result = manager.start_bulk([first, second])

        self.assertEqual(result["status"], "partial")
        self.assertEqual(len(result["files"]), 1)
        self.assertEqual(result["failures"][0]["code"], "bulk_size_limit")
        self.assertFalse(result["failures"][0]["retryable"])
        self.assertEqual(self.backend.calls, 2)
        with sqlite3.connect(str(self.files.db_path)) as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM files").fetchone()[0], 1)
        again = manager.resume(result["job_id"])
        self.assertEqual(again["status"], "partial")
        self.assertEqual(self.backend.calls, 2)

    def test_same_job_cross_process_lock_blocks_before_backend(self) -> None:
        item = self.item()
        job_id = self.checkpoints.create([item])
        lock_name = hashlib.sha256(job_id.encode("utf-8")).hexdigest() + ".lock"
        lock_path = self.manager.lock_dir / lock_name
        ctx = multiprocessing.get_context("fork")
        ready = ctx.Event()
        release = ctx.Event()
        process = ctx.Process(target=_hold_flock, args=(str(lock_path), ready, release))
        process.start()
        self.addCleanup(lambda: process.is_alive() and process.terminate())
        self.assertTrue(ready.wait(5), "lock holder did not start")
        try:
            with self.assertRaises(BridgeError) as caught:
                self.manager.resume(job_id)
            self.assertEqual(caught.exception.code, "job_busy")
            self.assertEqual(self.backend.calls, 0)
        finally:
            release.set()
            process.join(5)
        self.assertFalse(process.is_alive())
        self.assertEqual(self.manager.resume(job_id)["status"], "complete")
        self.assertEqual(self.backend.calls, 1)


if __name__ == "__main__":
    unittest.main()
