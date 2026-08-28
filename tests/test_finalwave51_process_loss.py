from __future__ import annotations

import hashlib
import multiprocessing
import os
import tempfile
import unittest
from pathlib import Path

from bridge.downloads import DownloadManager
from bridge.storage import CheckpointStore, DownloadItem, FileRecordStore


class ProcessBackend:
    def __init__(self, data: bytes = b"abc", *, crash_after_write: int | None = None) -> None:
        self.data = data
        self.crash_after_write = crash_after_write
        self.calls = 0

    def download_media(self, **kwargs):
        self.calls += 1
        target = Path(kwargs["destination"])
        target.write_bytes(self.data)
        if self.crash_after_write is not None:
            os._exit(self.crash_after_write)
        return {"path": str(target)}


def _stores(root: Path):
    files = FileRecordStore(root / "state" / "files.sqlite3", root / "files")
    checkpoints = CheckpointStore(root / "state" / "jobs.sqlite3")
    return files, checkpoints


def _manager(root: Path, backend: ProcessBackend) -> DownloadManager:
    files, checkpoints = _stores(root)
    return DownloadManager(
        backend=backend,
        files=files,
        checkpoints=checkpoints,
        staging_dir=root / "tmp" / "downloads",
    )


def _crash_mid_staging(root_text: str, job_id: str) -> None:
    root = Path(root_text)
    _manager(root, ProcessBackend(crash_after_write=71)).resume(job_id)
    os._exit(199)


def _crash_after_validation_before_move(root_text: str, job_id: str) -> None:
    root = Path(root_text)
    manager = _manager(root, ProcessBackend())
    real_persist = manager.validation_receipts.persist

    def persist_then_die(*args, **kwargs):
        real_persist(*args, **kwargs)
        os._exit(72)

    manager.validation_receipts.persist = persist_then_die  # type: ignore[method-assign]
    manager.resume(job_id)
    os._exit(199)


def _crash_after_move_before_registry(root_text: str, job_id: str) -> None:
    root = Path(root_text)
    manager = _manager(root, ProcessBackend())

    def die_before_registry(*args, **kwargs):
        del args, kwargs
        os._exit(73)

    manager.files.add = die_before_registry  # type: ignore[method-assign]
    manager.resume(job_id)
    os._exit(199)


def _crash_after_registry_before_checkpoint(root_text: str, job_id: str) -> None:
    root = Path(root_text)
    manager = _manager(root, ProcessBackend())
    real_save = manager.checkpoints.save
    calls = 0

    def die_on_result_checkpoint(payload):
        nonlocal calls
        calls += 1
        if calls == 2:
            os._exit(74)
        return real_save(payload)

    manager.checkpoints.save = die_on_result_checkpoint  # type: ignore[method-assign]
    manager.resume(job_id)
    os._exit(199)


def _crash_after_result_checkpoint_before_receipt_cleanup(root_text: str, job_id: str) -> None:
    root = Path(root_text)
    manager = _manager(root, ProcessBackend())

    def die_on_receipt_clear(*args, **kwargs):
        del args, kwargs
        os._exit(75)

    manager.validation_receipts.clear = die_on_receipt_clear  # type: ignore[method-assign]
    manager.resume(job_id)
    os._exit(199)


class FinalWave51HardProcessLossTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.files, self.checkpoints = _stores(self.root)
        self.ctx = multiprocessing.get_context("fork")

    @staticmethod
    def item() -> DownloadItem:
        return DownloadItem(
            "item1",
            "1",
            1,
            "tg_1_0123456789abcdefabcd",
            "process-loss.txt",
            "text/plain",
            3,
            None,
        )

    def run_crash(self, target, job_id: str, expected_exit: int) -> None:
        process = self.ctx.Process(target=target, args=(str(self.root), job_id))
        process.start()
        process.join(10)
        if process.is_alive():
            process.terminate()
            process.join(5)
            self.fail("crash worker did not terminate")
        self.assertEqual(process.exitcode, expected_exit)

    def parent_manager(self, backend: ProcessBackend | None = None) -> tuple[DownloadManager, ProcessBackend]:
        chosen = backend or ProcessBackend()
        manager = _manager(self.root, chosen)
        return manager, chosen

    def test_hard_loss_mid_staging_releases_flock_cleans_orphan_and_redownloads(self) -> None:
        job_id = self.checkpoints.create([self.item()])
        self.run_crash(_crash_mid_staging, job_id, 71)
        staging = self.root / "tmp" / "downloads"
        self.assertEqual(len(list(staging.glob(f"{job_id}_*.part"))), 1)

        manager, backend = self.parent_manager()
        result = manager.resume(job_id)

        self.assertEqual(result["status"], "complete")
        self.assertEqual(backend.calls, 1)
        self.assertEqual(list(staging.iterdir()), [])

    def test_hard_loss_after_validation_pre_move_discards_staging_and_resumes(self) -> None:
        job_id = self.checkpoints.create([self.item()])
        self.run_crash(_crash_after_validation_before_move, job_id, 72)
        receipt_root = self.root / "state" / ".download-validations"
        self.assertEqual(len(list(receipt_root.iterdir())), 1)

        manager, backend = self.parent_manager()
        result = manager.resume(job_id)

        self.assertEqual(result["status"], "complete")
        self.assertEqual(backend.calls, 1)
        self.assertEqual(list(manager.validation_receipts.root.iterdir()), [])
        self.assertEqual(list((self.root / "tmp" / "downloads").iterdir()), [])

    def test_hard_loss_after_move_pre_registry_uses_receipt_without_redownload(self) -> None:
        item = self.item()
        job_id = self.checkpoints.create([item])
        self.run_crash(_crash_after_move_before_registry, job_id, 73)
        final = DownloadManager._final_path(_manager(self.root, ProcessBackend()), item, job_id=job_id)
        self.assertTrue(final.exists())

        manager, backend = self.parent_manager()
        result = manager.resume(job_id)

        self.assertEqual(result["status"], "complete")
        self.assertEqual(backend.calls, 0)
        stored = self.files.get(result["files"][0]["file_ref"])
        self.assertIsNotNone(stored)
        self.assertEqual(list(manager.validation_receipts.root.iterdir()), [])

    def test_hard_loss_after_registry_pre_checkpoint_has_no_duplicate_backend_or_registry(self) -> None:
        item = self.item()
        job_id = self.checkpoints.create([item])
        self.run_crash(_crash_after_registry_before_checkpoint, job_id, 74)
        origin = DownloadManager._origin_key(job_id, item.item_id)
        registered = self.files.get_by_origin(origin)
        self.assertIsNotNone(registered)

        manager, backend = self.parent_manager()
        result = manager.resume(job_id)

        self.assertEqual(result["status"], "complete")
        self.assertEqual(backend.calls, 0)
        self.assertEqual(result["files"][0]["file_ref"], registered.file_ref)
        with self.files._connect() as connection:
            count = connection.execute("SELECT COUNT(*) FROM files WHERE origin_key=?", (origin,)).fetchone()[0]
        self.assertEqual(count, 1)

    def test_hard_loss_after_result_checkpoint_cleans_stale_receipt_on_first_resume(self) -> None:
        item = self.item()
        job_id = self.checkpoints.create([item])
        self.run_crash(_crash_after_result_checkpoint_before_receipt_cleanup, job_id, 75)
        payload = self.checkpoints.load(job_id)
        self.assertIn(item.item_id, payload["results"])
        receipt_root = self.root / "state" / ".download-validations"
        self.assertEqual(len(list(receipt_root.iterdir())), 1)

        manager, backend = self.parent_manager()
        result = manager.resume(job_id)

        self.assertEqual(result["status"], "complete")
        self.assertEqual(backend.calls, 0)
        self.assertEqual(list(manager.validation_receipts.root.iterdir()), [])

    def test_hard_loss_after_move_then_same_size_corruption_is_not_adopted(self) -> None:
        item = self.item()
        job_id = self.checkpoints.create([item])
        self.run_crash(_crash_after_move_before_registry, job_id, 73)
        manager, backend = self.parent_manager()
        final = manager._final_path(item, job_id=job_id)
        final.write_bytes(b"xyz")

        first = manager.resume(job_id)

        self.assertEqual(first["status"], "failed")
        self.assertEqual(first["failures"][0]["code"], "recovered_validation_mismatch")
        self.assertTrue(first["failures"][0]["retryable"])
        self.assertEqual(backend.calls, 0)
        self.assertFalse(final.exists())
        second = manager.resume(job_id)
        self.assertEqual(second["status"], "complete")
        self.assertEqual(backend.calls, 1)


if __name__ == "__main__":
    unittest.main()
