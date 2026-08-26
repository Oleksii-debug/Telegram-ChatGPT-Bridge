from __future__ import annotations

import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from bridge.downloads import DownloadManager
from bridge.errors import BridgeError
from bridge.storage import CheckpointStore, DownloadItem, FileRecordStore


class CountingBackend:
    def __init__(self, data: bytes = b"abc") -> None:
        self.data = data
        self.calls = 0

    def download_media(self, **kwargs):
        self.calls += 1
        target = Path(kwargs["destination"])
        target.write_bytes(self.data)
        return {"path": str(target)}


class StaleOriginRecoveryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.files = FileRecordStore(root / "state" / "files.sqlite3", root / "files")
        self.checkpoints = CheckpointStore(root / "state" / "jobs.sqlite3")
        self.backend = CountingBackend()
        self.manager = DownloadManager(
            backend=self.backend,
            files=self.files,
            checkpoints=self.checkpoints,
            staging_dir=root / "tmp" / "downloads",
        )

    @staticmethod
    def item() -> DownloadItem:
        return DownloadItem(
            "item1",
            "1",
            1,
            "tg_1_0123456789abcdefabcd",
            "report.txt",
            "text/plain",
            3,
            None,
        )

    def origin_row_count(self, origin: str) -> int:
        with sqlite3.connect(str(self.files.db_path)) as connection:
            return int(
                connection.execute(
                    "SELECT COUNT(*) FROM files WHERE origin_key=?",
                    (origin,),
                ).fetchone()[0]
            )

    def test_missing_registered_origin_is_pruned_then_redownloaded_once(self) -> None:
        item = self.item()
        job_id = self.checkpoints.create([item])
        origin = self.manager._origin_key(job_id, item.item_id)
        final = self.manager._final_path(item, job_id=job_id)
        final.write_bytes(b"abc")
        stale = self.files.add(
            final,
            name=item.name,
            mime_type=item.mime_type,
            origin_key=origin,
        )
        final.unlink()

        self.assertEqual(self.origin_row_count(origin), 1)
        self.assertIsNone(self.files.get(stale.file_ref))

        result = self.manager.resume(job_id)

        self.assertEqual(result["status"], "complete")
        self.assertEqual(self.backend.calls, 1)
        self.assertEqual(self.origin_row_count(origin), 1)
        recovered = self.files.get_by_origin(origin)
        self.assertIsNotNone(recovered)
        assert recovered is not None
        self.assertNotEqual(recovered.file_ref, stale.file_ref)
        self.assertEqual(recovered.size, 3)
        self.assertNotIn("origin_key", result["files"][0])

        second = self.manager.resume(job_id)
        self.assertEqual(second["status"], "complete")
        self.assertEqual(self.backend.calls, 1)
        self.assertEqual(self.origin_row_count(origin), 1)

    def test_existing_symlink_is_not_treated_as_missing_origin(self) -> None:
        item = self.item()
        job_id = self.checkpoints.create([item])
        origin = self.manager._origin_key(job_id, item.item_id)
        final = self.manager._final_path(item, job_id=job_id)
        final.write_bytes(b"abc")
        record = self.files.add(
            final,
            name=item.name,
            mime_type=item.mime_type,
            origin_key=origin,
        )
        outside = Path(self.tmp.name) / "outside-missing.bin"
        final.unlink()
        final.symlink_to(outside)

        self.assertIsNone(self.files.get_by_origin(origin))
        self.assertEqual(self.origin_row_count(origin), 1)
        with sqlite3.connect(str(self.files.db_path)) as connection:
            row = connection.execute(
                "SELECT file_ref FROM files WHERE origin_key=?",
                (origin,),
            ).fetchone()
        self.assertEqual(row[0], record.file_ref)

    def test_dangling_symlink_stale_origin_fails_before_backend_download(self) -> None:
        item = self.item()
        job_id = self.checkpoints.create([item])
        origin = self.manager._origin_key(job_id, item.item_id)
        final = self.manager._final_path(item, job_id=job_id)
        final.write_bytes(b"abc")
        self.files.add(
            final,
            name=item.name,
            mime_type=item.mime_type,
            origin_key=origin,
        )
        final.unlink()
        final.symlink_to(Path(self.tmp.name) / "missing-target.bin")

        result = self.manager.resume(job_id)

        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["failures"][0]["code"], "unsafe_recovered_file")
        self.assertFalse(result["failures"][0]["retryable"])
        self.assertEqual(self.backend.calls, 0)
        self.assertEqual(self.origin_row_count(origin), 1)
        self.assertTrue(os.path.lexists(final))

    def test_unknown_final_leaf_error_fails_before_backend_download(self) -> None:
        item = self.item()
        job_id = self.checkpoints.create([item])
        final = self.manager._final_path(item, job_id=job_id)
        real_lstat = os.lstat

        def guarded_lstat(path, *args, **kwargs):
            if Path(path) == final:
                raise PermissionError("simulated filesystem uncertainty")
            return real_lstat(path, *args, **kwargs)

        with patch("bridge.downloads.os.lstat", side_effect=guarded_lstat):
            result = self.manager.resume(job_id)

        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["failures"][0]["code"], "unsafe_recovered_file")
        self.assertFalse(result["failures"][0]["retryable"])
        self.assertEqual(self.backend.calls, 0)

    def test_nested_or_corrupt_origin_path_is_never_self_healed(self) -> None:
        item = self.item()
        job_id = self.checkpoints.create([item])
        origin = self.manager._origin_key(job_id, item.item_id)
        final = self.manager._final_path(item, job_id=job_id)
        final.write_bytes(b"abc")
        record = self.files.add(
            final,
            name=item.name,
            mime_type=item.mime_type,
            origin_key=origin,
        )
        final.unlink()
        with sqlite3.connect(str(self.files.db_path)) as connection:
            connection.execute(
                "UPDATE files SET rel_path=? WHERE file_ref=?",
                ("nested/missing.bin", record.file_ref),
            )
            connection.commit()

        self.assertIsNone(self.files.get_by_origin(origin))
        self.assertEqual(self.origin_row_count(origin), 1)

    def test_registry_collision_is_nonretryable_and_not_redownloaded(self) -> None:
        job_id = self.checkpoints.create([self.item()])
        collision = BridgeError(
            "Private file registry collision",
            status=409,
            code="file_registry_collision",
        )
        with patch.object(self.files, "add", side_effect=collision):
            first = self.manager.resume(job_id)

        self.assertEqual(first["status"], "failed")
        self.assertEqual(first["failures"][0]["code"], "file_registry_collision")
        self.assertFalse(first["failures"][0]["retryable"])
        self.assertEqual(self.backend.calls, 1)

        second = self.manager.resume(job_id)
        self.assertEqual(second["status"], "failed")
        self.assertEqual(self.backend.calls, 1)

    def test_backend_outside_staging_path_is_rejected_without_deleting_it(self) -> None:
        outside = Path(self.tmp.name) / "outside-owned.bin"

        class OutsideBackend:
            calls = 0

            def download_media(self, **kwargs):
                self.calls += 1
                outside.write_bytes(b"abc")
                return {"path": str(outside)}

        backend = OutsideBackend()
        self.manager.backend = backend
        job_id = self.checkpoints.create([self.item()])

        result = self.manager.resume(job_id)

        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["failures"][0]["code"], "unsafe_backend_path")
        self.assertFalse(result["failures"][0]["retryable"])
        self.assertEqual(backend.calls, 1)
        self.assertTrue(outside.exists())
        self.assertEqual(outside.read_bytes(), b"abc")

    def test_post_validation_replacement_is_not_registered(self) -> None:
        item = self.item()
        job_id = self.checkpoints.create([item])
        origin = self.manager._origin_key(job_id, item.item_id)
        final = self.manager._final_path(item, job_id=job_id)
        original_add = self.files.add

        def replace_before_registration(path, **kwargs):
            if Path(path) == final:
                Path(path).write_bytes(b"xyz")
            return original_add(path, **kwargs)

        with patch.object(self.files, "add", side_effect=replace_before_registration):
            result = self.manager.resume(job_id)

        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["failures"][0]["code"], "download_result_changed")
        self.assertFalse(result["failures"][0]["retryable"])
        self.assertEqual(self.backend.calls, 1)
        self.assertEqual(self.origin_row_count(origin), 0)
        self.assertFalse(os.path.lexists(final))


if __name__ == "__main__":
    unittest.main()
