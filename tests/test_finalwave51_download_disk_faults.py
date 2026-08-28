from __future__ import annotations

import hashlib
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from bridge.downloads import DownloadManager
from bridge.storage import CheckpointStore, DownloadItem, FileRecordStore


class DiskFaultBackend:
    def __init__(self, data: bytes = b"abc") -> None:
        self.data = data
        self.calls = 0

    def download_media(self, **kwargs):
        self.calls += 1
        target = Path(kwargs["destination"])
        target.write_bytes(self.data)
        return {"path": str(target)}


class FinalWave51DownloadDiskFaultTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.files = FileRecordStore(self.root / "state" / "files.sqlite3", self.root / "files")
        self.checkpoints = CheckpointStore(self.root / "state" / "jobs.sqlite3")
        self.backend = DiskFaultBackend()
        self.staging = self.root / "tmp" / "downloads"
        self.manager = DownloadManager(
            backend=self.backend,
            files=self.files,
            checkpoints=self.checkpoints,
            staging_dir=self.staging,
        )

    @staticmethod
    def item(
        *,
        expected_size: int | None = 3,
        expected_sha256: str | None = None,
    ) -> DownloadItem:
        return DownloadItem(
            "item1",
            "1",
            1,
            "tg_1_0123456789abcdefabcd",
            "report.txt",
            "text/plain",
            expected_size,
            expected_sha256,
        )

    def assert_no_registered_files(self) -> None:
        with sqlite3.connect(str(self.files.db_path)) as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM files").fetchone()[0], 0)

    def test_bytes_pre_validation_failure_cleans_staging_and_private_final(self) -> None:
        result = self.manager.start_bulk([self.item(expected_size=4)])

        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["failures"][0]["code"], "file_size_mismatch")
        self.assertFalse(result["failures"][0]["retryable"])
        self.assertEqual(self.backend.calls, 1)
        self.assertEqual(list(self.staging.iterdir()), [])
        self.assertEqual(list(self.files.root.iterdir()), [])
        self.assert_no_registered_files()

    def test_hash_read_disk_error_cleans_stage_and_retry_redownloads_once(self) -> None:
        job_id = self.checkpoints.create([self.item()])

        with patch("bridge.downloads._sha256", side_effect=OSError("synthetic hash read fault")):
            with self.assertRaises(OSError):
                self.manager.resume(job_id)

        self.assertEqual(self.backend.calls, 1)
        self.assertEqual(list(self.staging.iterdir()), [])
        self.assertEqual(list(self.files.root.iterdir()), [])
        self.assertEqual(self.checkpoints.load(job_id)["status"], "running")
        self.assertEqual(self.manager.resume(job_id)["status"], "complete")
        self.assertEqual(self.backend.calls, 2)

    def test_validation_pre_move_disk_error_cleans_and_retry_is_safe(self) -> None:
        job_id = self.checkpoints.create([self.item()])

        with patch.object(Path, "replace", side_effect=OSError("synthetic move fault")):
            with self.assertRaises(OSError):
                self.manager.resume(job_id)

        self.assertEqual(self.backend.calls, 1)
        self.assertEqual(list(self.staging.iterdir()), [])
        self.assertEqual(list(self.files.root.iterdir()), [])
        self.assert_no_registered_files()
        self.assertEqual(self.checkpoints.load(job_id)["status"], "running")
        self.assertEqual(self.manager.resume(job_id)["status"], "complete")
        self.assertEqual(self.backend.calls, 2)

    def test_registry_disk_error_after_move_cleans_final_and_retry_is_safe(self) -> None:
        job_id = self.checkpoints.create([self.item()])

        with patch.object(self.files, "add", side_effect=OSError("synthetic registry fault")):
            with self.assertRaises(OSError):
                self.manager.resume(job_id)

        self.assertEqual(self.backend.calls, 1)
        self.assertEqual(list(self.staging.iterdir()), [])
        self.assertEqual(list(self.files.root.iterdir()), [])
        self.assert_no_registered_files()
        self.assertEqual(self.checkpoints.load(job_id)["status"], "running")
        self.assertEqual(self.manager.resume(job_id)["status"], "complete")
        self.assertEqual(self.backend.calls, 2)

    def test_same_size_tamper_after_validation_before_move_is_never_served(self) -> None:
        expected = hashlib.sha256(b"abc").hexdigest()
        item = self.item(expected_sha256=expected)
        real_replace = Path.replace

        def tamper_then_replace(source: Path, target: Path):
            source.write_bytes(b"xyz")
            return real_replace(source, target)

        with patch.object(Path, "replace", new=tamper_then_replace):
            result = self.manager.start_bulk([item])

        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["failures"][0]["code"], "download_result_changed")
        self.assertFalse(result["failures"][0]["retryable"])
        self.assertEqual(self.backend.calls, 1)
        self.assertEqual(list(self.staging.iterdir()), [])
        self.assertEqual(list(self.files.root.iterdir()), [])
        self.assert_no_registered_files()


if __name__ == "__main__":
    unittest.main()
