from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from bridge.downloads import DownloadManager
from bridge.storage import CheckpointStore, DownloadItem, FileRecordStore


class Final10MediaResidualTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.root = root
        self.files = FileRecordStore(root / "state" / "files.sqlite3", root / "files")
        self.checkpoints = CheckpointStore(root / "state" / "jobs.sqlite3")

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

    def test_backend_outside_staging_path_is_rejected_without_deleting_it(self) -> None:
        outside = self.root / "outside-owned.bin"

        class OutsideBackend:
            calls = 0

            def download_media(self, **kwargs):
                self.calls += 1
                outside.write_bytes(b"abc")
                return {"path": str(outside)}

        backend = OutsideBackend()
        manager = DownloadManager(
            backend=backend,
            files=self.files,
            checkpoints=self.checkpoints,
            staging_dir=self.root / "tmp" / "downloads",
        )
        job_id = self.checkpoints.create([self.item()])

        result = manager.resume(job_id)

        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["failures"][0]["code"], "unsafe_backend_path")
        self.assertFalse(result["failures"][0]["retryable"])
        self.assertEqual(backend.calls, 1)
        self.assertTrue(outside.exists())
        self.assertEqual(outside.read_bytes(), b"abc")


if __name__ == "__main__":
    unittest.main()
