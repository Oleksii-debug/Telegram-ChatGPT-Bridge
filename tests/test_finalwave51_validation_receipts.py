from __future__ import annotations

import hashlib
import os
import tempfile
import unittest
from pathlib import Path

from bridge.download_validation import DownloadValidationReceipts
from bridge.downloads import DownloadManager
from bridge.errors import BridgeError
from bridge.storage import CheckpointStore, DownloadItem, FileRecordStore


class ReceiptBackend:
    def __init__(self, data: bytes = b"abc") -> None:
        self.data = data
        self.calls = 0

    def download_media(self, **kwargs):
        self.calls += 1
        target = Path(kwargs["destination"])
        target.write_bytes(self.data)
        return {"path": str(target)}


class FinalWave51ValidationReceiptTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.files = FileRecordStore(self.root / "state" / "files.sqlite3", self.root / "files")
        self.checkpoints = CheckpointStore(self.root / "state" / "jobs.sqlite3")
        self.backend = ReceiptBackend()
        self.manager = DownloadManager(
            backend=self.backend,
            files=self.files,
            checkpoints=self.checkpoints,
            staging_dir=self.root / "tmp" / "downloads",
        )

    @staticmethod
    def item() -> DownloadItem:
        return DownloadItem(
            "item1",
            "1",
            1,
            "tg_1_0123456789abcdefabcd",
            "receipt.txt",
            "text/plain",
            3,
            None,
        )

    def test_normal_download_clears_receipt_only_after_checkpoint_outcome(self) -> None:
        result = self.manager.start_bulk([self.item()])

        self.assertEqual(result["status"], "complete")
        self.assertEqual(self.backend.calls, 1)
        self.assertEqual(list(self.manager.validation_receipts.root.iterdir()), [])

    def test_exact_validated_move_before_registry_recovers_without_backend(self) -> None:
        item = self.item()
        job_id = self.checkpoints.create([item])
        digest = hashlib.sha256(b"abc").hexdigest()
        self.manager.validation_receipts.persist(
            job_id,
            item.item_id,
            size=3,
            sha256=digest,
        )
        final = self.manager._final_path(item, job_id=job_id)
        final.write_bytes(b"abc")

        result = self.manager.resume(job_id)

        self.assertEqual(result["status"], "complete")
        self.assertEqual(self.backend.calls, 0)
        self.assertEqual(list(self.manager.validation_receipts.root.iterdir()), [])

    def test_same_size_corrupt_move_before_registry_is_removed_and_retryable(self) -> None:
        item = self.item()
        job_id = self.checkpoints.create([item])
        digest = hashlib.sha256(b"abc").hexdigest()
        self.manager.validation_receipts.persist(
            job_id,
            item.item_id,
            size=3,
            sha256=digest,
        )
        final = self.manager._final_path(item, job_id=job_id)
        final.write_bytes(b"xyz")

        first = self.manager.resume(job_id)

        self.assertEqual(first["status"], "failed")
        self.assertEqual(first["failures"][0]["code"], "recovered_validation_mismatch")
        self.assertTrue(first["failures"][0]["retryable"])
        self.assertEqual(self.backend.calls, 0)
        self.assertFalse(final.exists())
        self.assertEqual(list(self.manager.validation_receipts.root.iterdir()), [])

        second = self.manager.resume(job_id)
        self.assertEqual(second["status"], "complete")
        self.assertEqual(self.backend.calls, 1)

    def test_registered_result_and_receipt_mismatch_is_removed_before_redownload(self) -> None:
        item = self.item()
        job_id = self.checkpoints.create([item])
        final = self.manager._final_path(item, job_id=job_id)
        final.write_bytes(b"xyz")
        origin = self.manager._origin_key(job_id, item.item_id)
        record = self.files.add(final, name=item.name, mime_type=item.mime_type, origin_key=origin)
        self.manager.validation_receipts.persist(
            job_id,
            item.item_id,
            size=3,
            sha256=hashlib.sha256(b"abc").hexdigest(),
        )

        first = self.manager.resume(job_id)

        self.assertEqual(first["status"], "failed")
        self.assertEqual(first["failures"][0]["code"], "recovered_validation_mismatch")
        self.assertIsNone(self.files.get(record.file_ref))
        self.assertFalse(final.exists())
        self.assertEqual(self.backend.calls, 0)
        self.assertEqual(self.manager.resume(job_id)["status"], "complete")
        self.assertEqual(self.backend.calls, 1)

    def test_validation_receipt_root_symlink_is_rejected_without_touching_target(self) -> None:
        parent = self.root / "receipt-root-test"
        parent.mkdir()
        outside = self.root / "outside-receipts"
        outside.mkdir()
        link = parent / "receipts"
        link.symlink_to(outside, target_is_directory=True)

        with self.assertRaises(BridgeError) as caught:
            DownloadValidationReceipts(link)

        self.assertEqual(caught.exception.code, "validation_receipt_unsafe")
        self.assertTrue(outside.is_dir())
        self.assertEqual(list(outside.iterdir()), [])

    def test_broad_or_hardlinked_receipt_fails_closed(self) -> None:
        store = DownloadValidationReceipts(self.root / "receipt-hardening")
        job_id = "A" * 18
        item_id = "item1"
        digest = hashlib.sha256(b"abc").hexdigest()
        store.persist(job_id, item_id, size=3, sha256=digest)
        path = store._path(job_id, item_id)

        os.chmod(path, 0o644)
        with self.assertRaises(BridgeError) as broad:
            store.load(job_id, item_id)
        self.assertEqual(broad.exception.code, "validation_receipt_unsafe")

        os.chmod(path, 0o600)
        peer = self.root / "receipt-peer"
        os.link(path, peer)
        with self.assertRaises(BridgeError) as linked:
            store.load(job_id, item_id)
        self.assertEqual(linked.exception.code, "validation_receipt_unsafe")
        self.assertTrue(peer.exists())

    def test_receipt_contains_only_version_size_and_digest(self) -> None:
        store = DownloadValidationReceipts(self.root / "receipt-shape")
        digest = hashlib.sha256(b"abc").hexdigest()
        store.persist("A" * 18, "item1", size=3, sha256=digest)
        receipt = next(store.root.iterdir()).read_text(encoding="ascii")
        self.assertEqual(receipt, f"v1 3 {digest}\n")
        self.assertNotIn("item1", receipt)
        self.assertNotIn("A" * 18, receipt)


if __name__ == "__main__":
    unittest.main()
