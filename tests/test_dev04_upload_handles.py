from __future__ import annotations

import io
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from bridge.file_access import (
    UploadFileIdentity,
    VerifiedUploadFile,
    open_verified_file,
    open_verified_upload_batch,
)
from bridge.storage import FileRecordStore


class VerifiedUploadHandleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.store = FileRecordStore(root / "state" / "files.sqlite3", root / "files")

    def add(
        self,
        data: bytes,
        *,
        physical_name: str,
        display_name: str | None = None,
    ):
        path = self.store.root / physical_name
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.parent != self.store.root:
            os.chmod(path.parent, 0o700)
        path.write_bytes(data)
        record = self.store.add(
            path,
            name=display_name if display_name is not None else physical_name,
            mime_type="application/octet-stream",
        )
        return record, path

    @staticmethod
    def identity(record) -> UploadFileIdentity:
        return UploadFileIdentity(record.file_ref, record.sha256, record.size)

    def test_exact_identity_yields_standard_read_only_path_free_stream(self) -> None:
        record, _ = self.add(
            b"abc",
            physical_name="stored.bin",
            display_name="../CON\u202e.txt",
        )
        batch = open_verified_upload_batch(self.store, [self.identity(record)])
        self.assertIsNotNone(batch)
        assert batch is not None
        try:
            upload = batch[0]
            self.assertIsInstance(upload, VerifiedUploadFile)
            self.assertIsInstance(upload, io.IOBase)
            self.assertEqual(upload.read(), b"abc")
            self.assertEqual(upload.seek(0), 0)
            self.assertEqual(upload.tell(), 0)
            self.assertTrue(upload.readable())
            self.assertTrue(upload.seekable())
            self.assertFalse(upload.writable())
            with self.assertRaises((io.UnsupportedOperation, AttributeError)):
                upload.write(b"x")
            self.assertEqual(upload.file_ref, record.file_ref)
            self.assertEqual(upload.sha256, record.sha256)
            self.assertEqual(upload.size, 3)
            self.assertNotIn("/", upload.name)
            self.assertNotIn("\\", upload.name)
            self.assertNotIn("\u202e", upload.name)
            self.assertFalse(hasattr(upload, "path"))
            self.assertFalse(hasattr(upload, "record"))
            self.assertNotIn(str(self.store.root), upload.name)
        finally:
            batch.close()
        self.assertTrue(upload.closed)

    def test_pinned_upload_reads_original_inode_after_path_replacement(self) -> None:
        record, path = self.add(b"ORIGINAL", physical_name="payload.bin")
        batch = open_verified_upload_batch(self.store, [self.identity(record)])
        self.assertIsNotNone(batch)
        assert batch is not None
        try:
            path.unlink()
            path.write_bytes(b"REPLACED")
            upload = batch[0]
            upload.seek(0)
            self.assertEqual(upload.read(), b"ORIGINAL")
        finally:
            batch.close()

    def test_identity_mismatch_closes_verified_handle_before_return(self) -> None:
        record, _ = self.add(b"abc", physical_name="one.bin")
        captured = []
        original = open_verified_file

        def capture(store, ref):
            verified = original(store, ref)
            if verified is not None:
                captured.append(verified)
            return verified

        bad = UploadFileIdentity(record.file_ref, "0" * 64, record.size)
        with patch("bridge.file_access.open_verified_file", side_effect=capture):
            self.assertIsNone(open_verified_upload_batch(self.store, [bad]))
        self.assertEqual(len(captured), 1)
        self.assertTrue(captured[0].handle.closed)

    def test_partial_batch_failure_closes_earlier_handles(self) -> None:
        first, _ = self.add(b"first", physical_name="one.bin")
        second, second_path = self.add(b"second", physical_name="two.bin")
        outside = Path(self.tmp.name) / "outside.bin"
        outside.write_bytes(b"second")
        second_path.unlink()
        second_path.symlink_to(outside)

        captured = []
        original = open_verified_file

        def capture(store, ref):
            verified = original(store, ref)
            if verified is not None:
                captured.append(verified)
            return verified

        with patch("bridge.file_access.open_verified_file", side_effect=capture):
            result = open_verified_upload_batch(
                self.store,
                [self.identity(first), self.identity(second)],
            )
        self.assertIsNone(result)
        self.assertEqual(len(captured), 1)
        self.assertTrue(captured[0].handle.closed)

    def test_batch_context_closes_all_handles_on_consumer_exception(self) -> None:
        first, _ = self.add(b"first", physical_name="one.bin")
        second, _ = self.add(b"second", physical_name="two.bin")
        batch = open_verified_upload_batch(
            self.store,
            [self.identity(first), self.identity(second)],
        )
        self.assertIsNotNone(batch)
        assert batch is not None
        uploads = batch.files
        with self.assertRaisesRegex(RuntimeError, "consumer failed"):
            with batch:
                raise RuntimeError("consumer failed")
        self.assertTrue(batch.closed)
        self.assertTrue(all(upload.closed for upload in uploads))

    def test_duplicate_reference_is_rejected_before_open(self) -> None:
        record, _ = self.add(b"abc", physical_name="one.bin")
        identity = self.identity(record)
        with patch("bridge.file_access.open_verified_file") as opener:
            with self.assertRaisesRegex(ValueError, "duplicate"):
                open_verified_upload_batch(self.store, [identity, identity])
        opener.assert_not_called()

    def test_invalid_identity_and_file_count_fail_before_open(self) -> None:
        record, _ = self.add(b"abc", physical_name="one.bin")
        with patch("bridge.file_access.open_verified_file") as opener:
            with self.assertRaises(ValueError):
                open_verified_upload_batch(self.store, [])
            with self.assertRaises(ValueError):
                open_verified_upload_batch(self.store, [object()])  # type: ignore[list-item]
            with self.assertRaises(ValueError):
                open_verified_upload_batch(self.store, [self.identity(record)], max_files=0)
        opener.assert_not_called()

    def test_fake_external_consumer_receives_pinned_objects_not_paths(self) -> None:
        first, first_path = self.add(b"alpha", physical_name="one.bin")
        second, second_path = self.add(b"beta", physical_name="two.bin")
        batch = open_verified_upload_batch(
            self.store,
            [self.identity(first), self.identity(second)],
        )
        self.assertIsNotNone(batch)
        assert batch is not None

        first_path.unlink()
        first_path.write_bytes(b"MUTATED_ALPHA")
        second_path.unlink()
        second_path.write_bytes(b"MUTATED_BETA")

        def fake_send_file(files):
            payloads = []
            names = []
            for item in files:
                self.assertIsInstance(item, VerifiedUploadFile)
                self.assertIsInstance(item, io.IOBase)
                item.seek(0)
                payloads.append(item.read())
                names.append(item.name)
            return payloads, names

        try:
            payloads, names = fake_send_file(batch.files)
            self.assertEqual(payloads, [b"alpha", b"beta"])
            self.assertEqual(names, ["one.bin", "two.bin"])
        finally:
            batch.close()


if __name__ == "__main__":
    unittest.main()
