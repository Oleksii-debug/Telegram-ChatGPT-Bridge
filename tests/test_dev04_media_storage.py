from __future__ import annotations

import fcntl
import os
import sqlite3
import tempfile
import unicodedata
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from bridge.archive import ArchiveBuilder
from bridge.downloads import DownloadManager
from bridge.errors import BridgeError
from bridge.filenames import filename_collision_key, safe_filename
from bridge.storage import CheckpointStore, DownloadItem, FileRecordStore


class FakeBackend:
    def __init__(self, *, data: bytes = b"abc", fail_first: bool = False) -> None:
        self.data = data
        self.fail_first = fail_first
        self.calls = 0

    def download_media(self, **kwargs):
        self.calls += 1
        if self.fail_first and self.calls == 1:
            raise BridgeError("temporary", status=502, code="telegram_rpc_error")
        target = Path(kwargs["destination"])
        target.write_bytes(self.data)
        return {"path": str(target)}


class Dev04DownloadHardeningTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.files = FileRecordStore(root / "state" / "files.sqlite3", root / "files")
        self.checkpoints = CheckpointStore(root / "state" / "jobs.sqlite3")
        self.backend = FakeBackend()
        self.manager = DownloadManager(
            backend=self.backend,
            files=self.files,
            checkpoints=self.checkpoints,
            staging_dir=root / "tmp" / "downloads",
        )

    @staticmethod
    def item(*, expected_size: int | None = 3) -> DownloadItem:
        return DownloadItem(
            "item1",
            "1",
            1,
            "tg_1_0123456789abcdefabcd",
            "report.txt",
            "text/plain",
            expected_size,
            None,
        )

    def test_nonretryable_integrity_failure_is_not_redownloaded_on_resume(self) -> None:
        job_id = self.checkpoints.create([self.item(expected_size=4)])
        first = self.manager.resume(job_id)
        self.assertEqual(first["status"], "failed")
        self.assertEqual(first["failures"][0]["code"], "file_size_mismatch")
        self.assertFalse(first["failures"][0]["retryable"])
        self.assertEqual(self.backend.calls, 1)
        second = self.manager.resume(job_id)
        self.assertEqual(second["status"], "failed")
        self.assertEqual(self.backend.calls, 1)

    def test_transient_backend_failure_remains_retryable(self) -> None:
        backend = FakeBackend(fail_first=True)
        manager = DownloadManager(
            backend=backend,
            files=self.files,
            checkpoints=self.checkpoints,
            staging_dir=Path(self.tmp.name) / "tmp" / "retry",
        )
        job_id = self.checkpoints.create([self.item()])
        first = manager.resume(job_id)
        self.assertTrue(first["failures"][0]["retryable"])
        second = manager.resume(job_id)
        self.assertEqual(second["status"], "complete")
        self.assertEqual(backend.calls, 2)

    def test_registration_failure_does_not_leave_orphan_private_file(self) -> None:
        with patch.object(
            self.files,
            "add",
            side_effect=BridgeError("registry unavailable", status=503, code="registry_unavailable"),
        ):
            result = self.manager.start_bulk([self.item()])
        self.assertEqual(result["status"], "failed")
        self.assertEqual(list(self.files.root.iterdir()), [])

    def test_registered_result_is_recovered_after_checkpoint_save_gap(self) -> None:
        item = self.item()
        job_id = self.checkpoints.create([item])
        final = self.manager._final_path(item, job_id=job_id)
        final.write_bytes(b"abc")
        origin = self.manager._origin_key(job_id, item.item_id)
        registered = self.files.add(final, name=item.name, mime_type=item.mime_type, origin_key=origin)

        result = self.manager.resume(job_id)

        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["files"][0]["file_ref"], registered.file_ref)
        self.assertNotIn("origin_key", result["files"][0])
        self.assertEqual(self.backend.calls, 0)

    def test_moved_unregistered_result_is_adopted_after_crash_gap(self) -> None:
        item = self.item()
        job_id = self.checkpoints.create([item])
        final = self.manager._final_path(item, job_id=job_id)
        final.write_bytes(b"abc")

        result = self.manager.resume(job_id)

        self.assertEqual(result["status"], "complete")
        self.assertEqual(self.backend.calls, 0)
        stored = self.files.get(result["files"][0]["file_ref"])
        self.assertIsNotNone(stored)
        self.assertEqual(stored.origin_key, self.manager._origin_key(job_id, item.item_id))
        self.assertNotIn("origin_key", stored.public_metadata())

    def test_legacy_file_registry_schema_is_migrated_in_place(self) -> None:
        root = Path(self.tmp.name) / "legacy"
        db = root / "state" / "files.sqlite3"
        db.parent.mkdir(parents=True)
        with sqlite3.connect(str(db)) as connection:
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
        FileRecordStore(db, root / "files")
        with sqlite3.connect(str(db)) as connection:
            columns = {str(row[1]) for row in connection.execute("PRAGMA table_info(files)")}
            indexes = {str(row[1]) for row in connection.execute("PRAGMA index_list(files)")}
        self.assertIn("origin_key", columns)
        self.assertIn("files_origin_key_unique", indexes)


class Dev04FilenamePolicyTests(unittest.TestCase):
    def test_unicode_is_normalized_to_nfc(self) -> None:
        decomposed = "Cafe\u0301.txt"
        result = safe_filename(decomposed)
        self.assertEqual(result, unicodedata.normalize("NFC", decomposed))
        self.assertEqual(unicodedata.normalize("NFC", result), result)

    def test_windows_reserved_device_name_is_neutralized(self) -> None:
        self.assertEqual(safe_filename("CON.txt"), "_CON.txt")
        self.assertEqual(safe_filename("lpt9"), "_lpt9")

    def test_bidi_override_is_not_preserved(self) -> None:
        result = safe_filename("safe\u202etxt.exe")
        self.assertNotIn("\u202e", result)

    def test_collision_key_equates_composed_and_decomposed_unicode(self) -> None:
        self.assertEqual(filename_collision_key("é.txt"), filename_collision_key("e\u0301.txt"))


class Dev04ArchiveHardeningTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.store = FileRecordStore(root / "state" / "files.sqlite3", root / "files")
        self.builder = ArchiveBuilder(files=self.store, output_dir=root / "tmp" / "archives")

    def add(self, name: str, data: bytes = b"abc"):
        path = self.store.root / f"source-{len(list(self.store.root.iterdir()))}.bin"
        path.write_bytes(data)
        return self.store.add(path, name=name)

    def test_same_size_source_tamper_between_lookup_and_open_fails_closed(self) -> None:
        record = self.add("one.txt", b"abc")
        original_get = self.store.get

        def tampering_get(file_ref: str):
            found = original_get(file_ref)
            assert found is not None
            Path(found.path).write_bytes(b"xyz")
            return found

        with patch.object(self.store, "get", side_effect=tampering_get):
            with self.assertRaises(BridgeError) as caught:
                self.builder.build([record.file_ref])
        self.assertEqual(caught.exception.code, "archive_source_changed")

    def test_symlink_swap_between_lookup_and_open_fails_closed(self) -> None:
        record = self.add("one.txt", b"abc")
        outside = Path(self.tmp.name) / "outside.bin"
        outside.write_bytes(b"abc")
        original_get = self.store.get

        def swapping_get(file_ref: str):
            found = original_get(file_ref)
            assert found is not None
            source = Path(found.path)
            source.unlink()
            source.symlink_to(outside)
            return found

        with patch.object(self.store, "get", side_effect=swapping_get):
            with self.assertRaises(BridgeError) as caught:
                self.builder.build([record.file_ref])
        self.assertEqual(caught.exception.code, "archive_source_changed")

    def test_archive_registration_failure_cleans_unregistered_final_file(self) -> None:
        source = self.add("one.txt", b"abc")
        before = {path.name for path in self.store.root.iterdir()}
        with patch.object(
            self.store,
            "add",
            side_effect=BridgeError("registry unavailable", status=503, code="registry_unavailable"),
        ):
            with self.assertRaises(BridgeError):
                self.builder.build([source.file_ref])
        after = {path.name for path in self.store.root.iterdir()}
        self.assertEqual(after, before)

    def test_process_loss_marker_cleans_part_and_unregistered_final(self) -> None:
        source = self.add("one.txt", b"abc")
        token = "a" * 40
        marker = self.builder._create_pending_marker(token)
        target = self.builder.output_dir / f"archive_{token}.zip.part"
        final = self.store.root / f".archive_{token}.zip"
        target.write_bytes(b"partial")
        final.write_bytes(b"orphan")

        archive = self.builder.build([source.file_ref])

        self.assertIsNotNone(self.store.get(archive.file_ref))
        self.assertFalse(marker.exists())
        self.assertFalse(target.exists())
        self.assertFalse(final.exists())

    def test_process_loss_marker_preserves_already_registered_final(self) -> None:
        token = "b" * 40
        marker = self.builder._create_pending_marker(token)
        final = self.store.root / f".archive_{token}.zip"
        final.write_bytes(b"registered")
        previous = self.store.add(final, name="previous.zip", mime_type="application/zip")
        source = self.add("one.txt", b"abc")

        self.builder.build([source.file_ref])

        self.assertFalse(marker.exists())
        recovered = self.store.get(previous.file_ref)
        self.assertIsNotNone(recovered)
        assert recovered is not None
        self.assertEqual(Path(recovered.path).read_bytes(), b"registered")

    def test_unsafe_pending_marker_fails_closed_without_following_symlink(self) -> None:
        token = "c" * 40
        outside = Path(self.tmp.name) / "outside-marker-target"
        outside.write_bytes(b"do-not-delete")
        marker = self.builder.output_dir / f".archive_{token}.pending"
        marker.symlink_to(outside)
        source = self.add("one.txt", b"abc")

        with self.assertRaises(BridgeError) as caught:
            self.builder.build([source.file_ref])

        self.assertEqual(caught.exception.code, "archive_recovery_unsafe")
        self.assertTrue(outside.exists())
        self.assertEqual(outside.read_bytes(), b"do-not-delete")
        self.assertTrue(os.path.lexists(marker))

    def test_archive_lock_contention_is_retryable_and_has_no_side_effect(self) -> None:
        source = self.add("one.txt", b"abc")
        flags = os.O_CREAT | os.O_RDWR
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(self.builder.lock_path, flags, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaises(BridgeError) as caught:
                self.builder.build([source.file_ref])
            self.assertEqual(caught.exception.code, "archive_busy")
            self.assertTrue(caught.exception.details.get("retryable"))
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def test_unicode_equivalent_member_names_are_disambiguated(self) -> None:
        first = self.add("é.txt", b"a")
        second = self.add("e\u0301.txt", b"b")
        archive = self.builder.build([first.file_ref, second.file_ref])
        with zipfile.ZipFile(archive.path) as zipped:
            names = zipped.namelist()
        self.assertEqual(len(names), 2)
        self.assertEqual(len({filename_collision_key(name) for name in names}), 2)

    def test_windows_reserved_archive_member_is_neutralized(self) -> None:
        source = self.add("CON.txt", b"a")
        archive = self.builder.build([source.file_ref])
        with zipfile.ZipFile(archive.path) as zipped:
            self.assertEqual(zipped.namelist(), ["_CON.txt"])


if __name__ == "__main__":
    unittest.main()
