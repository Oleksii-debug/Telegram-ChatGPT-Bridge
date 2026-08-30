from __future__ import annotations

import hashlib
import io
import tempfile
import unittest
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

from bridge.archive import ArchiveBuilder
from bridge.backend import TelethonReadBackend, TelethonReadConfig
from bridge.downloads import DownloadManager
from bridge.errors import BridgeError
from bridge.file_access import open_verified_file
from bridge.storage import CheckpointStore, DownloadItem, FileRecordStore
from bridge.upload_snapshot import UploadFileIdentity, open_verified_upload_batch


class Chat:
    def __init__(self, chat_id: int) -> None:
        self.id = chat_id
        self.title = f"chat-{chat_id}"


class FakeFile:
    def __init__(
        self,
        *,
        file_id: int,
        name: str,
        mime_type: str,
        payload: bytes,
        duration: float | None = None,
        width: int | None = None,
        height: int | None = None,
    ) -> None:
        self.id = file_id
        self.name = name
        self.mime_type = mime_type
        self.size = len(payload)
        self.duration = duration
        self.width = width
        self.height = height


class FakeMessage:
    def __init__(
        self,
        *,
        message_id: int,
        chat_id: int,
        kind: str,
        file_id: int,
        name: str,
        mime_type: str,
        payload: bytes,
        duration: float | None = None,
        width: int | None = None,
        height: int | None = None,
    ) -> None:
        self.id = message_id
        self.chat_id = chat_id
        self.peer_id = SimpleNamespace(chat_id=chat_id)
        self.message = f"{kind} fixture"
        self.date = datetime(2026, 8, 30, 9, message_id, tzinfo=timezone.utc)
        self.sender_id = 7
        self.out = False
        self.reply_to = None
        self.payload = payload
        self.media = object()
        self.file = FakeFile(
            file_id=file_id,
            name=name,
            mime_type=mime_type,
            payload=payload,
            duration=duration,
            width=width,
            height=height,
        )
        self.voice = kind == "voice"
        self.video_note = kind == "video_note"
        self.photo = SimpleNamespace(id=file_id) if kind == "photo" else None
        self.video = kind == "video"
        self.audio = kind == "audio"
        self.sticker = None
        self.document = None if kind == "photo" else SimpleNamespace(id=file_id)


class FloodWaitError(Exception):
    seconds = 1


class FakeTelegramClient:
    def __init__(self, messages: list[FakeMessage]) -> None:
        self.messages = {message.id: message for message in messages}
        self.download_calls: list[int] = []
        self.fail_once_ids: set[int] = set()
        self.failed_ids: set[int] = set()

    def get_entity(self, target: object) -> Chat:
        return Chat(int(str(target)))

    def get_messages(self, entity: Chat, ids: int) -> FakeMessage | None:
        del entity
        return self.messages.get(ids)

    def download_media(self, message: FakeMessage, file: str) -> str:
        self.download_calls.append(message.id)
        if message.id in self.fail_once_ids and message.id not in self.failed_ids:
            self.failed_ids.add(message.id)
            raise FloodWaitError()
        Path(file).write_bytes(message.payload)
        return file


class Final10MediaFilesAcceptanceTests(unittest.TestCase):
    CHAT_ID = 42

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        fixtures = [
            (1, "photo", 101, "photo.jpg", "image/jpeg", b"photo-bytes", None, 1920, 1080),
            (2, "document", 102, "notes.pdf", "application/pdf", b"document-bytes", None, None, None),
            (3, "voice", 103, "voice.ogg", "audio/ogg", b"voice-bytes", 4.25, None, None),
            (4, "audio", 104, "song.mp3", "audio/mpeg", b"audio-bytes", 12.5, None, None),
            (5, "video", 105, "clip.mp4", "video/mp4", b"video-bytes", 9.75, 1280, 720),
        ]
        self.messages = [
            FakeMessage(
                message_id=message_id,
                chat_id=self.CHAT_ID,
                kind=kind,
                file_id=file_id,
                name=name,
                mime_type=mime,
                payload=payload,
                duration=duration,
                width=width,
                height=height,
            )
            for message_id, kind, file_id, name, mime, payload, duration, width, height in fixtures
        ]
        self.client = FakeTelegramClient(self.messages)
        self.backend = TelethonReadBackend(
            client_factory=lambda: self.client,
            config=TelethonReadConfig(request_timeout_seconds=2, dialog_scan_limit=100, search_scan_limit=100),
        )
        self.files = FileRecordStore(self.root / "state" / "files.sqlite3", self.root / "private" / "files")
        self.checkpoints = CheckpointStore(self.root / "state" / "downloads.sqlite3")

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _manager(self) -> DownloadManager:
        return DownloadManager(
            backend=self.backend,
            files=self.files,
            checkpoints=self.checkpoints,
            staging_dir=self.root / "private" / "staging",
        )

    def _item(self, message: FakeMessage) -> DownloadItem:
        media = self.backend._media_records(message)[0]
        return DownloadItem(
            item_id=f"item-{message.id}",
            chat=str(self.CHAT_ID),
            message_id=message.id,
            source_file_ref=media.file_ref,
            name=media.name or f"message-{message.id}.bin",
            mime_type=media.mime_type or "application/octet-stream",
            expected_size=media.size,
        )

    def test_metadata_for_primary_media_types_is_stable_and_complete(self) -> None:
        expected = {
            "photo": ("image/jpeg", 1920, 1080, None),
            "document": ("application/pdf", None, None, None),
            "voice": ("audio/ogg", None, None, 4.25),
            "audio": ("audio/mpeg", None, None, 12.5),
            "video": ("video/mp4", 1280, 720, 9.75),
        }
        for message in self.messages:
            with self.subTest(message_id=message.id):
                first = self.backend._media_records(message)[0]
                second = TelethonReadBackend(client_factory=lambda: self.client)._media_records(message)[0]
                mime, width, height, duration = expected[first.type]
                self.assertEqual(first.file_ref, second.file_ref)
                self.assertRegex(first.file_ref, rf"^tg_{message.id}_[0-9a-f]{{20}}$")
                self.assertEqual(first.mime_type, mime)
                self.assertEqual(first.size, len(message.payload))
                self.assertEqual(first.width, width)
                self.assertEqual(first.height, height)
                self.assertEqual(first.duration_seconds, duration)

    def test_bulk_dedupe_restart_resume_hash_size_and_zip(self) -> None:
        items = [self._item(message) for message in self.messages]
        self.client.fail_once_ids.add(3)
        first = self._manager().start_bulk([*items, items[0]])
        self.assertEqual(first["status"], "partial")
        self.assertEqual(len(first["files"]), 4)
        self.assertEqual(first["pending"], 1)
        self.assertEqual(first["failures"][0]["item_id"], "item-3")
        self.assertTrue(first["failures"][0]["retryable"])

        job_id = first["job_id"]
        before_resume_calls = list(self.client.download_calls)
        second = self._manager().resume(job_id)
        self.assertEqual(second["status"], "complete")
        self.assertEqual(second["pending"], 0)
        self.assertEqual(second["failures"], [])
        self.assertEqual(len(second["files"]), 5)

        for message_id in (1, 2, 4, 5):
            self.assertEqual(self.client.download_calls.count(message_id), before_resume_calls.count(message_id))
        self.assertEqual(self.client.download_calls.count(3), 2)

        by_name = {entry["name"]: entry for entry in second["files"]}
        for message in self.messages:
            entry = by_name[message.file.name]
            self.assertEqual(entry["size"], len(message.payload))
            self.assertEqual(entry["sha256"], hashlib.sha256(message.payload).hexdigest())
            stored = self.files.get(entry["file_ref"])
            self.assertIsNotNone(stored)
            self.assertEqual(Path(stored.path).read_bytes(), message.payload)

        archive = ArchiveBuilder(files=self.files, output_dir=self.root / "private" / "archive-staging").build(
            [entry["file_ref"] for entry in second["files"]],
            archive_name="telegram-media.zip",
        )
        self.assertEqual(archive.mime_type, "application/zip")
        self.assertEqual(self.files.get(archive.file_ref).sha256, archive.sha256)
        with zipfile.ZipFile(archive.path, "r") as zf:
            self.assertEqual(len(zf.infolist()), 5)
            self.assertIsNone(zf.testzip())
            for message in self.messages:
                self.assertEqual(zf.read(message.file.name), message.payload)

    def test_private_serving_snapshot_survives_registered_inode_mutation(self) -> None:
        original = b"private-serving-original"
        source = self.files.root / "private-serving.bin"
        source.write_bytes(original)
        record = self.files.add(source, name="private-serving.bin", mime_type="application/octet-stream")

        verified = open_verified_file(self.files, record.file_ref)
        self.assertIsNotNone(verified)
        source.write_bytes(b"private-serving-mutated")
        verified.handle.seek(0)
        self.assertEqual(verified.handle.read(), original)
        self.assertEqual(verified.record.file_ref, record.file_ref)
        verified.close()
        self.assertTrue(verified.handle.closed)

    def test_private_serving_rejects_tampered_registered_bytes(self) -> None:
        original = b"private-serving-tamper"
        source = self.files.root / "private-serving-tamper.bin"
        source.write_bytes(original)
        record = self.files.add(source, name="private-serving-tamper.bin")

        replacement = b"X" * len(original)
        self.assertNotEqual(hashlib.sha256(replacement).hexdigest(), record.sha256)
        source.write_bytes(replacement)
        self.assertIsNone(open_verified_file(self.files, record.file_ref))

    def test_send_files_snapshot_is_immutable_pathless_and_identity_bound(self) -> None:
        original = b"approved-upload-bytes"
        source = self.files.root / "upload.bin"
        source.write_bytes(original)
        record = self.files.add(source, name="upload.bin", mime_type="application/octet-stream")
        identity = UploadFileIdentity(file_ref=record.file_ref, sha256=record.sha256, size=record.size)

        batch = open_verified_upload_batch(self.files, (identity,))
        self.assertIsNotNone(batch)
        upload = batch.files[0]
        self.assertEqual(upload.file_ref, record.file_ref)
        self.assertEqual(upload.sha256, record.sha256)
        self.assertEqual(upload.size, record.size)
        self.assertEqual(upload.name, "upload.bin")
        with self.assertRaises(io.UnsupportedOperation):
            upload.fileno()

        source.write_bytes(b"mutated-after-snapshot")
        upload.seek(0)
        self.assertEqual(upload.read(), original)
        batch.close()
        self.assertTrue(upload.closed)

    def test_send_files_snapshot_rejects_wrong_hash_before_effect_surface(self) -> None:
        payload = b"registered-upload"
        source = self.files.root / "wrong-hash.bin"
        source.write_bytes(payload)
        record = self.files.add(source, name="wrong-hash.bin")
        wrong = UploadFileIdentity(file_ref=record.file_ref, sha256="0" * 64, size=record.size)
        self.assertIsNone(open_verified_upload_batch(self.files, (wrong,)))
        self.assertEqual(source.read_bytes(), payload)

    def test_mismatched_file_ref_fails_before_telegram_download(self) -> None:
        message = self.messages[0]
        item = self._item(message)
        bad = DownloadItem(
            item_id="bad-ref",
            chat=item.chat,
            message_id=item.message_id,
            source_file_ref="wrong_file_reference_1234",
            name=item.name,
            mime_type=item.mime_type,
            expected_size=item.expected_size,
        )
        before = list(self.client.download_calls)
        with self.assertRaises(BridgeError) as caught:
            self._manager().start_single(bad)
        self.assertEqual(caught.exception.code, "file_not_found")
        self.assertEqual(self.client.download_calls, before)


if __name__ == "__main__":
    unittest.main()
