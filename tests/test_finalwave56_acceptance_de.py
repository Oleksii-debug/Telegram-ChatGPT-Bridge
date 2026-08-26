from __future__ import annotations

import hashlib
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import bridge.file_access as file_access
from bridge.backend import TelethonReadBackend, TelethonReadConfig
from bridge.downloads import DownloadManager
from bridge.errors import BridgeError
from bridge.storage import CheckpointStore, DownloadItem, FileRecordStore
from bridge.validation import DateRange


class User:
    def __init__(self, user_id: int, username: str = "reader") -> None:
        self.id = user_id
        self.username = username
        self.first_name = "Reader"
        self.last_name = ""


class Message:
    def __init__(self, message_id: int, *, sender_id: int = 42, text: str = "needle") -> None:
        self.id = message_id
        self.sender_id = sender_id
        self.date = datetime(2026, 8, 26, 8, 0, tzinfo=timezone.utc) + timedelta(seconds=message_id)
        self.message = text
        self.out = False
        self.reply_to = None
        self.media = None
        self.file = None
        self.voice = None
        self.video_note = None
        self.photo = None
        self.video = None
        self.audio = None
        self.sticker = None

    async def get_sender(self) -> User:
        return User(self.sender_id)


class Dialog:
    def __init__(self, dialog_id: int) -> None:
        self.entity = SimpleNamespace(id=dialog_id, title=f"Dialog {dialog_id}", username=None)
        self.message = SimpleNamespace(
            date=datetime(2026, 8, 26, 8, 0, tzinfo=timezone.utc) + timedelta(seconds=dialog_id)
        )
        self.unread_count = 0
        self.pinned = False


class StrictReadClient:
    """Telethon-like fake that rejects invalid global searches and bounds server windows."""

    def __init__(self) -> None:
        self.messages = [Message(i) for i in range(8, 0, -1)]
        self.dialogs = [Dialog(i) for i in range(5, 0, -1)]
        self.global_calls: list[dict[str, object]] = []

    async def connect(self) -> None:
        return None

    async def is_user_authorized(self) -> bool:
        return True

    async def disconnect(self) -> None:
        return None

    async def get_entity(self, target):  # type: ignore[no-untyped-def]
        if str(target).lstrip("-").isdigit():
            return SimpleNamespace(id=int(target), title="chat")
        if str(target).lstrip("@").casefold() == "reader":
            return User(42, "reader")
        raise ValueError("not found")

    def iter_dialogs(self, limit: int):
        return self.dialogs[:limit]

    def iter_messages(
        self,
        entity,
        limit: int,
        *,
        search: str = "",
        from_user=None,
        offset_id: int = 0,
    ):  # type: ignore[no-untyped-def]
        self.global_calls.append(
            {"entity": entity, "limit": limit, "search": search, "from_user": from_user, "offset_id": offset_id}
        )
        if entity is None and not search and from_user is None:
            raise ValueError("global search requires search/filter/from_user")
        rows = self.messages
        if offset_id:
            rows = [row for row in rows if row.id < offset_id]
        if from_user is not None:
            rows = [row for row in rows if row.sender_id == from_user.id]
        if search:
            folded = search.casefold()
            rows = [row for row in rows if folded in row.message.casefold()]
        return rows[:limit]


class ReadAcceptanceDiagnostics(unittest.TestCase):
    def backend(self, client: StrictReadClient, *, dialog_scan: int = 3, search_scan: int = 3) -> TelethonReadBackend:
        return TelethonReadBackend(
            client_factory=lambda: client,
            config=TelethonReadConfig(
                request_timeout_seconds=2,
                dialog_scan_limit=dialog_scan,
                search_scan_limit=search_scan,
            ),
        )

    def test_reproduces_global_sender_only_invalid_telethon_call(self) -> None:
        client = StrictReadClient()
        with self.assertRaises(BridgeError) as captured:
            self.backend(client).search(
                chat=None,
                sender="@reader",
                text="",
                dates=DateRange(None, None),
                limit=2,
                cursor=None,
                scan_limit=3,
            )
        self.assertEqual(captured.exception.code, "telegram_rpc_error")
        self.assertEqual(len(client.global_calls), 1)
        self.assertIsNone(client.global_calls[0]["entity"])
        self.assertEqual(client.global_calls[0]["search"], "")
        self.assertIsNone(client.global_calls[0]["from_user"])

    def test_reproduces_global_date_only_invalid_telethon_call(self) -> None:
        client = StrictReadClient()
        with self.assertRaises(BridgeError) as captured:
            self.backend(client).search(
                chat=None,
                sender=None,
                text="",
                dates=DateRange(datetime(2026, 8, 1, tzinfo=timezone.utc), None),
                limit=2,
                cursor=None,
                scan_limit=3,
            )
        self.assertEqual(captured.exception.code, "telegram_rpc_error")
        self.assertEqual(len(client.global_calls), 1)

    def test_reproduces_search_cursor_fixed_prefix_ceiling(self) -> None:
        client = StrictReadClient()
        backend = self.backend(client)
        first = backend.search(
            chat="1",
            sender=None,
            text="needle",
            dates=DateRange(None, None),
            limit=2,
            cursor=None,
            scan_limit=3,
        )
        second = backend.search(
            chat="1",
            sender=None,
            text="needle",
            dates=DateRange(None, None),
            limit=2,
            cursor=first.next_cursor,
            scan_limit=3,
        )
        self.assertEqual([item.id for item in first.items], [8, 7])
        self.assertEqual([item.id for item in second.items], [6])
        self.assertIsNone(second.next_cursor)
        self.assertEqual({item.id for item in first.items + second.items}, {6, 7, 8})
        self.assertTrue({1, 2, 3, 4, 5}.isdisjoint({item.id for item in first.items + second.items}))
        self.assertTrue(all(call["offset_id"] == 0 for call in client.global_calls))

    def test_reproduces_dialog_cursor_fixed_prefix_ceiling(self) -> None:
        client = StrictReadClient()
        backend = self.backend(client)
        first = backend.list_dialogs(limit=2, cursor=None, query="", unread_only=False)
        second = backend.list_dialogs(limit=2, cursor=first.next_cursor, query="", unread_only=False)
        self.assertEqual([item.id for item in first.items], ["5", "4"])
        self.assertEqual([item.id for item in second.items], ["3"])
        self.assertIsNone(second.next_cursor)
        self.assertNotIn("2", [item.id for item in first.items + second.items])
        self.assertNotIn("1", [item.id for item in first.items + second.items])


class DownloadBackend:
    def __init__(self, payload: bytes = b"abc", outside: Path | None = None) -> None:
        self.payload = payload
        self.outside = outside
        self.calls = 0

    def download_media(self, **kwargs):  # type: ignore[no-untyped-def]
        self.calls += 1
        if self.outside is not None:
            self.outside.write_bytes(self.payload)
            return {"path": str(self.outside)}
        destination = Path(kwargs["destination"])
        destination.write_bytes(self.payload)
        return {"path": str(destination)}


class MediaAcceptanceDiagnostics(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.files = FileRecordStore(self.root / "state/files.sqlite3", self.root / "files")
        self.checkpoints = CheckpointStore(self.root / "state/downloads.sqlite3")

    def item(self, *, item_id: str = "i1", expected_sha256: str | None = None) -> DownloadItem:
        return DownloadItem(
            item_id,
            "1",
            1,
            "tg_1_0123456789abcdefabcd",
            "sample.bin",
            "application/octet-stream",
            3,
            expected_sha256,
        )

    def manager(self, backend: DownloadBackend) -> DownloadManager:
        return DownloadManager(
            backend=backend,
            files=self.files,
            checkpoints=self.checkpoints,
            staging_dir=self.root / "tmp/downloads",
        )

    def test_reproduces_unsafe_backend_path_cleanup_deleting_outside_file(self) -> None:
        outside = self.root / "outside-owned.bin"
        backend = DownloadBackend(outside=outside)
        result = self.manager(backend).start_single(self.item())
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["failures"]["i1"]["code"], "unsafe_backend_path")
        self.assertFalse(outside.exists())

    def test_reproduces_stale_origin_redownload_loop(self) -> None:
        backend = DownloadBackend()
        manager = self.manager(backend)
        item = self.item()
        job_id = self.checkpoints.create([item])
        origin_key = manager._origin_key(job_id, item.item_id)
        stale_path = self.files.root / "stale.bin"
        stale_path.write_bytes(b"abc")
        stale = self.files.add(stale_path, name="stale.bin", origin_key=origin_key)
        Path(stale.path).unlink()

        first = manager.resume(job_id)
        self.assertEqual(first["status"], "failed")
        self.assertEqual(first["failures"]["i1"]["code"], "file_registry_collision")
        self.assertTrue(first["failures"]["i1"]["retryable"])
        self.assertEqual(backend.calls, 1)

        second = manager.resume(job_id)
        self.assertEqual(second["status"], "failed")
        self.assertEqual(second["failures"]["i1"]["code"], "file_registry_collision")
        self.assertEqual(backend.calls, 2)

    def test_reproduces_post_validation_replacement_registered_as_success(self) -> None:
        expected = hashlib.sha256(b"abc").hexdigest()
        backend = DownloadBackend(b"abc")
        manager = self.manager(backend)
        original_add = self.files.add

        def racing_add(path: Path, **kwargs):  # type: ignore[no-untyped-def]
            path.write_bytes(b"xyz")
            return original_add(path, **kwargs)

        with mock.patch.object(self.files, "add", side_effect=racing_add):
            result = manager.start_single(self.item(expected_sha256=expected))

        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["size"], 3)
        self.assertEqual(result["sha256"], hashlib.sha256(b"xyz").hexdigest())
        self.assertNotEqual(result["sha256"], expected)

    def test_reproduces_private_file_post_hash_same_inode_mutation(self) -> None:
        path = self.files.root / "serve.bin"
        path.write_bytes(b"abc")
        record = self.files.add(path, name="serve.bin")
        real_hash = file_access._hash_handle

        def racing_hash(handle, *, expected_size: int):  # type: ignore[no-untyped-def]
            digest = real_hash(handle, expected_size=expected_size)
            path.write_bytes(b"xyz")
            return digest

        with mock.patch.object(file_access, "_hash_handle", side_effect=racing_hash):
            verified = file_access.open_verified_file(self.files, record.file_ref)
        self.assertIsNotNone(verified)
        assert verified is not None
        try:
            self.assertEqual(verified.handle.read(), b"xyz")
        finally:
            verified.close()


if __name__ == "__main__":
    unittest.main()
