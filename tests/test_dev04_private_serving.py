from __future__ import annotations

import io
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from bridge.app import BridgeApplication, ReadAppConfig
from bridge.audit import AuditLog
from bridge.file_access import open_verified_file
from bridge.storage import FileRecordStore
from tests.test_read_app import AllowLimiter, FakeBackend, SIGN, TOKEN, request


class VerifiedPrivateFileTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.store = FileRecordStore(root / "state" / "files.sqlite3", root / "files")

    def add(self, data: bytes = b"abc", *, name: str = "file.txt"):
        path = self.store.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.parent != self.store.root:
            os.chmod(path.parent, 0o700)
        path.write_bytes(data)
        return self.store.add(path, name=path.name), path

    def test_verified_descriptor_survives_leaf_path_replacement(self) -> None:
        record, path = self.add()
        verified = open_verified_file(self.store, record.file_ref)
        self.assertIsNotNone(verified)
        assert verified is not None

        outside = Path(self.tmp.name) / "outside.txt"
        outside.write_bytes(b"PRIVATE_REPLACEMENT")
        path.unlink()
        path.symlink_to(outside)
        try:
            self.assertEqual(verified.handle.read(), b"abc")
        finally:
            verified.close()

    def test_verified_snapshot_survives_same_inode_same_size_mutation(self) -> None:
        record, path = self.add(b"abc")
        verified = open_verified_file(self.store, record.file_ref)
        self.assertIsNotNone(verified)
        assert verified is not None

        path.write_bytes(b"XYZ")
        try:
            self.assertEqual(verified.handle.read(), b"abc")
        finally:
            verified.close()

    def test_verified_open_rejects_symlink_leaf(self) -> None:
        record, path = self.add()
        outside = Path(self.tmp.name) / "outside.txt"
        outside.write_bytes(b"abc")
        path.unlink()
        path.symlink_to(outside)
        self.assertIsNone(open_verified_file(self.store, record.file_ref))

    def test_verified_open_rejects_hardlink_topology(self) -> None:
        record, path = self.add()
        alias = self.store.root / "alias.txt"
        os.link(path, alias)
        self.assertIsNone(open_verified_file(self.store, record.file_ref))

    def test_verified_open_rejects_broad_private_root(self) -> None:
        record, _ = self.add()
        os.chmod(self.store.root, 0o755)
        try:
            self.assertIsNone(open_verified_file(self.store, record.file_ref))
        finally:
            os.chmod(self.store.root, 0o700)

    def test_verified_open_supports_owner_private_nested_record(self) -> None:
        record, _ = self.add(name="nested/file.txt")
        verified = open_verified_file(self.store, record.file_ref)
        self.assertIsNotNone(verified)
        assert verified is not None
        try:
            self.assertEqual(verified.handle.read(), b"abc")
        finally:
            verified.close()

    def test_verified_open_rejects_broad_nested_directory(self) -> None:
        record, path = self.add(name="nested/file.txt")
        os.chmod(path.parent, 0o755)
        self.assertIsNone(open_verified_file(self.store, record.file_ref))


class PrivateServingDescriptorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.backend = FakeBackend()
        self.audit = AuditLog()
        self.app = BridgeApplication(
            config=ReadAppConfig(
                auth_secret=TOKEN,
                file_signing_secret=SIGN,
                private_root=Path(self.tmp.name),
                public_base_url="https://example.invalid",
            ),
            backend=self.backend,
            rate_limiter=AllowLimiter(),
            audit=self.audit,
        )

    def downloaded_ref(self) -> str:
        result = request(
            self.app,
            "/api/v1/downloads/single",
            {
                "chat": "2",
                "message_id": 2,
                "file_ref": "tg_2_0123456789abcdefabcd",
                "name": "safe.txt",
                "expected_size": 3,
            },
        )
        return result["json"]["data"]["file_ref"]

    def test_wsgi_stream_uses_pinned_descriptor_after_leaf_swap(self) -> None:
        ref = self.downloaded_ref()
        assert self.app.files is not None
        original = open_verified_file
        outside = Path(self.tmp.name) / "outside-private.txt"
        outside.write_bytes(b"DO_NOT_SERVE_THIS")

        def open_then_swap(store, file_ref):
            verified = original(store, file_ref)
            self.assertIsNotNone(verified)
            assert verified is not None
            source = Path(verified.record.path)
            source.unlink()
            source.symlink_to(outside)
            return verified

        with patch("bridge.app.open_verified_file", side_effect=open_then_swap):
            served = request(self.app, f"/api/v1/files/{ref}", method="GET", token=TOKEN, raw=b"")

        self.assertTrue(served["status"].startswith("200"))
        self.assertEqual(served["raw"], b"abc")
        self.assertEqual(served["headers"]["Content-Length"], "3")
        self.assertNotIn(b"DO_NOT_SERVE_THIS", served["raw"])

    def test_wsgi_stream_uses_snapshot_after_same_inode_mutation(self) -> None:
        ref = self.downloaded_ref()
        assert self.app.files is not None
        original = open_verified_file

        def open_then_mutate(store, file_ref):
            verified = original(store, file_ref)
            self.assertIsNotNone(verified)
            assert verified is not None
            Path(verified.record.path).write_bytes(b"XYZ")
            return verified

        with patch("bridge.app.open_verified_file", side_effect=open_then_mutate):
            served = request(self.app, f"/api/v1/files/{ref}", method="GET", token=TOKEN, raw=b"")

        self.assertTrue(served["status"].startswith("200"))
        self.assertEqual(served["raw"], b"abc")
        self.assertEqual(served["headers"]["Content-Length"], "3")

    def test_signed_wsgi_stream_uses_same_verified_descriptor_path(self) -> None:
        ref = self.downloaded_ref()
        metadata = request(self.app, "/api/v1/files/get", {"file_ref": ref})["json"]["data"]
        query = metadata["signed_url"].split("?", 1)[1]
        served = request(self.app, f"/api/v1/files/{ref}", method="GET", token=None, raw=b"", query=query)
        self.assertEqual(served["raw"], b"abc")
        self.assertEqual(served["headers"]["Cache-Control"], "private, no-store")

    def test_start_response_failure_closes_verified_descriptor(self) -> None:
        ref = self.downloaded_ref()
        assert self.app.files is not None
        verified = open_verified_file(self.app.files, ref)
        self.assertIsNotNone(verified)
        assert verified is not None

        env = {
            "REQUEST_METHOD": "GET",
            "PATH_INFO": f"/api/v1/files/{ref}",
            "QUERY_STRING": "",
            "wsgi.input": io.BytesIO(b""),
            "CONTENT_LENGTH": "0",
            "HTTP_AUTHORIZATION": "Bearer " + TOKEN,
        }

        with patch("bridge.app.open_verified_file", return_value=verified):
            with self.assertRaises(RuntimeError):
                self.app._serve_file(env, lambda status, headers: (_ for _ in ()).throw(RuntimeError("boom")), env["PATH_INFO"], "req")
        self.assertTrue(verified.handle.closed)


if __name__ == "__main__":
    unittest.main()
