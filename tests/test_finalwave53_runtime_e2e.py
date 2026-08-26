# -*- coding: utf-8 -*-
"""FINALWAVE-53 real runtime/WSGI no-network end-to-end oracle.

Everything inside the bridge boundary is production code.  Only the external
Telethon-compatible client factory is replaced by deterministic in-memory state.
"""
from __future__ import annotations

import asyncio
import hashlib
import io
import json
import os
import tempfile
import threading
import unittest
import zipfile
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from bridge import runtime_wsgi
from bridge.app import ReadAppConfig
from bridge.runtime import PrivateTelegramReferences

AUTH = "finalwave53-placeholder-auth-reference"
SIGNING = "finalwave53-placeholder-signing-reference"
PRIVATE = "FINALWAVE53_PRIVATE_MESSAGE_SENTINEL"


class FakeUser:
    def __init__(self, ident, first_name="Одержувач", username="reader_user"):
        self.id, self.first_name, self.last_name, self.username = ident, first_name, "", username


class FakeChat:
    def __init__(self, ident, title):
        self.id, self.title, self.username = ident, title, None


class FakeMessage:
    def __init__(self, ident, chat_id, text, sender, stamp, media=None, name=None, document_id=None):
        self.id, self.chat_id, self.message = ident, chat_id, text
        self.sender_id, self._sender, self.date = sender.id, sender, stamp
        self.out, self.reply_to, self.media_bytes = False, None, media
        self.voice = self.video_note = self.photo = self.video = self.audio = self.sticker = None
        if media is None:
            self.media = self.file = self.document = None
        else:
            self.media = object()
            self.file = SimpleNamespace(
                id=document_id or ident,
                name=name or f"{ident}.bin",
                mime_type="application/octet-stream",
                size=len(media),
                duration=None,
                width=None,
                height=None,
            )
            self.document = SimpleNamespace(id=document_id or ident)

    async def get_sender(self):
        return self._sender


class Boundary:
    def __init__(self, *, fail_once=(), send_delay=0.0):
        self.reader = FakeUser(20)
        self.read_chat, self.target, self.source = FakeChat(2, "FINALWAVE53_PRIVATE_CHAT"), FakeChat(100, "Target"), FakeChat(200, "Source")
        a, b = datetime(2026, 8, 23, 8, tzinfo=timezone.utc), datetime(2026, 8, 23, 7, tzinfo=timezone.utc)
        self.read = {
            101: FakeMessage(101, 2, "Привіт synthetic bridge", self.reader, a, b"finalwave53-media-one", "перший.bin", 5001),
            102: FakeMessage(102, 2, "Другий synthetic bridge", self.reader, b, b"finalwave53-media-two", "другий.bin", 5002),
        }
        self.write = {
            (100, 10): FakeMessage(10, 100, "reply fixture", self.reader, a),
            (200, 20): FakeMessage(20, 200, "forward fixture 20", self.reader, a),
            (200, 21): FakeMessage(21, 200, "forward fixture 21", self.reader, b),
        }
        self.fail_once, self.failed = set(fail_once), set()
        self.download_attempts, self.external_writes = Counter(), []
        self.send_delay, self.next_id, self.lock = float(send_delay), 2000, threading.Lock()

    def client_factory(self):
        return Client(self)

    def receipt(self, chat_id):
        with self.lock:
            self.next_id += 1
            ident = self.next_id
        return FakeMessage(ident, chat_id, "receipt", self.reader, datetime(2026, 8, 23, 9, tzinfo=timezone.utc))


class Client:
    def __init__(self, boundary):
        self.b = boundary

    async def connect(self):
        return None

    async def disconnect(self):
        return None

    async def is_user_authorized(self):
        return True

    async def get_me(self):
        return self.b.target

    async def get_entity(self, ref):
        mapping = {2: self.b.read_chat, 100: self.b.target, 200: self.b.source}
        if ref in mapping:
            return mapping[ref]
        raise ValueError("entity not found")

    def iter_dialogs(self, *, limit):
        row = SimpleNamespace(
            entity=self.b.read_chat,
            message=SimpleNamespace(date=datetime(2026, 8, 23, 8, tzinfo=timezone.utc)),
            unread_count=2,
            pinned=False,
        )
        return [row][:limit]

    def iter_messages(self, entity, *, limit, search="", offset_id=None):
        del search
        rows = sorted(self.b.read.values(), key=lambda row: row.id, reverse=True) if entity is None or getattr(entity, "id", None) == 2 else []
        if offset_id is not None:
            rows = [row for row in rows if row.id < int(offset_id)]
        return rows[:limit]

    async def get_messages(self, entity, ids):
        chat = int(getattr(entity, "id", 0))
        table = self.b.read if chat == 2 else None
        if isinstance(ids, list):
            return [(table.get(int(x)) if table is not None else self.b.write.get((chat, int(x)))) for x in ids]
        return table.get(int(ids)) if table is not None else self.b.write.get((chat, int(ids)))

    async def download_media(self, message, *, file):
        ident = int(message.id)
        self.b.download_attempts[ident] += 1
        if ident in self.b.fail_once and ident not in self.b.failed:
            self.b.failed.add(ident)
            raise RuntimeError("synthetic transient read failure")
        Path(file).write_bytes(message.media_bytes)
        return str(file)

    async def send_message(self, entity, text, *, reply_to=None):
        if self.b.send_delay:
            await asyncio.sleep(self.b.send_delay)
        with self.b.lock:
            self.b.external_writes.append({"kind": "send", "chat_id": entity.id, "reply_to": reply_to, "size": len(text)})
        return self.b.receipt(entity.id)

    async def send_file(self, entity, files, **kwargs):
        with self.b.lock:
            self.b.external_writes.append({"kind": "files", "chat_id": entity.id, "count": len(files), "voice_note": bool(kwargs.get("voice_note"))})
        return [self.b.receipt(entity.id) for _ in files]

    async def forward_messages(self, entity, ids, *, from_peer):
        with self.b.lock:
            self.b.external_writes.append({"kind": "forward", "source_id": from_peer.id, "chat_id": entity.id, "count": len(ids)})
        return [self.b.receipt(entity.id) for _ in ids]


def request(path, body=None, *, method="POST", auth=True):
    raw = b"" if body is None else json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode()
    env = {
        "REQUEST_METHOD": method, "PATH_INFO": path, "QUERY_STRING": "",
        "wsgi.input": io.BytesIO(raw), "CONTENT_TYPE": "application/json" if method != "GET" else "",
        "CONTENT_LENGTH": str(len(raw)),
    }
    if auth:
        env["HTTP_AUTHORIZATION"] = f"Bearer {AUTH}"
    out = {}
    def start(status, headers):
        out.update(status=status, headers=dict(headers))
    out["raw"] = b"".join(runtime_wsgi.application(env, start))
    if out["headers"].get("Content-Type", "").startswith("application/json"):
        out["payload"] = json.loads(out["raw"].decode())
    return out


class Finalwave53RuntimeE2E(unittest.TestCase):
    def setUp(self):
        runtime_wsgi.reset_runtime_application_for_tests()

    def tearDown(self):
        runtime_wsgi.reset_runtime_application_for_tests()

    @staticmethod
    def refs():
        return PrivateTelegramReferences(100023, "a" * 32, "synthetic-reference-material-" + "x" * 24)

    def boot(self, root, boundary):
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(root, 0o700)
        cfg = ReadAppConfig(auth_secret=AUTH, file_signing_secret=SIGNING, private_root=root, public_base_url="https://bridge.example.invalid")
        runtime_wsgi.reset_runtime_application_for_tests()
        with mock.patch.object(ReadAppConfig, "from_env", return_value=cfg), \
             mock.patch("bridge.runtime.load_private_telegram_references", return_value=self.refs()), \
             mock.patch("bridge.runtime._raw_telethon_factory", return_value=boundary.client_factory):
            health = request("/health", method="GET", auth=False)
        self.assertEqual("200 OK", health["status"])
        self.assertTrue(health["payload"]["ready"], health)
        return runtime_wsgi._default_application

    @staticmethod
    def data(response):
        if not response["status"].startswith("200"):
            raise AssertionError(response)
        return response["payload"]["data"]

    def test_continuous_runtime_wsgi_path_restart_and_privacy(self):
        with tempfile.TemporaryDirectory() as td:
            root, boundary = Path(td) / "private", Boundary(fail_once={102})
            app = self.boot(root, boundary)

            unauth = request("/api/v1/dialogs/list", {"limit": 1}, auth=False)
            self.assertEqual("404 Not Found", unauth["status"])
            self.assertNotIn("FINALWAVE53_PRIVATE_CHAT", unauth["raw"].decode(errors="ignore"))
            self.assertEqual("2", self.data(request("/api/v1/dialogs/list", {"limit": 10}))["items"][0]["id"])
            self.assertEqual([102, 101], [x["id"] for x in self.data(request("/api/v1/history/read", {"chat": "2", "limit": 10}))["items"]])
            search = self.data(request("/api/v1/search", {
                "chat": "2", "sender": "@reader_user", "text": "ПРИВІТ",
                "date_from": "2026-08-23T00:00:00Z", "date_to": "2026-08-24T00:00:00Z", "limit": 10,
            }))
            self.assertEqual([101], [x["id"] for x in search["items"]])

            m1 = self.data(request("/api/v1/media/metadata", {"chat": "2", "message_id": 101}))["media"][0]
            m2 = self.data(request("/api/v1/media/metadata", {"chat": "2", "message_id": 102}))["media"][0]
            b1, b2 = boundary.read[101].media_bytes, boundary.read[102].media_bytes
            one = {
                "chat": "2", "message_id": 101, "file_ref": m1["file_ref"], "name": "single.bin",
                "mime_type": "application/octet-stream", "expected_size": len(b1), "expected_sha256": hashlib.sha256(b1).hexdigest(),
            }
            single = self.data(request("/api/v1/downloads/single", one))
            self.assertEqual(hashlib.sha256(b1).hexdigest(), single["sha256"])
            two = {
                "chat": "2", "message_id": 102, "file_ref": m2["file_ref"], "name": "bulk-two.bin",
                "mime_type": "application/octet-stream", "expected_size": len(b2), "expected_sha256": hashlib.sha256(b2).hexdigest(),
            }
            bulk = self.data(request("/api/v1/downloads/bulk", {"items": [one, one, two]}))
            self.assertEqual("partial", bulk["status"], bulk)
            self.assertEqual(1, bulk["pending"])
            resumed = self.data(request("/api/v1/downloads/resume", {"job_id": bulk["job_id"]}))
            self.assertEqual("complete", resumed["status"], resumed)
            self.assertEqual(2, len(resumed["files"]))
            counts = dict(boundary.download_attempts)
            self.assertEqual(2, counts[102])
            self.assertEqual("complete", self.data(request("/api/v1/downloads/resume", {"job_id": bulk["job_id"]}))["status"])
            self.assertEqual(counts, dict(boundary.download_attempts))

            archive = self.data(request("/api/v1/archives/create", {
                "file_refs": [x["file_ref"] for x in resumed["files"]], "name": "finalwave53.zip",
            }))
            self.assertEqual("404 Not Found", request(f"/api/v1/files/{archive['file_ref']}", method="GET", auth=False)["status"])
            zipped = request(f"/api/v1/files/{archive['file_ref']}", method="GET")
            self.assertEqual("200 OK", zipped["status"])
            with zipfile.ZipFile(io.BytesIO(zipped["raw"])) as bundle:
                self.assertIsNone(bundle.testzip())
                self.assertEqual(2, len(bundle.infolist()))

            file_row = resumed["files"][0]
            meta = self.data(request("/api/v1/files/get", {"file_ref": file_row["file_ref"]}))
            self.assertNotIn(str(root), json.dumps(meta, sort_keys=True))
            served = request(f"/api/v1/files/{file_row['file_ref']}", method="GET")
            self.assertEqual("200 OK", served["status"])
            self.assertIn(served["raw"], {b1, b2})

            cases = [
                ("/api/v1/messages/send/preview", {"chat": "100", "text": PRIVATE}),
                ("/api/v1/messages/reply/preview", {"chat": "100", "reply_to_message_id": 10, "text": PRIVATE}),
                ("/api/v1/messages/forward/preview", {"from_chat": "200", "to_chat": "100", "message_ids": [20, 21]}),
                ("/api/v1/files/send/preview", {"chat": "100", "files": [{"file_ref": file_row["file_ref"], "sha256": file_row["sha256"], "size": file_row["size"]}], "caption": "", "voice_note": False}),
            ]
            previews = [self.data(request(path, body)) for path, body in cases]
            self.assertEqual([], boundary.external_writes)
            commit = {"preview_token": previews[0]["preview_token"], "idempotency_key": "finalwave53-idempotency-0001", "explicit_user_command": False}
            self.assertEqual("409 Conflict", request("/api/v1/messages/send/commit", commit)["status"])
            self.assertEqual([], boundary.external_writes)
            commit["explicit_user_command"] = True
            first = self.data(request("/api/v1/messages/send/commit", commit))
            replay = self.data(request("/api/v1/messages/send/commit", commit))
            self.assertFalse(first["idempotent_replay"])
            self.assertTrue(replay["idempotent_replay"])
            self.assertEqual(1, len(boundary.external_writes))

            audit = json.dumps(app.read_app.audit.events, ensure_ascii=False, sort_keys=True)
            for private in (PRIVATE, "FINALWAVE53_PRIVATE_CHAT", "Одержувач", AUTH, SIGNING, str(root)):
                self.assertNotIn(private, audit)

            restarted_boundary = Boundary()
            restarted = self.boot(root, restarted_boundary)
            self.assertEqual("complete", self.data(request("/api/v1/downloads/resume", {"job_id": bulk["job_id"]}))["status"])
            self.assertEqual("200 OK", request(f"/api/v1/files/{file_row['file_ref']}", method="GET")["status"])
            self.assertTrue(self.data(request("/api/v1/messages/send/commit", commit))["idempotent_replay"])
            self.assertEqual([], restarted_boundary.external_writes)
            self.assertEqual("COMMITTED", restarted.write_store.transaction_state(commit["idempotency_key"]))

    def test_duplicate_commit_concurrency_keeps_one_effect(self):
        with tempfile.TemporaryDirectory() as td:
            boundary = Boundary(send_delay=0.03)
            self.boot(Path(td) / "private", boundary)
            preview = self.data(request("/api/v1/messages/send/preview", {"chat": "100", "text": "contention"}))
            commit = {"preview_token": preview["preview_token"], "idempotency_key": "finalwave53-concurrent-idem-0001", "explicit_user_command": True}
            barrier = threading.Barrier(8)
            def worker():
                barrier.wait(10)
                return request("/api/v1/messages/send/commit", dict(commit))
            with ThreadPoolExecutor(max_workers=8) as pool:
                rows = [future.result(20) for future in [pool.submit(worker) for _ in range(8)]]
            ok, busy = [r for r in rows if r["status"].startswith("200")], [r for r in rows if r["status"] == "409 Conflict"]
            self.assertEqual(8, len(ok) + len(busy))
            self.assertEqual(1, len(boundary.external_writes))
            self.assertEqual(1, sum(not bool(r["payload"]["data"]["idempotent_replay"]) for r in ok))
            self.assertTrue(self.data(request("/api/v1/messages/send/commit", commit))["idempotent_replay"])
            self.assertEqual(1, len(boundary.external_writes))

    @unittest.expectedFailure
    def test_restart_should_terminalize_orphan_calling_without_blind_resend(self):
        """Residual HIGH oracle; naive global startup rewrite is unsafe under Passenger."""
        with tempfile.TemporaryDirectory() as td:
            root, boundary = Path(td) / "private", Boundary()
            app = self.boot(root, boundary)
            preview = self.data(request("/api/v1/messages/send/preview", {"chat": "100", "text": "orphan-calling"}))
            key = "finalwave53-orphan-calling-0001"
            app.write_store.simulate_calling_crash_for_test(preview["preview_token"], expected_action="SEND", idempotency_key=key, now=1_780_000_000)
            self.assertEqual("CALLING", app.write_store.transaction_state(key))
            restarted_boundary = Boundary()
            self.boot(root, restarted_boundary)
            result = request("/api/v1/messages/send/commit", {
                "preview_token": preview["preview_token"], "idempotency_key": key, "explicit_user_command": True,
            })
            self.assertEqual("409 Conflict", result["status"])
            self.assertEqual("write_outcome_unknown_reconciliation_required", result["payload"]["error"]["code"])
            self.assertEqual([], restarted_boundary.external_writes)


if __name__ == "__main__":
    unittest.main()
