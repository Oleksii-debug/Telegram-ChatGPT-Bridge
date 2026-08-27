from __future__ import annotations

import asyncio
import hashlib
import io
import json
import os
import sqlite3
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

from bridge.app import BridgeApplication, ReadAppConfig
from bridge.backend import TelethonReadBackend, TelethonReadConfig
from bridge.downloads import DownloadLimits, DownloadManager
from bridge.errors import BridgeError
from bridge.routes import READ_ROUTE_REGISTRY, registry_snapshot, resolve_route, validate_registry
from bridge.security import RateLimitDecision
from bridge.storage import CheckpointStore, DownloadItem, FileRecordStore
from bridge.validation import DateRange, bounded_int, bounded_text

AUTH = "a" * 32
SIGNING_MATERIAL = "b" * 32


class AllowLimiter:
    def __init__(self):
        self.actors: list[str] = []

    def check(self, actor: str) -> RateLimitDecision:
        self.actors.append(actor)
        return RateLimitDecision(True, remaining=9)


class DenyLimiter:
    def __init__(self):
        self.actors: list[str] = []

    def check(self, actor: str) -> RateLimitDecision:
        self.actors.append(actor)
        return RateLimitDecision(False, retry_after_seconds=4, remaining=0)


class EmptyBackend:
    def list_dialogs(self, **kwargs):
        raise AssertionError("backend must not be reached")

    def history(self, **kwargs):
        raise AssertionError("backend must not be reached")

    def search(self, **kwargs):
        raise AssertionError("backend must not be reached")

    def get_message(self, **kwargs):
        raise AssertionError("backend must not be reached")

    def download_media(self, **kwargs):
        raise AssertionError("backend must not be reached")


def wsgi_request(app, path: str, *, method: str = "POST", raw: bytes = b"{}", auth: str | None = AUTH, query: str = ""):
    environ = {
        "REQUEST_METHOD": method,
        "PATH_INFO": path,
        "QUERY_STRING": query,
        "CONTENT_TYPE": "application/json",
        "CONTENT_LENGTH": str(len(raw)),
        "wsgi.input": io.BytesIO(raw),
    }
    if auth is not None:
        environ["HTTP_AUTHORIZATION"] = "Bearer " + auth
    captured = {}

    def start_response(status, headers):
        captured["status"] = status
        captured["headers"] = dict(headers)

    body = b"".join(app(environ, start_response))
    captured["body"] = body
    if captured["headers"].get("Content-Type", "").startswith("application/json"):
        captured["json"] = json.loads(body.decode("utf-8"))
    return captured


class RouteRegistryTests(unittest.TestCase):
    def test_registry_is_self_consistent(self):
        validate_registry()
        ids = [route.operation_id for route in READ_ROUTE_REGISTRY]
        self.assertEqual(len(ids), len(set(ids)))

    def test_only_health_is_public(self):
        public = [(route.method, route.relative_path) for route in READ_ROUTE_REGISTRY if route.access == "public"]
        self.assertEqual(public, [("GET", "/health")])

    def test_all_non_health_routes_are_read_class_and_nonpublic(self):
        for route in READ_ROUTE_REGISTRY:
            if route.operation_id == "health.get":
                continue
            self.assertEqual(route.operation_class, "read")
            self.assertIn(route.access, {"protected", "protected_or_signed"})

    def test_dynamic_private_file_route_resolves(self):
        route = resolve_route("GET", "/api/v1/files/" + "A" * 32, "/api/v1")
        self.assertIsNotNone(route)
        self.assertEqual(route.operation_id, "files.content")
        self.assertEqual(route.access, "protected_or_signed")

    def test_wrong_method_does_not_resolve_protected_route(self):
        self.assertIsNone(resolve_route("GET", "/api/v1/dialogs/list", "/api/v1"))

    def test_unknown_route_never_resolves(self):
        self.assertIsNone(resolve_route("POST", "/api/v1/not-registered", "/api/v1"))

    def test_registry_snapshot_is_nonsecret_and_stable(self):
        snapshot = registry_snapshot()
        self.assertEqual(snapshot[0]["operation_id"], "health.get")
        self.assertEqual(snapshot[-1]["path"], "/api/v1/files/{file_ref}")
        self.assertNotIn("token", json.dumps(snapshot).casefold())


class RequestHardeningTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.limiter = AllowLimiter()
        self.app = BridgeApplication(
            config=ReadAppConfig(auth_secret=AUTH, file_signing_secret=SIGNING_MATERIAL, private_root=Path(self.tmp.name), public_base_url="https://example.invalid"),
            backend=EmptyBackend(),
            rate_limiter=self.limiter,
        )

    def test_duplicate_top_level_json_key_rejected_before_backend(self):
        result = wsgi_request(self.app, "/api/v1/dialogs/list", raw=b'{"limit":1,"limit":2}')
        self.assertEqual(result["json"]["error"]["code"], "duplicate_field")

    def test_duplicate_nested_json_key_rejected(self):
        result = wsgi_request(self.app, "/api/v1/dialogs/list", raw=b'{"x":{"a":1,"a":2}}')
        self.assertEqual(result["json"]["error"]["code"], "duplicate_field")

    def test_excessive_json_depth_rejected(self):
        value = 1
        for _ in range(12):
            value = {"x": value}
        raw = json.dumps(value).encode("utf-8")
        result = wsgi_request(self.app, "/api/v1/dialogs/list", raw=raw)
        self.assertEqual(result["json"]["error"]["code"], "json_depth_limit")

    def test_float_integer_field_rejected_without_truncation(self):
        result = wsgi_request(self.app, "/api/v1/dialogs/list", raw=b'{"limit":1.5}')
        self.assertEqual(result["json"]["error"]["code"], "invalid_integer")

    def test_numeric_string_integer_field_rejected(self):
        result = wsgi_request(self.app, "/api/v1/dialogs/list", raw=b'{"limit":"2"}')
        self.assertEqual(result["json"]["error"]["code"], "invalid_integer")

    def test_surrogate_text_rejected(self):
        with self.assertRaises(BridgeError) as captured:
            bounded_text("\ud800", field="text")
        self.assertEqual(captured.exception.code, "invalid_text")

    def test_strict_integer_helper(self):
        with self.assertRaises(BridgeError):
            bounded_int(2.0, field="n", default=0, minimum=0, maximum=10)
        self.assertEqual(bounded_int(2, field="n", default=0, minimum=0, maximum=10), 2)

    def test_protected_wrong_method_stays_hidden(self):
        result = wsgi_request(self.app, "/api/v1/dialogs/list", method="GET", raw=b"")
        self.assertTrue(result["status"].startswith("404"))

    def test_health_wrong_method_is_explicit_controlled_error(self):
        result = wsgi_request(self.app, "/health", method="POST")
        self.assertTrue(result["status"].startswith("405"))
        self.assertEqual(result["json"]["error"]["code"], "method_not_allowed")

    def _registered_file(self):
        assert self.app.files is not None
        path = self.app.files.root / "payload.bin"
        path.write_bytes(b"abc")
        os.chmod(path, 0o600)
        return self.app.files.add(path, name="payload.bin")

    def test_signed_file_read_uses_same_rate_limit_boundary(self):
        record = self._registered_file()
        assert self.app.signer is not None
        url, _ = self.app.signer.issue(
            base_url="https://example.invalid",
            route_prefix="/api/v1/files",
            file_ref=record.file_ref,
            ttl_seconds=60,
        )
        query = url.split("?", 1)[1]
        result = wsgi_request(self.app, f"/api/v1/files/{record.file_ref}", method="GET", raw=b"", auth=None, query=query)
        self.assertEqual(result["body"], b"abc")
        self.assertIn("private-file-read", self.limiter.actors)

    def test_signed_file_read_is_denied_by_limiter(self):
        record = self._registered_file()
        deny = DenyLimiter()
        app = BridgeApplication(config=self.app.config, backend=EmptyBackend(), rate_limiter=deny)
        assert app.signer is not None
        url, _ = app.signer.issue(base_url="https://example.invalid", route_prefix="/api/v1/files", file_ref=record.file_ref, ttl_seconds=60)
        # The second application has its own empty registry DB. Register the
        # same bytes under its private store before exercising the signed path.
        assert app.files is not None
        path = app.files.root / "payload2.bin"
        path.write_bytes(b"abc")
        os.chmod(path, 0o600)
        second = app.files.add(path, name="payload2.bin")
        url, _ = app.signer.issue(base_url="https://example.invalid", route_prefix="/api/v1/files", file_ref=second.file_ref, ttl_seconds=60)
        query = url.split("?", 1)[1]
        result = wsgi_request(app, f"/api/v1/files/{second.file_ref}", method="GET", raw=b"", auth=None, query=query)
        self.assertTrue(result["status"].startswith("429"))
        self.assertEqual(result["json"]["error"]["code"], "rate_limited")
        self.assertEqual(result["headers"]["Retry-After"], "4")

    def test_signed_query_duplicate_parameter_is_hidden(self):
        record = self._registered_file()
        assert self.app.signer is not None
        url, _ = self.app.signer.issue(base_url="https://example.invalid", route_prefix="/api/v1/files", file_ref=record.file_ref, ttl_seconds=60)
        query = url.split("?", 1)[1]
        result = wsgi_request(self.app, f"/api/v1/files/{record.file_ref}", method="GET", raw=b"", auth=None, query=query + "&exp=9999999999")
        self.assertTrue(result["status"].startswith("404"))


class LifecycleEntity:
    def __init__(self, entity_id=1):
        self.id = entity_id
        self.title = "Synthetic"


class LifecycleClient:
    def __init__(self, *, authorized=True, fail_connect=False, slow=False):
        self.authorized = authorized
        self.fail_connect = fail_connect
        self.slow = slow
        self.connected = 0
        self.disconnected = 0
        self.dialogs = []

    async def connect(self):
        self.connected += 1
        if self.fail_connect:
            raise RuntimeError("private connect detail")

    async def is_user_authorized(self):
        return self.authorized

    async def disconnect(self):
        self.disconnected += 1

    def iter_dialogs(self, limit):
        if not self.slow:
            return self.dialogs[:limit]

        async def generator():
            await asyncio.sleep(2)
            if False:
                yield None

        return generator()

    def get_entity(self, target):
        return LifecycleEntity(int(target) if str(target).isdigit() else 1)

    def iter_messages(self, entity, limit, **kwargs):
        return []

    def get_messages(self, entity, ids):
        return None


class TelethonLifecycleTests(unittest.TestCase):
    def test_connect_auth_disconnect_success(self):
        client = LifecycleClient()
        backend = TelethonReadBackend(client_factory=lambda: client, config=TelethonReadConfig(request_timeout_seconds=2))
        backend.list_dialogs(limit=5, cursor=None, query="", unread_only=False)
        self.assertEqual((client.connected, client.disconnected), (1, 1))

    def test_not_authorized_is_controlled_and_disconnects(self):
        client = LifecycleClient(authorized=False)
        backend = TelethonReadBackend(client_factory=lambda: client)
        with self.assertRaises(BridgeError) as captured:
            backend.list_dialogs(limit=1, cursor=None, query="", unread_only=False)
        self.assertEqual(captured.exception.code, "telegram_not_authorized")
        self.assertEqual(client.disconnected, 1)

    def test_connect_failure_hides_text_and_disconnects(self):
        client = LifecycleClient(fail_connect=True)
        backend = TelethonReadBackend(client_factory=lambda: client)
        with self.assertRaises(BridgeError) as captured:
            backend.list_dialogs(limit=1, cursor=None, query="", unread_only=False)
        self.assertEqual(captured.exception.code, "telegram_rpc_error")
        self.assertNotIn("private", captured.exception.message.casefold())
        self.assertEqual(client.disconnected, 1)

    def test_timeout_cancels_operation_and_disconnects(self):
        client = LifecycleClient(slow=True)
        backend = TelethonReadBackend(client_factory=lambda: client, config=TelethonReadConfig(request_timeout_seconds=1))
        with self.assertRaises(BridgeError) as captured:
            backend.list_dialogs(limit=1, cursor=None, query="", unread_only=False)
        self.assertEqual(captured.exception.code, "telegram_timeout")
        self.assertEqual(client.disconnected, 1)

    def test_partial_media_none_values_are_safe(self):
        file_obj = SimpleNamespace(name=None, mime_type=None, size=None, id=None, duration=None, width=None, height=None)
        message = SimpleNamespace(
            id=7,
            media=object(),
            file=file_obj,
            document=SimpleNamespace(id=123),
            voice=None,
            video_note=None,
            photo=None,
            video=None,
            audio=None,
            sticker=None,
            chat_id=1,
            peer_id=None,
        )
        record = TelethonReadBackend._media_records(message)[0]
        self.assertIsNone(record.name)
        self.assertIsNone(record.mime_type)
        self.assertIsNone(record.size)
        self.assertIsNone(record.duration_seconds)
        self.assertIsNone(record.width)
        self.assertIsNone(record.height)

    def test_naive_message_timestamp_is_normalized(self):
        class Msg:
            id = 1
            chat_id = 1
            sender_id = None
            date = datetime(2026, 1, 1, 12, 0, 0)
            message = "x"
            out = False
            reply_to = None
            media = None
            file = None

        result = asyncio.run(TelethonReadBackend._message_record(Msg(), "1"))
        self.assertTrue(result.timestamp.endswith("+00:00"))


class CheckpointAndConcurrencyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.files = FileRecordStore(root / "state" / "files.sqlite3", root / "files")
        self.checkpoints = CheckpointStore(root / "state" / "downloads.sqlite3")
        self.root = root

    @staticmethod
    def item(item_id="a" * 32, message_id=1):
        return DownloadItem(item_id, "1", message_id, "A" * 32, f"{message_id}.bin", "application/octet-stream")

    def _rewrite_checkpoint(self, job_id: str, mutator):
        with sqlite3.connect(self.checkpoints.db_path) as connection:
            raw, _ = connection.execute("SELECT payload_json,payload_sha256 FROM download_jobs WHERE job_id=?", (job_id,)).fetchone()
            payload = json.loads(raw)
            mutator(payload)
            encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            digest = hashlib.sha256(encoded.encode("utf-8")).hexdigest()
            connection.execute("UPDATE download_jobs SET payload_json=?,payload_sha256=? WHERE job_id=?", (encoded, digest, job_id))
            connection.commit()

    def test_checkpoint_embedded_job_id_mismatch_fails_closed(self):
        job_id = self.checkpoints.create([self.item()])
        self._rewrite_checkpoint(job_id, lambda payload: payload.__setitem__("job_id", "B" * 24))
        with self.assertRaises(BridgeError) as captured:
            self.checkpoints.load(job_id)
        self.assertEqual(captured.exception.code, "checkpoint_corrupt")

    def test_old_checkpoint_schema_fails_closed(self):
        job_id = self.checkpoints.create([self.item()])
        self._rewrite_checkpoint(job_id, lambda payload: payload.__setitem__("schema", 0))
        with self.assertRaises(BridgeError) as captured:
            self.checkpoints.load(job_id)
        self.assertEqual(captured.exception.code, "checkpoint_schema")

    def test_complete_checkpoint_with_missing_file_is_not_silent_success(self):
        class NoBackend:
            pass

        manager = DownloadManager(backend=NoBackend(), files=self.files, checkpoints=self.checkpoints, staging_dir=self.root / "tmp")
        job_id = self.checkpoints.create([self.item()])
        payload = self.checkpoints.load(job_id)
        payload["status"] = "complete"
        payload["results"] = {"a" * 32: "C" * 32}
        self.checkpoints.save(payload)
        with self.assertRaises(BridgeError) as captured:
            manager.resume(job_id)
        self.assertEqual(captured.exception.code, "checkpoint_result_missing")

    def test_same_job_concurrent_resume_fails_busy(self):
        class NoBackend:
            pass

        manager = DownloadManager(backend=NoBackend(), files=self.files, checkpoints=self.checkpoints, staging_dir=self.root / "tmp")
        job_id = self.checkpoints.create([self.item()])
        with manager._job_lock(job_id):
            with self.assertRaises(BridgeError) as captured:
                manager.resume(job_id)
        self.assertEqual(captured.exception.code, "job_busy")

    def test_different_job_locks_do_not_collide(self):
        class NoBackend:
            pass

        manager = DownloadManager(backend=NoBackend(), files=self.files, checkpoints=self.checkpoints, staging_dir=self.root / "tmp")
        first = self.checkpoints.create([self.item("a" * 32, 1)])
        second = self.checkpoints.create([self.item("b" * 32, 2)])
        with manager._job_lock(first):
            with manager._job_lock(second):
                pass

    def test_actual_bulk_cap_deletes_rejected_registry_record(self):
        class Backend:
            def download_media(self, **kwargs):
                path = Path(kwargs["destination"])
                path.write_bytes(b"abc")
                return {"path": str(path)}

        manager = DownloadManager(
            backend=Backend(),
            files=self.files,
            checkpoints=self.checkpoints,
            staging_dir=self.root / "tmp",
            limits=DownloadLimits(max_single_bytes=5, max_bulk_files=10, max_bulk_bytes=5),
        )
        result = manager.start_bulk([self.item("a" * 32, 1), self.item("b" * 32, 2)])
        self.assertEqual(result["status"], "partial")
        self.assertEqual(len(result["files"]), 1)
        self.assertEqual(result["failures"][0]["code"], "bulk_size_limit")
        with sqlite3.connect(self.files.db_path) as connection:
            count = connection.execute("SELECT COUNT(*) FROM files").fetchone()[0]
        self.assertEqual(count, 1)


if __name__ == "__main__":
    unittest.main()
