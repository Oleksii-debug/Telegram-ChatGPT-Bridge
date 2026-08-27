import json
import sqlite3
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from io import BytesIO
from pathlib import Path
from unittest.mock import patch

from bridge.app import BridgeApplication, ReadAppConfig
from bridge.backend import TelethonReadBackend, TelethonReadConfig
from bridge.errors import BridgeError
from bridge.integrated_app import UnifiedBridgeApplication
from bridge.security import RateLimitDecision
from bridge.storage import FileRecordStore
from ops.dev06_runtime_conformance import build_compatible_chatgpt_action_openapi
from ops.telegram_write_adapter import TelegramContractError
from ops.write_endpoint_policy import EndpointPolicyError, structured_write_error
from ops.write_safety import PersistentWriteStore, WriteAction, WriteSafetyError


AUTH = "unit-test-auth-secret-000000000001"
PRIVATE_MARKER = "private-diagnostic-should-not-escape"


class AllowAll:
    def check(self, actor):
        del actor
        return RateLimitDecision(allowed=True, retry_after_seconds=None, remaining=100)


class ExplodingInput:
    def __init__(self):
        self.read_called = False

    def read(self, *args, **kwargs):
        del args, kwargs
        self.read_called = True
        raise AssertionError(PRIVATE_MARKER)


def call_wsgi(app, path, *, body=b"{}", auth=True, method="POST", content_type="application/json", stream=None):
    headers = {}
    status_line = ""

    def start_response(status, response_headers):
        nonlocal status_line
        status_line = status
        headers.update(response_headers)

    environ = {
        "REQUEST_METHOD": method,
        "PATH_INFO": path,
        "QUERY_STRING": "",
        "CONTENT_TYPE": content_type,
        "CONTENT_LENGTH": str(len(body)),
        "wsgi.input": stream if stream is not None else BytesIO(body),
        "REMOTE_ADDR": "127.0.0.1",
    }
    if auth:
        environ["HTTP_AUTHORIZATION"] = f"Bearer {AUTH}"
    raw = b"".join(app(environ, start_response))
    payload = json.loads(raw.decode("utf-8")) if raw else None
    return int(status_line.split()[0]), headers, payload, raw


class PublicErrorBoundaryTests(unittest.TestCase):
    def test_retry_after_is_bounded_and_non_429_retry_is_removed(self):
        rate = BridgeError("Rate limit exceeded", status=429, code="rate_limited", retry_after_seconds=9999)
        self.assertEqual(rate.public_payload("0123456789abcdef")["error"]["retry_after_seconds"], 600)
        upstream = BridgeError("Telegram read operation failed", status=502, code="telegram_rpc_error", retry_after_seconds=30)
        self.assertNotIn("retry_after_seconds", upstream.public_payload("0123456789abcdef")["error"])

    def test_invalid_status_code_and_free_form_details_fail_closed(self):
        err = BridgeError("private\ntrace", status=599, code="bad code /srv/private", details={"reason": "private message body with spaces", "field": "chat"})
        payload = err.public_payload("0123456789abcdef")
        self.assertEqual((err.status, err.code), (500, "internal_error"))
        self.assertNotIn("private", json.dumps(payload))
        safe = BridgeError("Invalid request", status=400, code="bad_request", details={"reason": "private message body with spaces", "field": "chat", "retryable": False})
        self.assertEqual(safe.public_payload("0123456789abcdef")["error"]["details"], {"field": "chat", "retryable": False})

    def test_foreign_forged_attrs_fail_closed(self):
        class Forged(Exception):
            code = "telegram_flood_wait"
            status = 429
            retry_after = 9999
        self.assertEqual(structured_write_error(Forged(PRIVATE_MARKER)), {"error": "internal_bridge_error", "status": 500})

    def test_known_exception_class_requires_exact_code_status(self):
        self.assertEqual(structured_write_error(TelegramContractError("telegram_timeout", status=400)), {"error": "internal_bridge_error", "status": 500})
        self.assertEqual(structured_write_error(WriteSafetyError("expired_preview", status=502)), {"error": "internal_bridge_error", "status": 500})
        self.assertEqual(structured_write_error(EndpointPolicyError("rate_limited", status=400, retry_after_seconds=7)), {"error": "internal_bridge_error", "status": 500})

    def test_reviewed_retry_metadata_is_capped(self):
        self.assertEqual(structured_write_error(TelegramContractError("telegram_flood_wait", status=429, retry_after=9999)), {"error": "telegram_flood_wait", "status": 429, "retry_after_seconds": 600})
        self.assertEqual(structured_write_error(EndpointPolicyError("rate_limited", status=429, retry_after_seconds=3600)), {"error": "rate_limited", "status": 429, "retry_after_seconds": 600})

    def test_concurrent_forged_errors_are_deterministic(self):
        class Forged(Exception):
            code = "telegram_flood_wait"
            status = 429
            retry_after = 50
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(lambda _: structured_write_error(Forged(PRIVATE_MARKER)), range(64)))
        self.assertTrue(all(item == {"error": "internal_bridge_error", "status": 500} for item in results))


class AuthParserAndFailureTests(unittest.TestCase):
    def test_read_unauthorized_rejected_before_body_read(self):
        stream = ExplodingInput()
        app = BridgeApplication(config=ReadAppConfig(auth_secret=AUTH), rate_limiter=AllowAll())
        status, _, payload, _ = call_wsgi(app, "/api/v1/dialogs/list", auth=False, stream=stream)
        self.assertEqual((status, payload["error"]["code"]), (404, "not_found"))
        self.assertFalse(stream.read_called)

    def test_write_unauthorized_rejected_before_body_read(self):
        stream = ExplodingInput()
        read_app = BridgeApplication(config=ReadAppConfig(auth_secret=AUTH), rate_limiter=AllowAll())
        app = UnifiedBridgeApplication(read_app=read_app)
        status, _, payload, _ = call_wsgi(app, "/api/v1/messages/send/preview", auth=False, stream=stream)
        self.assertEqual((status, payload["error"]["code"]), (404, "not_found"))
        self.assertFalse(stream.read_called)

    def test_authorized_malformed_json_is_controlled(self):
        app = BridgeApplication(config=ReadAppConfig(auth_secret=AUTH), rate_limiter=AllowAll())
        status, _, payload, raw = call_wsgi(app, "/api/v1/dialogs/list", body=b'{"limit":')
        self.assertEqual((status, payload["error"]["code"]), (400, "malformed_json"))
        self.assertNotIn(PRIVATE_MARKER.encode(), raw)

    def test_backend_unconfigured_is_stable_503(self):
        app = BridgeApplication(config=ReadAppConfig(auth_secret=AUTH), rate_limiter=AllowAll())
        status, _, payload, _ = call_wsgi(app, "/api/v1/dialogs/list")
        self.assertEqual((status, payload["error"]["code"]), (503, "telegram_backend_unconfigured"))

    def test_timeout_contract_is_stable_504(self):
        class TimeoutBackend:
            def list_dialogs(self, **kwargs):
                del kwargs
                raise BridgeError("Telegram read timed out", status=504, code="telegram_timeout")
        app = BridgeApplication(config=ReadAppConfig(auth_secret=AUTH), backend=TimeoutBackend(), rate_limiter=AllowAll())
        status, _, payload, raw = call_wsgi(app, "/api/v1/dialogs/list")
        self.assertEqual((status, payload["error"]["code"]), (504, "telegram_timeout"))
        self.assertNotIn(PRIVATE_MARKER.encode(), raw)

    def test_foreign_backend_failure_is_generic_500(self):
        class DbFailBackend:
            def list_dialogs(self, **kwargs):
                del kwargs
                raise sqlite3.OperationalError("SELECT private_column FROM private_table /srv/private/bridge.sqlite")
        app = BridgeApplication(config=ReadAppConfig(auth_secret=AUTH), backend=DbFailBackend(), rate_limiter=AllowAll())
        status, _, payload, raw = call_wsgi(app, "/api/v1/dialogs/list")
        self.assertEqual((status, payload["error"]["code"]), (500, "internal_error"))
        self.assertNotIn(b"SELECT", raw)
        self.assertNotIn(b"/srv/private", raw)


class FilesystemAndTelegramTests(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.root = Path(self.td.name) / "private"
        self.app = BridgeApplication(config=ReadAppConfig(auth_secret=AUTH, private_root=self.root), rate_limiter=AllowAll())

    def tearDown(self):
        self.td.cleanup()

    def test_traversal_file_ref_is_opaque_404(self):
        body = json.dumps({"file_ref": "../../etc/passwd"}).encode()
        status, _, payload, raw = call_wsgi(self.app, "/api/v1/files/get", body=body)
        self.assertEqual((status, payload["error"]["code"]), (404, "file_not_found"))
        self.assertNotIn(b"etc/passwd", raw)

    def test_sqlite_registry_failure_is_generic_500(self):
        body = json.dumps({"file_ref": "A" * 16}).encode()
        with patch.object(FileRecordStore, "get", side_effect=sqlite3.OperationalError("database disk image /srv/private/files.sqlite3")):
            status, _, payload, raw = call_wsgi(self.app, "/api/v1/files/get", body=body)
        self.assertEqual((status, payload["error"]["code"]), (500, "internal_error"))
        self.assertNotIn(b"/srv/private", raw)

    def test_filesystem_open_failure_is_generic_500(self):
        ref = "A" * 16
        with patch("bridge.app.open_verified_file", side_effect=OSError("/srv/private/files/private.bin")):
            status, _, payload, raw = call_wsgi(self.app, f"/api/v1/files/{ref}", method="GET", body=b"")
        self.assertEqual((status, payload["error"]["code"]), (500, "internal_error"))
        self.assertNotIn(b"/srv/private", raw)

    def test_telethon_rpc_exception_text_is_not_public(self):
        class Client:
            async def connect(self): return None
            async def is_user_authorized(self): return True
            async def disconnect(self): return None
            def iter_dialogs(self, limit):
                del limit
                raise RuntimeError("peer @private_peer says private message body")
        backend = TelethonReadBackend(client_factory=Client, config=TelethonReadConfig(flood_wait_cap_seconds=30))
        with self.assertRaises(BridgeError) as cm:
            backend.list_dialogs(limit=10, cursor=None, query="", unread_only=False)
        self.assertEqual((cm.exception.status, cm.exception.code), (502, "telegram_rpc_error"))
        self.assertNotIn("private_peer", json.dumps(cm.exception.public_payload("0123456789abcdef")))

    def test_telethon_floodwait_is_bounded_429(self):
        class FloodWaitError(RuntimeError):
            def __init__(self):
                super().__init__("peer @private_peer private message")
                self.seconds = 9999
        class Client:
            async def connect(self): return None
            async def is_user_authorized(self): return True
            async def disconnect(self): return None
            def iter_dialogs(self, limit):
                del limit
                raise FloodWaitError()
        backend = TelethonReadBackend(client_factory=Client, config=TelethonReadConfig(flood_wait_cap_seconds=30))
        with self.assertRaises(BridgeError) as cm:
            backend.list_dialogs(limit=10, cursor=None, query="", unread_only=False)
        payload = cm.exception.public_payload("0123456789abcdef")
        self.assertEqual((cm.exception.status, cm.exception.code, payload["error"]["retry_after_seconds"]), (429, "telegram_flood_wait", 30))
        self.assertNotIn("private_peer", json.dumps(payload))


class CrashRestartAndOpenApiTests(unittest.TestCase):
    def test_calling_crash_restart_exposes_only_stable_reconciliation_code(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "writes.sqlite3"
            first = PersistentWriteStore(path)
            preview = first.create_preview(WriteAction.SEND, {"target": "@target_user", "text": "private draft"}, now=100)
            first.simulate_calling_crash_for_test(preview.token, expected_action=WriteAction.SEND, idempotency_key="idem-key-001", now=101)
            restarted = PersistentWriteStore(path)
            self.assertEqual(restarted.mark_calling_transaction_ambiguous_on_recovery(now=102), 1)
            with self.assertRaises(WriteSafetyError) as cm:
                restarted.commit(preview.token, expected_action=WriteAction.SEND, idempotency_key="idem-key-001", external_write=lambda payload: {"id": 1}, now=103)
            public = structured_write_error(cm.exception)
            self.assertEqual(public, {"error": "write_outcome_unknown_reconciliation_required", "status": 409})
            self.assertNotIn("private draft", json.dumps(public))

    def test_canonical_openapi_declares_runtime_error_envelope_and_statuses(self):
        schema = build_compatible_chatgpt_action_openapi("https://tg-api.rukadopomogy.org.ua")
        op = schema["paths"]["/api/v1/search"]["post"]
        self.assertEqual(set(op["responses"]), {"200", "400", "404", "409", "413", "415", "429", "500", "502", "503", "504"})
        error_schema = op["responses"]["502"]["content"]["application/json"]["schema"]
        detail = error_schema["properties"]["error"]
        self.assertEqual(set(error_schema["required"]), {"ok", "request_id", "error"})
        self.assertTrue({"code", "message"} <= set(detail["required"]))
        retry = op["responses"]["429"]["headers"]["Retry-After"]["schema"]
        self.assertEqual((retry["minimum"], retry["maximum"]), (1, 600))


if __name__ == "__main__":
    unittest.main()
