"""FINALWAVE-26 adversarial OpenAPI/runtime request-parity regressions.

Credential-free synthetic tests only.  They exercise the exact public WSGI boundary
without Telegram or production access and must fail closed before preview/effect.
"""
from __future__ import annotations

import io
import json
import tempfile
import unittest
from pathlib import Path

from bridge.app import BridgeApplication, ReadAppConfig
from bridge.integrated_app import UnifiedBridgeApplication, validate_unified_registry
from bridge.models import Page
from bridge.security import RateLimitDecision
from ops.dev06_api_contracts import CANONICAL_ROUTES, build_chatgpt_action_openapi, validate_runtime_parity
from ops.openapi_registry import OPERATIONS
from ops.telegram_write_adapter import (
    DeterministicFakeTelegramClient,
    TelegramRuntimeConfig,
    TelegramWriteAdapter,
)
from ops.write_endpoint_policy import FixedWindowEndpointLimiter


TOKEN = "finalwave26-synthetic-bearer-reference"
SIGNING = "finalwave26-synthetic-signing-reference"
BASE_URL = "https://tg-api.rukadopomogy.org.ua"


class _AllowReadLimiter:
    def check(self, actor: str) -> RateLimitDecision:
        del actor
        return RateLimitDecision(True, remaining=99)


class _EmptyReadBackend:
    def list_dialogs(self, **kwargs):
        del kwargs
        return Page(tuple(), None, 0)

    def history(self, **kwargs):
        del kwargs
        return Page(tuple(), None, 0)

    def search(self, **kwargs):
        del kwargs
        return Page(tuple(), None, 0)

    def get_message(self, **kwargs):
        raise AssertionError(f"unexpected get_message call: {sorted(kwargs)}")

    def download_media(self, **kwargs):
        raise AssertionError(f"unexpected download_media call: {sorted(kwargs)}")


def _request(
    app,
    path: str,
    body: object | None = None,
    *,
    method: str = "POST",
    token: str | None = TOKEN,
    raw: bytes | None = None,
    content_length: str | None = None,
):
    payload = raw if raw is not None else json.dumps(body if body is not None else {}).encode("utf-8")
    environ = {
        "REQUEST_METHOD": method,
        "PATH_INFO": path,
        "QUERY_STRING": "",
        "CONTENT_TYPE": "application/json",
        "CONTENT_LENGTH": str(len(payload)) if content_length is None else content_length,
        "wsgi.input": io.BytesIO(payload),
    }
    if token is not None:
        environ["HTTP_AUTHORIZATION"] = "Bearer " + token
    captured: dict[str, object] = {}

    def start_response(status, headers):
        captured["status_line"] = status
        captured["headers"] = dict(headers)

    output = b"".join(app(environ, start_response))
    captured["status"] = int(str(captured["status_line"]).split(" ", 1)[0])
    captured["raw"] = output
    headers = captured.get("headers") or {}
    if str(headers.get("Content-Type", "")).startswith("application/json"):
        captured["json"] = json.loads(output.decode("utf-8"))
    return captured


class Finalwave26OpenApiRuntimeParityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.client = DeterministicFakeTelegramClient()
        self.adapter = TelegramWriteAdapter(
            TelegramRuntimeConfig(
                application_id_ref=12345,
                application_hash_ref="synthetic-hash-reference",
                session_reference="synthetic-session-reference",
                synthetic_test_mode=True,
            ),
            lambda: self.client,
        )

    def _app(self, *, write_limit: int = 100) -> UnifiedBridgeApplication:
        read_app = BridgeApplication(
            config=ReadAppConfig(
                auth_secret=TOKEN,
                file_signing_secret=SIGNING,
                private_root=Path(self.tmp.name),
                public_base_url="https://example.invalid",
            ),
            backend=_EmptyReadBackend(),
            rate_limiter=_AllowReadLimiter(),
        )
        return UnifiedBridgeApplication(
            read_app=read_app,
            write_adapter=self.adapter,
            write_limiter=FixedWindowEndpointLimiter(
                limit=write_limit,
                window_seconds=60,
                clock=lambda: 120.0,
            ),
        )

    def test_live_registry_openapi_and_wsgi_inventory_are_bidirectionally_exact(self):
        self.assertEqual([], validate_runtime_parity())
        self.assertEqual([], validate_unified_registry())
        self.assertEqual(19, len(CANONICAL_ROUTES))
        self.assertEqual(17, len(OPERATIONS))
        schema = build_chatgpt_action_openapi(BASE_URL)
        action_pairs = {
            (method.upper(), path)
            for path, item in schema["paths"].items()
            for method, operation in item.items()
            if isinstance(operation, dict) and "operationId" in operation
        }
        canonical_action_pairs = {
            (route.method, route.path) for route in CANONICAL_ROUTES if route.action_visible
        }
        self.assertEqual(canonical_action_pairs, action_pairs)
        lowered = json.dumps(schema, sort_keys=True).lower()
        for private_word in ("setup", "login_code", "2fa", "session_string", "api_hash"):
            self.assertNotIn(private_word, lowered)

    def test_write_preview_runtime_rejects_openapi_type_coercions_before_preview(self):
        app = self._app()
        cases = (
            ("/api/v1/messages/reply/preview", {"chat": "@target", "reply_to_message_id": 1.9, "text": "draft"}),
            ("/api/v1/messages/reply/preview", {"chat": "@target", "reply_to_message_id": "7", "text": "draft"}),
            ("/api/v1/messages/forward/preview", {"from_chat": "@source", "to_chat": "@target", "message_ids": [20.9]}),
            ("/api/v1/messages/send/preview", {"chat": 123, "text": "draft"}),
            (
                "/api/v1/files/send/preview",
                {
                    "chat": "@target",
                    "files": [{"file_ref": "opaque-ref", "sha256": "a" * 64, "size": "12"}],
                    "caption": "",
                    "voice_note": False,
                },
            ),
            (
                "/api/v1/files/send/preview",
                {
                    "chat": "@target",
                    "files": [{"file_ref": "opaque-ref", "sha256": "a" * 64, "size": 12}],
                    "caption": "",
                    "voice_note": "false",
                },
            ),
        )
        for path, body in cases:
            with self.subTest(path=path, body=body):
                result = _request(app, path, body)
                self.assertEqual(400, result["status"], result)
                self.assertEqual([], self.client.external_writes)

    def test_content_length_zero_is_zero_bytes_not_unknown_length(self):
        app = self._app()
        result = _request(
            app,
            "/api/v1/dialogs/list",
            raw=b'{"private_debug":true}',
            content_length="0",
        )
        self.assertEqual(200, result["status"], result)

    def test_malformed_authenticated_write_attempts_consume_prebody_request_quota(self):
        app = self._app(write_limit=1)
        bad = {"chat": "@target", "text": "draft", "private_debug": True}
        first = _request(app, "/api/v1/messages/send/preview", bad)
        second = _request(app, "/api/v1/messages/send/preview", bad)
        self.assertEqual(400, first["status"], first)
        self.assertEqual(429, second["status"], second)
        self.assertGreaterEqual(int(second["headers"]["Retry-After"]), 1)
        self.assertEqual([], self.client.external_writes)

    def test_unknown_write_operation_fails_closed_without_preview_or_effect(self):
        app = self._app()
        result = _request(app, "/api/v1/messages/private-setup/preview", {"chat": "@target", "text": "draft"})
        self.assertEqual(404, result["status"], result)
        self.assertEqual([], self.client.external_writes)


if __name__ == "__main__":
    unittest.main()
