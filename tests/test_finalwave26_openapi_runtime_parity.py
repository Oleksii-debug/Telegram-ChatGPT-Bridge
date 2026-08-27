"""FINALWAVE-26 strict generated-OpenAPI ↔ write-runtime parity tests.

Credential-free synthetic tests only. They exercise the production request guard
without Telegram or production access and require rejection before preview/effect.
"""
from __future__ import annotations

import io
import json
import tempfile
import unittest
from pathlib import Path

from bridge.action_request_guard import ActionRequestGuard, validate_action_request
from bridge.app import BridgeApplication, ReadAppConfig
from bridge.integrated_app import UnifiedBridgeApplication, validate_unified_registry
from bridge.models import Page
from bridge.security import RateLimitDecision
from ops.dev06_api_contracts import ApiExposure, CANONICAL_ROUTES, build_chatgpt_action_openapi, validate_runtime_parity
from ops.openapi_registry import OPERATIONS, OperationClass
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


class _PoisonStream:
    def __init__(self):
        self.read_count = 0

    def read(self, size=-1):
        self.read_count += 1
        raise AssertionError(f"unauthorized body must not be read: size={size}")


def _request(app, path: str, body: object | None = None, *, token: str | None = TOKEN, stream=None):
    payload = json.dumps(body if body is not None else {}).encode("utf-8")
    environ = {
        "REQUEST_METHOD": "POST",
        "PATH_INFO": path,
        "QUERY_STRING": "",
        "CONTENT_TYPE": "application/json",
        "CONTENT_LENGTH": str(len(payload)),
        "wsgi.input": stream if stream is not None else io.BytesIO(payload),
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

    def _app(self) -> ActionRequestGuard:
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
        unified = UnifiedBridgeApplication(
            read_app=read_app,
            write_adapter=self.adapter,
            write_limiter=FixedWindowEndpointLimiter(limit=100, window_seconds=60, clock=lambda: 120.0),
        )
        return ActionRequestGuard(unified)

    def test_registry_openapi_and_wsgi_inventory_are_bidirectionally_exact(self):
        self.assertEqual([], validate_runtime_parity())
        expected_read_routes = tuple(
            sorted(
                (spec.method.upper(), spec.path)
                for spec in OPERATIONS
                if spec.operation_class is OperationClass.READ
            )
        )
        self.assertEqual(expected_read_routes, validate_unified_registry())
        self.assertEqual(19, len(CANONICAL_ROUTES))
        self.assertEqual(17, len(OPERATIONS))
        schema = build_chatgpt_action_openapi(BASE_URL)
        action_pairs = {
            (method.upper(), path)
            for path, item in schema["paths"].items()
            for method, operation in item.items()
            if isinstance(operation, dict) and "operationId" in operation
        }
        self.assertEqual(
            {(route.method, route.path) for route in CANONICAL_ROUTES if route.exposure is ApiExposure.ACTION},
            action_pairs,
        )
        lowered = json.dumps(schema, sort_keys=True).lower()
        for private_word in ("setup", "login_code", "2fa", "session_string", "api_hash"):
            self.assertNotIn(private_word, lowered)

    def test_every_write_operation_has_the_same_runtime_request_schema_source(self):
        write_specs = [
            spec for spec in OPERATIONS
            if spec.operation_class in {OperationClass.WRITE_PREVIEW, OperationClass.WRITE_COMMIT}
        ]
        self.assertEqual(8, len(write_specs))
        for spec in write_specs:
            with self.subTest(operation_id=spec.operation_id):
                # Empty object must produce at least one required-field error for
                # every write operation, proving a concrete canonical schema exists.
                self.assertTrue(validate_action_request(spec, {}))

    def test_all_preview_families_reject_openapi_type_coercions_before_preview(self):
        app = self._app()
        cases = (
            ("/api/v1/messages/send/preview", {"chat": 123, "text": "draft"}),
            ("/api/v1/messages/send/preview", {"chat": "@target", "text": 123}),
            ("/api/v1/messages/reply/preview", {"chat": "@target", "reply_to_message_id": 1.9, "text": "draft"}),
            ("/api/v1/messages/reply/preview", {"chat": "@target", "reply_to_message_id": "7", "text": "draft"}),
            ("/api/v1/messages/forward/preview", {"from_chat": "@source", "to_chat": "@target", "message_ids": [20.9]}),
            ("/api/v1/messages/forward/preview", {"from_chat": "@source", "to_chat": 7, "message_ids": [20]}),
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
            (
                "/api/v1/files/send/preview",
                {
                    "chat": "@target",
                    "files": [{"file_ref": 9, "sha256": "a" * 64, "size": 12}],
                    "caption": "",
                    "voice_note": False,
                },
            ),
        )
        for path, body in cases:
            with self.subTest(path=path, body=body):
                result = _request(app, path, body)
                self.assertEqual(400, result["status"], result)
                self.assertEqual("invalid_request_contract", result["json"]["error"]["code"])
                self.assertEqual([], self.client.external_writes)
                self.assertNotIn("@target", result["raw"].decode("utf-8"))

    def test_all_commit_families_require_exact_boolean_true_without_coercion(self):
        app = self._app()
        commit_paths = (
            "/api/v1/messages/send/commit",
            "/api/v1/messages/reply/commit",
            "/api/v1/messages/forward/commit",
            "/api/v1/files/send/commit",
        )
        for path in commit_paths:
            for value in (1, "true", False):
                with self.subTest(path=path, value=value):
                    result = _request(
                        app,
                        path,
                        {
                            "preview_token": "p" * 32,
                            "idempotency_key": "idem-key-0001",
                            "explicit_user_command": value,
                        },
                    )
                    self.assertEqual(400, result["status"], result)
                    self.assertEqual("invalid_request_contract", result["json"]["error"]["code"])
                    self.assertEqual([], self.client.external_writes)

    def test_valid_preview_families_preserve_existing_zero_effect_semantics(self):
        app = self._app()
        valid = (
            ("/api/v1/messages/send/preview", {"chat": "@target", "text": "synthetic draft"}, "SEND"),
            (
                "/api/v1/messages/reply/preview",
                {"chat": "@target", "reply_to_message_id": 7, "text": "synthetic draft"},
                "REPLY",
            ),
            (
                "/api/v1/messages/forward/preview",
                {"from_chat": "@source", "to_chat": "@target", "message_ids": [7, 8]},
                "FORWARD",
            ),
            (
                "/api/v1/files/send/preview",
                {
                    "chat": "@target",
                    "files": [{"file_ref": "opaque-ref", "sha256": "a" * 64, "size": 12}],
                    "caption": "",
                    "voice_note": False,
                },
                "SEND_FILES",
            ),
        )
        for path, body, action in valid:
            with self.subTest(path=path):
                result = _request(app, path, body)
                self.assertEqual(200, result["status"], result)
                self.assertEqual(action, result["json"]["data"]["action"])
                self.assertTrue(result["json"]["data"]["preview_token"])
                self.assertEqual([], self.client.external_writes)

    def test_unauthorized_write_is_hidden_before_guard_reads_body(self):
        app = self._app()
        poison = _PoisonStream()
        result = _request(
            app,
            "/api/v1/messages/send/preview",
            {"chat": "@target", "text": "draft"},
            token=None,
            stream=poison,
        )
        self.assertEqual(404, result["status"], result)
        self.assertEqual(0, poison.read_count)
        self.assertEqual([], self.client.external_writes)

    def test_read_action_passes_through_guard_without_write_semantics(self):
        app = self._app()
        result = _request(app, "/api/v1/dialogs/list", {})
        self.assertEqual(200, result["status"], result)
        self.assertEqual([], self.client.external_writes)

    def test_unknown_write_like_operation_fails_closed_without_preview_or_effect(self):
        app = self._app()
        result = _request(app, "/api/v1/messages/private-setup/preview", {"chat": "@target", "text": "draft"})
        self.assertEqual(404, result["status"], result)
        self.assertEqual([], self.client.external_writes)


if __name__ == "__main__":
    unittest.main()
