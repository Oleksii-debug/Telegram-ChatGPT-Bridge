# -*- coding: utf-8 -*-
"""DEV_C gates for the current unified DEV_A validation head.

All Telegram behavior here uses the deterministic synthetic adapter.  Nothing in
this module performs live Telegram, HOSTiQ or ChatGPT Action I/O.
"""
from __future__ import annotations

import io
import json
import os
import tempfile
import unittest
from pathlib import Path

try:
    from bridge.app import BridgeApplication, ReadAppConfig
    from bridge.integrated_app import UnifiedBridgeApplication, validate_unified_registry
    from bridge.models import Page
    from bridge.routes import registry_snapshot
    from bridge.security import RateLimitDecision
    from ops import openapi_registry
    from ops.openapi_registry import OperationClass
    from ops.telegram_write_adapter import (
        DeterministicFakeTelegramClient,
        TelegramRuntimeConfig,
        TelegramWriteAdapter,
    )
    from ops.write_endpoint_policy import FixedWindowEndpointLimiter
    CANDIDATE_COMPONENTS_AVAILABLE = True
except (ImportError, ModuleNotFoundError):
    CANDIDATE_COMPONENTS_AVAILABLE = False


TEST_AUTH_SECRET = "devc-placeholder-auth-secret-0001"
TEST_SIGNING_SECRET = "devc-placeholder-signing-secret-0001"


class AllowReadLimiter:
    def check(self, _actor_class):
        return RateLimitDecision(True, remaining=99)


class EmptyReadBackend:
    def list_dialogs(self, **_kwargs):
        return Page(tuple(), None, 0)

    def history(self, **_kwargs):
        return Page(tuple(), None, 0)

    def search(self, **_kwargs):
        return Page(tuple(), None, 0)

    def get_message(self, **_kwargs):
        raise AssertionError("not used by DEV_C integrated QA")

    def download_media(self, **_kwargs):
        raise AssertionError("not used by DEV_C integrated QA")


def _request(app, path: str, body: dict | None = None, *, method: str = "POST", auth: bool = True) -> dict:
    raw = json.dumps(body or {}, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    environ = {
        "REQUEST_METHOD": method,
        "PATH_INFO": path,
        "QUERY_STRING": "",
        "wsgi.input": io.BytesIO(raw),
        "CONTENT_TYPE": "application/json",
        "CONTENT_LENGTH": str(len(raw)),
    }
    if auth:
        environ["HTTP_AUTHORIZATION"] = f"Bearer {TEST_AUTH_SECRET}"
    seen: dict = {}

    def start_response(status, headers):
        seen["status"] = status
        seen["headers"] = dict(headers)

    payload = b"".join(app(environ, start_response))
    seen["raw"] = payload
    content_type = seen["headers"].get("Content-Type", "")
    if content_type.startswith("application/json"):
        seen["payload"] = json.loads(payload.decode("utf-8"))
    return seen


@unittest.skipUnless(CANDIDATE_COMPONENTS_AVAILABLE, "unified candidate components not present on this validation head")
class IntegratedCandidateContractTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.read_app = BridgeApplication(
            config=ReadAppConfig(
                auth_secret=TEST_AUTH_SECRET,
                file_signing_secret=TEST_SIGNING_SECRET,
                private_root=Path(self.tmp.name),
                public_base_url="https://bridge.example.invalid",
            ),
            backend=EmptyReadBackend(),
            rate_limiter=AllowReadLimiter(),
        )
        self.fake_client = DeterministicFakeTelegramClient()
        self.write_adapter = TelegramWriteAdapter(
            TelegramRuntimeConfig(
                application_id_ref=12345,
                application_hash_ref="synthetic-hash-reference",
                session_reference="synthetic-session-reference",
                synthetic_test_mode=True,
            ),
            lambda: self.fake_client,
        )
        self.app = UnifiedBridgeApplication(
            read_app=self.read_app,
            write_adapter=self.write_adapter,
            write_limiter=FixedWindowEndpointLimiter(limit=100, window_seconds=60, clock=lambda: 120.0),
        )

    @staticmethod
    def _read_registry_keys() -> set[tuple[str, str]]:
        return {(str(item["method"]).upper(), str(item["path"])) for item in registry_snapshot("/api/v1")}

    @staticmethod
    def _action_keys() -> set[tuple[str, str]]:
        return {(str(item.method).upper(), str(item.path)) for item in openapi_registry.OPERATIONS}

    def test_every_action_operation_resolves_on_unified_runtime_dispatch(self):
        """H1/H4 prerequisite: no generated Action operation may be a phantom."""
        unresolved = []
        for spec in openapi_registry.OPERATIONS:
            resolved = self.app._operation_for_request(str(spec.method).upper(), str(spec.path))
            if resolved is None or resolved.operation_id != spec.operation_id:
                unresolved.append((str(spec.method).upper(), str(spec.path)))
        self.assertEqual([], unresolved)
        self.assertEqual(
            {
                (str(spec.method).upper(), str(spec.path))
                for spec in openapi_registry.OPERATIONS
                if spec.operation_class is OperationClass.READ
            },
            set(validate_unified_registry()),
        )

    def test_all_four_write_previews_reach_unified_handler_without_external_write(self):
        """F1-F4/H4 prerequisite: all preview actions exist and are side-effect free."""
        assert self.read_app.files is not None
        file_path = self.read_app.files.root / "voice.ogg"
        file_path.write_bytes(b"synthetic-voice-bytes")
        os.chmod(file_path, 0o600)
        record = self.read_app.files.add(file_path, name="voice.ogg", mime_type="audio/ogg")

        cases = (
            ("/api/v1/messages/send/preview", {"chat": "100", "text": "preview"}),
            ("/api/v1/messages/reply/preview", {"chat": "100", "reply_to_message_id": 1, "text": "reply"}),
            ("/api/v1/messages/forward/preview", {"from_chat": "200", "to_chat": "100", "message_ids": [1]}),
            (
                "/api/v1/files/send/preview",
                {
                    "chat": "100",
                    "files": [{"file_ref": record.file_ref, "sha256": record.sha256, "size": record.size}],
                    "caption": "",
                    "voice_note": True,
                },
            ),
        )
        for path, body in cases:
            with self.subTest(path=path):
                response = _request(self.app, path, body)
                self.assertTrue(str(response["status"]).startswith("200"), response)
                self.assertIn("preview_token", response["payload"]["data"])
        self.assertEqual([], self.fake_client.external_writes)
        self.assertEqual(0, self.fake_client.connect_count)

    def test_commit_requires_explicit_current_user_command_and_replay_is_exactly_once(self):
        preview = _request(
            self.app,
            "/api/v1/messages/send/preview",
            {"chat": "100", "text": "synthetic exactly once"},
        )["payload"]["data"]
        blocked = _request(
            self.app,
            "/api/v1/messages/send/commit",
            {
                "preview_token": preview["preview_token"],
                "idempotency_key": "devc-idem-000001",
                "explicit_user_command": False,
            },
        )
        self.assertTrue(str(blocked["status"]).startswith("409"), blocked)
        self.assertEqual([], self.fake_client.external_writes)

        body = {
            "preview_token": preview["preview_token"],
            "idempotency_key": "devc-idem-000001",
            "explicit_user_command": True,
        }
        first = _request(self.app, "/api/v1/messages/send/commit", body)
        second = _request(self.app, "/api/v1/messages/send/commit", body)
        self.assertTrue(str(first["status"]).startswith("200"), first)
        self.assertTrue(str(second["status"]).startswith("200"), second)
        self.assertFalse(first["payload"]["data"]["idempotent_replay"])
        self.assertTrue(second["payload"]["data"]["idempotent_replay"])
        self.assertEqual(1, len(self.fake_client.external_writes))

    def test_unauthenticated_write_is_hidden_before_private_body_processing(self):
        response = _request(
            self.app,
            "/api/v1/messages/send/preview",
            {"chat": "100", "text": "private synthetic body"},
            auth=False,
        )
        self.assertTrue(str(response["status"]).startswith("404"), response)
        self.assertEqual([], self.fake_client.external_writes)

    def test_openapi_schema_is_deterministic_and_commit_strict(self):
        first = openapi_registry.build_action_openapi("https://bridge.example.invalid")
        second = openapi_registry.build_action_openapi("https://bridge.example.invalid")
        self.assertEqual(first, second)
        self.assertNotIn("setup", " ".join(first.get("paths", {})).casefold())
        for spec in openapi_registry.OPERATIONS:
            operation = first["paths"][spec.path][str(spec.method).lower()]
            if spec.operation_class is not OperationClass.WRITE_COMMIT:
                continue
            schema = operation["requestBody"]["content"]["application/json"]["schema"]
            self.assertFalse(schema.get("additionalProperties", True))
            self.assertEqual(
                {"preview_token", "idempotency_key", "explicit_user_command"},
                set(schema.get("required", [])),
            )
            explicit = schema["properties"]["explicit_user_command"]
            self.assertIs(explicit.get("const"), True)
            self.assertIs(operation.get("x-openai-isConsequential"), True)

    def test_read_router_non_action_exclusions_are_only_health_and_binary_serving(self):
        read = self._read_registry_keys()
        action = self._action_keys()
        extra = read - action
        self.assertEqual(
            {("GET", "/health"), ("GET", "/api/v1/files/{file_ref}")},
            extra,
        )


if __name__ == "__main__":
    unittest.main()
