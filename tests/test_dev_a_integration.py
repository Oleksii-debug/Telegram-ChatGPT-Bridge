from __future__ import annotations

import io
import json
import os
import tempfile
import unittest
from pathlib import Path

import bridge
import bridge.app as app_module
from bridge.app import BridgeApplication, ReadAppConfig
from bridge.integrated_app import UnifiedBridgeApplication, validate_unified_registry
from bridge.models import Page
from bridge.security import RateLimitDecision
from ops.openapi_registry import OPERATIONS, OperationClass, build_action_openapi
from ops.telegram_write_adapter import DeterministicFakeTelegramClient, TelegramRuntimeConfig, TelegramWriteAdapter
from ops.write_endpoint_policy import FixedWindowEndpointLimiter


TOKEN = "dev-a-test-bearer-token-000000000001"
SIGN = "dev-a-test-signing-secret-0000000001"


class AllowReadLimiter:
    def check(self, actor):
        return RateLimitDecision(True, remaining=99)


class EmptyReadBackend:
    def list_dialogs(self, **kwargs):
        return Page(tuple(), None, 0)

    def history(self, **kwargs):
        return Page(tuple(), None, 0)

    def search(self, **kwargs):
        return Page(tuple(), None, 0)

    def get_message(self, **kwargs):
        raise AssertionError("not used in DEV_A integration tests")

    def download_media(self, **kwargs):
        raise AssertionError("not used in DEV_A integration tests")


def request(app, path, body=None, *, method="POST", token=TOKEN, raw=None):
    payload = raw if raw is not None else json.dumps(body or {}, ensure_ascii=False).encode("utf-8")
    environ = {
        "REQUEST_METHOD": method,
        "PATH_INFO": path,
        "QUERY_STRING": "",
        "CONTENT_TYPE": "application/json",
        "CONTENT_LENGTH": str(len(payload)),
        "wsgi.input": io.BytesIO(payload),
    }
    if token is not None:
        environ["HTTP_AUTHORIZATION"] = "Bearer " + token
    captured = {}

    def start_response(status, headers):
        captured["status"] = status
        captured["headers"] = dict(headers)

    chunks = app(environ, start_response)
    output = b"".join(chunks)
    captured["raw"] = output
    if captured["headers"].get("Content-Type", "").startswith("application/json"):
        captured["json"] = json.loads(output.decode("utf-8"))
    return captured


class UnifiedReleaseCandidateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.read_app = BridgeApplication(
            config=ReadAppConfig(
                auth_secret=TOKEN,
                file_signing_secret=SIGN,
                private_root=Path(self.tmp.name),
                public_base_url="https://example.invalid",
            ),
            backend=EmptyReadBackend(),
            rate_limiter=AllowReadLimiter(),
        )
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
        self.app = UnifiedBridgeApplication(
            read_app=self.read_app,
            write_adapter=self.adapter,
            write_limiter=FixedWindowEndpointLimiter(limit=100, window_seconds=60, clock=lambda: 120.0),
        )

    def _preview(self, path, body):
        result = request(self.app, path, body)
        self.assertTrue(result["status"].startswith("200"), result)
        return result["json"]["data"]

    def _commit(self, path, token, key="idem-key-000001", explicit=True):
        return request(
            self.app,
            path,
            {
                "preview_token": token,
                "idempotency_key": key,
                "explicit_user_command": explicit,
            },
        )

    def test_recovered_bridge_app_import_target_now_exports_lazy_unified_entrypoint(self):
        from bridge import runtime_wsgi

        self.assertIs(bridge.application, app_module.application)
        self.assertIs(app_module.application, runtime_wsgi.application)
        self.assertEqual(app_module.application.__module__, "bridge.runtime_wsgi")

    def test_canonical_read_registry_and_openapi_runtime_paths_are_exactly_equal(self):
        parity = set(validate_unified_registry())
        schema_reads = {
            (spec.method.upper(), spec.path)
            for spec in OPERATIONS
            if spec.operation_class is OperationClass.READ
        }
        self.assertEqual(parity, schema_reads)
        document = build_action_openapi("https://example.invalid")
        self.assertEqual(set(document["paths"]), {spec.path for spec in OPERATIONS})

    def test_read_operation_delegates_to_existing_dev3_core(self):
        result = request(self.app, "/api/v1/dialogs/list", {"limit": 1})
        self.assertTrue(result["status"].startswith("200"))
        self.assertEqual(result["json"]["data"]["items"], [])

    def test_unified_health_includes_write_readiness_without_private_values(self):
        result = request(self.app, "/health", method="GET", token=None, raw=b"")
        self.assertTrue(result["status"].startswith("200"))
        self.assertTrue(result["json"]["ready"])
        self.assertEqual(result["json"]["components"]["telegram_writer"], "configured")
        serialized = result["raw"].decode("utf-8")
        self.assertNotIn(TOKEN, serialized)
        self.assertNotIn("synthetic-session-reference", serialized)

    def test_preview_requires_bearer_before_parsing_private_body(self):
        private = "VERY_PRIVATE_PREVIEW_TEXT"
        result = request(
            self.app,
            "/api/v1/messages/send/preview",
            raw=("{bad-json:" + private).encode("utf-8"),
            token=None,
        )
        self.assertTrue(result["status"].startswith("404"))
        self.assertNotIn(private, result["raw"].decode("utf-8"))
        self.assertEqual(self.client.connect_count, 0)

    def test_send_preview_has_zero_telegram_side_effects(self):
        data = self._preview(
            "/api/v1/messages/send/preview",
            {"chat": "@target_user", "text": "Привіт, світе"},
        )
        self.assertEqual(data["action"], "SEND")
        self.assertEqual(data["preview"]["text"], "Привіт, світе")
        self.assertGreaterEqual(len(data["preview_token"]), 24)
        self.assertEqual(self.client.connect_count, 0)
        self.assertEqual(self.client.external_writes, [])

    def test_commit_requires_explicit_current_user_command(self):
        preview = self._preview(
            "/api/v1/messages/send/preview",
            {"chat": "@target_user", "text": "do not infer approval"},
        )
        result = self._commit(
            "/api/v1/messages/send/commit",
            preview["preview_token"],
            explicit=False,
        )
        self.assertTrue(result["status"].startswith("409"))
        self.assertEqual(result["json"]["error"]["code"], "explicit_user_commit_required")
        self.assertEqual(self.client.external_writes, [])

    def test_send_commit_and_exact_replay_produce_one_external_write(self):
        preview = self._preview(
            "/api/v1/messages/send/preview",
            {"chat": "@target_user", "text": "exactly once"},
        )
        first = self._commit(
            "/api/v1/messages/send/commit",
            preview["preview_token"],
            key="idem-send-000001",
        )
        second = self._commit(
            "/api/v1/messages/send/commit",
            preview["preview_token"],
            key="idem-send-000001",
        )
        self.assertTrue(first["status"].startswith("200"))
        self.assertTrue(second["status"].startswith("200"))
        self.assertFalse(first["json"]["data"]["idempotent_replay"])
        self.assertTrue(second["json"]["data"]["idempotent_replay"])
        self.assertEqual(len(self.client.external_writes), 1)
        self.assertEqual(first["json"]["data"]["result"]["operation"], "SEND")

    def test_writer_unconfigured_rejects_before_preview_is_consumed(self):
        app = UnifiedBridgeApplication(
            read_app=self.read_app,
            write_adapter=None,
            write_limiter=FixedWindowEndpointLimiter(limit=100, window_seconds=60, clock=lambda: 120.0),
        )
        preview = request(
            app,
            "/api/v1/messages/send/preview",
            {"chat": "@target_user", "text": "preserve preview"},
        )["json"]["data"]
        blocked = request(
            app,
            "/api/v1/messages/send/commit",
            {"preview_token": preview["preview_token"], "idempotency_key": "idem-writer-0001", "explicit_user_command": True},
        )
        self.assertTrue(blocked["status"].startswith("503"))
        self.assertEqual(blocked["json"]["error"]["code"], "telegram_writer_unconfigured")
        app.write_adapter = self.adapter
        allowed = request(
            app,
            "/api/v1/messages/send/commit",
            {"preview_token": preview["preview_token"], "idempotency_key": "idem-writer-0001", "explicit_user_command": True},
        )
        self.assertTrue(allowed["status"].startswith("200"))
        self.assertEqual(len(self.client.external_writes), 1)

    def test_reply_forward_and_file_send_reach_correct_adapter_methods_only_after_commit(self):
        reply = self._preview(
            "/api/v1/messages/reply/preview",
            {"chat": "100", "reply_to_message_id": 10, "text": "reply"},
        )
        self.assertEqual(self.client.external_writes, [])
        reply_result = self._commit(
            "/api/v1/messages/reply/commit",
            reply["preview_token"],
            key="idem-reply-0001",
        )
        self.assertTrue(reply_result["status"].startswith("200"))
        self.assertEqual(self.client.external_writes[-1]["reply_to"], 10)

        forward = self._preview(
            "/api/v1/messages/forward/preview",
            {"from_chat": "200", "to_chat": "100", "message_ids": [20, 21]},
        )
        forward_result = self._commit(
            "/api/v1/messages/forward/commit",
            forward["preview_token"],
            key="idem-forward-0001",
        )
        self.assertTrue(forward_result["status"].startswith("200"))
        self.assertEqual(self.client.external_writes[-1]["kind"], "forward")
        self.assertEqual(self.client.external_writes[-1]["count"], 2)

        assert self.read_app.files is not None
        file_path = self.read_app.files.root / "voice.ogg"
        file_path.write_bytes(b"voice-bytes")
        os.chmod(file_path, 0o600)
        record = self.read_app.files.add(file_path, name="voice.ogg", mime_type="audio/ogg")
        files = self._preview(
            "/api/v1/files/send/preview",
            {
                "chat": "100",
                "files": [{"file_ref": record.file_ref, "sha256": record.sha256, "size": record.size}],
                "caption": "",
                "voice_note": True,
            },
        )
        self.assertEqual(files["preview"]["files"][0]["file_ref"], record.file_ref)
        files_result = self._commit(
            "/api/v1/files/send/commit",
            files["preview_token"],
            key="idem-files-000001",
        )
        self.assertTrue(files_result["status"].startswith("200"))
        self.assertEqual(self.client.external_writes[-1]["kind"], "files")
        self.assertTrue(self.client.external_writes[-1]["voice_note"])

    def test_commit_route_cannot_consume_preview_for_another_action(self):
        preview = self._preview(
            "/api/v1/messages/send/preview",
            {"chat": "@target_user", "text": "wrong route"},
        )
        result = self._commit(
            "/api/v1/messages/reply/commit",
            preview["preview_token"],
            key="idem-mismatch-001",
        )
        self.assertTrue(result["status"].startswith("409"))
        self.assertEqual(result["json"]["error"]["code"], "preview_action_mismatch")
        self.assertEqual(self.client.external_writes, [])

    def test_preview_rejects_unknown_top_level_and_nested_file_fields(self):
        top = request(
            self.app,
            "/api/v1/messages/send/preview",
            {"chat": "@target_user", "text": "x", "unexpected": "private"},
        )
        self.assertEqual(top["json"]["error"]["code"], "unknown_field")
        nested = request(
            self.app,
            "/api/v1/files/send/preview",
            {"chat": "100", "files": [{"file_ref": "abc", "sha256": "0" * 64, "size": 1, "path": "/tmp/no"}]},
        )
        self.assertEqual(nested["json"]["error"]["code"], "unknown_field")
        self.assertNotIn("/tmp/no", nested["raw"].decode("utf-8"))

    def test_write_rate_limit_is_operation_scoped_and_bounded(self):
        app = UnifiedBridgeApplication(
            read_app=self.read_app,
            write_adapter=self.adapter,
            write_limiter=FixedWindowEndpointLimiter(limit=1, window_seconds=60, clock=lambda: 120.0),
        )
        first = request(app, "/api/v1/messages/send/preview", {"chat": "@target_user", "text": "one"})
        second = request(app, "/api/v1/messages/send/preview", {"chat": "@target_user", "text": "two"})
        self.assertTrue(first["status"].startswith("200"))
        self.assertTrue(second["status"].startswith("429"))
        self.assertEqual(second["json"]["error"]["code"], "rate_limited")
        self.assertGreaterEqual(second["json"]["error"]["retry_after_seconds"], 1)
        self.assertEqual(self.client.external_writes, [])

    def test_audit_metadata_never_contains_private_preview_body_or_tokens(self):
        private = "PRIVATE_BODY_DEV_A_123"
        preview = self._preview(
            "/api/v1/messages/send/preview",
            {"chat": "@target_user", "text": private},
        )
        self._commit(
            "/api/v1/messages/send/commit",
            preview["preview_token"],
            key="idem-audit-00001",
        )
        encoded = json.dumps(self.read_app.audit.events, ensure_ascii=False)
        self.assertNotIn(private, encoded)
        self.assertNotIn(preview["preview_token"], encoded)
        self.assertNotIn(TOKEN, encoded)
        self.assertNotIn("@target_user", encoded)

    def test_default_write_policy_fails_closed_without_explicit_limiter(self):
        app = UnifiedBridgeApplication(read_app=self.read_app, write_adapter=self.adapter)
        result = request(app, "/api/v1/messages/send/preview", {"chat": "@target_user", "text": "blocked"})
        self.assertTrue(result["status"].startswith("503"))
        self.assertEqual(result["json"]["error"]["code"], "write_rate_limiter_unconfigured")
        self.assertEqual(self.client.external_writes, [])


if __name__ == "__main__":
    unittest.main()
