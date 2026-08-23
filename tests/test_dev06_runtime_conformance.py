from __future__ import annotations

import copy
import io
import json
import tempfile
import unittest
from pathlib import Path

from bridge.app import BridgeApplication, ReadAppConfig
from bridge.integrated_app import UnifiedBridgeApplication
from bridge.models import Page
from bridge.security import RateLimitDecision
from ops.dev06_runtime_conformance import (
    build_compatible_chatgpt_action_openapi,
    validate_action_compatibility,
    validate_action_runtime_response,
    validate_json_instance,
)
from ops.telegram_write_adapter import (
    DeterministicFakeTelegramClient,
    TelegramRuntimeConfig,
    TelegramWriteAdapter,
)
from ops.write_endpoint_policy import FixedWindowEndpointLimiter


BASE_URL = "https://tg-api.rukadopomogy.org.ua"
TOKEN = "dev06-synthetic-bearer-token-00000001"
SIGNING = "dev06-synthetic-signing-key-0000001"


class AllowReadLimiter:
    def check(self, actor: str) -> RateLimitDecision:
        del actor
        return RateLimitDecision(True, remaining=99)


class DenyReadLimiter:
    def __init__(self, retry_after_seconds: int = 7) -> None:
        self.retry_after_seconds = retry_after_seconds

    def check(self, actor: str) -> RateLimitDecision:
        del actor
        return RateLimitDecision(False, retry_after_seconds=self.retry_after_seconds, remaining=0)


class EmptyReadBackend:
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


def request(
    app,
    path: str,
    body: dict | None = None,
    *,
    method: str = "POST",
    token: str | None = TOKEN,
    content_type: str = "application/json",
    raw: bytes | None = None,
):
    payload = raw if raw is not None else json.dumps(body or {}, ensure_ascii=False).encode("utf-8")
    environ = {
        "REQUEST_METHOD": method,
        "PATH_INFO": path,
        "QUERY_STRING": "",
        "CONTENT_TYPE": content_type,
        "CONTENT_LENGTH": str(len(payload)),
        "wsgi.input": io.BytesIO(payload),
    }
    if token is not None:
        environ["HTTP_AUTHORIZATION"] = "Bearer " + token
    captured: dict[str, object] = {}

    def start_response(status, headers):
        captured["status_line"] = status
        captured["headers"] = dict(headers)

    chunks = app(environ, start_response)
    output = b"".join(chunks)
    captured["raw"] = output
    captured["status"] = int(str(captured["status_line"]).split(" ", 1)[0])
    headers = captured.get("headers") or {}
    if str(headers.get("Content-Type", "")).startswith("application/json"):
        captured["json"] = json.loads(output.decode("utf-8"))
    return captured


class RuntimeResponseConformanceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.schema = build_compatible_chatgpt_action_openapi(BASE_URL)
        self.assertEqual(validate_action_compatibility(self.schema), [])

        self.read_app = BridgeApplication(
            config=ReadAppConfig(
                auth_secret=TOKEN,
                file_signing_secret=SIGNING,
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
            write_limiter=FixedWindowEndpointLimiter(
                limit=100,
                window_seconds=60,
                clock=lambda: 120.0,
            ),
        )

    def assert_response_matches(self, operation_id: str, result: dict[str, object]) -> None:
        self.assertIn("json", result, result)
        errors = validate_action_runtime_response(
            self.schema,
            operation_id,
            int(result["status"]),
            result["headers"],
            result["json"],
        )
        self.assertEqual(errors, [], errors)

    def test_preview_token_is_response_visible_not_directionally_hidden(self):
        for operation_id in (
            "previewTelegramSend",
            "previewTelegramReply",
            "previewTelegramForward",
            "previewTelegramFiles",
        ):
            operation = next(
                op
                for item in self.schema["paths"].values()
                for op in item.values()
                if isinstance(op, dict) and op.get("operationId") == operation_id
            )
            data = operation["responses"]["200"]["content"]["application/json"]["schema"]["properties"]["data"]
            token = data["properties"]["preview_token"]
            self.assertNotIn("writeOnly", token)
            self.assertNotIn("readOnly", token)
            self.assertIn("single-use", token["description"])

    def test_actual_dialog_success_matches_generated_action_response(self):
        result = request(self.app, "/api/v1/dialogs/list", {"limit": 1})
        self.assertEqual(result["status"], 200)
        self.assert_response_matches("listTelegramDialogs", result)

    def test_actual_unauthorized_error_matches_structured_404_contract(self):
        result = request(self.app, "/api/v1/dialogs/list", {"limit": 1}, token=None)
        self.assertEqual(result["status"], 404)
        self.assertEqual(result["json"]["error"]["code"], "not_found")
        self.assert_response_matches("listTelegramDialogs", result)

    def test_actual_read_rate_limit_matches_body_and_retry_after_header(self):
        limited_read = BridgeApplication(
            config=ReadAppConfig(
                auth_secret=TOKEN,
                file_signing_secret=SIGNING,
                private_root=Path(self.tmp.name) / "limited",
                public_base_url="https://example.invalid",
            ),
            backend=EmptyReadBackend(),
            rate_limiter=DenyReadLimiter(7),
        )
        limited = UnifiedBridgeApplication(read_app=limited_read)
        result = request(limited, "/api/v1/dialogs/list", {"limit": 1})
        self.assertEqual(result["status"], 429)
        self.assertEqual(result["headers"].get("Retry-After"), "7")
        self.assertEqual(result["json"]["error"]["retry_after_seconds"], 7)
        self.assert_response_matches("listTelegramDialogs", result)

    def test_actual_content_type_failure_matches_415_contract(self):
        result = request(
            self.app,
            "/api/v1/search",
            {"text": "synthetic"},
            content_type="text/plain",
        )
        self.assertEqual(result["status"], 415)
        self.assertEqual(result["json"]["error"]["code"], "invalid_content_type")
        self.assert_response_matches("searchTelegramMessages", result)

    def test_actual_send_preview_and_commit_match_contract_and_write_once(self):
        preview = request(
            self.app,
            "/api/v1/messages/send/preview",
            {"chat": "@synthetic_target", "text": "synthetic draft"},
        )
        self.assertEqual(preview["status"], 200)
        self.assert_response_matches("previewTelegramSend", preview)
        self.assertEqual(self.client.external_writes, [])

        token = preview["json"]["data"]["preview_token"]
        commit_body = {
            "preview_token": token,
            "idempotency_key": "dev06-idempotency-000001",
            "explicit_user_command": True,
        }
        first = request(self.app, "/api/v1/messages/send/commit", commit_body)
        second = request(self.app, "/api/v1/messages/send/commit", commit_body)
        self.assertEqual(first["status"], 200)
        self.assertEqual(second["status"], 200)
        self.assert_response_matches("commitTelegramSend", first)
        self.assert_response_matches("commitTelegramSend", second)
        self.assertFalse(first["json"]["data"]["idempotent_replay"])
        self.assertTrue(second["json"]["data"]["idempotent_replay"])
        self.assertEqual(len(self.client.external_writes), 1)

    def test_instance_validator_rejects_missing_and_extra_runtime_fields(self):
        valid = request(self.app, "/api/v1/dialogs/list", {"limit": 1})
        self.assert_response_matches("listTelegramDialogs", valid)
        operation = self.schema["paths"]["/api/v1/dialogs/list"]["post"]
        response_schema = operation["responses"]["200"]["content"]["application/json"]["schema"]

        missing = copy.deepcopy(valid["json"])
        del missing["data"]
        self.assertTrue(any("REQUIRED_MISSING:$.data" in item for item in validate_json_instance(missing, response_schema)))

        extra = copy.deepcopy(valid["json"])
        extra["private_debug"] = "must never be accepted"
        self.assertTrue(any("ADDITIONAL_PROPERTY" in item for item in validate_json_instance(extra, response_schema)))

    def test_runtime_response_validator_rejects_content_type_and_retry_after_drift(self):
        result = request(self.app, "/api/v1/dialogs/list", {"limit": 1})
        bad_headers = dict(result["headers"])
        bad_headers["Content-Type"] = "text/html"
        errors = validate_action_runtime_response(
            self.schema,
            "listTelegramDialogs",
            200,
            bad_headers,
            result["json"],
        )
        self.assertIn("ACTION_RESPONSE_CONTENT_TYPE_INVALID", errors)

        limited_read = BridgeApplication(
            config=ReadAppConfig(
                auth_secret=TOKEN,
                file_signing_secret=SIGNING,
                private_root=Path(self.tmp.name) / "limited-drift",
                public_base_url="https://example.invalid",
            ),
            backend=EmptyReadBackend(),
            rate_limiter=DenyReadLimiter(9),
        )
        limited = UnifiedBridgeApplication(read_app=limited_read)
        rate = request(limited, "/api/v1/dialogs/list", {"limit": 1})
        missing_header = dict(rate["headers"])
        missing_header.pop("Retry-After")
        errors = validate_action_runtime_response(
            self.schema,
            "listTelegramDialogs",
            429,
            missing_header,
            rate["json"],
        )
        self.assertIn("RUNTIME_RETRY_AFTER_HEADER_MISSING", errors)

        mismatched = dict(rate["headers"])
        mismatched["Retry-After"] = "8"
        errors = validate_action_runtime_response(
            self.schema,
            "listTelegramDialogs",
            429,
            mismatched,
            rate["json"],
        )
        self.assertIn("RUNTIME_RETRY_AFTER_BODY_HEADER_DRIFT", errors)

    def test_runtime_response_validator_fails_closed_for_unknown_operation_and_status(self):
        result = request(self.app, "/api/v1/dialogs/list", {"limit": 1})
        unknown = validate_action_runtime_response(
            self.schema,
            "privateSetupOperation",
            200,
            result["headers"],
            result["json"],
        )
        self.assertIn("ACTION_OPERATION_NOT_UNIQUE", unknown)

        undeclared = validate_action_runtime_response(
            self.schema,
            "listTelegramDialogs",
            418,
            result["headers"],
            result["json"],
        )
        self.assertIn("RESPONSE_STATUS_UNDECLARED", undeclared)


if __name__ == "__main__":
    unittest.main()
