from __future__ import annotations

import io
import json
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from bridge.app import BridgeApplication, ReadAppConfig
from bridge.integrated_app import UnifiedBridgeApplication
from bridge.models import DialogRecord, EntityRef, MediaRecord, MessageRecord, Page
from bridge.security import RateLimitDecision
from ops.dev06_api_contracts import ApiExposure, CANONICAL_ROUTES, canonical_action
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
TOKEN = "finalwave54-synthetic-bearer-token-00000001"
SIGNING = "finalwave54-synthetic-signing-key-0000001"


class AllowReadLimiter:
    def check(self, actor: str) -> RateLimitDecision:
        del actor
        return RateLimitDecision(True, remaining=99)


class DenyReadLimiter:
    def __init__(self, retry_after_seconds: int = 7) -> None:
        self.retry_after_seconds = retry_after_seconds

    def check(self, actor: str) -> RateLimitDecision:
        del actor
        return RateLimitDecision(
            False,
            retry_after_seconds=self.retry_after_seconds,
            remaining=0,
        )


class FullFakeReadBackend:
    """Synthetic read/media backend with no network or private Telegram data."""

    SOURCE_REF = "tg_2_0123456789abcdefabcd"

    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.dialogs = (
            DialogRecord(
                "2",
                "group",
                "Синтетичний діалог",
                "synthetic_group",
                1,
                False,
                "2026-08-21T09:00:00+00:00",
            ),
        )
        self.message = MessageRecord(
            20,
            "2",
            "2026-08-21T09:00:00+00:00",
            "Синтетичне повідомлення",
            EntityRef("200", "user", "Synthetic Sender", "source_user"),
            media=(
                MediaRecord(
                    "document",
                    self.SOURCE_REF,
                    "synthetic.txt",
                    "text/plain",
                    3,
                ),
            ),
        )

    def list_dialogs(self, **kwargs: Any) -> Page:
        self.calls.append(("dialogs", dict(kwargs)))
        return Page(self.dialogs[: kwargs["limit"]], None, len(self.dialogs))

    def history(self, **kwargs: Any) -> Page:
        self.calls.append(("history", dict(kwargs)))
        return Page((self.message,), None, 1)

    def search(self, **kwargs: Any) -> Page:
        self.calls.append(("search", dict(kwargs)))
        return Page((self.message,), None, 1)

    def get_message(self, **kwargs: Any) -> MessageRecord:
        self.calls.append(("message", dict(kwargs)))
        return self.message

    def download_media(self, **kwargs: Any) -> dict[str, str]:
        self.calls.append(("download", dict(kwargs)))
        destination = Path(kwargs["destination"])
        destination.write_bytes(b"abc")
        return {"path": str(destination)}


def wsgi_request(
    app: Any,
    path: str,
    body: dict[str, Any] | None = None,
    *,
    method: str = "POST",
    token: str | None = TOKEN,
    content_type: str = "application/json",
    raw: bytes | None = None,
) -> dict[str, Any]:
    payload = raw if raw is not None else json.dumps(body or {}, ensure_ascii=False).encode("utf-8")
    environ: dict[str, Any] = {
        "REQUEST_METHOD": method,
        "PATH_INFO": path,
        "QUERY_STRING": "",
        "CONTENT_TYPE": content_type,
        "CONTENT_LENGTH": str(len(payload)),
        "wsgi.input": io.BytesIO(payload),
    }
    if token is not None:
        environ["HTTP_AUTHORIZATION"] = "Bearer " + token

    captured: dict[str, Any] = {}

    def start_response(status: str, headers: list[tuple[str, str]]) -> None:
        captured["status_line"] = status
        captured["headers"] = dict(headers)

    output = b"".join(app(environ, start_response))
    captured["raw"] = output
    captured["status"] = int(captured["status_line"].split(" ", 1)[0])
    if str(captured["headers"].get("Content-Type", "")).startswith("application/json"):
        captured["json"] = json.loads(output.decode("utf-8"))
    return captured


class ActionMockE2ETests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.schema = build_compatible_chatgpt_action_openapi(BASE_URL)
        self.assertEqual(validate_action_compatibility(self.schema), [])
        self.backend = FullFakeReadBackend()
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
        self.app = self._build_app()

    def _build_app(
        self,
        *,
        read_limiter: Any | None = None,
        write_limiter: Any | None = None,
    ) -> UnifiedBridgeApplication:
        read_app = BridgeApplication(
            config=ReadAppConfig(
                auth_secret=TOKEN,
                file_signing_secret=SIGNING,
                private_root=self.root,
                public_base_url="https://example.invalid",
            ),
            backend=self.backend,
            rate_limiter=read_limiter or AllowReadLimiter(),
        )
        return UnifiedBridgeApplication(
            read_app=read_app,
            write_adapter=self.adapter,
            write_limiter=write_limiter
            or FixedWindowEndpointLimiter(
                limit=1000,
                window_seconds=60,
                clock=lambda: 120.0,
            ),
        )

    def _operation(self, operation_id: str) -> dict[str, Any]:
        route = canonical_action(operation_id)
        return self.schema["paths"][route.path][route.method.lower()]

    def _request_schema(self, operation_id: str) -> dict[str, Any]:
        return self._operation(operation_id)["requestBody"]["content"]["application/json"]["schema"]

    def _assert_request_matches_schema(
        self,
        operation_id: str,
        body: dict[str, Any],
    ) -> None:
        errors = validate_json_instance(body, self._request_schema(operation_id))
        self.assertEqual(errors, [], (operation_id, errors))

    def _invoke(
        self,
        operation_id: str,
        body: dict[str, Any],
        *,
        app: UnifiedBridgeApplication | None = None,
        token: str | None = TOKEN,
    ) -> dict[str, Any]:
        route = canonical_action(operation_id)
        return wsgi_request(app or self.app, route.path, body, method=route.method, token=token)

    def _assert_response_matches_schema(
        self,
        operation_id: str,
        result: dict[str, Any],
    ) -> None:
        self.assertIn("json", result, (operation_id, result))
        errors = validate_action_runtime_response(
            self.schema,
            operation_id,
            result["status"],
            result["headers"],
            result["json"],
        )
        self.assertEqual(errors, [], (operation_id, errors, result))

    def _call_success(
        self,
        operation_id: str,
        body: dict[str, Any],
        *,
        app: UnifiedBridgeApplication | None = None,
    ) -> dict[str, Any]:
        self._assert_request_matches_schema(operation_id, body)
        result = self._invoke(operation_id, body, app=app)
        self.assertEqual(result["status"], 200, (operation_id, result))
        self._assert_response_matches_schema(operation_id, result)
        return result

    @staticmethod
    def _download_body() -> dict[str, Any]:
        return {
            "chat": "2",
            "message_id": 20,
            "file_ref": FullFakeReadBackend.SOURCE_REF,
            "name": "synthetic.txt",
            "mime_type": "text/plain",
            "expected_size": 3,
        }

    def _seed_storage(self) -> tuple[dict[str, Any], dict[str, Any]]:
        single = self._call_success("downloadTelegramMediaSingle", self._download_body())
        bulk = self._call_success(
            "downloadTelegramMediaBulk",
            {"items": [self._download_body()]},
        )
        return single["json"]["data"], bulk["json"]["data"]

    @staticmethod
    def _idempotency(action: str, suffix: int = 1) -> str:
        return f"finalwave54-{action.casefold()}-{suffix:02d}-idempotency-00000001"

    def _preview_and_commit(
        self,
        preview_operation: str,
        commit_operation: str,
        preview_body: dict[str, Any],
        *,
        action_label: str,
        app: UnifiedBridgeApplication | None = None,
    ) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
        target_app = app or self.app
        before = len(self.client.external_writes)
        preview = self._call_success(preview_operation, preview_body, app=target_app)
        self.assertEqual(len(self.client.external_writes), before, preview_operation)

        commit_body = {
            "preview_token": preview["json"]["data"]["preview_token"],
            "idempotency_key": self._idempotency(action_label),
            "explicit_user_command": True,
        }
        first = self._call_success(commit_operation, commit_body, app=target_app)
        replay = self._call_success(commit_operation, commit_body, app=target_app)
        self.assertFalse(first["json"]["data"]["idempotent_replay"])
        self.assertTrue(replay["json"]["data"]["idempotent_replay"])
        self.assertEqual(len(self.client.external_writes), before + 1, commit_operation)
        return preview, first, replay

    def test_generated_schema_drives_real_wsgi_for_every_action_operation(self) -> None:
        """All 17 Action operation IDs cross the actual in-memory WSGI boundary."""
        seen: set[str] = set()

        read_bodies: dict[str, dict[str, Any]] = {
            "listTelegramDialogs": {"limit": 1},
            "readTelegramHistory": {"chat": "2", "limit": 1},
            "searchTelegramMessages": {"text": "Синтетичне", "limit": 1},
            "getTelegramMediaMetadata": {"chat": "2", "message_id": 20},
        }
        for operation_id, body in read_bodies.items():
            self._call_success(operation_id, body)
            seen.add(operation_id)

        single = self._call_success("downloadTelegramMediaSingle", self._download_body())
        seen.add("downloadTelegramMediaSingle")
        single_file = single["json"]["data"]

        bulk = self._call_success(
            "downloadTelegramMediaBulk",
            {"items": [self._download_body()]},
        )
        seen.add("downloadTelegramMediaBulk")
        bulk_data = bulk["json"]["data"]

        self._call_success(
            "resumeTelegramDownload",
            {"job_id": bulk_data["job_id"]},
        )
        seen.add("resumeTelegramDownload")

        self._call_success(
            "createTelegramArchive",
            {"file_refs": [single_file["file_ref"]], "name": "synthetic.zip"},
        )
        seen.add("createTelegramArchive")

        self._call_success(
            "getStoredTelegramFile",
            {"file_ref": single_file["file_ref"]},
        )
        seen.add("getStoredTelegramFile")

        write_pairs = (
            (
                "previewTelegramSend",
                "commitTelegramSend",
                {"chat": "@target_user", "text": "synthetic send"},
                "SEND",
            ),
            (
                "previewTelegramReply",
                "commitTelegramReply",
                {
                    "chat": "@target_user",
                    "reply_to_message_id": 10,
                    "text": "synthetic reply",
                },
                "REPLY",
            ),
            (
                "previewTelegramForward",
                "commitTelegramForward",
                {
                    "from_chat": "@source_user",
                    "to_chat": "@target_user",
                    "message_ids": [20, 21],
                },
                "FORWARD",
            ),
            (
                "previewTelegramFiles",
                "commitTelegramFiles",
                {
                    "chat": "@target_user",
                    "files": [
                        {
                            "file_ref": single_file["file_ref"],
                            "sha256": single_file["sha256"],
                            "size": single_file["size"],
                        }
                    ],
                    "caption": "synthetic file",
                    "voice_note": False,
                },
                "SEND_FILES",
            ),
        )
        for preview_operation, commit_operation, body, action_label in write_pairs:
            self._preview_and_commit(
                preview_operation,
                commit_operation,
                body,
                action_label=action_label,
            )
            seen.update((preview_operation, commit_operation))

        expected = {
            route.action_operation_id
            for route in CANONICAL_ROUTES
            if route.exposure is ApiExposure.ACTION
        }
        self.assertNotIn(None, expected)
        self.assertEqual(seen, expected)
        self.assertEqual(len(seen), 17)
        self.assertEqual(len(self.client.external_writes), 4)

    def test_every_action_rejects_extra_fields_at_schema_and_wsgi_boundary(self) -> None:
        single_file, bulk_data = self._seed_storage()

        valid: dict[str, dict[str, Any]] = {
            "listTelegramDialogs": {"limit": 1},
            "readTelegramHistory": {"chat": "2", "limit": 1},
            "searchTelegramMessages": {"text": "synthetic"},
            "getTelegramMediaMetadata": {"chat": "2", "message_id": 20},
            "downloadTelegramMediaSingle": self._download_body(),
            "downloadTelegramMediaBulk": {"items": [self._download_body()]},
            "resumeTelegramDownload": {"job_id": bulk_data["job_id"]},
            "createTelegramArchive": {"file_refs": [single_file["file_ref"]]},
            "getStoredTelegramFile": {"file_ref": single_file["file_ref"]},
        }

        preview_bodies = {
            "previewTelegramSend": {"chat": "@target_user", "text": "synthetic"},
            "previewTelegramReply": {
                "chat": "@target_user",
                "reply_to_message_id": 10,
                "text": "synthetic",
            },
            "previewTelegramForward": {
                "from_chat": "@source_user",
                "to_chat": "@target_user",
                "message_ids": [20],
            },
            "previewTelegramFiles": {
                "chat": "@target_user",
                "files": [
                    {
                        "file_ref": single_file["file_ref"],
                        "sha256": single_file["sha256"],
                        "size": single_file["size"],
                    }
                ],
            },
        }
        valid.update(preview_bodies)

        commit_for_preview = {
            "previewTelegramSend": "commitTelegramSend",
            "previewTelegramReply": "commitTelegramReply",
            "previewTelegramForward": "commitTelegramForward",
            "previewTelegramFiles": "commitTelegramFiles",
        }
        for preview_operation, commit_operation in commit_for_preview.items():
            preview = self._call_success(preview_operation, preview_bodies[preview_operation])
            valid[commit_operation] = {
                "preview_token": preview["json"]["data"]["preview_token"],
                "idempotency_key": self._idempotency(commit_operation),
                "explicit_user_command": True,
            }

        before = len(self.client.external_writes)
        for operation_id, body in valid.items():
            with self.subTest(operation_id=operation_id):
                bad = dict(body)
                bad["finalwave54_unexpected"] = True
                schema_errors = validate_json_instance(
                    bad,
                    self._request_schema(operation_id),
                )
                self.assertTrue(
                    any("ADDITIONAL_PROPERTY" in item for item in schema_errors),
                    (operation_id, schema_errors),
                )
                result = self._invoke(operation_id, bad)
                self.assertEqual(result["status"], 400, (operation_id, result))
                self.assertEqual(result["json"]["error"]["code"], "unknown_field")
                self._assert_response_matches_schema(operation_id, result)
        self.assertEqual(len(self.client.external_writes), before)

    def test_all_commit_pairs_require_bearer_preview_idempotency_and_explicit_command(self) -> None:
        single_file, _ = self._seed_storage()
        pairs = (
            (
                "previewTelegramSend",
                "commitTelegramSend",
                {"chat": "@target_user", "text": "synthetic"},
            ),
            (
                "previewTelegramReply",
                "commitTelegramReply",
                {
                    "chat": "@target_user",
                    "reply_to_message_id": 10,
                    "text": "synthetic",
                },
            ),
            (
                "previewTelegramForward",
                "commitTelegramForward",
                {
                    "from_chat": "@source_user",
                    "to_chat": "@target_user",
                    "message_ids": [20],
                },
            ),
            (
                "previewTelegramFiles",
                "commitTelegramFiles",
                {
                    "chat": "@target_user",
                    "files": [
                        {
                            "file_ref": single_file["file_ref"],
                            "sha256": single_file["sha256"],
                            "size": single_file["size"],
                        }
                    ],
                },
            ),
        )
        for index, (preview_operation, commit_operation, preview_body) in enumerate(pairs, start=1):
            with self.subTest(commit_operation=commit_operation):
                before = len(self.client.external_writes)
                preview = self._call_success(preview_operation, preview_body)
                preview_token = preview["json"]["data"]["preview_token"]
                valid = {
                    "preview_token": preview_token,
                    "idempotency_key": self._idempotency(commit_operation, index),
                    "explicit_user_command": True,
                }

                missing_bearer = self._invoke(
                    commit_operation,
                    valid,
                    token=None,
                )
                self.assertEqual(missing_bearer["status"], 404)
                self._assert_response_matches_schema(commit_operation, missing_bearer)
                self.assertEqual(len(self.client.external_writes), before)

                for missing in ("preview_token", "idempotency_key", "explicit_user_command"):
                    malformed = dict(valid)
                    malformed.pop(missing)
                    schema_errors = validate_json_instance(
                        malformed,
                        self._request_schema(commit_operation),
                    )
                    self.assertTrue(schema_errors, (commit_operation, missing))
                    rejected = self._invoke(commit_operation, malformed)
                    self.assertNotEqual(rejected["status"], 200, (commit_operation, missing, rejected))
                    self._assert_response_matches_schema(commit_operation, rejected)
                    self.assertEqual(len(self.client.external_writes), before)

                explicit_false = dict(valid)
                explicit_false["explicit_user_command"] = False
                self.assertTrue(
                    validate_json_instance(
                        explicit_false,
                        self._request_schema(commit_operation),
                    )
                )
                rejected_false = self._invoke(commit_operation, explicit_false)
                self.assertEqual(rejected_false["status"], 409)
                self._assert_response_matches_schema(commit_operation, rejected_false)
                self.assertEqual(len(self.client.external_writes), before)

                wrong_preview = dict(valid)
                wrong_preview["preview_token"] = "0" * 64
                rejected_wrong = self._invoke(commit_operation, wrong_preview)
                self.assertNotEqual(rejected_wrong["status"], 200)
                self._assert_response_matches_schema(commit_operation, rejected_wrong)
                self.assertEqual(len(self.client.external_writes), before)

                first = self._call_success(commit_operation, valid)
                replay = self._call_success(commit_operation, valid)
                self.assertFalse(first["json"]["data"]["idempotent_replay"])
                self.assertTrue(replay["json"]["data"]["idempotent_replay"])
                self.assertEqual(len(self.client.external_writes), before + 1)

    def test_preview_survives_restart_and_committed_replay_does_not_repeat_effect(self) -> None:
        preview = self._call_success(
            "previewTelegramSend",
            {"chat": "@target_user", "text": "restart-safe synthetic"},
        )
        self.assertEqual(self.client.external_writes, [])
        commit_body = {
            "preview_token": preview["json"]["data"]["preview_token"],
            "idempotency_key": self._idempotency("restart"),
            "explicit_user_command": True,
        }

        restarted = self._build_app()
        first = self._call_success("commitTelegramSend", commit_body, app=restarted)
        self.assertFalse(first["json"]["data"]["idempotent_replay"])
        self.assertEqual(len(self.client.external_writes), 1)

        restarted_again = self._build_app()
        replay = self._call_success("commitTelegramSend", commit_body, app=restarted_again)
        self.assertTrue(replay["json"]["data"]["idempotent_replay"])
        self.assertEqual(len(self.client.external_writes), 1)

    def test_concurrent_same_commit_never_duplicates_fake_effect(self) -> None:
        preview = self._call_success(
            "previewTelegramSend",
            {"chat": "@target_user", "text": "concurrent synthetic"},
        )
        commit_body = {
            "preview_token": preview["json"]["data"]["preview_token"],
            "idempotency_key": self._idempotency("concurrency"),
            "explicit_user_command": True,
        }
        barrier = threading.Barrier(2)

        def worker() -> dict[str, Any]:
            barrier.wait()
            return self._invoke("commitTelegramSend", commit_body)

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = [future.result() for future in (pool.submit(worker), pool.submit(worker))]

        for result in results:
            self.assertIn(result["status"], {200, 409}, result)
            self._assert_response_matches_schema("commitTelegramSend", result)
        self.assertEqual(sum(result["status"] == 200 for result in results), 1)
        self.assertEqual(len(self.client.external_writes), 1)

        terminal_replay = self._call_success("commitTelegramSend", commit_body)
        self.assertTrue(terminal_replay["json"]["data"]["idempotent_replay"])
        self.assertEqual(len(self.client.external_writes), 1)

    def test_every_action_is_bearer_hidden_before_request_parsing(self) -> None:
        before_backend = len(self.backend.calls)
        before_writes = len(self.client.external_writes)
        for route in CANONICAL_ROUTES:
            if route.exposure is not ApiExposure.ACTION:
                continue
            with self.subTest(operation_id=route.action_operation_id):
                result = wsgi_request(
                    self.app,
                    route.path,
                    {},
                    method=route.method,
                    token=None,
                )
                self.assertEqual(result["status"], 404, result)
                self._assert_response_matches_schema(route.action_operation_id or "", result)
        self.assertEqual(len(self.backend.calls), before_backend)
        self.assertEqual(len(self.client.external_writes), before_writes)

    def test_read_and_write_rate_limits_emit_contractual_retry_after(self) -> None:
        read_limited = self._build_app(read_limiter=DenyReadLimiter(7))
        read_result = self._invoke(
            "listTelegramDialogs",
            {"limit": 1},
            app=read_limited,
        )
        self.assertEqual(read_result["status"], 429)
        self.assertEqual(read_result["headers"].get("Retry-After"), "7")
        self._assert_response_matches_schema("listTelegramDialogs", read_result)

        write_limited = self._build_app(
            write_limiter=FixedWindowEndpointLimiter(
                limit=1,
                window_seconds=60,
                clock=lambda: 120.0,
            )
        )
        body = {"chat": "@target_user", "text": "rate synthetic"}
        first = self._call_success("previewTelegramSend", body, app=write_limited)
        self.assertEqual(first["status"], 200)
        limited = self._invoke("previewTelegramSend", body, app=write_limited)
        self.assertEqual(limited["status"], 429, limited)
        self.assertEqual(limited["headers"].get("Retry-After"), "60")
        self._assert_response_matches_schema("previewTelegramSend", limited)
        self.assertEqual(self.client.external_writes, [])

    def test_private_setup_is_absent_from_action_schema_and_hidden_at_wsgi(self) -> None:
        private_words = ("setup", "bootstrap", "authorize", "login", "2fa", "session")
        for path in self.schema["paths"]:
            lowered = path.casefold()
            self.assertFalse(
                any(word in lowered for word in private_words),
                path,
            )

        result = wsgi_request(
            self.app,
            "/api/v1/setup/login",
            {"anything": "synthetic"},
            token=TOKEN,
        )
        self.assertEqual(result["status"], 404)
        self.assertEqual(result["json"]["error"]["code"], "not_found")
        self.assertEqual(self.client.external_writes, [])


if __name__ == "__main__":
    unittest.main()
