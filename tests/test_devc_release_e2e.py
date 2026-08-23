# -*- coding: utf-8 -*-
"""DEV_C packaged-candidate integrated WSGI QA.

All external effects use deterministic synthetic adapters.  Nothing here talks
to Telegram, HOSTiQ, ChatGPT Actions, or production services.
"""
from __future__ import annotations

import io
import json
import os
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from bridge.app import BridgeApplication, ReadAppConfig
from bridge.audit import AuditLog
from bridge.integrated_app import UnifiedBridgeApplication, validate_unified_registry
from bridge.models import DialogRecord, EntityRef, MediaRecord, MessageRecord, Page
from bridge.security import RateLimitDecision
from ops import openapi_registry
from ops.openapi_registry import OperationClass
from ops.telegram_write_adapter import (
    DeterministicFakeTelegramClient,
    TelegramRuntimeConfig,
    TelegramWriteAdapter,
)
from ops.write_endpoint_policy import FixedWindowEndpointLimiter

AUTH = "devc-release-placeholder-auth-0001"
SIGNING = "devc-release-placeholder-signing-0001"


class AllowReadLimiter:
    def check(self, _actor_class):
        return RateLimitDecision(True, remaining=999)


class ScenarioBackend:
    def __init__(self):
        self._lock = threading.Lock()
        self.download_count = 0
        self.media_bytes = b"devc-release-synthetic-media"
        self.source_ref = "tg_2_0123456789abcdefabcd"
        self.private_title = "DEV_C_PRIVATE_CHAT_LABEL"
        self.private_sender = "DEV_C_PRIVATE_PERSON_LABEL"
        self.private_body = "DEV_C_PRIVATE_MESSAGE_BODY"
        media = MediaRecord(
            "document",
            self.source_ref,
            "devc-private-file.bin",
            "application/octet-stream",
            len(self.media_bytes),
        )
        self.dialogs = (
            DialogRecord("2", "group", self.private_title, None, 1, False, "2026-08-23T07:00:00+00:00"),
        )
        self.messages = (
            MessageRecord(
                2,
                "2",
                "2026-08-23T07:00:00+00:00",
                self.private_body,
                EntityRef("20", "user", self.private_sender),
                media=(media,),
            ),
        )

    def list_dialogs(self, **_kwargs):
        return Page(self.dialogs, None, len(self.dialogs))

    def history(self, **_kwargs):
        return Page(self.messages, None, len(self.messages))

    def search(self, **_kwargs):
        return Page(self.messages, None, len(self.messages))

    def get_message(self, **_kwargs):
        return self.messages[0]

    def download_media(self, **kwargs):
        target = Path(kwargs["destination"])
        target.write_bytes(self.media_bytes)
        with self._lock:
            self.download_count += 1
        return {"path": str(target)}


def request(app, path: str, body: dict | None = None, *, method: str = "POST", auth: bool = True) -> dict:
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
        environ["HTTP_AUTHORIZATION"] = f"Bearer {AUTH}"
    seen: dict = {}

    def start_response(status, headers):
        seen["status"] = status
        seen["headers"] = dict(headers)

    payload = b"".join(app(environ, start_response))
    seen["raw"] = payload
    if seen["headers"].get("Content-Type", "").startswith("application/json"):
        seen["payload"] = json.loads(payload.decode("utf-8"))
    return seen


def make_app(root: Path, backend: ScenarioBackend, fake: DeterministicFakeTelegramClient, audit: AuditLog | None = None):
    read = BridgeApplication(
        config=ReadAppConfig(
            auth_secret=AUTH,
            file_signing_secret=SIGNING,
            private_root=root,
            public_base_url="https://bridge.example.invalid",
        ),
        backend=backend,
        rate_limiter=AllowReadLimiter(),
        audit=audit or AuditLog(),
    )
    adapter = TelegramWriteAdapter(
        TelegramRuntimeConfig(
            application_id_ref=12345,
            application_hash_ref="synthetic-hash-reference",
            session_reference="synthetic-session-reference",
            synthetic_test_mode=True,
        ),
        lambda: fake,
    )
    app = UnifiedBridgeApplication(
        read_app=read,
        write_adapter=adapter,
        write_limiter=FixedWindowEndpointLimiter(limit=1000, window_seconds=60, clock=lambda: 300.0),
    )
    return app, read


class PackagedCandidateRouteParityTests(unittest.TestCase):
    def test_all_action_operations_resolve_through_unified_runtime(self):
        with tempfile.TemporaryDirectory() as temp:
            app, _ = make_app(Path(temp), ScenarioBackend(), DeterministicFakeTelegramClient())
            unresolved = []
            for spec in openapi_registry.OPERATIONS:
                resolved = app._operation_for_request(str(spec.method).upper(), str(spec.path))
                if resolved is None or resolved.operation_id != spec.operation_id:
                    unresolved.append((str(spec.method).upper(), str(spec.path), spec.operation_id))
            self.assertEqual([], unresolved)
            self.assertEqual(
                {
                    (str(spec.method).upper(), str(spec.path))
                    for spec in openapi_registry.OPERATIONS
                    if spec.operation_class is OperationClass.READ
                },
                set(validate_unified_registry()),
            )
            self.assertEqual(17, len(openapi_registry.OPERATIONS))

    def test_generated_action_schema_is_deterministic_and_write_commit_is_strict(self):
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
            self.assertIs(schema["properties"]["explicit_user_command"].get("const"), True)
            self.assertIs(operation.get("x-openai-isConsequential"), True)


class ContinuousPackagedCandidateScenarioTests(unittest.TestCase):
    def test_one_continuous_mocked_action_flow_is_private_and_exactly_once_across_restart(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            audit = AuditLog()
            backend = ScenarioBackend()
            fake = DeterministicFakeTelegramClient()
            app, _ = make_app(root, backend, fake, audit)

            for path, body in (
                ("/api/v1/dialogs/list", {"limit": 10}),
                ("/api/v1/history/read", {"chat": "2", "limit": 10}),
                ("/api/v1/search", {"chat": "2", "text": "synthetic"}),
                ("/api/v1/search", {"text": "synthetic"}),
                ("/api/v1/media/metadata", {"chat": "2", "message_id": 2}),
            ):
                response = request(app, path, body)
                self.assertTrue(str(response["status"]).startswith("200"), (path, response))

            item = {
                "chat": "2",
                "message_id": 2,
                "file_ref": backend.source_ref,
                "name": "scenario.bin",
                "mime_type": "application/octet-stream",
                "expected_size": len(backend.media_bytes),
            }
            single = request(app, "/api/v1/downloads/single", item)
            self.assertTrue(str(single["status"]).startswith("200"), single)
            single_file = single["payload"]["data"]

            bulk = request(app, "/api/v1/downloads/bulk", {"items": [item]})
            self.assertTrue(str(bulk["status"]).startswith("200"), bulk)
            bulk_data = bulk["payload"]["data"]
            self.assertEqual("complete", bulk_data["status"])
            before_resume_downloads = backend.download_count
            resumed = request(app, "/api/v1/downloads/resume", {"job_id": bulk_data["job_id"]})
            self.assertEqual("complete", resumed["payload"]["data"]["status"])
            self.assertEqual(before_resume_downloads, backend.download_count)

            archive = request(
                app,
                "/api/v1/archives/create",
                {"file_refs": [single_file["file_ref"]], "name": "scenario.zip"},
            )
            self.assertTrue(str(archive["status"]).startswith("200"), archive)
            metadata = request(app, "/api/v1/files/get", {"file_ref": single_file["file_ref"]})
            self.assertTrue(str(metadata["status"]).startswith("200"), metadata)
            binary = request(app, f"/api/v1/files/{single_file['file_ref']}", method="GET")
            self.assertTrue(str(binary["status"]).startswith("200"), binary)
            self.assertEqual(backend.media_bytes, binary["raw"])

            previews = []
            for path, body in (
                ("/api/v1/messages/send/preview", {"chat": "100", "text": backend.private_body}),
                ("/api/v1/messages/reply/preview", {"chat": "100", "reply_to_message_id": 1, "text": backend.private_body}),
                ("/api/v1/messages/forward/preview", {"from_chat": "200", "to_chat": "100", "message_ids": [1]}),
                (
                    "/api/v1/files/send/preview",
                    {
                        "chat": "100",
                        "files": [
                            {
                                "file_ref": single_file["file_ref"],
                                "sha256": single_file["sha256"],
                                "size": single_file["size"],
                            }
                        ],
                        "caption": "",
                        "voice_note": False,
                    },
                ),
            ):
                response = request(app, path, body)
                self.assertTrue(str(response["status"]).startswith("200"), (path, response))
                previews.append(response["payload"]["data"])
            self.assertEqual([], fake.external_writes)
            self.assertEqual(0, fake.connect_count)

            commit = {
                "preview_token": previews[0]["preview_token"],
                "idempotency_key": "devc-release-idem-0001",
                "explicit_user_command": False,
            }
            blocked = request(app, "/api/v1/messages/send/commit", commit)
            self.assertTrue(str(blocked["status"]).startswith("409"), blocked)
            self.assertEqual([], fake.external_writes)

            commit["explicit_user_command"] = True
            first = request(app, "/api/v1/messages/send/commit", commit)
            replay = request(app, "/api/v1/messages/send/commit", commit)
            self.assertTrue(str(first["status"]).startswith("200"), first)
            self.assertTrue(str(replay["status"]).startswith("200"), replay)
            self.assertFalse(first["payload"]["data"]["idempotent_replay"])
            self.assertTrue(replay["payload"]["data"]["idempotent_replay"])
            self.assertEqual(1, len(fake.external_writes))

            evidence_text = json.dumps(audit.events, ensure_ascii=False, sort_keys=True)
            for private_value in (
                backend.private_title,
                backend.private_sender,
                backend.private_body,
                "devc-private-file.bin",
                AUTH,
                SIGNING,
                str(root),
            ):
                self.assertNotIn(private_value, evidence_text)

            restarted_fake = DeterministicFakeTelegramClient()
            restarted, _ = make_app(root, ScenarioBackend(), restarted_fake, AuditLog())
            after_file = request(restarted, "/api/v1/files/get", {"file_ref": single_file["file_ref"]})
            self.assertTrue(str(after_file["status"]).startswith("200"), after_file)
            after_resume = request(restarted, "/api/v1/downloads/resume", {"job_id": bulk_data["job_id"]})
            self.assertEqual("complete", after_resume["payload"]["data"]["status"])
            after_replay = request(restarted, "/api/v1/messages/send/commit", commit)
            self.assertTrue(str(after_replay["status"]).startswith("200"), after_replay)
            self.assertTrue(after_replay["payload"]["data"]["idempotent_replay"])
            self.assertEqual([], restarted_fake.external_writes)

    def test_unauthenticated_write_is_hidden_before_private_body_processing(self):
        with tempfile.TemporaryDirectory() as temp:
            fake = DeterministicFakeTelegramClient()
            app, _ = make_app(Path(temp), ScenarioBackend(), fake)
            response = request(
                app,
                "/api/v1/messages/send/preview",
                {"chat": "100", "text": "DEV_C_PRIVATE_UNAUTH_BODY"},
                auth=False,
            )
            self.assertTrue(str(response["status"]).startswith("404"), response)
            self.assertEqual([], fake.external_writes)


class CrossNamespaceContentionTests(unittest.TestCase):
    def test_read_resume_and_duplicate_commit_do_not_deadlock_or_duplicate_effect(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            backend = ScenarioBackend()
            fake = DeterministicFakeTelegramClient()
            app, _ = make_app(root, backend, fake)

            item = {
                "chat": "2",
                "message_id": 2,
                "file_ref": backend.source_ref,
                "name": "contention.bin",
                "mime_type": "application/octet-stream",
                "expected_size": len(backend.media_bytes),
            }
            bulk = request(app, "/api/v1/downloads/bulk", {"items": [item]})
            self.assertEqual("complete", bulk["payload"]["data"]["status"])
            job_id = bulk["payload"]["data"]["job_id"]
            completed_download_count = backend.download_count

            preview = request(app, "/api/v1/messages/send/preview", {"chat": "100", "text": "contention"})
            commit_body = {
                "preview_token": preview["payload"]["data"]["preview_token"],
                "idempotency_key": "devc-release-concurrent-idem-0001",
                "explicit_user_command": True,
            }

            task_count = 18
            barrier = threading.Barrier(task_count)

            def read_task():
                barrier.wait(timeout=10)
                return "read", request(app, "/api/v1/dialogs/list", {"limit": 5})

            def resume_task():
                barrier.wait(timeout=10)
                return "resume", request(app, "/api/v1/downloads/resume", {"job_id": job_id})

            def commit_task():
                barrier.wait(timeout=10)
                return "commit", request(app, "/api/v1/messages/send/commit", commit_body)

            callables = [read_task] * 6 + [resume_task] * 6 + [commit_task] * 6
            with ThreadPoolExecutor(max_workers=task_count) as pool:
                futures = [pool.submit(fn) for fn in callables]
                results = [future.result(timeout=20) for future in futures]

            replay_flags: list[bool] = []
            for kind, response in results:
                self.assertTrue(str(response["status"]).startswith("200"), (kind, response))
                if kind == "resume":
                    self.assertEqual("complete", response["payload"]["data"]["status"])
                elif kind == "read":
                    self.assertEqual(1, len(response["payload"]["data"]["items"]))
                else:
                    replay_flags.append(bool(response["payload"]["data"]["idempotent_replay"]))

            self.assertEqual(completed_download_count, backend.download_count)
            self.assertEqual(1, len(fake.external_writes))
            self.assertEqual(6, len(replay_flags))
            self.assertEqual(1, replay_flags.count(False))
            self.assertEqual(5, replay_flags.count(True))


if __name__ == "__main__":
    unittest.main()
