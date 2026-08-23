# -*- coding: utf-8 -*-
"""DEV_C Release-to-Live cross-namespace concurrency gate.

Network-free. Drives the actual unified WSGI surface while authenticated read,
completed download-resume checkpoint reads, and duplicate write commits contend.
Also pins the RESERVED -> CALLING duplicate-commit race directly so ordinary
live contention can never be mislabeled as an unknown external outcome.
"""
from __future__ import annotations

import io
import json
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from bridge.app import BridgeApplication, ReadAppConfig
from bridge.integrated_app import UnifiedBridgeApplication
from bridge.models import DialogRecord, Page
from bridge.security import RateLimitDecision
from ops.telegram_write_adapter import DeterministicFakeTelegramClient, TelegramRuntimeConfig, TelegramWriteAdapter
from ops.write_endpoint_policy import FixedWindowEndpointLimiter
from ops.write_safety import PersistentWriteStore, ReconciliationRequired, WriteAction, WriteSafetyError

AUTH = "devc-round2-concurrency-auth-0001"
SIGNING = "devc-round2-concurrency-signing-0001"


class AllowReadLimiter:
    def check(self, _actor_class):
        return RateLimitDecision(True, remaining=999)


class ConcurrentBackend:
    def __init__(self):
        self._lock = threading.Lock()
        self.download_count = 0
        self.payloads = {
            "tg_11_0123456789abcdefabcd": b"round2-a",
            "tg_12_0123456789abcdefabcd": b"round2-b",
        }

    def list_dialogs(self, **_kwargs):
        return Page((DialogRecord("11", "group", "synthetic", None, 0, False, "2026-08-22T18:00:00+00:00"),), None, 1)

    def history(self, **_kwargs):
        return Page(tuple(), None, 0)

    def search(self, **_kwargs):
        return Page(tuple(), None, 0)

    def get_message(self, **_kwargs):
        raise AssertionError("not needed by this gate")

    def download_media(self, **kwargs):
        source_ref = str(kwargs["source_ref"])
        destination = Path(kwargs["destination"])
        destination.write_bytes(self.payloads[source_ref])
        with self._lock:
            self.download_count += 1
        return {"path": str(destination)}


def request(app, path: str, body: dict | None = None) -> dict:
    raw = json.dumps(body or {}, separators=(",", ":")).encode("utf-8")
    environ = {
        "REQUEST_METHOD": "POST",
        "PATH_INFO": path,
        "QUERY_STRING": "",
        "wsgi.input": io.BytesIO(raw),
        "CONTENT_TYPE": "application/json",
        "CONTENT_LENGTH": str(len(raw)),
        "HTTP_AUTHORIZATION": f"Bearer {AUTH}",
    }
    seen: dict = {}

    def start_response(status, headers):
        seen["status"] = status
        seen["headers"] = dict(headers)

    payload = b"".join(app(environ, start_response))
    seen["raw"] = payload
    if seen["headers"].get("Content-Type", "").startswith("application/json"):
        seen["payload"] = json.loads(payload.decode("utf-8"))
    return seen


class WriteStateRaceTests(unittest.TestCase):
    def test_reserved_resume_that_loses_transition_race_is_in_progress_not_ambiguous(self):
        """A live CALLING owner is known, so duplicate callers must retry, not reconcile."""
        with tempfile.TemporaryDirectory() as temp:
            store = PersistentWriteStore(Path(temp) / "write.sqlite3")
            preview = store.create_preview(WriteAction.SEND, {"target": "100", "text": "synthetic"}, now=100)
            key = "devc-race-idem-0001"

            mode1, row1, _ = store._begin_commit(
                preview.token,
                expected_action=WriteAction.SEND,
                idempotency_key=key,
                now=101,
            )
            mode2, row2, _ = store._begin_commit(
                preview.token,
                expected_action=WriteAction.SEND,
                idempotency_key=key,
                now=101,
            )
            self.assertEqual("NEW", mode1)
            self.assertEqual("RESUME_RESERVED", mode2)
            self.assertEqual(row1["request_fingerprint"], row2["request_fingerprint"])

            store._transition_to_calling(key, row1["request_fingerprint"], now=101)
            try:
                store._transition_to_calling(key, row2["request_fingerprint"], now=101)
            except ReconciliationRequired as exc:
                self.fail(f"live CALLING contention was mislabeled ambiguous: {exc.code}")
            except WriteSafetyError as exc:
                self.assertEqual("write_in_progress", exc.code)
                self.assertEqual(409, exc.status)
            else:
                self.fail("duplicate transition unexpectedly crossed the external-effect boundary")


class CrossNamespaceConcurrencyTests(unittest.TestCase):
    def test_read_checkpoint_and_duplicate_commit_are_isolated_under_contention(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            backend = ConcurrentBackend()
            read_app = BridgeApplication(
                config=ReadAppConfig(
                    auth_secret=AUTH,
                    file_signing_secret=SIGNING,
                    private_root=root,
                    public_base_url="https://bridge.example.invalid",
                ),
                backend=backend,
                rate_limiter=AllowReadLimiter(),
            )
            fake = DeterministicFakeTelegramClient()
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
                read_app=read_app,
                write_adapter=adapter,
                write_limiter=FixedWindowEndpointLimiter(limit=1000, window_seconds=60, clock=lambda: 300.0),
            )

            items = [
                {
                    "chat": "11", "message_id": 11,
                    "file_ref": "tg_11_0123456789abcdefabcd", "name": "a.bin",
                    "mime_type": "application/octet-stream",
                    "expected_size": len(backend.payloads["tg_11_0123456789abcdefabcd"]),
                },
                {
                    "chat": "11", "message_id": 12,
                    "file_ref": "tg_12_0123456789abcdefabcd", "name": "b.bin",
                    "mime_type": "application/octet-stream",
                    "expected_size": len(backend.payloads["tg_12_0123456789abcdefabcd"]),
                },
            ]
            bulk = request(app, "/api/v1/downloads/bulk", {"items": items})
            self.assertTrue(str(bulk["status"]).startswith("200"), bulk)
            job_id = bulk["payload"]["data"]["job_id"]
            self.assertEqual("complete", bulk["payload"]["data"]["status"])
            initial_download_count = backend.download_count

            preview = request(app, "/api/v1/messages/send/preview", {"chat": "100", "text": "round2 concurrent exactly once"})
            self.assertTrue(str(preview["status"]).startswith("200"), preview)
            commit_body = {
                "preview_token": preview["payload"]["data"]["preview_token"],
                "idempotency_key": "devc-round2-concurrent-idem-0001",
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

            successful_commit_replays: list[bool] = []
            busy_commits = 0
            busy_resumes = 0
            for kind, response in results:
                status = str(response["status"])
                if kind == "read":
                    self.assertTrue(status.startswith("200"), (kind, response))
                    self.assertEqual(1, len(response["payload"]["data"]["items"]))
                    continue
                if kind == "resume":
                    if status.startswith("409"):
                        error = response.get("payload", {}).get("error", {})
                        self.assertEqual("job_busy", error.get("code"), (kind, response))
                        self.assertIs(error.get("details", {}).get("retryable"), True, (kind, response))
                        busy_resumes += 1
                    else:
                        self.assertTrue(status.startswith("200"), (kind, response))
                        self.assertEqual("complete", response["payload"]["data"]["status"])
                    continue

                if status.startswith("409"):
                    error = response.get("payload", {}).get("error", {})
                    self.assertEqual("write_in_progress", error.get("code"), (kind, response))
                    busy_commits += 1
                else:
                    self.assertTrue(status.startswith("200"), (kind, response))
                    successful_commit_replays.append(bool(response["payload"]["data"]["idempotent_replay"]))

            # Busy is optional because scheduling may serialize all callers. It may
            # never be upgraded to reconciliation_required merely because callers raced.
            self.assertGreaterEqual(busy_resumes, 0)
            self.assertGreaterEqual(busy_commits, 0)
            self.assertEqual(initial_download_count, backend.download_count)
            self.assertEqual(1, len(fake.external_writes))
            self.assertEqual(1, successful_commit_replays.count(False))

            # Once the winning call is durable, the same explicit commit must replay
            # without another external effect regardless of how many callers were busy.
            replay = request(app, "/api/v1/messages/send/commit", commit_body)
            self.assertTrue(str(replay["status"]).startswith("200"), replay)
            self.assertTrue(replay["payload"]["data"]["idempotent_replay"])
            self.assertEqual(1, len(fake.external_writes))


if __name__ == "__main__":
    unittest.main()
