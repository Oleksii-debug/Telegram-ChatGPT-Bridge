# -*- coding: utf-8 -*-
"""DEV_C Release-to-Live cross-namespace concurrency gate.

Network-free. Drives the actual unified WSGI surface while authenticated read,
completed download-resume checkpoint reads, and duplicate write commits contend.
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

            commit_replays: list[bool] = []
            for kind, response in results:
                self.assertTrue(str(response["status"]).startswith("200"), (kind, response))
                if kind == "resume":
                    self.assertEqual("complete", response["payload"]["data"]["status"])
                elif kind == "read":
                    self.assertEqual(1, len(response["payload"]["data"]["items"]))
                else:
                    commit_replays.append(bool(response["payload"]["data"]["idempotent_replay"]))

            self.assertEqual(initial_download_count, backend.download_count)
            self.assertEqual(1, len(fake.external_writes))
            self.assertEqual(6, len(commit_replays))
            self.assertEqual(1, commit_replays.count(False))
            self.assertEqual(5, commit_replays.count(True))


if __name__ == "__main__":
    unittest.main()
