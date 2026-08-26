"""FINALWAVE-26 persistence/concurrency regressions for Action request attempts."""
from __future__ import annotations

import io
import json
import multiprocessing
import os
import tempfile
import unittest
from pathlib import Path

from bridge.action_request_guard import ActionRequestGuard
from bridge.app import BridgeApplication, ReadAppConfig
from bridge.integrated_app import UnifiedBridgeApplication
from bridge.runtime import SQLiteWriteRateLimiter, _SQLiteFixedWindowStore
from ops.write_endpoint_policy import EndpointPolicyError


TOKEN = "finalwave26-persistence-synthetic-token-reference"
ACTOR = "a" * 64
OPERATION = "request-attempt:previewTelegramSend"


def _request(app, body: dict[str, object]) -> dict[str, object]:
    raw = json.dumps(body).encode("utf-8")
    environ = {
        "REQUEST_METHOD": "POST",
        "PATH_INFO": "/api/v1/messages/send/preview",
        "QUERY_STRING": "",
        "CONTENT_TYPE": "application/json",
        "CONTENT_LENGTH": str(len(raw)),
        "HTTP_AUTHORIZATION": "Bearer " + TOKEN,
        "wsgi.input": io.BytesIO(raw),
    }
    captured: dict[str, object] = {}

    def start_response(status, headers):
        captured["status_line"] = status
        captured["headers"] = dict(headers)

    output = b"".join(app(environ, start_response))
    captured["status"] = int(str(captured["status_line"]).split(" ", 1)[0])
    captured["json"] = json.loads(output.decode("utf-8"))
    return captured


def _process_take(database: str, start_event, result_queue) -> None:
    try:
        start_event.wait(10.0)
        limiter = SQLiteWriteRateLimiter(
            _SQLiteFixedWindowStore(Path(database), clock=lambda: 120.0),
            limit=1,
            window_seconds=60,
        )
        limiter.consume(ACTOR, OPERATION)
        result_queue.put("allowed")
    except EndpointPolicyError as exc:
        result_queue.put(exc.code)
    except BaseException as exc:  # stable class only; no private values
        result_queue.put(type(exc).__name__)


class _UnavailableLimiter:
    def consume(self, actor_sha256: str, operation_id: str):
        del actor_sha256, operation_id
        raise EndpointPolicyError("rate_limiter_unavailable", status=503)


class Finalwave26RequestGuardPersistenceTests(unittest.TestCase):
    @staticmethod
    def _private_root(base: str) -> Path:
        root = Path(base) / "private"
        root.mkdir(mode=0o700)
        os.chmod(root, 0o700)
        state = root / "state"
        state.mkdir(mode=0o700)
        os.chmod(state, 0o700)
        return root

    @staticmethod
    def _guard(root: Path, limiter) -> ActionRequestGuard:
        read_app = BridgeApplication(
            config=ReadAppConfig(auth_secret=TOKEN, private_root=root),
        )
        return ActionRequestGuard(
            UnifiedBridgeApplication(
                read_app=read_app,
                write_limiter=limiter,
            )
        )

    def test_malformed_request_quota_survives_application_reconstruction(self):
        with tempfile.TemporaryDirectory() as td:
            root = self._private_root(td)
            database = root / "state" / "rate.sqlite3"
            first_limiter = SQLiteWriteRateLimiter(
                _SQLiteFixedWindowStore(database, clock=lambda: 120.0),
                limit=1,
                window_seconds=60,
            )
            malformed = {"chat": "@target", "text": "draft", "unsupported": True}
            first = _request(self._guard(root, first_limiter), malformed)
            self.assertEqual(400, first["status"], first)

            # Simulate a fresh Passenger/application object over the same private
            # persistent quota database. The malformed-attempt bucket must remain.
            second_limiter = SQLiteWriteRateLimiter(
                _SQLiteFixedWindowStore(database, clock=lambda: 120.0),
                limit=1,
                window_seconds=60,
            )
            second = _request(self._guard(root, second_limiter), malformed)
            self.assertEqual(429, second["status"], second)
            self.assertGreaterEqual(int(second["headers"]["Retry-After"]), 1)

    def test_two_processes_cannot_oversubscribe_same_request_attempt_bucket(self):
        with tempfile.TemporaryDirectory() as td:
            root = self._private_root(td)
            database = root / "state" / "rate.sqlite3"
            _SQLiteFixedWindowStore(database, clock=lambda: 120.0)
            context = multiprocessing.get_context("spawn")
            start_event = context.Event()
            result_queue = context.Queue()
            processes = [
                context.Process(target=_process_take, args=(str(database), start_event, result_queue))
                for _ in range(2)
            ]
            for process in processes:
                process.start()
            start_event.set()
            results = [result_queue.get(timeout=20.0) for _ in processes]
            for process in processes:
                process.join(timeout=20.0)
                if process.is_alive():
                    process.kill()
                    process.join(timeout=5.0)
                    self.fail("request-quota worker did not terminate")
                self.assertEqual(0, process.exitcode)
            result_queue.close()
            result_queue.join_thread()
            self.assertCountEqual(["allowed", "rate_limited"], results)

    def test_request_limiter_failure_is_503_before_preview_or_writer_need(self):
        with tempfile.TemporaryDirectory() as td:
            root = self._private_root(td)
            result = _request(
                self._guard(root, _UnavailableLimiter()),
                {"chat": "@target", "text": "draft"},
            )
            self.assertEqual(503, result["status"], result)
            self.assertEqual("rate_limiter_unavailable", result["json"]["error"]["code"])


if __name__ == "__main__":
    unittest.main()
