"""Current-production composition regressions for authenticated parser-attempt B8."""
from __future__ import annotations

import io
import json
import os
import tempfile
import threading
import unittest
from pathlib import Path

from bridge.app import BridgeApplication, ReadAppConfig
from bridge.integrated_app import UnifiedBridgeApplication
from bridge.preparse_rate_guard import PreparseRateLimitedActionGuard
from ops.write_endpoint_policy import EndpointPolicyError


class _CountingLimiter:
    def __init__(self, *, reject_request: bool = False):
        self.operations: list[str] = []
        self.reject_request = reject_request
        self._lock = threading.Lock()

    def consume(self, _actor_sha256: str, operation_id: str):
        with self._lock:
            self.operations.append(operation_id)
        if self.reject_request and operation_id.startswith("request:"):
            raise EndpointPolicyError("rate_limited", status=429, retry_after_seconds=7)
        return (9, 180)


class _InterruptingLimiter(_CountingLimiter):
    def consume(self, actor_sha256: str, operation_id: str):
        with self._lock:
            self.operations.append(operation_id)
        if operation_id.startswith("request:"):
            raise KeyboardInterrupt("synthetic process-control interruption")
        return super().consume(actor_sha256, operation_id)


class _BombInput:
    def read(self, *_args, **_kwargs):
        raise AssertionError("request body must not be read")


def _capture():
    statuses: list[str] = []
    headers: list[list[tuple[str, str]]] = []

    def start_response(status, response_headers):
        statuses.append(status)
        headers.append(list(response_headers))

    return statuses, headers, start_response


class Final5Task2PreparseB8CompositionTests(unittest.TestCase):
    def _application(self, limiter: _CountingLimiter):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        private_root = Path(td.name) / "private"
        private_root.mkdir(mode=0o700)
        os.chmod(private_root, 0o700)
        auth = "synthetic-auth-reference-value"
        app = UnifiedBridgeApplication(
            read_app=BridgeApplication(
                config=ReadAppConfig(auth_secret=auth, private_root=private_root)
            ),
            write_limiter=limiter,
        )
        return auth, PreparseRateLimitedActionGuard(app)

    @staticmethod
    def _environ(auth: str, raw: bytes, *, body=None):
        return {
            "REQUEST_METHOD": "POST",
            "PATH_INFO": "/api/v1/messages/send/preview",
            "HTTP_AUTHORIZATION": f"Bearer {auth}",
            "CONTENT_TYPE": "application/json",
            "CONTENT_LENGTH": str(len(raw)),
            "wsgi.input": io.BytesIO(raw) if body is None else body,
        }

    def test_authenticated_malformed_json_consumes_request_bucket_before_parse(self):
        limiter = _CountingLimiter()
        auth, app = self._application(limiter)
        statuses, _headers, start_response = _capture()
        raw = b"{"
        body = b"".join(app(self._environ(auth, raw), start_response))
        self.assertTrue(statuses and statuses[0].startswith("400 "), statuses)
        self.assertIn(b"malformed_json", body)
        self.assertEqual(["request:previewTelegramSend"], limiter.operations)

    def test_valid_preview_consumes_request_bucket_once_and_semantic_bucket_once(self):
        limiter = _CountingLimiter()
        auth, app = self._application(limiter)
        statuses, _headers, start_response = _capture()
        raw = json.dumps({"chat": "@target_user", "text": "synthetic draft"}).encode("utf-8")
        body = b"".join(app(self._environ(auth, raw), start_response))
        self.assertTrue(statuses and statuses[0].startswith("200 "), (statuses, body))
        self.assertEqual(
            ["request:previewTelegramSend", "previewTelegramSend"],
            limiter.operations,
        )

    def test_request_bucket_rejection_happens_before_body_read(self):
        limiter = _CountingLimiter(reject_request=True)
        auth, app = self._application(limiter)
        statuses, headers, start_response = _capture()
        body = b"".join(app(self._environ(auth, b"xxxx", body=_BombInput()), start_response))
        self.assertTrue(statuses and statuses[0].startswith("429 "), statuses)
        self.assertIn(b"rate_limited", body)
        self.assertEqual(["request:previewTelegramSend"], limiter.operations)
        retry_after = [value for name, value in headers[0] if name.lower() == "retry-after"]
        self.assertEqual(["7"], retry_after)

    def test_process_control_exception_from_request_limiter_propagates(self):
        limiter = _InterruptingLimiter()
        auth, app = self._application(limiter)
        statuses, _headers, start_response = _capture()
        with self.assertRaises(KeyboardInterrupt):
            list(app(self._environ(auth, b"xxxx", body=_BombInput()), start_response))
        self.assertEqual(["request:previewTelegramSend"], limiter.operations)
        self.assertEqual([], statuses)

    def test_inner_canonical_write_handler_cannot_swallow_process_control_exception(self):
        limiter = _InterruptingLimiter()
        auth, guarded = self._application(limiter)
        statuses, _headers, start_response = _capture()
        raw = json.dumps({"chat": "@target_user", "text": "synthetic draft"}).encode("utf-8")
        # Bypass the outer preparse call deliberately. Construction of the guard
        # installs the process-control passthrough on the canonical application,
        # so the current canonical `except BaseException` cannot turn a real
        # process-control interruption into an HTTP response.
        with self.assertRaises(KeyboardInterrupt):
            list(guarded.application(self._environ(auth, raw), start_response))
        self.assertEqual(["request:previewTelegramSend"], limiter.operations)
        self.assertEqual([], statuses)

    def test_wrong_bearer_does_not_consume_quota_or_read_body(self):
        limiter = _CountingLimiter()
        auth, app = self._application(limiter)
        statuses, _headers, start_response = _capture()
        environ = self._environ(auth, b"xxxx", body=_BombInput())
        environ["HTTP_AUTHORIZATION"] = "Bearer wrong-reference"
        body = b"".join(app(environ, start_response))
        self.assertTrue(statuses and statuses[0].startswith("404 "), statuses)
        self.assertEqual([], limiter.operations)
        self.assertNotIn(b"wrong-reference", body)

    def test_concurrent_valid_requests_do_not_share_dedup_state(self):
        limiter = _CountingLimiter()
        auth, app = self._application(limiter)
        barrier = threading.Barrier(3)
        failures: list[BaseException] = []

        def worker(target: str) -> None:
            try:
                raw = json.dumps({"chat": target, "text": "synthetic draft"}).encode("utf-8")
                statuses, _headers, start_response = _capture()
                barrier.wait(timeout=5)
                body = b"".join(app(self._environ(auth, raw), start_response))
                if not statuses or not statuses[0].startswith("200 "):
                    raise AssertionError((statuses, body))
            except BaseException as exc:
                failures.append(exc)

        threads = [threading.Thread(target=worker, args=(f"@target_{idx}",)) for idx in range(2)]
        for thread in threads:
            thread.start()
        barrier.wait(timeout=5)
        for thread in threads:
            thread.join(timeout=10)
        self.assertFalse(failures, failures)
        self.assertFalse(any(thread.is_alive() for thread in threads))
        self.assertEqual(2, limiter.operations.count("request:previewTelegramSend"))
        self.assertEqual(2, limiter.operations.count("previewTelegramSend"))


if __name__ == "__main__":
    unittest.main()
