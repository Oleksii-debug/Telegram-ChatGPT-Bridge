"""Current-production composition regressions for authenticated parser-attempt B8."""
from __future__ import annotations

import io
import json
import os
import tempfile
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

    def consume(self, _actor_sha256: str, operation_id: str):
        self.operations.append(operation_id)
        if self.reject_request and operation_id.startswith("request:"):
            raise EndpointPolicyError("rate_limit_exceeded", status=429, retry_after_seconds=7)
        return (9, 180)


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
            "PATH_INFO": "/api/v1/telegram/send/preview",
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
        self.assertIn(b"rate_limit_exceeded", body)
        self.assertEqual(["request:previewTelegramSend"], limiter.operations)
        retry_after = [value for name, value in headers[0] if name.lower() == "retry-after"]
        self.assertEqual(["7"], retry_after)

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


if __name__ == "__main__":
    unittest.main()
