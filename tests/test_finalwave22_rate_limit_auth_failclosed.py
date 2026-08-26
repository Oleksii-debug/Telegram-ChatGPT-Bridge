"""FINALWAVE-22 auth-order and fail-closed B8 adapter regressions."""
from __future__ import annotations

import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from bridge.app import BridgeApplication, ReadAppConfig
from bridge.errors import BridgeError, HiddenNotFound
from bridge.integrated_app import UnifiedBridgeApplication
from bridge.runtime import (
    RuntimeBootstrapError,
    SQLiteReadRateLimiter,
    SQLiteWriteRateLimiter,
    build_production_application_from_env,
)
from bridge.security import RateLimitDecision
from ops.openapi_registry import OperationClass, registry_by_operation_id
from ops.write_endpoint_policy import EndpointPolicyError


class _UnavailableStore:
    def take_outcome(self, **_kwargs):
        raise RuntimeBootstrapError("rate_limit_database_unavailable")


class _CountingReadLimiter:
    def __init__(self):
        self.calls = 0

    def check(self, _actor: str) -> RateLimitDecision:
        self.calls += 1
        return RateLimitDecision(allowed=True, remaining=9)


class _CountingWriteLimiter:
    def __init__(self):
        self.calls = 0
        self.operations: list[str] = []

    def consume(self, _actor_sha256: str, operation_id: str) -> tuple[int, int]:
        self.calls += 1
        self.operations.append(operation_id)
        return 9, 180


def _capture_status():
    captured: list[str] = []

    def start_response(status, _headers):
        captured.append(status)

    return captured, start_response


class Finalwave22RateLimitAuthFailclosedTests(unittest.TestCase):
    def test_read_adapter_maps_store_failure_to_stable_503(self):
        limiter = SQLiteReadRateLimiter(_UnavailableStore(), limit=10, window_seconds=60)
        with self.assertRaises(BridgeError) as caught:
            limiter.check("authenticated-read-api")
        self.assertEqual(503, caught.exception.status)
        self.assertEqual("rate_limiter_unavailable", caught.exception.code)

    def test_write_adapter_maps_store_failure_to_stable_503(self):
        limiter = SQLiteWriteRateLimiter(_UnavailableStore(), limit=10, window_seconds=60)
        with self.assertRaises(EndpointPolicyError) as caught:
            limiter.consume("a" * 64, "previewTelegramSend")
        self.assertEqual(503, caught.exception.status)
        self.assertEqual("rate_limiter_unavailable", caught.exception.code)

    def test_unauthorized_read_is_rejected_before_quota_consumption(self):
        limiter = _CountingReadLimiter()
        auth_reference = "synthetic-auth-reference-value"
        app = BridgeApplication(
            config=ReadAppConfig(auth_secret=auth_reference),
            rate_limiter=limiter,
        )
        with self.assertRaises(HiddenNotFound):
            app._require_auth_and_rate({"HTTP_AUTHORIZATION": "Bearer wrong-reference"})
        self.assertEqual(0, limiter.calls)
        app._require_auth_and_rate({"HTTP_AUTHORIZATION": f"Bearer {auth_reference}"})
        self.assertEqual(1, limiter.calls)

    def test_write_auth_is_rejected_before_write_policy_quota(self):
        limiter = _CountingWriteLimiter()
        auth_reference = "synthetic-auth-reference-value"
        read_app = BridgeApplication(config=ReadAppConfig(auth_secret=auth_reference))
        app = UnifiedBridgeApplication(read_app=read_app, write_limiter=limiter)
        with self.assertRaises(HiddenNotFound):
            app._require_write_auth({"HTTP_AUTHORIZATION": "Bearer wrong-reference"})
        self.assertEqual(0, limiter.calls)
        context = app._require_write_auth({"HTTP_AUTHORIZATION": f"Bearer {auth_reference}"})
        from ops.write_endpoint_policy import WriteEndpointPolicy
        WriteEndpointPolicy(limiter).authorize(
            "previewTelegramSend",
            context,
            expected_class=OperationClass.WRITE_PREVIEW,
        )
        self.assertEqual(1, limiter.calls)

    def test_authenticated_malformed_write_is_rate_limited_before_json_parse(self):
        with tempfile.TemporaryDirectory() as td:
            private_root = Path(td) / "private"
            private_root.mkdir(mode=0o700)
            os.chmod(private_root, 0o700)
            auth_reference = "synthetic-auth-reference-value"
            limiter = _CountingWriteLimiter()
            app = UnifiedBridgeApplication(
                read_app=BridgeApplication(
                    config=ReadAppConfig(auth_secret=auth_reference, private_root=private_root)
                ),
                write_limiter=limiter,
            )
            captured, start_response = _capture_status()
            spec = registry_by_operation_id("previewTelegramSend")
            raw = b"{"
            body = b"".join(
                app._handle_write(
                    spec,
                    {
                        "HTTP_AUTHORIZATION": f"Bearer {auth_reference}",
                        "CONTENT_TYPE": "application/json",
                        "CONTENT_LENGTH": str(len(raw)),
                        "wsgi.input": io.BytesIO(raw),
                    },
                    start_response,
                )
            )
            self.assertTrue(captured and captured[0].startswith("400 "), captured)
            self.assertIn(b"malformed_json", body)
            self.assertEqual(["request:previewTelegramSend"], limiter.operations)

    def test_valid_write_preview_has_preparse_and_operation_quota_layers(self):
        with tempfile.TemporaryDirectory() as td:
            private_root = Path(td) / "private"
            private_root.mkdir(mode=0o700)
            os.chmod(private_root, 0o700)
            auth_reference = "synthetic-auth-reference-value"
            limiter = _CountingWriteLimiter()
            app = UnifiedBridgeApplication(
                read_app=BridgeApplication(
                    config=ReadAppConfig(auth_secret=auth_reference, private_root=private_root)
                ),
                write_limiter=limiter,
            )
            captured, start_response = _capture_status()
            spec = registry_by_operation_id("previewTelegramSend")
            raw = json.dumps({"chat": "@target_user", "text": "synthetic draft"}).encode("utf-8")
            body = b"".join(
                app._handle_write(
                    spec,
                    {
                        "HTTP_AUTHORIZATION": f"Bearer {auth_reference}",
                        "CONTENT_TYPE": "application/json",
                        "CONTENT_LENGTH": str(len(raw)),
                        "wsgi.input": io.BytesIO(raw),
                    },
                    start_response,
                )
            )
            self.assertTrue(captured and captured[0].startswith("200 "), (captured, body))
            self.assertEqual(
                ["request:previewTelegramSend", "previewTelegramSend"],
                limiter.operations,
            )

    def test_runtime_read_and_write_limiters_share_exact_store_instance(self):
        with tempfile.TemporaryDirectory() as td:
            private_root = Path(td) / "private"
            private_root.mkdir(mode=0o700)
            os.chmod(private_root, 0o700)
            config = ReadAppConfig(auth_secret="synthetic-auth-reference-value", private_root=private_root)
            with mock.patch.object(ReadAppConfig, "from_env", return_value=config), mock.patch(
                "bridge.runtime.load_private_telegram_references", return_value=None
            ):
                app = build_production_application_from_env()
            self.assertIs(app.read_app.rate_limiter.store, app._write_limiter.store)
            self.assertEqual(private_root / "state" / "rate_limit.sqlite3", app.read_app.rate_limiter.store.database_path)


if __name__ == "__main__":
    unittest.main()
