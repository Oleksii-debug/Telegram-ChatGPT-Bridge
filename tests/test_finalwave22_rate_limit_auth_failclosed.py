"""FINALWAVE-22 auth-order and fail-closed B8 adapter regressions."""
from __future__ import annotations

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
from ops.openapi_registry import OperationClass
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

    def consume(self, _actor_sha256: str, _operation_id: str) -> tuple[int, int]:
        self.calls += 1
        return 9, 180


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
