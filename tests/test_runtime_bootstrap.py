"""Credential-free production-runtime bootstrap regressions.

No test creates a real Telethon client, connects to Telegram, or records a secret
value. Environment values are synthetic in-memory fixtures only.
"""
from __future__ import annotations

import io
import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path

from bridge.backend import TelethonReadBackend, UnavailableReadBackend
from bridge.runtime import (
    RuntimeBootstrapError,
    SQLiteReadRateLimiter,
    SQLiteWriteRateLimiter,
    _SQLiteFixedWindowStore,
    build_production_application_from_env,
    load_private_telegram_references,
)
from bridge.security import RejectingRateLimiter
from ops.write_endpoint_policy import EndpointPolicyError


_ENV_NAMES = (
    "TG_API_ID",
    "TG_API_HASH",
    "TG_SESSION_STRING",
    "BRIDGE_TOKEN",
    "BRIDGE_FILE_SIGNING_SECRET",
    "BRIDGE_PRIVATE_ROOT",
    "BRIDGE_PUBLIC_BASE_URL",
    "BRIDGE_RATE_WINDOW_SECONDS",
    "BRIDGE_READ_RATE_LIMIT",
    "BRIDGE_WRITE_RATE_LIMIT",
    "BRIDGE_PREVIEW_TTL_SECONDS",
    "TELEGRAM_LOCK_TIMEOUT_SECONDS",
    "TELEGRAM_REQUEST_TIMEOUT_SECONDS",
    "TELEGRAM_FLOOD_WAIT_CAP_SECONDS",
    "TELEGRAM_DIALOG_SCAN_LIMIT",
    "TELEGRAM_SEARCH_SCAN_LIMIT",
    "TELEGRAM_MAX_SEND_CHARS",
    "TELEGRAM_MAX_FORWARD_MESSAGES",
    "TELEGRAM_MAX_SEND_FILES",
)


class _EnvSandbox:
    def __enter__(self):
        self._before = {name: os.environ.get(name) for name in _ENV_NAMES}
        for name in _ENV_NAMES:
            os.environ.pop(name, None)
        return self

    def __exit__(self, exc_type, exc, tb):
        for name in _ENV_NAMES:
            os.environ.pop(name, None)
        for name, value in self._before.items():
            if value is not None:
                os.environ[name] = value


class _Clock:
    def __init__(self, value: float):
        self.value = value

    def __call__(self) -> float:
        return self.value


class RuntimeBootstrapTests(unittest.TestCase):
    def _set_private_root(self, root: Path) -> None:
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(root, 0o700)
        os.environ["BRIDGE_PRIVATE_ROOT"] = str(root)
        os.environ["BRIDGE_TOKEN"] = "t" * 32

    @staticmethod
    def _set_synthetic_telegram_refs() -> None:
        os.environ["TG_API_ID"] = str(100_000 + 23)
        os.environ["TG_API_HASH"] = "ab" * 16
        os.environ["TG_SESSION_STRING"] = "synthetic-session-" + ("x" * 32)

    @staticmethod
    def _health(app) -> dict:
        captured = {}

        def start_response(status, headers):
            captured["status"] = status
            captured["headers"] = dict(headers)

        environ = {
            "REQUEST_METHOD": "GET",
            "PATH_INFO": "/health",
            "QUERY_STRING": "",
            "CONTENT_TYPE": "",
            "CONTENT_LENGTH": "0",
            "wsgi.input": io.BytesIO(b""),
        }
        body = b"".join(app(environ, start_response))
        self_status = captured["status"]
        if self_status != "200 OK":
            raise AssertionError(self_status)
        return json.loads(body.decode("utf-8"))

    def test_absent_private_root_remains_intentionally_fail_closed(self):
        with _EnvSandbox():
            app = build_production_application_from_env()
            self.assertIsInstance(app.read_app.backend, UnavailableReadBackend)
            self.assertIsInstance(app.read_app.rate_limiter, RejectingRateLimiter)
            self.assertIsNone(app.write_adapter)
            self.assertFalse(self._health(app)["ready"])

    def test_private_root_without_telegram_refs_is_bootstrap_not_ready(self):
        with _EnvSandbox(), tempfile.TemporaryDirectory() as td:
            root = Path(td) / "private"
            self._set_private_root(root)
            app = build_production_application_from_env()
            payload = self._health(app)
            self.assertFalse(payload["ready"])
            self.assertEqual("configured", payload["components"]["read_rate_limit"])
            self.assertEqual("configured", payload["components"]["write_rate_limit"])
            self.assertEqual("configured", payload["components"]["write_store"])
            self.assertEqual("unconfigured", payload["components"]["backend"])
            self.assertEqual("unconfigured", payload["components"]["telegram_writer"])

    def test_complete_private_refs_wire_read_and_write_without_importing_telethon(self):
        with _EnvSandbox(), tempfile.TemporaryDirectory() as td:
            root = Path(td) / "private"
            self._set_private_root(root)
            self._set_synthetic_telegram_refs()
            for name in tuple(sys.modules):
                if name == "telethon" or name.startswith("telethon."):
                    sys.modules.pop(name, None)
            app = build_production_application_from_env()
            self.assertIsInstance(app.read_app.backend, TelethonReadBackend)
            self.assertIsInstance(app.read_app.rate_limiter, SQLiteReadRateLimiter)
            self.assertIsNotNone(app.write_adapter)
            self.assertIsInstance(app._write_limiter, SQLiteWriteRateLimiter)
            self.assertTrue(self._health(app)["ready"])
            self.assertFalse(any(name == "telethon" or name.startswith("telethon.") for name in sys.modules))

    def test_partial_or_malformed_private_refs_fail_closed(self):
        with _EnvSandbox():
            os.environ["TG_API_ID"] = str(100_001)
            with self.assertRaises(RuntimeBootstrapError):
                load_private_telegram_references()
        with _EnvSandbox():
            self._set_synthetic_telegram_refs()
            os.environ["TG_API_HASH"] = "not-a-valid-reference"
            with self.assertRaises(RuntimeBootstrapError):
                load_private_telegram_references()

    def test_broad_existing_private_root_is_rejected_not_silently_trusted(self):
        with _EnvSandbox(), tempfile.TemporaryDirectory() as td:
            root = Path(td) / "private"
            root.mkdir()
            os.chmod(root, 0o755)
            os.environ["BRIDGE_PRIVATE_ROOT"] = str(root)
            with self.assertRaises(RuntimeBootstrapError):
                build_production_application_from_env()

    def test_sqlite_read_quota_is_shared_between_instances_and_survives_reopen(self):
        with tempfile.TemporaryDirectory() as td:
            state = Path(td) / "state"
            state.mkdir(mode=0o700)
            os.chmod(state, 0o700)
            clock = _Clock(120.0)
            db = state / "rate.sqlite3"
            first = SQLiteReadRateLimiter(_SQLiteFixedWindowStore(db, clock=clock), limit=2, window_seconds=60)
            second = SQLiteReadRateLimiter(_SQLiteFixedWindowStore(db, clock=clock), limit=2, window_seconds=60)
            self.assertTrue(first.check("actor-a").allowed)
            self.assertTrue(second.check("actor-a").allowed)
            blocked = SQLiteReadRateLimiter(_SQLiteFixedWindowStore(db, clock=clock), limit=2, window_seconds=60).check("actor-a")
            self.assertFalse(blocked.allowed)
            self.assertEqual(60, blocked.retry_after_seconds)
            self.assertEqual(0o600, stat.S_IMODE(db.stat().st_mode))
            clock.value = 180.0
            self.assertTrue(first.check("actor-a").allowed)

    def test_sqlite_write_quota_is_operation_scoped_and_fails_closed(self):
        with tempfile.TemporaryDirectory() as td:
            state = Path(td) / "state"
            state.mkdir(mode=0o700)
            os.chmod(state, 0o700)
            clock = _Clock(600.0)
            store = _SQLiteFixedWindowStore(state / "rate.sqlite3", clock=clock)
            limiter = SQLiteWriteRateLimiter(store, limit=1, window_seconds=60)
            actor = "a" * 64
            remaining, _reset = limiter.consume(actor, "sendMessagePreview")
            self.assertEqual(0, remaining)
            with self.assertRaises(EndpointPolicyError) as ctx:
                limiter.consume(actor, "sendMessagePreview")
            self.assertEqual("rate_limited", ctx.exception.code)
            self.assertEqual(429, ctx.exception.status)
            self.assertEqual(60, ctx.exception.retry_after_seconds)
            # A distinct canonical operation has an independent bucket.
            self.assertEqual(0, limiter.consume(actor, "sendMessageCommit")[0])

    def test_recovered_passenger_target_now_resolves_runtime_wrapper(self):
        with _EnvSandbox():
            import bridge
            import bridge.app as app_module
            import passenger_wsgi
            from bridge import runtime_wsgi

            self.assertIs(passenger_wsgi.application, runtime_wsgi.application)
            self.assertIs(bridge.application, runtime_wsgi.application)
            self.assertIs(app_module.application, runtime_wsgi.application)
            self.assertFalse(any(name == "telethon" or name.startswith("telethon.") for name in sys.modules))


if __name__ == "__main__":
    unittest.main()
