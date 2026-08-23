"""Credential-free production runtime bootstrap regressions.

No test creates a real Telethon client, connects to Telegram, or stores private
reference values. Private-reference loading is exercised through mocked lookup
functions so the repository secret scanner remains authoritative.
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
from unittest import mock

from bridge.app import ReadAppConfig
from bridge.backend import TelethonReadBackend, UnavailableReadBackend
from bridge.runtime import (
    PrivateTelegramReferences,
    RuntimeBootstrapError,
    SQLiteReadRateLimiter,
    SQLiteWriteRateLimiter,
    _SQLiteFixedWindowStore,
    build_production_application_from_env,
    load_private_telegram_references,
)
from bridge.security import RejectingRateLimiter
from ops.write_endpoint_policy import EndpointPolicyError


class _Clock:
    def __init__(self, value: float):
        self.value = value

    def __call__(self) -> float:
        return self.value


class RuntimeBootstrapTests(unittest.TestCase):
    @staticmethod
    def _private_config(root: Path) -> ReadAppConfig:
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(root, 0o700)
        return ReadAppConfig(auth_secret="synthetic-auth-reference", private_root=root)

    @staticmethod
    def _synthetic_refs() -> PrivateTelegramReferences:
        return PrivateTelegramReferences(
            application_id_ref=100_023,
            application_hash_ref="a" * 32,
            session_reference="synthetic-reference-material-" + ("x" * 24),
        )

    @staticmethod
    def _health(app) -> dict:
        captured: dict[str, object] = {}

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
        if captured.get("status") != "200 OK":
            raise AssertionError(captured.get("status"))
        return json.loads(body.decode("utf-8"))

    def test_absent_private_root_remains_intentionally_fail_closed(self):
        with mock.patch.object(ReadAppConfig, "from_env", return_value=ReadAppConfig()):
            app = build_production_application_from_env()
        self.assertIsInstance(app.read_app.backend, UnavailableReadBackend)
        self.assertIsInstance(app.read_app.rate_limiter, RejectingRateLimiter)
        self.assertIsNone(app.write_adapter)
        self.assertFalse(self._health(app)["ready"])

    def test_private_root_without_telegram_refs_is_bootstrap_not_ready(self):
        with tempfile.TemporaryDirectory() as td:
            config = self._private_config(Path(td) / "private")
            with mock.patch.object(ReadAppConfig, "from_env", return_value=config), \
                 mock.patch("bridge.runtime.load_private_telegram_references", return_value=None):
                app = build_production_application_from_env()
            payload = self._health(app)
            self.assertFalse(payload["ready"])
            self.assertEqual("configured", payload["components"]["read_rate_limit"])
            self.assertEqual("configured", payload["components"]["write_rate_limit"])
            self.assertEqual("configured", payload["components"]["write_store"])
            self.assertEqual("unconfigured", payload["components"]["backend"])
            self.assertEqual("unconfigured", payload["components"]["telegram_writer"])

    def test_complete_private_refs_wire_read_and_write_without_importing_telethon(self):
        with tempfile.TemporaryDirectory() as td:
            config = self._private_config(Path(td) / "private")
            before = {name for name in sys.modules if name == "telethon" or name.startswith("telethon.")}
            with mock.patch.object(ReadAppConfig, "from_env", return_value=config), \
                 mock.patch("bridge.runtime.load_private_telegram_references", return_value=self._synthetic_refs()):
                app = build_production_application_from_env()
            after = {name for name in sys.modules if name == "telethon" or name.startswith("telethon.")}
            self.assertIsInstance(app.read_app.backend, TelethonReadBackend)
            self.assertIsInstance(app.read_app.rate_limiter, SQLiteReadRateLimiter)
            self.assertIsNotNone(app.write_adapter)
            self.assertIsInstance(app._write_limiter, SQLiteWriteRateLimiter)
            self.assertTrue(self._health(app)["ready"])
            self.assertEqual(before, after)

    def test_reference_loader_all_absent_partial_and_malformed_are_distinct(self):
        def absent(_name: str):
            return None

        with mock.patch("bridge.runtime.os.getenv", side_effect=absent):
            self.assertIsNone(load_private_telegram_references())

        def partial(name: str):
            if name.endswith("ID"):
                return "100023"
            return None

        with mock.patch("bridge.runtime.os.getenv", side_effect=partial):
            with self.assertRaises(RuntimeBootstrapError):
                load_private_telegram_references()

        def malformed(name: str):
            if name.endswith("ID"):
                return "100023"
            if name.endswith("HASH"):
                return "not-a-reference"
            return "synthetic-reference-material-xxxxxxxxxxxxxxxxxxxxxxxx"

        with mock.patch("bridge.runtime.os.getenv", side_effect=malformed):
            with self.assertRaises(RuntimeBootstrapError):
                load_private_telegram_references()

    def test_private_root_symlink_and_broad_mode_are_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            broad = base / "broad"
            broad.mkdir(mode=0o755)
            os.chmod(broad, 0o755)
            with mock.patch.object(ReadAppConfig, "from_env", return_value=ReadAppConfig(private_root=broad)):
                with self.assertRaises(RuntimeBootstrapError):
                    build_production_application_from_env()

            target = base / "target"
            target.mkdir(mode=0o700)
            os.chmod(target, 0o700)
            link = base / "link"
            link.symlink_to(target, target_is_directory=True)
            with mock.patch.object(ReadAppConfig, "from_env", return_value=ReadAppConfig(private_root=link)):
                with self.assertRaises(RuntimeBootstrapError):
                    build_production_application_from_env()

    def test_existing_database_broad_mode_symlink_and_hardlink_fail_closed(self):
        with tempfile.TemporaryDirectory() as td:
            state = Path(td) / "state"
            state.mkdir(mode=0o700)
            os.chmod(state, 0o700)

            broad = state / "broad.sqlite3"
            broad.write_bytes(b"")
            os.chmod(broad, 0o644)
            with self.assertRaises(RuntimeBootstrapError):
                _SQLiteFixedWindowStore(broad)
            self.assertEqual(0o644, stat.S_IMODE(broad.stat().st_mode))

            target = state / "target.sqlite3"
            target.write_bytes(b"")
            os.chmod(target, 0o600)
            link = state / "link.sqlite3"
            link.symlink_to(target)
            with self.assertRaises(RuntimeBootstrapError):
                _SQLiteFixedWindowStore(link)

            hard = state / "hard.sqlite3"
            os.link(target, hard)
            with self.assertRaises(RuntimeBootstrapError):
                _SQLiteFixedWindowStore(target)

    def test_sqlite_read_quota_is_shared_and_rolls_over(self):
        with tempfile.TemporaryDirectory() as td:
            state = Path(td) / "state"
            state.mkdir(mode=0o700)
            os.chmod(state, 0o700)
            clock = _Clock(120.0)
            database = state / "rate.sqlite3"
            first = SQLiteReadRateLimiter(_SQLiteFixedWindowStore(database, clock=clock), limit=2, window_seconds=60)
            second = SQLiteReadRateLimiter(_SQLiteFixedWindowStore(database, clock=clock), limit=2, window_seconds=60)
            self.assertTrue(first.check("actor-a").allowed)
            self.assertTrue(second.check("actor-a").allowed)
            blocked = SQLiteReadRateLimiter(_SQLiteFixedWindowStore(database, clock=clock), limit=2, window_seconds=60).check("actor-a")
            self.assertFalse(blocked.allowed)
            self.assertEqual(60, blocked.retry_after_seconds)
            self.assertEqual(0o600, stat.S_IMODE(database.stat().st_mode))
            clock.value = 180.0
            self.assertTrue(first.check("actor-a").allowed)

    def test_sqlite_backward_clock_fails_closed_across_store_instances(self):
        with tempfile.TemporaryDirectory() as td:
            state = Path(td) / "state"
            state.mkdir(mode=0o700)
            os.chmod(state, 0o700)
            clock = _Clock(120.0)
            database = state / "rate.sqlite3"
            first = _SQLiteFixedWindowStore(database, clock=clock)
            allowed, remaining, retry = first.take(
                namespace="read", actor="actor-a", operation="read-api", limit=1, window_seconds=60
            )
            self.assertTrue(allowed)
            self.assertEqual(0, remaining)
            self.assertEqual(0, retry)
            self.assertFalse(first.take(
                namespace="read", actor="actor-a", operation="read-api", limit=1, window_seconds=60
            )[0])

            clock.value = 119.0
            with self.assertRaises(RuntimeBootstrapError) as first_error:
                first.take(namespace="read", actor="actor-a", operation="read-api", limit=1, window_seconds=60)
            self.assertEqual("rate_limit_clock_moved_backward", first_error.exception.code)

            second = _SQLiteFixedWindowStore(database, clock=clock)
            with self.assertRaises(RuntimeBootstrapError) as second_error:
                second.take(namespace="read", actor="actor-a", operation="read-api", limit=1, window_seconds=60)
            self.assertEqual("rate_limit_clock_moved_backward", second_error.exception.code)

            clock.value = 121.0
            self.assertFalse(second.take(
                namespace="read", actor="actor-a", operation="read-api", limit=1, window_seconds=60
            )[0])

    def test_sqlite_write_quota_is_operation_scoped(self):
        with tempfile.TemporaryDirectory() as td:
            state = Path(td) / "state"
            state.mkdir(mode=0o700)
            os.chmod(state, 0o700)
            clock = _Clock(600.0)
            limiter = SQLiteWriteRateLimiter(
                _SQLiteFixedWindowStore(state / "rate.sqlite3", clock=clock),
                limit=1,
                window_seconds=60,
            )
            actor = "a" * 64
            self.assertEqual(0, limiter.consume(actor, "sendMessagePreview")[0])
            with self.assertRaises(EndpointPolicyError) as ctx:
                limiter.consume(actor, "sendMessagePreview")
            self.assertEqual("rate_limited", ctx.exception.code)
            self.assertEqual(429, ctx.exception.status)
            self.assertEqual(60, ctx.exception.retry_after_seconds)
            self.assertEqual(0, limiter.consume(actor, "sendMessageCommit")[0])

    def test_read_and_write_factories_share_exact_private_session_lock_path(self):
        with tempfile.TemporaryDirectory() as td:
            config = self._private_config(Path(td) / "private")
            with mock.patch.object(ReadAppConfig, "from_env", return_value=config), \
                 mock.patch("bridge.runtime.load_private_telegram_references", return_value=self._synthetic_refs()):
                app = build_production_application_from_env()
            read_backend = app.read_app.backend
            self.assertIsInstance(read_backend, TelethonReadBackend)
            write_adapter = app.write_adapter
            self.assertIsNotNone(write_adapter)
            write_lock = write_adapter.session_lock_factory()
            # Build the read wrapper without calling connect() or importing Telethon.
            fake_raw = object()
            with mock.patch("bridge.runtime._raw_telethon_factory", return_value=lambda: fake_raw), \
                 mock.patch.object(ReadAppConfig, "from_env", return_value=config), \
                 mock.patch("bridge.runtime.load_private_telegram_references", return_value=self._synthetic_refs()):
                second_app = build_production_application_from_env()
            read_client = second_app.read_app.backend.client_factory()
            read_lock = read_client._lock_factory()
            self.assertEqual(write_lock.path, read_lock.path)
            self.assertEqual(config.private_root / "locks" / "telegram-session.lock", write_lock.path)

    def test_runtime_wsgi_redacts_builder_failure_and_does_not_cache_failure(self):
        from bridge import runtime_wsgi

        runtime_wsgi.reset_runtime_application_for_tests()
        captured: dict[str, object] = {}

        def start_response(status, headers):
            captured["status"] = status
            captured["headers"] = dict(headers)

        with mock.patch("bridge.runtime.build_production_application_from_env", side_effect=RuntimeError("private-detail")):
            body = b"".join(runtime_wsgi.application({}, start_response))
        self.assertEqual("500 Internal Server Error", captured["status"])
        self.assertNotIn(b"private-detail", body)
        self.assertIn(b"startup_configuration_error", body)
        self.assertIsNone(runtime_wsgi._default_application)

    def test_recovered_passenger_target_resolves_runtime_wrapper_without_telethon_import(self):
        import bridge
        import bridge.app as app_module
        import passenger_wsgi
        from bridge import runtime_wsgi

        before = {name for name in sys.modules if name == "telethon" or name.startswith("telethon.")}
        self.assertIs(passenger_wsgi.application, runtime_wsgi.application)
        self.assertIs(bridge.application, runtime_wsgi.application)
        self.assertIs(app_module.application, runtime_wsgi.application)
        after = {name for name in sys.modules if name == "telethon" or name.startswith("telethon.")}
        self.assertEqual(before, after)


if __name__ == "__main__":
    unittest.main()
