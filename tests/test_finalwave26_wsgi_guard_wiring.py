"""FINALWAVE-26 production WSGI wiring regressions."""
from __future__ import annotations

import hashlib
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from bridge.action_request_guard import ActionRequestGuard
from ops import passenger_evidence_hook, private_evidence


class _SentinelApplication:
    def __init__(self):
        self.calls = 0

    def __call__(self, environ, start_response):
        del environ
        self.calls += 1
        start_response("204 No Content", [("Content-Length", "0")])
        return [b""]


class _RaisingApplication:
    def __call__(self, environ, start_response):
        del environ, start_response
        raise RuntimeError("synthetic dispatch failure")


class Finalwave26WsgiGuardWiringTests(unittest.TestCase):
    CANDIDATE_SHA = "a" * 40
    RAW_CHALLENGE = "1" * 64

    def tearDown(self):
        from bridge import runtime_wsgi

        runtime_wsgi.reset_runtime_application_for_tests()

    @staticmethod
    def _serving_environ(*, challenge: str | None = None, scheme: str = "https", path: str = "/health"):
        return {
            "REQUEST_METHOD": "GET",
            "PATH_INFO": path,
            "QUERY_STRING": "",
            "CONTENT_TYPE": "",
            "CONTENT_LENGTH": "0",
            "wsgi.input": io.BytesIO(b""),
            "wsgi.version": (1, 0),
            "wsgi.url_scheme": scheme,
            "SERVER_PROTOCOL": "HTTP/1.1",
            passenger_evidence_hook.CHALLENGE_HEADER_ENV: challenge or Finalwave26WsgiGuardWiringTests.RAW_CHALLENGE,
        }

    @classmethod
    def _candidate_evidence(cls, wsgi_sha: str) -> dict:
        report = {
            "schema_version": 3,
            "collector_context": "APPLICATION_PROCESS",
            "python_version": "3.11.16",
            "python_major_minor": "3.11",
            "python_implementation": "CPython",
            "runtime_compliance": "PYTHON_3_11_CANDIDATE_CONTEXT",
            "python_executable_sha256": "2" * 64,
            "python_executable_owner_uid": os.geteuid() if hasattr(os, "geteuid") else 0,
            "python_executable_mode": 0o755,
            "python_executable_nlink": 1,
            "sys_prefix_sha256": "3" * 64,
            "sys_base_prefix_sha256": "4" * 64,
            "virtual_environment_active": True,
            "wsgi_relative_path": "passenger_wsgi.py",
            "wsgi_sha256": wsgi_sha,
            "application_import_target": "bridge.app.application",
            "application_import_ok": True,
            "process_cwd_inside_app_root": True,
            "passenger_context_present": True,
            "serving_request_verified": False,
            "package_evidence": [
                {"name": "telethon", "present": True, "version": "1.44.0", "metadata_sha256": "5" * 64},
                {"name": "pypdf", "present": False, "version": "NOT_INSTALLED", "metadata_sha256": "0" * 64},
            ],
            "environment_values_recorded": False,
            "request_data_recorded": False,
            "secret_values_recorded": False,
        }
        report["payload_sha256"] = private_evidence.canonical_json_sha256(report)
        return private_evidence.validate_runtime_report(report)

    @classmethod
    def _arm_real_hook(cls, home: Path, wsgi_sha: str) -> tuple[Path, Path]:
        control = home / passenger_evidence_hook.CONTROL_DIR_NAME
        control.mkdir(mode=0o700)
        os.chmod(control, 0o700)
        marker = control / passenger_evidence_hook.ARM_MARKER_NAME
        challenge_sha = hashlib.sha256(cls.RAW_CHALLENGE.encode("ascii")).hexdigest()
        payload = passenger_evidence_hook.build_arm_marker(cls.CANDIDATE_SHA, wsgi_sha, challenge_sha)
        marker.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
        os.chmod(marker, 0o600)
        return control, marker

    def test_lazy_runtime_builder_is_wrapped_exactly_once(self):
        from bridge import runtime_wsgi

        runtime_wsgi.reset_runtime_application_for_tests()
        sentinel = _SentinelApplication()
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
        with mock.patch("bridge.runtime_composition.build_production_application_from_env", return_value=sentinel) as builder, \
             mock.patch.object(runtime_wsgi, "_observe_passenger_serving_request") as observe:
            body1 = b"".join(runtime_wsgi.application(environ, start_response))
            body2 = b"".join(runtime_wsgi.application(environ, start_response))
        self.assertEqual(b"", body1)
        self.assertEqual(b"", body2)
        self.assertEqual("204 No Content", captured["status"])
        builder.assert_called_once_with()
        self.assertIsInstance(runtime_wsgi._default_application, ActionRequestGuard)
        self.assertIs(runtime_wsgi._default_application.application, sentinel)
        self.assertEqual(2, sentinel.calls)
        self.assertEqual(2, observe.call_count)

    def test_recovered_passenger_import_contract_still_resolves_guarded_runtime_wrapper(self):
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

    def test_actual_runtime_wsgi_health_dispatch_materializes_strong_passenger_evidence(self):
        from bridge import runtime_wsgi

        repo_root = Path(runtime_wsgi.__file__).resolve().parents[1]
        wsgi_sha = hashlib.sha256((repo_root / "passenger_wsgi.py").read_bytes()).hexdigest()
        candidate = self._candidate_evidence(wsgi_sha)
        captured = {}

        def start_response(status, headers):
            captured["status"] = status
            captured["headers"] = dict(headers)

        with tempfile.TemporaryDirectory() as td:
            home = Path(td)
            control, _ = self._arm_real_hook(home, wsgi_sha)
            runtime_wsgi._default_application = _SentinelApplication()
            with mock.patch.object(passenger_evidence_hook.Path, "home", return_value=home), \
                 mock.patch.object(passenger_evidence_hook, "collect_runtime_evidence", return_value=candidate):
                body = b"".join(runtime_wsgi.application(self._serving_environ(), start_response))

            self.assertEqual(b"", body)
            self.assertEqual("204 No Content", captured["status"])
            evidence_root = home / passenger_evidence_hook.EVIDENCE_DIR_NAME
            report_path = evidence_root / passenger_evidence_hook.REPORT_NAME
            binding_path = evidence_root / passenger_evidence_hook.BINDING_REPORT_NAME
            receipt_path = control / passenger_evidence_hook.CONSUMED_RECEIPT_NAME
            for path in (report_path, binding_path, receipt_path):
                self.assertTrue(path.is_file(), path)
                self.assertEqual(0, path.stat().st_mode & 0o077)
            report = private_evidence.validate_runtime_report(json.loads(report_path.read_text(encoding="utf-8")))
            binding = passenger_evidence_hook.validate_binding_report(json.loads(binding_path.read_text(encoding="utf-8")))
            receipt = passenger_evidence_hook.validate_consumed_receipt(json.loads(receipt_path.read_text(encoding="utf-8")))
            self.assertEqual(passenger_evidence_hook.STRONG_STATUS, report["runtime_compliance"])
            self.assertTrue(report["serving_request_verified"])
            self.assertEqual(self.CANDIDATE_SHA, binding["candidate_sha"])
            self.assertEqual(binding["serving_probe_sha256"], receipt["serving_probe_sha256"])
            serialized = report_path.read_text() + binding_path.read_text() + receipt_path.read_text()
            self.assertNotIn(self.RAW_CHALLENGE, serialized)

    def test_wrong_challenge_http_or_wrong_path_do_not_materialize_strong_evidence(self):
        from bridge import runtime_wsgi

        repo_root = Path(runtime_wsgi.__file__).resolve().parents[1]
        wsgi_sha = hashlib.sha256((repo_root / "passenger_wsgi.py").read_bytes()).hexdigest()
        candidate = self._candidate_evidence(wsgi_sha)
        cases = (
            self._serving_environ(challenge="2" * 64),
            self._serving_environ(scheme="http"),
            self._serving_environ(path="/api/v1/dialogs/list"),
        )
        for environ in cases:
            with self.subTest(path=environ["PATH_INFO"], scheme=environ["wsgi.url_scheme"]), tempfile.TemporaryDirectory() as td:
                home = Path(td)
                control, _ = self._arm_real_hook(home, wsgi_sha)
                runtime_wsgi._default_application = _SentinelApplication()
                captured = {}

                def start_response(status, headers):
                    captured["status"] = status
                    captured["headers"] = dict(headers)

                with mock.patch.object(passenger_evidence_hook.Path, "home", return_value=home), \
                     mock.patch.object(passenger_evidence_hook, "collect_runtime_evidence", return_value=candidate):
                    body = b"".join(runtime_wsgi.application(environ, start_response))
                self.assertEqual(b"", body)
                self.assertEqual("204 No Content", captured["status"])
                self.assertFalse((control / passenger_evidence_hook.CONSUMED_RECEIPT_NAME).exists())
                runtime_wsgi.reset_runtime_application_for_tests()

    def test_evidence_failure_never_breaks_health_but_process_control_propagates(self):
        from bridge import runtime_wsgi

        captured = {}

        def start_response(status, headers):
            captured["status"] = status
            captured["headers"] = dict(headers)

        runtime_wsgi._default_application = _SentinelApplication()
        with mock.patch(
            "ops.passenger_evidence_hook.collect_if_armed_from_bridge_app",
            side_effect=RuntimeError("synthetic private evidence failure"),
        ):
            body = b"".join(runtime_wsgi.application(self._serving_environ(), start_response))
        self.assertEqual(b"", body)
        self.assertEqual("204 No Content", captured["status"])

        runtime_wsgi._default_application = _SentinelApplication()
        with mock.patch(
            "ops.passenger_evidence_hook.collect_if_armed_from_bridge_app",
            side_effect=KeyboardInterrupt(),
        ):
            with self.assertRaises(KeyboardInterrupt):
                runtime_wsgi.application(self._serving_environ(), start_response)

    def test_failed_application_dispatch_never_attempts_strong_evidence(self):
        from bridge import runtime_wsgi

        runtime_wsgi._default_application = _RaisingApplication()
        with mock.patch("ops.passenger_evidence_hook.collect_if_armed_from_bridge_app") as observe:
            with self.assertRaises(RuntimeError):
                runtime_wsgi.application(self._serving_environ(), lambda *_args: None)
        observe.assert_not_called()


if __name__ == "__main__":
    unittest.main()
