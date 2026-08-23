# -*- coding: utf-8 -*-
import hashlib
import json
import os
import tempfile
import unittest
from io import BytesIO
from pathlib import Path
from unittest import mock

from ops import passenger_evidence_hook, private_evidence


class PassengerEvidenceHookTests(unittest.TestCase):
    CANDIDATE_SHA = "a" * 40
    WSGI_SHA = "b" * 64
    RAW_CHALLENGE = "1" * 64
    CHALLENGE_SHA = hashlib.sha256(RAW_CHALLENGE.encode("ascii")).hexdigest()

    def roots(self, td):
        home = Path(td)
        control = home / passenger_evidence_hook.CONTROL_DIR_NAME
        control.mkdir(mode=0o700)
        os.chmod(control, 0o700)
        marker = control / passenger_evidence_hook.ARM_MARKER_NAME
        return home, control, marker

    def app_tree(self, home: Path):
        bridge = home / "bridge"
        bridge.mkdir(exist_ok=True)
        app_file = bridge / "app.py"
        app_file.write_text("# app\n", encoding="utf-8")
        wsgi = home / "passenger_wsgi.py"
        wsgi.write_text("from bridge.app import application\n", encoding="utf-8")
        return app_file, wsgi

    def arm(self, marker: Path, *, candidate_sha=None, wsgi_sha=None, challenge_sha=None, mode=0o600):
        payload = passenger_evidence_hook.build_arm_marker(
            candidate_sha or self.CANDIDATE_SHA,
            wsgi_sha or self.WSGI_SHA,
            challenge_sha or self.CHALLENGE_SHA,
        )
        marker.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
        os.chmod(marker, mode)
        return payload

    def candidate_evidence(self, *, wsgi_sha=None, passenger=True):
        report = {
            "schema_version": 3,
            "collector_context": "APPLICATION_PROCESS",
            "python_version": "3.11.16",
            "python_major_minor": "3.11",
            "python_implementation": "CPython",
            "runtime_compliance": "PYTHON_3_11_CANDIDATE_CONTEXT",
            "python_executable_sha256": "2" * 64,
            "python_executable_owner_uid": 1000,
            "python_executable_mode": 0o755,
            "python_executable_nlink": 1,
            "sys_prefix_sha256": "3" * 64,
            "sys_base_prefix_sha256": "4" * 64,
            "virtual_environment_active": True,
            "wsgi_relative_path": "passenger_wsgi.py",
            "wsgi_sha256": wsgi_sha or self.WSGI_SHA,
            "application_import_target": "bridge.app.application",
            "application_import_ok": True,
            "process_cwd_inside_app_root": True,
            "passenger_context_present": passenger,
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
        private_evidence.validate_runtime_report(report)
        return report

    def serving_environ(self, challenge=None, *, scheme="https", method="GET", path="/health"):
        return {
            "REQUEST_METHOD": method,
            "PATH_INFO": path,
            "wsgi.version": (1, 0),
            "wsgi.url_scheme": scheme,
            "SERVER_PROTOCOL": "HTTP/1.1",
            "wsgi.input": BytesIO(b""),
            passenger_evidence_hook.CHALLENGE_HEADER_ENV: challenge or self.RAW_CHALLENGE,
        }

    def test_not_armed_has_no_side_effect(self):
        with tempfile.TemporaryDirectory() as td:
            home, _, _ = self.roots(td); _, wsgi = self.app_tree(home)
            with mock.patch.object(passenger_evidence_hook, "collect_runtime_evidence") as collect:
                result = passenger_evidence_hook.collect_if_armed(app_root=home, wsgi_file=wsgi, home=home)
            self.assertEqual("PASSENGER_EVIDENCE_NOT_ARMED", result)
            collect.assert_not_called()

    def test_import_time_armed_observation_never_writes_strong_evidence(self):
        with tempfile.TemporaryDirectory() as td:
            home, _, marker = self.roots(td); _, wsgi = self.app_tree(home); self.arm(marker)
            candidate = self.candidate_evidence()
            with mock.patch.object(passenger_evidence_hook, "collect_runtime_evidence", return_value=candidate):
                result = passenger_evidence_hook.collect_if_armed(app_root=home, wsgi_file=wsgi, home=home)
            self.assertEqual("PASSENGER_EVIDENCE_AWAITING_SERVING_REQUEST", result)
            self.assertTrue(marker.exists())
            evidence_root = home / passenger_evidence_hook.EVIDENCE_DIR_NAME
            self.assertFalse((evidence_root / passenger_evidence_hook.REPORT_NAME).exists())
            self.assertFalse((evidence_root / passenger_evidence_hook.BINDING_REPORT_NAME).exists())

    def test_verified_https_health_request_writes_reports_and_terminal_receipt(self):
        with tempfile.TemporaryDirectory() as td:
            home, control, marker = self.roots(td); app_file, _ = self.app_tree(home); self.arm(marker)
            candidate = self.candidate_evidence()
            with mock.patch.object(passenger_evidence_hook, "collect_runtime_evidence", return_value=candidate):
                result = passenger_evidence_hook.collect_if_armed_from_bridge_app(
                    app_file, environ=self.serving_environ(), home=home
                )
            self.assertEqual("PASSENGER_EVIDENCE_PRIVATE_REPORT_WRITTEN", result)
            self.assertTrue(marker.exists())
            evidence_root = home / passenger_evidence_hook.EVIDENCE_DIR_NAME
            report_path = evidence_root / passenger_evidence_hook.REPORT_NAME
            binding_path = evidence_root / passenger_evidence_hook.BINDING_REPORT_NAME
            receipt_path = control / passenger_evidence_hook.CONSUMED_RECEIPT_NAME
            for path in (report_path, binding_path, receipt_path):
                self.assertTrue(path.is_file())
                self.assertEqual(0, path.stat().st_mode & 0o077)
            report = json.loads(report_path.read_text(encoding="utf-8"))
            self.assertEqual(passenger_evidence_hook.STRONG_STATUS, report["runtime_compliance"])
            self.assertTrue(report["serving_request_verified"])
            binding = passenger_evidence_hook.validate_binding_report(json.loads(binding_path.read_text(encoding="utf-8")))
            receipt = passenger_evidence_hook.validate_consumed_receipt(json.loads(receipt_path.read_text(encoding="utf-8")))
            self.assertEqual(self.CANDIDATE_SHA, binding["candidate_sha"])
            self.assertEqual(binding["serving_probe_sha256"], receipt["serving_probe_sha256"])
            serialized = report_path.read_text() + binding_path.read_text() + receipt_path.read_text()
            self.assertNotIn(self.RAW_CHALLENGE, serialized)

    def test_consumed_receipt_blocks_challenge_replay(self):
        with tempfile.TemporaryDirectory() as td:
            home, _, marker = self.roots(td); app_file, _ = self.app_tree(home); self.arm(marker)
            with mock.patch.object(passenger_evidence_hook, "collect_runtime_evidence", return_value=self.candidate_evidence()):
                first = passenger_evidence_hook.collect_if_armed_from_bridge_app(app_file, environ=self.serving_environ(), home=home)
                second = passenger_evidence_hook.collect_if_armed_from_bridge_app(app_file, environ=self.serving_environ(), home=home)
            self.assertEqual("PASSENGER_EVIDENCE_PRIVATE_REPORT_WRITTEN", first)
            self.assertEqual("PASSENGER_EVIDENCE_ALREADY_CONSUMED", second)

    def test_wrong_challenge_http_scheme_method_or_path_never_finalize(self):
        cases = [
            self.serving_environ("2" * 64),
            self.serving_environ(scheme="http"),
            self.serving_environ(method="POST"),
            self.serving_environ(path="/api/v1/dialogs/list"),
        ]
        for environ in cases:
            with self.subTest(environ={k: environ[k] for k in ("REQUEST_METHOD", "PATH_INFO", "wsgi.url_scheme")}), tempfile.TemporaryDirectory() as td:
                home, control, marker = self.roots(td); app_file, _ = self.app_tree(home); self.arm(marker)
                with mock.patch.object(passenger_evidence_hook, "collect_runtime_evidence") as collect:
                    result = passenger_evidence_hook.collect_if_armed_from_bridge_app(app_file, environ=environ, home=home)
                self.assertEqual("PASSENGER_EVIDENCE_SERVING_REQUEST_NOT_VERIFIED", result)
                collect.assert_not_called()
                self.assertFalse((control / passenger_evidence_hook.CONSUMED_RECEIPT_NAME).exists())

    def test_candidate_without_passenger_signal_cannot_be_promoted(self):
        with tempfile.TemporaryDirectory() as td:
            home, _, marker = self.roots(td); app_file, _ = self.app_tree(home); self.arm(marker)
            with mock.patch.object(passenger_evidence_hook, "collect_runtime_evidence", return_value=self.candidate_evidence(passenger=False)):
                result = passenger_evidence_hook.collect_if_armed_from_bridge_app(app_file, environ=self.serving_environ(), home=home)
            self.assertEqual("PASSENGER_EVIDENCE_BLOCKED", result)

    def test_wrong_wsgi_hash_blocks_before_report_and_preserves_marker(self):
        with tempfile.TemporaryDirectory() as td:
            home, _, marker = self.roots(td); app_file, _ = self.app_tree(home); self.arm(marker)
            with mock.patch.object(passenger_evidence_hook, "collect_runtime_evidence", return_value=self.candidate_evidence(wsgi_sha="d" * 64)):
                result = passenger_evidence_hook.collect_if_armed_from_bridge_app(app_file, environ=self.serving_environ(), home=home)
            self.assertEqual("PASSENGER_EVIDENCE_BLOCKED", result)
            self.assertTrue(marker.exists())

    def test_marker_replacement_between_read_and_finalize_fails_closed(self):
        with tempfile.TemporaryDirectory() as td:
            home, control, marker = self.roots(td); app_file, _ = self.app_tree(home); self.arm(marker)
            real_verify = passenger_evidence_hook.verify_private_file_identity
            calls = {"n": 0}
            def racing_verify(root, path, expected):
                calls["n"] += 1
                if calls["n"] == 2:
                    replacement = control / "replacement"
                    self.arm(replacement)
                    marker.unlink()
                    replacement.rename(marker)
                return real_verify(root, path, expected)
            with mock.patch.object(passenger_evidence_hook, "collect_runtime_evidence", return_value=self.candidate_evidence()), \
                 mock.patch.object(passenger_evidence_hook, "verify_private_file_identity", side_effect=racing_verify):
                result = passenger_evidence_hook.collect_if_armed_from_bridge_app(app_file, environ=self.serving_environ(), home=home)
            self.assertEqual("PASSENGER_EVIDENCE_BLOCKED", result)
            self.assertFalse((control / passenger_evidence_hook.CONSUMED_RECEIPT_NAME).exists())

    def test_evidence_root_symlink_final_symlink_and_hardlink_fail_closed(self):
        with tempfile.TemporaryDirectory() as td:
            home, _, marker = self.roots(td); app_file, _ = self.app_tree(home); self.arm(marker)
            target = home / "outside"; target.mkdir(mode=0o700)
            (home / passenger_evidence_hook.EVIDENCE_DIR_NAME).symlink_to(target, target_is_directory=True)
            with mock.patch.object(passenger_evidence_hook, "collect_runtime_evidence", return_value=self.candidate_evidence()):
                self.assertEqual("PASSENGER_EVIDENCE_BLOCKED", passenger_evidence_hook.collect_if_armed_from_bridge_app(app_file, environ=self.serving_environ(), home=home))
        with tempfile.TemporaryDirectory() as td:
            home, _, marker = self.roots(td); app_file, _ = self.app_tree(home); self.arm(marker)
            evidence_root = home / passenger_evidence_hook.EVIDENCE_DIR_NAME; evidence_root.mkdir(mode=0o700); os.chmod(evidence_root, 0o700)
            target = home / "target"; target.write_text("unchanged", encoding="utf-8"); os.chmod(target, 0o600)
            (evidence_root / passenger_evidence_hook.REPORT_NAME).symlink_to(target)
            with mock.patch.object(passenger_evidence_hook, "collect_runtime_evidence", return_value=self.candidate_evidence()):
                self.assertEqual("PASSENGER_EVIDENCE_BLOCKED", passenger_evidence_hook.collect_if_armed_from_bridge_app(app_file, environ=self.serving_environ(), home=home))
            self.assertEqual("unchanged", target.read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as td:
            home, _, marker = self.roots(td); app_file, _ = self.app_tree(home); self.arm(marker)
            evidence_root = home / passenger_evidence_hook.EVIDENCE_DIR_NAME; evidence_root.mkdir(mode=0o700); os.chmod(evidence_root, 0o700)
            target = home / "target"; target.write_text("unchanged", encoding="utf-8"); os.chmod(target, 0o600)
            os.link(target, evidence_root / passenger_evidence_hook.BINDING_REPORT_NAME)
            with mock.patch.object(passenger_evidence_hook, "collect_runtime_evidence", return_value=self.candidate_evidence()):
                self.assertEqual("PASSENGER_EVIDENCE_BLOCKED", passenger_evidence_hook.collect_if_armed_from_bridge_app(app_file, environ=self.serving_environ(), home=home))

    def test_broad_or_legacy_marker_blocks_without_application_failure(self):
        with tempfile.TemporaryDirectory() as td:
            home, _, marker = self.roots(td); _, wsgi = self.app_tree(home); self.arm(marker, mode=0o644)
            result = passenger_evidence_hook.collect_if_armed(app_root=home, wsgi_file=wsgi, home=home)
            self.assertEqual("PASSENGER_EVIDENCE_BLOCKED", result)
        with tempfile.TemporaryDirectory() as td:
            home, _, marker = self.roots(td); _, wsgi = self.app_tree(home)
            marker.write_text('{"schema_version":1,"candidate_sha":"bad"}', encoding="utf-8"); os.chmod(marker, 0o600)
            result = passenger_evidence_hook.collect_if_armed(app_root=home, wsgi_file=wsgi, home=home)
            self.assertEqual("PASSENGER_EVIDENCE_BLOCKED", result)

    def test_binding_report_tamper_is_rejected(self):
        marker = passenger_evidence_hook.build_arm_marker(self.CANDIDATE_SHA, self.WSGI_SHA, self.CHALLENGE_SHA)
        strong = passenger_evidence_hook._promote_runtime_for_verified_request(self.candidate_evidence())
        payload = passenger_evidence_hook.build_binding_report(marker, strong)
        passenger_evidence_hook.validate_binding_report(payload)
        for key, value in (("candidate_sha", "e" * 40), ("serving_probe_sha256", "f" * 64)):
            mutated = dict(payload); mutated[key] = value
            with self.subTest(key=key), self.assertRaises(Exception):
                passenger_evidence_hook.validate_binding_report(mutated)

    def test_collection_exception_is_sanitized(self):
        with tempfile.TemporaryDirectory() as td:
            home, _, marker = self.roots(td); app_file, _ = self.app_tree(home); self.arm(marker)
            with mock.patch.object(passenger_evidence_hook, "collect_runtime_evidence", side_effect=RuntimeError("private path or value")):
                result = passenger_evidence_hook.collect_if_armed_from_bridge_app(app_file, environ=self.serving_environ(), home=home)
            self.assertEqual("PASSENGER_EVIDENCE_BLOCKED", result)
            self.assertNotIn("private", result.casefold())

    def test_bridge_app_adapter_requires_real_topology_and_environ(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            wrong = root / "app.py"; wrong.write_text("# wrong\n", encoding="utf-8")
            self.assertEqual("PASSENGER_EVIDENCE_APP_TOPOLOGY_BLOCKED", passenger_evidence_hook.collect_if_armed_from_bridge_app(wrong))
        with tempfile.TemporaryDirectory() as td:
            home, _, _ = self.roots(td); app_file, _ = self.app_tree(home)
            self.assertEqual("PASSENGER_EVIDENCE_SERVING_REQUEST_REQUIRED", passenger_evidence_hook.collect_if_armed_from_bridge_app(app_file, home=home))


if __name__ == "__main__":
    unittest.main()
