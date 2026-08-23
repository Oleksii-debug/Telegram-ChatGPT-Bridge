# -*- coding: utf-8 -*-
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from ops import passenger_evidence_hook


class PassengerEvidenceHookTests(unittest.TestCase):
    CANDIDATE_SHA = "a" * 40
    WSGI_SHA = "b" * 64
    RUNTIME_SHA = "c" * 64

    def roots(self, td):
        home = Path(td)
        control = home / passenger_evidence_hook.CONTROL_DIR_NAME
        control.mkdir(mode=0o700)
        os.chmod(control, 0o700)
        marker = control / passenger_evidence_hook.ARM_MARKER_NAME
        return home, control, marker

    def arm(self, marker: Path, *, candidate_sha=None, wsgi_sha=None, mode=0o600):
        payload = passenger_evidence_hook.build_arm_marker(
            candidate_sha or self.CANDIDATE_SHA,
            wsgi_sha or self.WSGI_SHA,
        )
        marker.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
        os.chmod(marker, mode)
        return payload

    def strong_evidence(self, *, wsgi_sha=None):
        return {
            "runtime_compliance": passenger_evidence_hook.STRONG_STATUS,
            "wsgi_sha256": wsgi_sha or self.WSGI_SHA,
            "payload_sha256": self.RUNTIME_SHA,
        }

    def test_not_armed_has_no_side_effect(self):
        with tempfile.TemporaryDirectory() as td:
            home, _, _ = self.roots(td)
            with mock.patch.object(passenger_evidence_hook, "collect_runtime_evidence") as collect:
                result = passenger_evidence_hook.collect_if_armed(app_root=home, wsgi_file=home / "passenger_wsgi.py", home=home)
            self.assertEqual("PASSENGER_EVIDENCE_NOT_ARMED", result)
            collect.assert_not_called()

    def test_strong_application_context_writes_both_private_reports_and_consumes_marker(self):
        with tempfile.TemporaryDirectory() as td:
            home, _, marker = self.roots(td); self.arm(marker)
            evidence = self.strong_evidence()
            with mock.patch.object(passenger_evidence_hook, "collect_runtime_evidence", return_value=evidence) as collect, \
                 mock.patch.object(passenger_evidence_hook, "write_private_report") as write:
                result = passenger_evidence_hook.collect_if_armed(app_root=home, wsgi_file=home / "passenger_wsgi.py", home=home)
            self.assertEqual("PASSENGER_EVIDENCE_PRIVATE_REPORT_WRITTEN", result)
            self.assertFalse(marker.exists())
            self.assertTrue(collect.call_args.kwargs["application_process"])
            write.assert_called_once()
            binding = home / passenger_evidence_hook.EVIDENCE_DIR_NAME / passenger_evidence_hook.BINDING_REPORT_NAME
            self.assertTrue(binding.exists())
            payload = json.loads(binding.read_text(encoding="utf-8"))
            passenger_evidence_hook.validate_binding_report(payload)
            self.assertEqual(self.CANDIDATE_SHA, payload["candidate_sha"])
            self.assertEqual(self.WSGI_SHA, payload["actual_wsgi_sha256"])

    def test_candidate_context_does_not_write_or_consume_marker(self):
        with tempfile.TemporaryDirectory() as td:
            home, _, marker = self.roots(td); self.arm(marker)
            evidence = {"runtime_compliance": "PYTHON_3_11_CANDIDATE_CONTEXT"}
            with mock.patch.object(passenger_evidence_hook, "collect_runtime_evidence", return_value=evidence), \
                 mock.patch.object(passenger_evidence_hook, "write_private_report") as write:
                result = passenger_evidence_hook.collect_if_armed(app_root=home, wsgi_file=home / "passenger_wsgi.py", home=home)
            self.assertEqual("PASSENGER_EVIDENCE_CONTEXT_NOT_CONFIRMED", result)
            self.assertTrue(marker.exists())
            write.assert_not_called()

    def test_wrong_wsgi_hash_blocks_before_report_and_preserves_marker(self):
        with tempfile.TemporaryDirectory() as td:
            home, _, marker = self.roots(td); self.arm(marker)
            evidence = self.strong_evidence(wsgi_sha="d" * 64)
            with mock.patch.object(passenger_evidence_hook, "collect_runtime_evidence", return_value=evidence), \
                 mock.patch.object(passenger_evidence_hook, "write_private_report") as write:
                result = passenger_evidence_hook.collect_if_armed(app_root=home, wsgi_file=home / "passenger_wsgi.py", home=home)
            self.assertEqual("PASSENGER_EVIDENCE_BLOCKED", result)
            self.assertTrue(marker.exists())
            write.assert_not_called()

    def test_empty_legacy_marker_and_malformed_binding_block(self):
        with tempfile.TemporaryDirectory() as td:
            home, _, marker = self.roots(td)
            marker.write_bytes(b""); os.chmod(marker, 0o600)
            result = passenger_evidence_hook.collect_if_armed(app_root=home, wsgi_file=home / "passenger_wsgi.py", home=home)
            self.assertEqual("PASSENGER_EVIDENCE_BLOCKED", result)
            self.assertTrue(marker.exists())
        with tempfile.TemporaryDirectory() as td:
            home, _, marker = self.roots(td)
            marker.write_text('{"schema_version":1,"candidate_sha":"bad"}', encoding="utf-8"); os.chmod(marker, 0o600)
            result = passenger_evidence_hook.collect_if_armed(app_root=home, wsgi_file=home / "passenger_wsgi.py", home=home)
            self.assertEqual("PASSENGER_EVIDENCE_BLOCKED", result)
            self.assertTrue(marker.exists())

    def test_broad_marker_mode_blocks_without_application_failure(self):
        with tempfile.TemporaryDirectory() as td:
            home, _, marker = self.roots(td); self.arm(marker, mode=0o644)
            result = passenger_evidence_hook.collect_if_armed(app_root=home, wsgi_file=home / "passenger_wsgi.py", home=home)
            self.assertEqual("PASSENGER_EVIDENCE_BLOCKED", result)
            self.assertTrue(marker.exists())

    def test_binding_report_tamper_is_rejected(self):
        marker = passenger_evidence_hook.build_arm_marker(self.CANDIDATE_SHA, self.WSGI_SHA)
        payload = passenger_evidence_hook.build_binding_report(marker, self.strong_evidence())
        passenger_evidence_hook.validate_binding_report(payload)
        mutated = dict(payload); mutated["candidate_sha"] = "e" * 40
        with self.assertRaises(Exception):
            passenger_evidence_hook.validate_binding_report(mutated)

    def test_collection_exception_is_sanitized(self):
        with tempfile.TemporaryDirectory() as td:
            home, _, marker = self.roots(td); self.arm(marker)
            with mock.patch.object(passenger_evidence_hook, "collect_runtime_evidence", side_effect=RuntimeError("private path or value")):
                result = passenger_evidence_hook.collect_if_armed(app_root=home, wsgi_file=home / "passenger_wsgi.py", home=home)
            self.assertEqual("PASSENGER_EVIDENCE_BLOCKED", result)
            self.assertNotIn("private", result.casefold())
            self.assertTrue(marker.exists())

    def test_bridge_app_request_adapter_derives_canonical_root_and_wsgi(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            bridge = root / "bridge"
            bridge.mkdir()
            app_file = bridge / "app.py"
            app_file.write_text("# app\n", encoding="utf-8")
            wsgi = root / "passenger_wsgi.py"
            wsgi.write_text("from bridge.app import application\n", encoding="utf-8")
            with mock.patch.object(passenger_evidence_hook, "collect_if_armed", return_value="PASSENGER_EVIDENCE_NOT_ARMED") as collect:
                result = passenger_evidence_hook.collect_if_armed_from_bridge_app(app_file)
            self.assertEqual("PASSENGER_EVIDENCE_NOT_ARMED", result)
            collect.assert_called_once_with(app_root=root, wsgi_file=wsgi, home=None)

    def test_bridge_app_request_adapter_rejects_wrong_topology_and_never_raises(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            wrong = root / "app.py"
            wrong.write_text("# wrong\n", encoding="utf-8")
            self.assertEqual(
                "PASSENGER_EVIDENCE_APP_TOPOLOGY_BLOCKED",
                passenger_evidence_hook.collect_if_armed_from_bridge_app(wrong),
            )
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            bridge = root / "bridge"; bridge.mkdir()
            app_file = bridge / "app.py"; app_file.write_text("# app\n", encoding="utf-8")
            self.assertEqual(
                "PASSENGER_EVIDENCE_APP_TOPOLOGY_BLOCKED",
                passenger_evidence_hook.collect_if_armed_from_bridge_app(app_file),
            )

    def test_bridge_app_request_adapter_does_not_mask_collector_bounded_code(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); bridge = root / "bridge"; bridge.mkdir()
            app_file = bridge / "app.py"; app_file.write_text("# app\n", encoding="utf-8")
            wsgi = root / "passenger_wsgi.py"; wsgi.write_text("from bridge.app import application\n", encoding="utf-8")
            with mock.patch.object(passenger_evidence_hook, "collect_if_armed", return_value="PASSENGER_EVIDENCE_BLOCKED"):
                self.assertEqual(
                    "PASSENGER_EVIDENCE_BLOCKED",
                    passenger_evidence_hook.collect_if_armed_from_bridge_app(app_file),
                )


if __name__ == "__main__":
    unittest.main()
