# -*- coding: utf-8 -*-
import hashlib
import io
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
    CHALLENGE = "d" * 64
    CHALLENGE_SHA = hashlib.sha256(CHALLENGE.encode("ascii")).hexdigest()

    def roots(self, td):
        home = Path(td) / "home"
        home.mkdir()
        control = home / passenger_evidence_hook.CONTROL_DIR_NAME
        evidence = home / passenger_evidence_hook.EVIDENCE_DIR_NAME
        control.mkdir(mode=0o700); evidence.mkdir(mode=0o700)
        os.chmod(control, 0o700); os.chmod(evidence, 0o700)
        marker = control / passenger_evidence_hook.ARM_MARKER_NAME
        return home, control, marker

    def app_tree(self, td):
        root = Path(td) / "app"
        bridge = root / "bridge"; bridge.mkdir(parents=True)
        app_file = bridge / "app.py"; app_file.write_text("# app\n", encoding="utf-8")
        wsgi = root / "passenger_wsgi.py"; wsgi.write_text("from bridge.app import application\n", encoding="utf-8")
        return root, app_file, wsgi

    def environ(self, *, challenge=None):
        return {
            "REQUEST_METHOD": "GET",
            "PATH_INFO": "/health",
            "wsgi.version": (1, 0),
            "wsgi.url_scheme": "https",
            "SERVER_PROTOCOL": "HTTP/1.1",
            "wsgi.input": io.BytesIO(b""),
            passenger_evidence_hook.CHALLENGE_HEADER_ENV: challenge or self.CHALLENGE,
        }

    def arm(self, marker: Path, *, candidate_sha=None, wsgi_sha=None, mode=0o600, challenge_sha=None):
        payload = passenger_evidence_hook.build_arm_marker(
            candidate_sha or self.CANDIDATE_SHA,
            wsgi_sha or self.WSGI_SHA,
            challenge_sha or self.CHALLENGE_SHA,
        )
        marker.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
        os.chmod(marker, mode)
        return payload

    def strong_evidence(self, *, wsgi_sha=None):
        return {
            "runtime_compliance": passenger_evidence_hook.STRONG_STATUS,
            "wsgi_sha256": wsgi_sha or self.WSGI_SHA,
            "payload_sha256": self.RUNTIME_SHA,
            "serving_request_verified": True,
        }

    def test_not_armed_has_no_side_effect(self):
        with tempfile.TemporaryDirectory() as td:
            home, _, _ = self.roots(td)
            with mock.patch.object(passenger_evidence_hook, "collect_runtime_evidence") as collect:
                result = passenger_evidence_hook.collect_if_armed(app_root=home, wsgi_file=home / "passenger_wsgi.py", home=home)
            self.assertEqual("PASSENGER_EVIDENCE_NOT_ARMED", result)
            collect.assert_not_called()

    def test_import_time_context_never_writes_strong_evidence(self):
        with tempfile.TemporaryDirectory() as td:
            home, _, marker = self.roots(td); self.arm(marker)
            evidence = self.strong_evidence()
            with mock.patch.object(passenger_evidence_hook, "collect_runtime_evidence", return_value=evidence) as collect, \
                 mock.patch.object(passenger_evidence_hook, "write_private_report") as write:
                result = passenger_evidence_hook.collect_if_armed(app_root=home, wsgi_file=home / "passenger_wsgi.py", home=home)
            self.assertEqual("PASSENGER_EVIDENCE_AWAITING_SERVING_REQUEST", result)
            self.assertTrue(marker.exists())
            self.assertFalse(collect.call_args.kwargs["serving_request_verified"])
            write.assert_not_called()

    def test_challenged_serving_request_writes_reports_and_consumed_receipt(self):
        with tempfile.TemporaryDirectory() as td:
            home, _, marker = self.roots(td); self.arm(marker)
            _, app_file, _ = self.app_tree(td)
            evidence = self.strong_evidence()
            with mock.patch.object(passenger_evidence_hook, "collect_runtime_evidence", return_value=evidence) as collect, \
                 mock.patch.object(passenger_evidence_hook, "write_private_report") as write:
                result = passenger_evidence_hook.collect_if_armed_from_bridge_app(
                    app_file, environ=self.environ(), home=home
                )
            self.assertEqual("PASSENGER_EVIDENCE_PRIVATE_REPORT_WRITTEN", result)
            # Marker is retained; immutable receipt is the terminal one-shot state.
            self.assertTrue(marker.exists())
            self.assertTrue(collect.call_args.kwargs["application_process"])
            self.assertTrue(collect.call_args.kwargs["serving_request_verified"])
            write.assert_called_once()
            binding = home / passenger_evidence_hook.EVIDENCE_DIR_NAME / passenger_evidence_hook.BINDING_REPORT_NAME
            self.assertTrue(binding.exists())
            payload = json.loads(binding.read_text(encoding="utf-8"))
            passenger_evidence_hook.validate_binding_report(payload)
            self.assertEqual(self.CANDIDATE_SHA, payload["candidate_sha"])
            self.assertEqual(self.WSGI_SHA, payload["actual_wsgi_sha256"])
            self.assertTrue(payload["serving_request_verified"])
            receipt = passenger_evidence_hook.consumed_receipt_path(home)
            self.assertTrue(receipt.exists())
            passenger_evidence_hook.validate_consumed_receipt(json.loads(receipt.read_text(encoding="utf-8")))

    def test_candidate_context_does_not_finalize_or_consume_marker(self):
        with tempfile.TemporaryDirectory() as td:
            home, _, marker = self.roots(td); self.arm(marker)
            evidence = {"runtime_compliance": "PYTHON_3_11_CANDIDATE_CONTEXT"}
            with mock.patch.object(passenger_evidence_hook, "collect_runtime_evidence", return_value=evidence), \
                 mock.patch.object(passenger_evidence_hook, "write_private_report") as write:
                result = passenger_evidence_hook.collect_if_armed(app_root=home, wsgi_file=home / "passenger_wsgi.py", home=home)
            self.assertEqual("PASSENGER_EVIDENCE_AWAITING_SERVING_REQUEST", result)
            self.assertTrue(marker.exists())
            self.assertFalse(passenger_evidence_hook.consumed_receipt_path(home).exists())
            write.assert_not_called()

    def test_wrong_or_missing_challenge_never_finalizes(self):
        with tempfile.TemporaryDirectory() as td:
            home, _, marker = self.roots(td); self.arm(marker)
            _, app_file, _ = self.app_tree(td)
            with mock.patch.object(passenger_evidence_hook, "collect_runtime_evidence") as collect:
                result = passenger_evidence_hook.collect_if_armed_from_bridge_app(
                    app_file, environ=self.environ(challenge="e" * 64), home=home
                )
            self.assertEqual("PASSENGER_EVIDENCE_SERVING_REQUEST_NOT_VERIFIED", result)
            collect.assert_not_called()
            self.assertTrue(marker.exists())
            self.assertFalse(passenger_evidence_hook.consumed_receipt_path(home).exists())

    def test_wrong_wsgi_hash_blocks_before_report_and_preserves_marker(self):
        with tempfile.TemporaryDirectory() as td:
            home, _, marker = self.roots(td); self.arm(marker)
            _, app_file, _ = self.app_tree(td)
            evidence = self.strong_evidence(wsgi_sha="e" * 64)
            with mock.patch.object(passenger_evidence_hook, "collect_runtime_evidence", return_value=evidence), \
                 mock.patch.object(passenger_evidence_hook, "write_private_report") as write:
                result = passenger_evidence_hook.collect_if_armed_from_bridge_app(
                    app_file, environ=self.environ(), home=home
                )
            self.assertEqual("PASSENGER_EVIDENCE_BLOCKED", result)
            self.assertTrue(marker.exists())
            self.assertFalse(passenger_evidence_hook.consumed_receipt_path(home).exists())
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
        marker = passenger_evidence_hook.build_arm_marker(
            self.CANDIDATE_SHA, self.WSGI_SHA, self.CHALLENGE_SHA
        )
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

    def test_bridge_app_request_adapter_requires_real_environ_then_checks_topology(self):
        with tempfile.TemporaryDirectory() as td:
            _, app_file, _ = self.app_tree(td)
            self.assertEqual(
                "PASSENGER_EVIDENCE_SERVING_REQUEST_REQUIRED",
                passenger_evidence_hook.collect_if_armed_from_bridge_app(app_file),
            )
            # With a request environ and no marker, normal topology reaches NOT_ARMED.
            self.assertEqual(
                "PASSENGER_EVIDENCE_NOT_ARMED",
                passenger_evidence_hook.collect_if_armed_from_bridge_app(app_file, environ={}),
            )
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            wrong = root / "app.py"; wrong.write_text("# wrong\n", encoding="utf-8")
            self.assertEqual(
                "PASSENGER_EVIDENCE_APP_TOPOLOGY_BLOCKED",
                passenger_evidence_hook.collect_if_armed_from_bridge_app(wrong, environ={}),
            )

    def test_bridge_app_request_adapter_preserves_bounded_finalize_code(self):
        with tempfile.TemporaryDirectory() as td:
            home, _, marker = self.roots(td); self.arm(marker)
            _, app_file, _ = self.app_tree(td)
            with mock.patch.object(
                passenger_evidence_hook, "_finalize_strong_evidence", return_value="PASSENGER_EVIDENCE_BLOCKED"
            ) as finalize:
                result = passenger_evidence_hook.collect_if_armed_from_bridge_app(
                    app_file, environ=self.environ(), home=home
                )
            self.assertEqual("PASSENGER_EVIDENCE_BLOCKED", result)
            finalize.assert_called_once()


if __name__ == "__main__":
    unittest.main()
