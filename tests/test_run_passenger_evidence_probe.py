# -*- coding: utf-8 -*-
from __future__ import annotations

import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from ops import passenger_evidence_hook, passenger_probe, private_evidence
from ops.private_control import write_private_json_no_clobber
from ops.release_guard import SafetyError
from tools import run_passenger_evidence_probe


class OneShotPassengerProbeTests(unittest.TestCase):
    RAW = "1" * 64
    SHA = "a" * 40
    WSGI = "b" * 64

    def roots(self, td: str):
        home = Path(td)
        evidence = home / passenger_evidence_hook.EVIDENCE_DIR_NAME
        control = home / passenger_evidence_hook.CONTROL_DIR_NAME
        evidence.mkdir(mode=0o700); control.mkdir(mode=0o700)
        os.chmod(evidence, 0o700); os.chmod(control, 0o700)
        preflight = evidence / "candidate_runtime_preflight.json"
        preflight.write_text(json.dumps({
            "schema_version": 2,
            "candidate_sha": self.SHA,
            "wsgi_sha256": self.WSGI,
            "requirements_sha256": "c" * 64,
            "requirements_lock_sha256": "d" * 64,
            "direct_package_count": 1,
            "locked_package_count": 3,
            "required_packages_present": True,
            "startup_import_contract_ok": True,
            "fully_hash_locked": True,
            "test_dependencies": {
                "present": False,
                "requirements_sha256": "0" * 64,
                "requirements_lock_sha256": "0" * 64,
                "direct_package_count": 0,
                "locked_package_count": 0,
            },
            "private_runtime_payload_present": False,
            "preflight_pass": True,
            "promotion_authorized": False,
        }), encoding="utf-8")
        os.chmod(preflight, 0o600)
        return home, evidence, control, preflight

    def strong_runtime(self):
        report = {
            "schema_version": 3,
            "collector_context": "APPLICATION_PROCESS",
            "python_version": "3.11.16",
            "python_major_minor": "3.11",
            "python_implementation": "CPython",
            "runtime_compliance": passenger_evidence_hook.STRONG_STATUS,
            "python_executable_sha256": "2" * 64,
            "python_executable_owner_uid": 1000,
            "python_executable_mode": 0o755,
            "python_executable_nlink": 1,
            "sys_prefix_sha256": "3" * 64,
            "sys_base_prefix_sha256": "4" * 64,
            "virtual_environment_active": True,
            "wsgi_relative_path": "passenger_wsgi.py",
            "wsgi_sha256": self.WSGI,
            "application_import_target": "bridge.app.application",
            "application_import_ok": True,
            "process_cwd_inside_app_root": True,
            "passenger_context_present": True,
            "serving_request_verified": True,
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

    def materialize_terminal(self, control: Path, evidence: Path):
        marker_path = control / passenger_evidence_hook.ARM_MARKER_NAME
        marker, identity = passenger_evidence_hook._read_arm_marker(control, marker_path)
        report = self.strong_runtime()
        binding = passenger_evidence_hook.build_binding_report(marker, report)
        receipt = passenger_evidence_hook.build_consumed_receipt(marker, identity, report, binding)
        write_private_json_no_clobber(evidence, evidence / passenger_evidence_hook.REPORT_NAME, report)
        write_private_json_no_clobber(evidence, evidence / passenger_evidence_hook.BINDING_REPORT_NAME, binding)
        write_private_json_no_clobber(control, control / passenger_evidence_hook.CONSUMED_RECEIPT_NAME, receipt)

    def test_success_requires_http_probe_and_matching_terminal_artifacts(self):
        with tempfile.TemporaryDirectory() as td:
            _, evidence, control, preflight = self.roots(td)
            def dispatch(endpoint, raw, timeout=5.0):
                self.assertEqual(self.RAW, raw)
                self.materialize_terminal(control, evidence)
                return passenger_probe.ProbeResult("PASS", 200, "PROBE_HEALTH_REQUEST_CONFIRMED")
            with mock.patch.object(run_passenger_evidence_probe.secrets, "token_hex", return_value=self.RAW), \
                 mock.patch.object(run_passenger_evidence_probe, "dispatch_challenged_health_probe", side_effect=dispatch):
                status = run_passenger_evidence_probe.run_one_shot_probe(
                    preflight_path=preflight,
                    control_root=control,
                    evidence_root=evidence,
                )
            self.assertEqual("PASSENGER_EVIDENCE_ONE_SHOT_CONFIRMED", status)
            digest = hashlib.sha256(self.RAW.encode("ascii")).hexdigest()
            marker_text = (control / passenger_evidence_hook.ARM_MARKER_NAME).read_text()
            self.assertIn(digest, marker_text)
            combined = "".join(path.read_text() for path in (
                evidence / passenger_evidence_hook.REPORT_NAME,
                evidence / passenger_evidence_hook.BINDING_REPORT_NAME,
                control / passenger_evidence_hook.CONSUMED_RECEIPT_NAME,
            ))
            self.assertNotIn(self.RAW, combined)

    def test_http_pass_without_terminal_artifacts_is_blocked(self):
        with tempfile.TemporaryDirectory() as td:
            _, evidence, control, preflight = self.roots(td)
            with mock.patch.object(run_passenger_evidence_probe.secrets, "token_hex", return_value=self.RAW), \
                 mock.patch.object(run_passenger_evidence_probe, "dispatch_challenged_health_probe", return_value=passenger_probe.ProbeResult("PASS", 200, "PROBE_HEALTH_REQUEST_CONFIRMED")):
                with self.assertRaises((SafetyError, OSError)):
                    run_passenger_evidence_probe.run_one_shot_probe(
                        preflight_path=preflight,
                        control_root=control,
                        evidence_root=evidence,
                    )

    def test_bounded_probe_failure_retries_without_rearming_or_leaking_raw(self):
        with tempfile.TemporaryDirectory() as td:
            _, evidence, control, preflight = self.roots(td)
            failed = passenger_probe.ProbeResult("FAIL", None, "PROBE_NETWORK_FAILURE")
            with mock.patch.object(run_passenger_evidence_probe.secrets, "token_hex", return_value=self.RAW), \
                 mock.patch.object(run_passenger_evidence_probe, "dispatch_challenged_health_probe", return_value=failed) as dispatch:
                status = run_passenger_evidence_probe.run_one_shot_probe(
                    preflight_path=preflight,
                    control_root=control,
                    evidence_root=evidence,
                    attempts=3,
                )
            self.assertEqual("PASSENGER_EVIDENCE_ONE_SHOT_NOT_CONFIRMED", status)
            self.assertEqual(3, dispatch.call_count)
            marker_text = (control / passenger_evidence_hook.ARM_MARKER_NAME).read_text()
            self.assertNotIn(self.RAW, marker_text)
            self.assertFalse((control / passenger_evidence_hook.CONSUMED_RECEIPT_NAME).exists())

    def test_invalid_attempt_count_fails_before_arming(self):
        with tempfile.TemporaryDirectory() as td:
            _, evidence, control, preflight = self.roots(td)
            with self.assertRaises(SafetyError):
                run_passenger_evidence_probe.run_one_shot_probe(
                    preflight_path=preflight,
                    control_root=control,
                    evidence_root=evidence,
                    attempts=0,
                )
            self.assertFalse((control / passenger_evidence_hook.ARM_MARKER_NAME).exists())

    def test_terminal_artifact_tamper_blocks_confirmation(self):
        with tempfile.TemporaryDirectory() as td:
            _, evidence, control, preflight = self.roots(td)
            def dispatch(endpoint, raw, timeout=5.0):
                self.materialize_terminal(control, evidence)
                binding_path = evidence / passenger_evidence_hook.BINDING_REPORT_NAME
                payload = json.loads(binding_path.read_text())
                payload["serving_probe_sha256"] = "f" * 64
                binding_path.unlink()
                write_private_json_no_clobber(evidence, binding_path, payload)
                return passenger_probe.ProbeResult("PASS", 200, "PROBE_HEALTH_REQUEST_CONFIRMED")
            with mock.patch.object(run_passenger_evidence_probe.secrets, "token_hex", return_value=self.RAW), \
                 mock.patch.object(run_passenger_evidence_probe, "dispatch_challenged_health_probe", side_effect=dispatch):
                with self.assertRaises(SafetyError):
                    run_passenger_evidence_probe.run_one_shot_probe(
                        preflight_path=preflight,
                        control_root=control,
                        evidence_root=evidence,
                    )


if __name__ == "__main__":
    unittest.main()
