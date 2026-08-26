# -*- coding: utf-8 -*-
from __future__ import annotations

import json
import os
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from ops import passenger_evidence_hook, passenger_probe
from ops.release_guard import SafetyError
from tools import run_passenger_evidence_probe


class Finalwave28PassengerV3Tests(unittest.TestCase):
    SHA = "a" * 40
    WSGI = "b" * 64

    def roots(self, td: str):
        home = Path(td)
        evidence = home / passenger_evidence_hook.EVIDENCE_DIR_NAME
        control = home / passenger_evidence_hook.CONTROL_DIR_NAME
        evidence.mkdir(mode=0o700)
        control.mkdir(mode=0o700)
        os.chmod(evidence, 0o700)
        os.chmod(control, 0o700)
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
        return evidence, control, preflight

    def test_concurrent_probe_cannot_rearm_dispatch_capable_attempt(self):
        """A second caller cannot replace an armed one-shot marker mid-request."""
        with tempfile.TemporaryDirectory() as td:
            evidence, control, preflight = self.roots(td)
            entered_dispatch = threading.Event()
            release_dispatch = threading.Event()
            first_result = []
            first_error = []

            def dispatch(endpoint, raw, timeout=5.0):
                entered_dispatch.set()
                if not release_dispatch.wait(timeout=5):
                    raise AssertionError("test dispatch release timeout")
                return passenger_probe.ProbeResult("FAIL", None, "PROBE_NETWORK_FAILURE")

            def first_probe():
                try:
                    first_result.append(run_passenger_evidence_probe.run_one_shot_probe(
                        preflight_path=preflight,
                        control_root=control,
                        evidence_root=evidence,
                        attempts=1,
                    ))
                except Exception as exc:  # pragma: no cover - asserted below
                    first_error.append(exc)

            with mock.patch.object(
                run_passenger_evidence_probe,
                "dispatch_challenged_health_probe",
                side_effect=dispatch,
            ):
                thread = threading.Thread(target=first_probe)
                thread.start()
                self.assertTrue(entered_dispatch.wait(timeout=5))
                marker = control / passenger_evidence_hook.ARM_MARKER_NAME
                before = marker.read_bytes()
                before_stat = marker.stat()
                with self.assertRaises(SafetyError):
                    run_passenger_evidence_probe.run_one_shot_probe(
                        preflight_path=preflight,
                        control_root=control,
                        evidence_root=evidence,
                        attempts=1,
                    )
                self.assertEqual(before, marker.read_bytes())
                self.assertEqual(before_stat.st_ino, marker.stat().st_ino)
                release_dispatch.set()
                thread.join(timeout=5)

            self.assertFalse(thread.is_alive())
            self.assertEqual([], first_error)
            self.assertEqual(["PASSENGER_EVIDENCE_ONE_SHOT_AMBIGUOUS_RETAINED"], first_result)
            self.assertEqual(
                "PASSENGER_EVIDENCE_EXISTING_ARMED_AMBIGUOUS",
                run_passenger_evidence_probe.inspect_existing_evidence_state(
                    control_root=control,
                    evidence_root=evidence,
                ),
            )

    def test_orphan_terminal_artifact_blocks_read_only_inspection(self):
        """Inspection cannot normalize terminal evidence that has no arm marker."""
        with tempfile.TemporaryDirectory() as td:
            evidence, control, _ = self.roots(td)
            orphan = evidence / passenger_evidence_hook.REPORT_NAME
            orphan.write_text("{}", encoding="utf-8")
            os.chmod(orphan, 0o600)
            before = orphan.read_bytes()
            with self.assertRaises(SafetyError):
                run_passenger_evidence_probe.inspect_existing_evidence_state(
                    control_root=control,
                    evidence_root=evidence,
                )
            self.assertEqual(before, orphan.read_bytes())
            self.assertFalse((control / passenger_evidence_hook.ARM_MARKER_NAME).exists())


if __name__ == "__main__":
    unittest.main()
