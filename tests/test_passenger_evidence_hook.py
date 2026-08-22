# -*- coding: utf-8 -*-
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from ops import passenger_evidence_hook


class PassengerEvidenceHookTests(unittest.TestCase):
    def roots(self, td):
        home = Path(td)
        control = home / passenger_evidence_hook.CONTROL_DIR_NAME
        control.mkdir(mode=0o700)
        os.chmod(control, 0o700)
        marker = control / passenger_evidence_hook.ARM_MARKER_NAME
        return home, control, marker

    def test_not_armed_has_no_side_effect(self):
        with tempfile.TemporaryDirectory() as td:
            home, _, _ = self.roots(td)
            with mock.patch.object(passenger_evidence_hook, "collect_runtime_evidence") as collect:
                result = passenger_evidence_hook.collect_if_armed(app_root=home, wsgi_file=home / "passenger_wsgi.py", home=home)
            self.assertEqual("PASSENGER_EVIDENCE_NOT_ARMED", result)
            collect.assert_not_called()

    def test_strong_application_context_writes_private_report_and_consumes_marker(self):
        with tempfile.TemporaryDirectory() as td:
            home, _, marker = self.roots(td)
            marker.write_bytes(b""); os.chmod(marker, 0o600)
            evidence = {"runtime_compliance": passenger_evidence_hook.STRONG_STATUS}
            with mock.patch.object(passenger_evidence_hook, "collect_runtime_evidence", return_value=evidence) as collect, \
                 mock.patch.object(passenger_evidence_hook, "write_private_report") as write:
                result = passenger_evidence_hook.collect_if_armed(app_root=home, wsgi_file=home / "passenger_wsgi.py", home=home)
            self.assertEqual("PASSENGER_EVIDENCE_PRIVATE_REPORT_WRITTEN", result)
            self.assertFalse(marker.exists())
            self.assertTrue(collect.call_args.kwargs["application_process"])
            write.assert_called_once()

    def test_candidate_context_does_not_write_or_consume_marker(self):
        with tempfile.TemporaryDirectory() as td:
            home, _, marker = self.roots(td)
            marker.write_bytes(b""); os.chmod(marker, 0o600)
            evidence = {"runtime_compliance": "PYTHON_3_11_CANDIDATE_CONTEXT"}
            with mock.patch.object(passenger_evidence_hook, "collect_runtime_evidence", return_value=evidence), \
                 mock.patch.object(passenger_evidence_hook, "write_private_report") as write:
                result = passenger_evidence_hook.collect_if_armed(app_root=home, wsgi_file=home / "passenger_wsgi.py", home=home)
            self.assertEqual("PASSENGER_EVIDENCE_CONTEXT_NOT_CONFIRMED", result)
            self.assertTrue(marker.exists())
            write.assert_not_called()

    def test_broad_marker_mode_blocks_without_application_failure(self):
        with tempfile.TemporaryDirectory() as td:
            home, _, marker = self.roots(td)
            marker.write_bytes(b""); os.chmod(marker, 0o644)
            result = passenger_evidence_hook.collect_if_armed(app_root=home, wsgi_file=home / "passenger_wsgi.py", home=home)
            self.assertEqual("PASSENGER_EVIDENCE_BLOCKED", result)
            self.assertTrue(marker.exists())

    def test_collection_exception_is_sanitized(self):
        with tempfile.TemporaryDirectory() as td:
            home, _, marker = self.roots(td)
            marker.write_bytes(b""); os.chmod(marker, 0o600)
            with mock.patch.object(passenger_evidence_hook, "collect_runtime_evidence", side_effect=RuntimeError("private path or value")):
                result = passenger_evidence_hook.collect_if_armed(app_root=home, wsgi_file=home / "passenger_wsgi.py", home=home)
            self.assertEqual("PASSENGER_EVIDENCE_BLOCKED", result)
            self.assertNotIn("private", result.casefold())
            self.assertTrue(marker.exists())


if __name__ == "__main__":
    unittest.main()
