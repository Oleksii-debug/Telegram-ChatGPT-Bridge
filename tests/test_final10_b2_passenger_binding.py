# -*- coding: utf-8 -*-
from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from ops import passenger_bound_evidence
from ops.deployed_release_identity import PREPARED_RELEASE_NAME, bound_deployed_release_root
from ops.passenger_evidence_hook import CONSUMED_RECEIPT_NAME


@unittest.skipUnless(os.name == "posix" and Path("/proc/self/fd").is_dir(), "Linux descriptor binding required")
class Final10B2PassengerBindingTests(unittest.TestCase):
    SHA = "a" * 40
    OTHER = "b" * 40

    def _release(self, base: Path, sha: str | None = None) -> tuple[Path, Path]:
        sha = sha or self.SHA
        root = base / sha
        (root / "bridge").mkdir(parents=True)
        app = root / "bridge" / "app.py"
        app.write_text("# synthetic app\n", encoding="utf-8")
        (root / "passenger_wsgi.py").write_text("# synthetic wsgi\n", encoding="utf-8")
        (root / PREPARED_RELEASE_NAME).write_text(json.dumps({"sha": sha}), encoding="utf-8")
        return root, app

    def test_bound_root_keeps_original_release_inode_live(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            root, _ = self._release(base)
            displaced = base / "displaced"
            with bound_deployed_release_root(root, self.SHA) as (bound_root, deployed_sha):
                self.assertEqual(self.SHA, deployed_sha)
                root.rename(displaced)
                replacement, _ = self._release(base)
                self.assertEqual(self.SHA, replacement.name)
                self.assertTrue((bound_root / "passenger_wsgi.py").is_file())
                self.assertEqual("# synthetic wsgi\n", (bound_root / "passenger_wsgi.py").read_text(encoding="utf-8"))

    def test_armed_deployed_mismatch_blocks_before_finalizer_and_creates_zero_artifacts(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            _root, app = self._release(base, self.SHA)
            home = base / "home"
            control = home / "control"
            report = home / "evidence" / "report.json"
            binding = home / "evidence" / "binding.json"
            marker_path = control / "marker.json"
            control.mkdir(parents=True)
            marker_path.write_text("{}", encoding="utf-8")
            marker = {
                "schema_version": 2,
                "candidate_sha": self.OTHER,
                "expected_wsgi_sha256": "1" * 64,
                "request_challenge_sha256": "2" * 64,
            }
            fake_identity = object()
            with mock.patch.object(passenger_bound_evidence, "_paths", return_value=(control, marker_path, report, binding)), \
                 mock.patch.object(passenger_bound_evidence, "_read_arm_marker", return_value=(marker, fake_identity)), \
                 mock.patch.object(passenger_bound_evidence, "_verified_serving_request", return_value=True), \
                 mock.patch.object(passenger_bound_evidence, "_finalize_strong_evidence") as finalize:
                result = passenger_bound_evidence.collect_bound_if_armed_from_bridge_app(
                    app,
                    environ={"REQUEST_METHOD": "GET", "PATH_INFO": "/health"},
                    home=home,
                )
            self.assertEqual("PASSENGER_EVIDENCE_BLOCKED", result)
            finalize.assert_not_called()
            self.assertFalse(report.exists())
            self.assertFalse(binding.exists())
            self.assertFalse((control / CONSUMED_RECEIPT_NAME).exists())

    def test_matching_release_reaches_finalizer_with_bound_root(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            _root, app = self._release(base, self.SHA)
            home = base / "home"
            control = home / "control"
            report = home / "evidence" / "report.json"
            binding = home / "evidence" / "binding.json"
            marker_path = control / "marker.json"
            control.mkdir(parents=True)
            marker_path.write_text("{}", encoding="utf-8")
            marker = {
                "schema_version": 2,
                "candidate_sha": self.SHA,
                "expected_wsgi_sha256": "1" * 64,
                "request_challenge_sha256": "2" * 64,
            }
            fake_identity = object()

            def finalize(**kwargs):
                bound_root = kwargs["app_root"]
                self.assertTrue(str(bound_root).startswith("/proc/self/fd/"))
                self.assertTrue((bound_root / "passenger_wsgi.py").is_file())
                self.assertEqual(bound_root / "passenger_wsgi.py", kwargs["wsgi_file"])
                return "PASSENGER_EVIDENCE_PRIVATE_REPORT_WRITTEN"

            with mock.patch.object(passenger_bound_evidence, "_paths", return_value=(control, marker_path, report, binding)), \
                 mock.patch.object(passenger_bound_evidence, "_read_arm_marker", return_value=(marker, fake_identity)), \
                 mock.patch.object(passenger_bound_evidence, "_verified_serving_request", return_value=True), \
                 mock.patch.object(passenger_bound_evidence, "_finalize_strong_evidence", side_effect=finalize) as finalize_mock:
                result = passenger_bound_evidence.collect_bound_if_armed_from_bridge_app(
                    app,
                    environ={"REQUEST_METHOD": "GET", "PATH_INFO": "/health"},
                    home=home,
                )
            self.assertEqual("PASSENGER_EVIDENCE_PRIVATE_REPORT_WRITTEN", result)
            finalize_mock.assert_called_once()


if __name__ == "__main__":
    unittest.main()
