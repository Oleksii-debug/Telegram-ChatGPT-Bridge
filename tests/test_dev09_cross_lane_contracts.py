from __future__ import annotations

import inspect
import tempfile
import unittest
from pathlib import Path

from ops import candidate_runtime_preflight, passenger_evidence_hook
from ops.production_readiness import build_deployment_readiness, validate_support_return
from ops.release_guard import SafetyError


SHA = "a" * 40
HASH = "b" * 64


def _legacy_v2_support_return() -> dict:
    return {
        "schema_version": 2,
        "candidate_sha": SHA,
        "evidence_classes": {
            "source": "PRIVATE_SERVER_EVIDENCE",
            "runtime": "PRIVATE_SERVER_EVIDENCE",
            "lifecycle": "PRIVATE_SERVER_EVIDENCE",
        },
        "server_manifest": {"artifact_sha256": HASH, "manifest_sha256": HASH, "file_count": 42},
        "reconciliation": {
            "artifact_sha256": HASH,
            "status": "EXACT_ACCOUNTED",
            "server_file_count": 42,
            "candidate_file_count": 100,
            "unreviewed_difference_count": 0,
            "startup_accounted": True,
        },
        "runtime": {
            "artifact_sha256": HASH,
            "collector_context": "APPLICATION_PROCESS",
            "python_major_minor": "3.11",
            "runtime_compliance": "PYTHON_3_11_APPLICATION_CONTEXT_CONFIRMED",
            "application_import_ok": True,
            "passenger_context_present": True,
            "wsgi_sha256": HASH,
            "payload_sha256": HASH,
        },
        "candidate_package": {
            "identity_artifact_sha256": HASH,
            "manifest_sha256": HASH,
            "wsgi_sha256": HASH,
            "requirements_lock_sha256": HASH,
            "package_preflight_pass": True,
        },
        "runtime_binding": {
            "artifact_sha256": HASH,
            "candidate_sha": SHA,
            "expected_wsgi_sha256": HASH,
            "actual_wsgi_sha256": HASH,
            "runtime_payload_sha256": HASH,
            "binding_valid": True,
        },
        "lifecycle": {
            "mode": "LIVE_SERVER",
            "candidate_sha": SHA,
            "backup": "PASS",
            "restart": "PASS",
            "running_identity": "PASS",
            "health": "PASS",
            "unauth_smoke": "PASS",
            "auth_smoke": "PASS",
            "resume": "PASS",
            "rollback": "PASS",
        },
        "privacy": {"private_values_copied": False, "raw_response_copied": False},
    }


class HardenedCrossLaneContractTests(unittest.TestCase):
    def test_passenger_arm_marker_now_requires_challenge_digest(self):
        signature = inspect.signature(passenger_evidence_hook.build_arm_marker)
        challenge = signature.parameters["request_challenge_sha256"]
        self.assertIs(challenge.default, inspect.Parameter.empty)
        with self.assertRaises(TypeError):
            passenger_evidence_hook.build_arm_marker(SHA, HASH)
        marker = passenger_evidence_hook.build_arm_marker(SHA, HASH, "c" * 64)
        self.assertEqual(marker["request_challenge_sha256"], "c" * 64)

    def test_legacy_one_line_wsgi_fixture_is_rejected_by_current_preflight(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "passenger_wsgi.py").write_text("from bridge.app import application\n", encoding="utf-8")
            (root / "requirements.txt").write_text("Telethon==1.42.0\n", encoding="utf-8")
            (root / "requirements.lock").write_text(
                "Telethon==1.42.0 --hash=sha256:" + HASH + "\n", encoding="utf-8"
            )
            with self.assertRaisesRegex(SafetyError, "passenger_wsgi.py statement count mismatch"):
                candidate_runtime_preflight.validate_candidate_release_envelope(root, candidate_sha=SHA)

    def test_legacy_v2_binding_is_parseable_but_cannot_pass_strong_passenger_gate(self):
        payload = _legacy_v2_support_return()
        self.assertEqual(validate_support_return(payload)["schema_version"], 2)
        readiness = build_deployment_readiness(payload)
        self.assertEqual(readiness["checks"]["exact_candidate_runtime_binding"]["status"], "PASS")
        self.assertEqual(readiness["checks"]["passenger_python_311"]["status"], "BLOCKED_EXTERNAL")
        self.assertFalse(readiness["non_auditor_prerequisites_structurally_present"])
        self.assertFalse(readiness["promotion_authorized"])


if __name__ == "__main__":
    unittest.main()
