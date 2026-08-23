# -*- coding: utf-8 -*-
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from ops.devc_release_qa import (
    assess_release_root,
    keyboard_nvda_protocol,
    release_live_protocols,
    remaining_gate_classes,
    validate_dependency_envelope,
    validate_passenger_wsgi_source,
    validate_prepared_release_metadata,
)
from ops.production_readiness import build_deployment_readiness, validate_support_return
from ops.release_guard import SafetyError

ROOT = Path(__file__).resolve().parents[1]
SHA = "a" * 40
HASH = "b" * 64


def prepared_payload() -> dict:
    return {
        "schema_version": 2,
        "repository": "Oleksii-debug/Telegram-ChatGPT-Bridge",
        "approved_ref": "refs/heads/work3/integration-release-candidate",
        "sha": SHA,
        "configured_python_version": "3.11.16",
        "python_version": "3.11.16",
        "approved_python_identity": {
            "canonical_path": "/opt/python/bin/python3.11",
            "version": "3.11.16",
            "sha256": HASH,
            "size": 1,
            "uid": 1000,
            "gid": 1000,
            "mode": 493,
        },
        "source_manifest_sha256": HASH,
        "requirements_lock_sha256": HASH,
        "requirements_test_lock_sha256": None,
        "payload_manifest_sha256": HASH,
        "runtime_entries": ["var"],
        "persistent_state_mode": "shared_external",
        "immutable_permission_policy": "no-write-bits-v1",
    }


def legacy_live_support_return() -> dict:
    """Schema-v1 payload that old DEV_B code can structurally promote.

    It contains no private values; all digests are placeholders.  DEV_C uses it
    only to prove why exact candidate/runtime binding from newer DEV_B v2 is a
    required release integration before production acceptance.
    """
    return {
        "schema_version": 1,
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


class ReleasePackageIndependentTests(unittest.TestCase):
    def test_exact_current_release_package_is_ready_for_prepare(self):
        result = assess_release_root(ROOT)
        self.assertEqual("READY_FOR_PREPARE", result.status, result)
        self.assertEqual((), result.defect_codes)
        self.assertEqual(1, result.direct_requirement_count)
        self.assertEqual(4, result.locked_requirement_count)

    def test_actual_passenger_wsgi_matches_exact_audited_sequence(self):
        source = (ROOT / "passenger_wsgi.py").read_text(encoding="utf-8")
        self.assertEqual([], validate_passenger_wsgi_source(source))

    def test_wsgi_rejects_old_minimal_shim_wrong_import_and_arbitrary_call(self):
        old = 'from bridge.app import application\n__all__ = ["application"]\n'
        self.assertIn("PASSENGER_WSGI_STATEMENT_SET_MISMATCH", validate_passenger_wsgi_source(old))
        wrong = '''from pathlib import Path
from bridge.integrated_app import application
from ops.passenger_evidence_hook import collect_if_armed
_here = Path(__file__).resolve()
collect_if_armed(app_root=_here.parent, wsgi_file=_here)
__all__ = ["application"]
'''
        self.assertIn("PASSENGER_WSGI_APPLICATION_IMPORT_MISMATCH", validate_passenger_wsgi_source(wrong))
        called = (ROOT / "passenger_wsgi.py").read_text(encoding="utf-8") + "\napplication()\n"
        self.assertIn("PASSENGER_WSGI_STATEMENT_SET_MISMATCH", validate_passenger_wsgi_source(called))

    def test_wsgi_rejects_private_material_and_evidence_argument_drift(self):
        source = (ROOT / "passenger_wsgi.py").read_text(encoding="utf-8")
        private = source + '\n# TG_API_HASH must never be embedded here\n'
        self.assertIn("PASSENGER_WSGI_PRIVATE_MATERIAL", validate_passenger_wsgi_source(private))
        drift = source.replace("app_root=_here.parent, wsgi_file=_here", "wsgi_file=_here, app_root=_here.parent")
        self.assertIn("PASSENGER_WSGI_EVIDENCE_CALL_MISMATCH", validate_passenger_wsgi_source(drift))

    def test_actual_dependency_envelope_is_exact_and_hash_locked(self):
        req = (ROOT / "requirements.txt").read_text(encoding="utf-8")
        lock = (ROOT / "requirements.lock").read_text(encoding="utf-8")
        defects, direct, locked = validate_dependency_envelope(req, lock)
        self.assertEqual([], defects)
        self.assertEqual((1, 4), (direct, locked))

    def test_dependency_negatives_fail_closed(self):
        exact_hash = "c" * 64
        cases = (
            (None, None, {"REQUIREMENTS_INPUT_MISSING", "REQUIREMENTS_LOCK_MISSING"}),
            ("Telethon>=1,<2\n", f"Telethon==1.44.0 --hash=sha256:{exact_hash}\n", {"REQUIREMENTS_INPUT_NOT_EXACT_PIN"}),
            ("Telethon==1.44.0\n", "Telethon==1.44.0\n", {"REQUIREMENTS_LOCK_NOT_EXACT_HASH_PIN"}),
            ("Telethon==1.43.0\n", f"Telethon==1.44.0 --hash=sha256:{exact_hash}\n", {"DIRECT_RUNTIME_SET_MISMATCH", "DIRECT_LOCK_VERSION_MISMATCH"}),
            ("Telethon==1.44.0\n", f"Telethon==1.44.0 --hash=sha256:{exact_hash}\n", {"LOCKED_RUNTIME_CLOSURE_MISMATCH"}),
            ("Telethon==1.44.0 @ https://example.invalid/x\n", f"Telethon==1.44.0 --hash=sha256:{exact_hash}\n", {"REQUIREMENTS_INPUT_UNSAFE_SOURCE"}),
        )
        for req, lock, expected in cases:
            with self.subTest(expected=expected):
                defects, _, _ = validate_dependency_envelope(req, lock)
                self.assertTrue(expected.issubset(set(defects)), defects)

    def test_private_runtime_artifact_in_public_release_is_detected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "passenger_wsgi.py").write_text((ROOT / "passenger_wsgi.py").read_text(encoding="utf-8"), encoding="utf-8")
            (root / "requirements.txt").write_text((ROOT / "requirements.txt").read_text(encoding="utf-8"), encoding="utf-8")
            (root / "requirements.lock").write_text((ROOT / "requirements.lock").read_text(encoding="utf-8"), encoding="utf-8")
            (root / "private").mkdir()
            (root / "private" / "runtime.session").write_text("placeholder", encoding="utf-8")
            result = assess_release_root(root)
            self.assertEqual("INTERNAL_RELEASE_BLOCKER", result.status)
            self.assertIn("PRIVATE_RUNTIME_ARTIFACT_IN_RELEASE", result.defect_codes)


class PreparedReleaseTruthTests(unittest.TestCase):
    def test_prepared_metadata_positive_contract(self):
        self.assertEqual([], validate_prepared_release_metadata(prepared_payload(), SHA))

    def test_stale_sha_bad_hash_wrong_python_and_mutable_policy_fail(self):
        payload = prepared_payload()
        payload["sha"] = "d" * 40
        payload["requirements_lock_sha256"] = "bad"
        payload["python_version"] = "3.12.0"
        payload["immutable_permission_policy"] = "mutable"
        defects = set(validate_prepared_release_metadata(payload, SHA))
        self.assertTrue(
            {
                "PREPARED_METADATA_STALE_SHA",
                "PREPARED_METADATA_HASH_MISSING_OR_INVALID",
                "PREPARED_METADATA_BUILT_PYTHON_INVALID",
                "PREPARED_METADATA_IMMUTABILITY_POLICY_INVALID",
            }.issubset(defects),
            defects,
        )

    def test_unknown_metadata_key_fails_closed(self):
        payload = prepared_payload()
        payload["unexpected"] = True
        self.assertEqual(["PREPARED_METADATA_SCHEMA_MISMATCH"], validate_prepared_release_metadata(payload, SHA))


class CrossLaneRuntimeBindingTests(unittest.TestCase):
    def test_current_candidate_is_legacy_v1_and_can_structurally_pass_without_exact_binding(self):
        payload = legacy_live_support_return()
        validated = validate_support_return(payload)
        self.assertEqual(1, validated["schema_version"])
        readiness = build_deployment_readiness(payload)
        # This is a factual probe, not an approval: the imported legacy DEV_B
        # contract can report Passenger PASS without candidate_package/runtime_binding.
        self.assertEqual("PASS", readiness["checks"]["passenger_python_311"]["status"])
        self.assertFalse(readiness["promotion_authorized"])
        self.assertEqual("BLOCKED_EXTERNAL", readiness["checks"]["independent_auditor_gate"]["status"])

    def test_current_candidate_rejects_newer_v2_shape_until_devb_sync_is_integrated(self):
        payload = legacy_live_support_return()
        payload["schema_version"] = 2
        payload["candidate_package"] = {
            "identity_artifact_sha256": HASH,
            "manifest_sha256": HASH,
            "wsgi_sha256": HASH,
            "requirements_lock_sha256": HASH,
            "package_preflight_pass": True,
        }
        payload["runtime"]["payload_sha256"] = HASH
        payload["runtime_binding"] = {
            "artifact_sha256": HASH,
            "candidate_sha": SHA,
            "expected_wsgi_sha256": HASH,
            "actual_wsgi_sha256": HASH,
            "runtime_payload_sha256": HASH,
            "binding_valid": True,
        }
        with self.assertRaises(SafetyError):
            validate_support_return(payload)


class ProtocolTruthTests(unittest.TestCase):
    def test_h_and_k_protocols_are_complete_and_never_execute_in_source_qa(self):
        protocols = release_live_protocols()
        self.assertEqual({"H1", "H2", "H3", "H4", "H5", "K1", "K2", "K3", "K4", "K5"}, set(protocols))
        self.assertTrue(all(protocol.execute_now is False for protocol in protocols.values()))
        self.assertIn("INDEPENDENT_AUDITOR_WRITE_APPROVAL", protocols["K5"].required_gates)
        self.assertIn("SAFE_DESTINATION_CONFIRMED", protocols["K5"].required_gates)
        self.assertIn("FRESH_EXPLICIT_USER_COMMIT", protocols["K5"].required_gates)

    def test_nvda_protocol_is_explicitly_human_live_only(self):
        steps = keyboard_nvda_protocol()
        self.assertGreaterEqual(len(steps), 8)
        self.assertTrue(any("KEYBOARD_ONLY" in step for step in steps))
        self.assertTrue(any("NVDA" in step for step in steps))
        self.assertTrue(any("WITHOUT_MOUSE" in step for step in steps))

    def test_remaining_gate_classes_are_prioritized_and_separate(self):
        self.assertEqual(
            (
                "INTERNAL_RELEASE_BLOCKER",
                "HOSTIQ_LIVE",
                "TELEGRAM_AUTH_E2E",
                "DEPLOYED_ACTION",
                "HUMAN_NVDA",
                "K5",
            ),
            remaining_gate_classes(),
        )


if __name__ == "__main__":
    unittest.main()
