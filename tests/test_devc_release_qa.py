# -*- coding: utf-8 -*-
from __future__ import annotations

import shutil
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


def prepared_payload():
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


def legacy_live_support_return():
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


def exact_bound_v2_support_return():
    payload = legacy_live_support_return()
    payload["schema_version"] = 2
    payload["runtime"]["payload_sha256"] = HASH
    payload["candidate_package"] = {
        "identity_artifact_sha256": HASH,
        "manifest_sha256": HASH,
        "wsgi_sha256": HASH,
        "requirements_lock_sha256": HASH,
        "package_preflight_pass": True,
    }
    payload["runtime_binding"] = {
        "artifact_sha256": HASH,
        "candidate_sha": SHA,
        "expected_wsgi_sha256": HASH,
        "actual_wsgi_sha256": HASH,
        "runtime_payload_sha256": HASH,
        "binding_valid": True,
    }
    return payload


class ReleasePackageIndependentTests(unittest.TestCase):
    def test_current_release_package_contract_ready_for_prepare(self):
        # In the normal PR checkout, assess the repository tree directly so any
        # accidentally tracked .venv/private runtime material is still caught.
        # During real PREPARE the exact Git export intentionally has no .git and
        # already contains a generated hash-locked .venv. That generated runtime
        # dependency tree is payload-manifest bound and is not source input to
        # this READY_FOR_PREPARE check, so reconstruct only the Git-exported
        # source view for this source-level assertion.
        if (ROOT / ".git").exists() or not (ROOT / ".venv").is_dir():
            result = assess_release_root(ROOT)
        else:
            with tempfile.TemporaryDirectory() as td:
                source_root = Path(td) / "source"
                source_root.mkdir()
                for child in ROOT.iterdir():
                    if child.name == ".venv":
                        continue
                    target = source_root / child.name
                    if child.is_dir():
                        shutil.copytree(child, target, symlinks=True)
                    elif child.is_file():
                        shutil.copy2(child, target, follow_symlinks=False)
                result = assess_release_root(source_root)
        self.assertEqual("READY_FOR_PREPARE", result.status, result)
        self.assertEqual((), result.defect_codes)
        self.assertEqual((1, 4), (result.direct_requirement_count, result.locked_requirement_count))

    def test_actual_wsgi_exact_and_negatives_fail_closed(self):
        source = (ROOT / "passenger_wsgi.py").read_text(encoding="utf-8")
        self.assertEqual([], validate_passenger_wsgi_source(source))
        self.assertIn(
            "PASSENGER_WSGI_STATEMENT_SET_MISMATCH",
            validate_passenger_wsgi_source('from bridge.app import application\n__all__=["application"]\n'),
        )
        self.assertIn(
            "PASSENGER_WSGI_APPLICATION_IMPORT_MISMATCH",
            validate_passenger_wsgi_source(source.replace("from bridge.app import application", "from bridge.integrated_app import application")),
        )
        self.assertIn("PASSENGER_WSGI_STATEMENT_SET_MISMATCH", validate_passenger_wsgi_source(source + "\napplication()\n"))
        self.assertIn("PASSENGER_WSGI_PRIVATE_MATERIAL", validate_passenger_wsgi_source(source + "\n# TG_API_HASH forbidden marker\n"))
        self.assertIn(
            "PASSENGER_WSGI_EVIDENCE_CALL_MISMATCH",
            validate_passenger_wsgi_source(source.replace("app_root=_here.parent, wsgi_file=_here", "wsgi_file=_here, app_root=_here.parent")),
        )

    def test_dependency_actual_and_negative_matrix(self):
        requirements = (ROOT / "requirements.txt").read_text(encoding="utf-8")
        lock = (ROOT / "requirements.lock").read_text(encoding="utf-8")
        self.assertEqual(([], 1, 4), validate_dependency_envelope(requirements, lock))
        digest = "c" * 64
        cases = (
            (None, None, {"REQUIREMENTS_INPUT_MISSING", "REQUIREMENTS_LOCK_MISSING"}),
            ("Telethon>=1,<2\n", f"Telethon==1.44.0 --hash=sha256:{digest}\n", {"REQUIREMENTS_INPUT_NOT_EXACT_PIN"}),
            ("Telethon==1.44.0\n", "Telethon==1.44.0\n", {"REQUIREMENTS_LOCK_NOT_EXACT_HASH_PIN"}),
            ("Telethon==1.43.0\n", f"Telethon==1.44.0 --hash=sha256:{digest}\n", {"DIRECT_RUNTIME_SET_MISMATCH", "DIRECT_LOCK_VERSION_MISMATCH"}),
            ("Telethon==1.44.0\n", f"Telethon==1.44.0 --hash=sha256:{digest}\n", {"LOCKED_RUNTIME_CLOSURE_MISMATCH"}),
        )
        for req, locked, expected in cases:
            with self.subTest(expected=expected):
                self.assertTrue(expected.issubset(set(validate_dependency_envelope(req, locked)[0])))

    def test_private_runtime_artifact_detected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for name in ("passenger_wsgi.py", "requirements.txt", "requirements.lock"):
                (root / name).write_text((ROOT / name).read_text(encoding="utf-8"), encoding="utf-8")
            (root / "private").mkdir()
            (root / "private" / "runtime.session").write_text("placeholder", encoding="utf-8")
            self.assertIn("PRIVATE_RUNTIME_ARTIFACT_IN_RELEASE", assess_release_root(root).defect_codes)


class PreparedAndCrossLaneTruthTests(unittest.TestCase):
    def test_prepared_metadata_positive_and_fail_closed(self):
        self.assertEqual([], validate_prepared_release_metadata(prepared_payload(), SHA))
        payload = prepared_payload()
        payload["sha"] = "d" * 40
        payload["requirements_lock_sha256"] = "bad"
        payload["python_version"] = "3.12.0"
        payload["immutable_permission_policy"] = "mutable"
        defects = set(validate_prepared_release_metadata(payload, SHA))
        self.assertTrue({
            "PREPARED_METADATA_STALE_SHA",
            "PREPARED_METADATA_HASH_MISSING_OR_INVALID",
            "PREPARED_METADATA_BUILT_PYTHON_INVALID",
            "PREPARED_METADATA_IMMUTABILITY_POLICY_INVALID",
        }.issubset(defects))
        payload = prepared_payload()
        payload["unexpected"] = True
        self.assertEqual(["PREPARED_METADATA_SCHEMA_MISMATCH"], validate_prepared_release_metadata(payload, SHA))

    def test_legacy_v1_is_parseable_but_cannot_satisfy_exact_runtime_binding(self):
        payload = legacy_live_support_return()
        validated = validate_support_return(payload)
        self.assertEqual(1, validated["schema_version"])
        readiness = build_deployment_readiness(payload)
        self.assertEqual("BLOCKED_EXTERNAL", readiness["checks"]["exact_candidate_runtime_binding"]["status"])
        self.assertEqual("BLOCKED_EXTERNAL", readiness["checks"]["passenger_python_311"]["status"])
        self.assertFalse(readiness["promotion_authorized"])

    def test_v2_exact_binding_is_accepted_but_never_self_authorizes_promotion(self):
        payload = exact_bound_v2_support_return()
        validated = validate_support_return(payload)
        self.assertEqual(2, validated["schema_version"])
        readiness = build_deployment_readiness(payload)
        self.assertEqual("PASS", readiness["checks"]["exact_candidate_runtime_binding"]["status"])
        self.assertEqual("BLOCKED_EXTERNAL", readiness["checks"]["passenger_python_311"]["status"])
        self.assertEqual("PASS", readiness["checks"]["source_reconciliation"]["status"])
        self.assertEqual("PASS", readiness["checks"]["backup_restart_identity_health_smoke_resume"]["status"])
        self.assertEqual("PASS", readiness["checks"]["rollback"]["status"])
        self.assertFalse(readiness["non_auditor_prerequisites_structurally_present"])
        self.assertEqual("BLOCKED_EXTERNAL", readiness["checks"]["independent_auditor_gate"]["status"])
        self.assertEqual("BLOCKED_EXTERNAL", readiness["checks"]["production_switch"]["status"])
        self.assertFalse(readiness["promotion_authorized"])

    def test_v2_binding_mismatch_fails_closed(self):
        payload = exact_bound_v2_support_return()
        payload["runtime_binding"]["actual_wsgi_sha256"] = "c" * 64
        with self.assertRaises(SafetyError):
            validate_support_return(payload)


class ProtocolTruthTests(unittest.TestCase):
    def test_hk_protocols_never_execute_and_k5_stays_locked(self):
        protocols = release_live_protocols()
        self.assertEqual({"H1", "H2", "H3", "H4", "H5", "K1", "K2", "K3", "K4", "K5"}, set(protocols))
        self.assertTrue(all(item.execute_now is False for item in protocols.values()))
        for gate in ("INDEPENDENT_AUDITOR_WRITE_APPROVAL", "SAFE_DESTINATION_CONFIRMED", "FRESH_EXPLICIT_USER_COMMIT"):
            self.assertIn(gate, protocols["K5"].required_gates)

    def test_nvda_is_human_live_only_and_gate_order_exact(self):
        steps = keyboard_nvda_protocol()
        self.assertTrue(any("KEYBOARD_ONLY" in step for step in steps))
        self.assertTrue(any("NVDA" in step for step in steps))
        self.assertTrue(any("WITHOUT_MOUSE" in step for step in steps))
        self.assertEqual(
            ("INTERNAL_RELEASE_BLOCKER", "HOSTIQ_LIVE", "TELEGRAM_AUTH_E2E", "DEPLOYED_ACTION", "HUMAN_NVDA", "K5"),
            remaining_gate_classes(),
        )


if __name__ == "__main__":
    unittest.main()
