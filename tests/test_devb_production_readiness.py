# -*- coding: utf-8 -*-
import copy
import hashlib
import unittest

from ops import production_readiness
from ops.release_guard import SafetyError


def h(value: bytes = b"x") -> str:
    return hashlib.sha256(value).hexdigest()


def valid_package(candidate: str = "a" * 40) -> dict:
    return {
        "schema_version": 1,
        "candidate_sha": candidate,
        "evidence_classes": {
            "source": "PRIVATE_SERVER_EVIDENCE",
            "runtime": "FIRST_HAND_LIVE",
            "lifecycle": "FIRST_HAND_LIVE",
        },
        "server_manifest": {
            "artifact_sha256": h(b"server-artifact"),
            "manifest_sha256": h(b"server-manifest"),
            "file_count": 42,
        },
        "reconciliation": {
            "artifact_sha256": h(b"reconciliation"),
            "status": "EXACT_ACCOUNTED",
            "server_file_count": 42,
            "candidate_file_count": 42,
            "unreviewed_difference_count": 0,
            "startup_accounted": True,
        },
        "runtime": {
            "artifact_sha256": h(b"runtime"),
            "collector_context": "APPLICATION_PROCESS",
            "python_major_minor": "3.11",
            "runtime_compliance": "PYTHON_3_11_APPLICATION_CONTEXT_CONFIRMED",
            "application_import_ok": True,
            "passenger_context_present": True,
            "wsgi_sha256": h(b"wsgi"),
        },
        "lifecycle": {
            "mode": "LIVE_SERVER",
            "candidate_sha": candidate,
            "backup": "PASS",
            "restart": "PASS",
            "running_identity": "PASS",
            "health": "PASS",
            "unauth_smoke": "PASS",
            "auth_smoke": "PASS",
            "resume": "PASS",
            "rollback": "PASS",
        },
        "privacy": {
            "private_values_copied": False,
            "raw_response_copied": False,
        },
    }


class SupportReturnValidationTests(unittest.TestCase):
    def test_strong_structural_package_is_accepted_but_never_authorizes(self):
        package = valid_package()
        validated = production_readiness.validate_support_return(package)
        self.assertEqual(package["candidate_sha"], validated["candidate_sha"])
        result = production_readiness.build_deployment_readiness(package)
        self.assertEqual("PASS", result["checks"]["source_reconciliation"]["status"])
        self.assertEqual("PASS", result["checks"]["passenger_python_311"]["status"])
        self.assertEqual("PASS", result["checks"]["backup_restart_identity_health_smoke_resume"]["status"])
        self.assertEqual("PASS", result["checks"]["rollback"]["status"])
        self.assertEqual("BLOCKED_EXTERNAL", result["checks"]["independent_auditor_gate"]["status"])
        self.assertEqual("BLOCKED_EXTERNAL", result["checks"]["production_switch"]["status"])
        self.assertFalse(result["promotion_authorized"])
        self.assertTrue(result["non_auditor_prerequisites_structurally_present"])
        production_readiness.validate_public_readiness(result)

    def test_reference_source_cannot_satisfy_live_reconciliation(self):
        package = valid_package()
        package["evidence_classes"]["source"] = "REFERENCE_ONLY"
        result = production_readiness.build_deployment_readiness(package)
        self.assertEqual("BLOCKED_EXTERNAL", result["checks"]["source_reconciliation"]["status"])

    def test_test_simulation_cannot_satisfy_live_lifecycle(self):
        package = valid_package()
        package["evidence_classes"]["lifecycle"] = "TEST_SIMULATION"
        package["lifecycle"]["mode"] = "TEST_SIMULATION"
        result = production_readiness.build_deployment_readiness(package)
        self.assertEqual("BLOCKED_EXTERNAL", result["checks"]["backup_restart_identity_health_smoke_resume"]["status"])
        self.assertEqual("BLOCKED_EXTERNAL", result["checks"]["rollback"]["status"])

    def test_cli_python_311_candidate_never_satisfies_passenger_proof(self):
        package = valid_package()
        package["runtime"]["collector_context"] = "PRIVATE_CLI_CANDIDATE"
        package["runtime"]["runtime_compliance"] = "PYTHON_3_11_CANDIDATE_CONTEXT"
        package["runtime"]["passenger_context_present"] = False
        result = production_readiness.build_deployment_readiness(package)
        self.assertEqual("BLOCKED_EXTERNAL", result["checks"]["passenger_python_311"]["status"])

    def test_non_311_runtime_never_satisfies_passenger_proof(self):
        package = valid_package()
        package["runtime"]["python_major_minor"] = "3.6"
        package["runtime"]["runtime_compliance"] = "NONCOMPLIANT_NOT_PYTHON_3_11"
        package["runtime"]["collector_context"] = "PRIVATE_CLI_CANDIDATE"
        package["runtime"]["passenger_context_present"] = False
        result = production_readiness.build_deployment_readiness(package)
        self.assertEqual("BLOCKED_EXTERNAL", result["checks"]["passenger_python_311"]["status"])

    def test_candidate_sha_mismatch_blocks(self):
        package = valid_package()
        package["lifecycle"]["candidate_sha"] = "b" * 40
        with self.assertRaises(SafetyError):
            production_readiness.validate_support_return(package)

    def test_exact_reconciliation_with_unreviewed_difference_blocks(self):
        package = valid_package()
        package["reconciliation"]["unreviewed_difference_count"] = 1
        with self.assertRaises(SafetyError):
            production_readiness.validate_support_return(package)

    def test_exact_reconciliation_without_startup_accounting_blocks(self):
        package = valid_package()
        package["reconciliation"]["startup_accounted"] = False
        with self.assertRaises(SafetyError):
            production_readiness.validate_support_return(package)

    def test_manifest_count_disagreement_blocks(self):
        package = valid_package()
        package["reconciliation"]["server_file_count"] = 41
        with self.assertRaises(SafetyError):
            production_readiness.validate_support_return(package)

    def test_strong_runtime_claim_requires_application_process(self):
        package = valid_package()
        package["runtime"]["collector_context"] = "PRIVATE_CLI_CANDIDATE"
        with self.assertRaises(SafetyError):
            production_readiness.validate_support_return(package)

    def test_simulation_with_live_classification_blocks(self):
        package = valid_package()
        package["lifecycle"]["mode"] = "TEST_SIMULATION"
        with self.assertRaises(SafetyError):
            production_readiness.validate_support_return(package)

    def test_not_executed_lifecycle_cannot_claim_pass(self):
        package = valid_package()
        package["evidence_classes"]["lifecycle"] = "TEST_SIMULATION"
        package["lifecycle"]["mode"] = "NOT_EXECUTED"
        with self.assertRaises(SafetyError):
            production_readiness.validate_support_return(package)

    def test_privacy_flags_fail_closed(self):
        for field in ("private_values_copied", "raw_response_copied"):
            package = valid_package()
            package["privacy"][field] = True
            with self.subTest(field=field), self.assertRaises(SafetyError):
                production_readiness.validate_support_return(package)

    def test_unknown_fields_fail_closed(self):
        package = valid_package()
        package["runtime"]["note"] = "x"
        with self.assertRaises(SafetyError):
            production_readiness.validate_support_return(package)

    def test_malformed_hash_fails_closed(self):
        package = valid_package()
        package["server_manifest"]["artifact_sha256"] = "not-a-digest"
        with self.assertRaises(SafetyError):
            production_readiness.validate_support_return(package)

    def test_live_failure_keeps_lifecycle_blocked(self):
        package = valid_package()
        package["lifecycle"]["health"] = "FAIL"
        result = production_readiness.build_deployment_readiness(package)
        self.assertEqual("BLOCKED_EXTERNAL", result["checks"]["backup_restart_identity_health_smoke_resume"]["status"])

    def test_rollback_not_run_keeps_rollback_blocked(self):
        package = valid_package()
        package["lifecycle"]["rollback"] = "NOT_RUN"
        result = production_readiness.build_deployment_readiness(package)
        self.assertEqual("BLOCKED_EXTERNAL", result["checks"]["rollback"]["status"])

    def test_current_telegram_auth_is_explicitly_not_applicable(self):
        result = production_readiness.build_deployment_readiness(valid_package())
        check = result["checks"]["telegram_user_authorization"]
        self.assertEqual("NOT_APPLICABLE", check["status"])
        self.assertEqual("USER_TELEGRAM_AUTH_NOT_YET_REQUIRED", check["reason_code"])

    def test_public_readiness_mutation_cannot_self_authorize(self):
        result = production_readiness.build_deployment_readiness(valid_package())
        mutated = copy.deepcopy(result)
        mutated["promotion_authorized"] = True
        with self.assertRaises(SafetyError):
            production_readiness.validate_public_readiness(mutated)
        mutated = copy.deepcopy(result)
        mutated["checks"]["production_switch"] = {"status": "PASS", "reason_code": "FAKE_PASS"}
        with self.assertRaises(SafetyError):
            production_readiness.validate_public_readiness(mutated)

    def test_public_output_contains_only_bounded_status_accounting(self):
        result = production_readiness.build_deployment_readiness(valid_package())
        encoded = str(result)
        self.assertNotIn("artifact_sha256", encoded)
        self.assertNotIn("wsgi_sha256", encoded)
        self.assertNotIn("server_manifest", encoded)
        self.assertFalse(result["private_values_copied"])
        self.assertFalse(result["raw_response_copied"])


if __name__ == "__main__":
    unittest.main()
