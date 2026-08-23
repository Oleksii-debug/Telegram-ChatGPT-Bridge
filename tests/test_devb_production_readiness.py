# -*- coding: utf-8 -*-
import copy
import hashlib
import unittest

from ops import production_readiness
from ops.release_guard import SafetyError


def h(value: bytes = b"x") -> str:
    return hashlib.sha256(value).hexdigest()


def valid_package(candidate: str = "a" * 40) -> dict:
    wsgi = h(b"wsgi")
    runtime_payload = h(b"runtime-payload")
    challenge = h(b"serving-challenge")
    probe = production_readiness._probe_sha(candidate, wsgi, challenge, runtime_payload)
    return {
        "schema_version": 3,
        "candidate_sha": candidate,
        "evidence_classes": {
            "source": "PRIVATE_SERVER_EVIDENCE",
            "runtime": "FIRST_HAND_LIVE",
            "lifecycle": "FIRST_HAND_LIVE",
        },
        "candidate_package": {
            "identity_artifact_sha256": h(b"candidate-identity"),
            "manifest_sha256": h(b"candidate-manifest"),
            "wsgi_sha256": wsgi,
            "requirements_lock_sha256": h(b"requirements-lock"),
            "package_preflight_pass": True,
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
            "payload_sha256": runtime_payload,
            "collector_context": "APPLICATION_PROCESS",
            "python_major_minor": "3.11",
            "runtime_compliance": "PYTHON_3_11_APPLICATION_CONTEXT_CONFIRMED",
            "application_import_ok": True,
            "passenger_context_present": True,
            "serving_request_verified": True,
            "wsgi_sha256": wsgi,
        },
        "runtime_binding": {
            "artifact_sha256": h(b"runtime-binding"),
            "candidate_sha": candidate,
            "expected_wsgi_sha256": wsgi,
            "actual_wsgi_sha256": wsgi,
            "request_challenge_sha256": challenge,
            "runtime_payload_sha256": runtime_payload,
            "serving_probe_sha256": probe,
            "serving_request_verified": True,
            "binding_valid": True,
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


def legacy_v2(candidate: str = "a" * 40) -> dict:
    package = valid_package(candidate)
    package["schema_version"] = 2
    package["runtime"].pop("serving_request_verified")
    for key in ("request_challenge_sha256", "serving_probe_sha256", "serving_request_verified"):
        package["runtime_binding"].pop(key)
    return package


def legacy_v1(candidate: str = "a" * 40) -> dict:
    package = legacy_v2(candidate)
    package["schema_version"] = 1
    package.pop("candidate_package")
    package.pop("runtime_binding")
    package["runtime"].pop("payload_sha256")
    return package


class SupportReturnValidationTests(unittest.TestCase):
    def test_strong_v3_package_is_accepted_but_never_authorizes(self):
        package = valid_package()
        validated = production_readiness.validate_support_return(package)
        self.assertEqual(package["candidate_sha"], validated["candidate_sha"])
        result = production_readiness.build_deployment_readiness(package)
        self.assertEqual(3, result["schema_version"])
        self.assertEqual("PASS", result["checks"]["source_reconciliation"]["status"])
        self.assertEqual("PASS", result["checks"]["exact_candidate_runtime_binding"]["status"])
        self.assertEqual("PASS", result["checks"]["passenger_python_311"]["status"])
        self.assertEqual("PASSENGER_CHALLENGED_SERVING_CONTEXT_CONFIRMED", result["checks"]["passenger_python_311"]["reason_code"])
        self.assertEqual("PASS", result["checks"]["backup_restart_identity_health_smoke_resume"]["status"])
        self.assertEqual("PASS", result["checks"]["rollback"]["status"])
        self.assertEqual("BLOCKED_EXTERNAL", result["checks"]["independent_auditor_gate"]["status"])
        self.assertEqual("BLOCKED_EXTERNAL", result["checks"]["production_switch"]["status"])
        self.assertFalse(result["promotion_authorized"])
        self.assertTrue(result["non_auditor_prerequisites_structurally_present"])
        production_readiness.validate_public_readiness(result)

    def test_legacy_v2_exact_binding_remains_parseable_but_not_strong(self):
        package = legacy_v2()
        production_readiness.validate_support_return(package)
        result = production_readiness.build_deployment_readiness(package)
        self.assertEqual("PASS", result["checks"]["exact_candidate_runtime_binding"]["status"])
        self.assertEqual("BLOCKED_EXTERNAL", result["checks"]["passenger_python_311"]["status"])
        self.assertFalse(result["non_auditor_prerequisites_structurally_present"])

    def test_legacy_v1_remains_parseable_but_cannot_satisfy_exact_runtime_gate(self):
        package = legacy_v1()
        production_readiness.validate_support_return(package)
        result = production_readiness.build_deployment_readiness(package)
        self.assertEqual("BLOCKED_EXTERNAL", result["checks"]["exact_candidate_runtime_binding"]["status"])
        self.assertEqual("BLOCKED_EXTERNAL", result["checks"]["passenger_python_311"]["status"])
        self.assertFalse(result["non_auditor_prerequisites_structurally_present"])

    def test_candidate_binding_sha_mismatch_blocks(self):
        package = valid_package(); package["runtime_binding"]["candidate_sha"] = "b" * 40
        with self.assertRaises(SafetyError): production_readiness.validate_support_return(package)

    def test_candidate_package_runtime_wsgi_mismatch_blocks(self):
        package = valid_package(); package["candidate_package"]["wsgi_sha256"] = h(b"other-wsgi")
        with self.assertRaises(SafetyError): production_readiness.validate_support_return(package)

    def test_binding_actual_wsgi_mismatch_blocks(self):
        package = valid_package(); package["runtime_binding"]["actual_wsgi_sha256"] = h(b"other-wsgi")
        with self.assertRaises(SafetyError): production_readiness.validate_support_return(package)

    def test_binding_runtime_payload_mismatch_blocks(self):
        package = valid_package(); package["runtime_binding"]["runtime_payload_sha256"] = h(b"other-runtime")
        with self.assertRaises(SafetyError): production_readiness.validate_support_return(package)

    def test_probe_hash_or_challenge_mismatch_blocks(self):
        package = valid_package(); package["runtime_binding"]["serving_probe_sha256"] = h(b"wrong-probe")
        with self.assertRaises(SafetyError): production_readiness.validate_support_return(package)
        package = valid_package(); package["runtime_binding"]["request_challenge_sha256"] = h(b"wrong-challenge")
        with self.assertRaises(SafetyError): production_readiness.validate_support_return(package)

    def test_missing_serving_request_cannot_support_strong_runtime(self):
        package = valid_package(); package["runtime"]["serving_request_verified"] = False
        with self.assertRaises(SafetyError): production_readiness.validate_support_return(package)
        package = valid_package(); package["runtime_binding"]["serving_request_verified"] = False
        with self.assertRaises(SafetyError): production_readiness.validate_support_return(package)

    def test_negative_binding_or_package_preflight_blocks(self):
        package = valid_package(); package["runtime_binding"]["binding_valid"] = False
        with self.assertRaises(SafetyError): production_readiness.validate_support_return(package)
        package = valid_package(); package["candidate_package"]["package_preflight_pass"] = False
        with self.assertRaises(SafetyError): production_readiness.validate_support_return(package)

    def test_reference_source_cannot_satisfy_live_reconciliation(self):
        package = valid_package(); package["evidence_classes"]["source"] = "REFERENCE_ONLY"
        result = production_readiness.build_deployment_readiness(package)
        self.assertEqual("BLOCKED_EXTERNAL", result["checks"]["source_reconciliation"]["status"])

    def test_test_simulation_cannot_satisfy_live_lifecycle(self):
        package = valid_package(); package["evidence_classes"]["lifecycle"] = "TEST_SIMULATION"; package["lifecycle"]["mode"] = "TEST_SIMULATION"
        result = production_readiness.build_deployment_readiness(package)
        self.assertEqual("BLOCKED_EXTERNAL", result["checks"]["backup_restart_identity_health_smoke_resume"]["status"])
        self.assertEqual("BLOCKED_EXTERNAL", result["checks"]["rollback"]["status"])

    def test_cli_python_311_candidate_never_satisfies_passenger_proof(self):
        package = valid_package()
        package["runtime"]["collector_context"] = "PRIVATE_CLI_CANDIDATE"
        package["runtime"]["runtime_compliance"] = "PYTHON_3_11_CANDIDATE_CONTEXT"
        package["runtime"]["passenger_context_present"] = False
        package["runtime"]["serving_request_verified"] = False
        package["runtime_binding"]["serving_request_verified"] = False
        with self.assertRaises(SafetyError): production_readiness.validate_support_return(package)

    def test_non_311_runtime_never_satisfies_passenger_proof(self):
        package = valid_package()
        package["runtime"]["python_major_minor"] = "3.6"
        package["runtime"]["runtime_compliance"] = "NONCOMPLIANT_NOT_PYTHON_3_11"
        package["runtime"]["collector_context"] = "PRIVATE_CLI_CANDIDATE"
        package["runtime"]["passenger_context_present"] = False
        package["runtime"]["serving_request_verified"] = False
        package["runtime_binding"]["serving_request_verified"] = False
        with self.assertRaises(SafetyError): production_readiness.validate_support_return(package)

    def test_lifecycle_candidate_sha_mismatch_blocks(self):
        package = valid_package(); package["lifecycle"]["candidate_sha"] = "b" * 40
        with self.assertRaises(SafetyError): production_readiness.validate_support_return(package)

    def test_exact_reconciliation_requires_zero_differences_and_startup(self):
        package = valid_package(); package["reconciliation"]["unreviewed_difference_count"] = 1
        with self.assertRaises(SafetyError): production_readiness.validate_support_return(package)
        package = valid_package(); package["reconciliation"]["startup_accounted"] = False
        with self.assertRaises(SafetyError): production_readiness.validate_support_return(package)

    def test_manifest_count_disagreement_blocks(self):
        package = valid_package(); package["reconciliation"]["server_file_count"] = 41
        with self.assertRaises(SafetyError): production_readiness.validate_support_return(package)

    def test_strong_runtime_claim_requires_application_process(self):
        package = valid_package(); package["runtime"]["collector_context"] = "PRIVATE_CLI_CANDIDATE"
        with self.assertRaises(SafetyError): production_readiness.validate_support_return(package)

    def test_simulation_with_live_classification_blocks(self):
        package = valid_package(); package["lifecycle"]["mode"] = "TEST_SIMULATION"
        with self.assertRaises(SafetyError): production_readiness.validate_support_return(package)

    def test_not_executed_lifecycle_cannot_claim_pass(self):
        package = valid_package(); package["evidence_classes"]["lifecycle"] = "TEST_SIMULATION"; package["lifecycle"]["mode"] = "NOT_EXECUTED"
        with self.assertRaises(SafetyError): production_readiness.validate_support_return(package)

    def test_privacy_flags_and_unknown_fields_fail_closed(self):
        for field in ("private_values_copied", "raw_response_copied"):
            package = valid_package(); package["privacy"][field] = True
            with self.subTest(field=field), self.assertRaises(SafetyError): production_readiness.validate_support_return(package)
        package = valid_package(); package["runtime"]["note"] = "x"
        with self.assertRaises(SafetyError): production_readiness.validate_support_return(package)

    def test_malformed_hash_fails_closed(self):
        package = valid_package(); package["candidate_package"]["manifest_sha256"] = "not-a-digest"
        with self.assertRaises(SafetyError): production_readiness.validate_support_return(package)

    def test_live_failure_and_missing_rollback_keep_gates_blocked(self):
        package = valid_package(); package["lifecycle"]["health"] = "FAIL"
        result = production_readiness.build_deployment_readiness(package)
        self.assertEqual("BLOCKED_EXTERNAL", result["checks"]["backup_restart_identity_health_smoke_resume"]["status"])
        package = valid_package(); package["lifecycle"]["rollback"] = "NOT_RUN"
        result = production_readiness.build_deployment_readiness(package)
        self.assertEqual("BLOCKED_EXTERNAL", result["checks"]["rollback"]["status"])

    def test_current_telegram_auth_is_explicitly_not_applicable(self):
        check = production_readiness.build_deployment_readiness(valid_package())["checks"]["telegram_user_authorization"]
        self.assertEqual("NOT_APPLICABLE", check["status"])
        self.assertEqual("USER_TELEGRAM_AUTH_NOT_YET_REQUIRED", check["reason_code"])

    def test_public_readiness_mutation_cannot_self_authorize(self):
        result = production_readiness.build_deployment_readiness(valid_package())
        mutated = copy.deepcopy(result); mutated["promotion_authorized"] = True
        with self.assertRaises(SafetyError): production_readiness.validate_public_readiness(mutated)
        mutated = copy.deepcopy(result); mutated["checks"]["production_switch"] = {"status": "PASS", "reason_code": "FAKE_PASS"}
        with self.assertRaises(SafetyError): production_readiness.validate_public_readiness(mutated)

    def test_public_output_contains_only_bounded_status_accounting(self):
        result = production_readiness.build_deployment_readiness(valid_package())
        encoded = str(result)
        for forbidden in ("artifact_sha256", "wsgi_sha256", "server_manifest", "request_challenge_sha256", "serving_probe_sha256"):
            self.assertNotIn(forbidden, encoded)
        self.assertFalse(result["private_values_copied"])
        self.assertFalse(result["raw_response_copied"])


if __name__ == "__main__":
    unittest.main()
