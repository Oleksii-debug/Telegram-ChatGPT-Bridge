# -*- coding: utf-8 -*-
"""Acceptance harness/privacy/auth-gate regressions. Synthetic readiness is never product PASS."""
from __future__ import annotations

import json
import unittest

from ops import acceptance_harness as ah
from ops import evidence_privacy as privacy


class AcceptanceMatrixTests(unittest.TestCase):
    def test_exact_a_to_k_matrix_shape(self):
        ah.validate_matrix()
        ids = [item["criterion"] for item in ah.ACCEPTANCE_MATRIX]
        self.assertEqual(67, len(ids))
        self.assertEqual(67, len(set(ids)))
        self.assertEqual(set("ABCDEFGHIJK"), {item[0] for item in ids})

    def test_planning_matrix_does_not_claim_product_pass(self):
        self.assertNotIn("PASS", {item["plan_status"] for item in ah.ACCEPTANCE_MATRIX})
        self.assertEqual("IMPLEMENTED_TEST", ah.CRITERIA["B4"]["plan_status"])
        self.assertEqual("IMPLEMENTED_TEST", ah.CRITERIA["J5"]["plan_status"])
        self.assertEqual("EXTERNALLY_BLOCKED", ah.CRITERIA["J1"]["plan_status"])
        self.assertEqual("READY_FOR_REAL_SOURCE", ah.CRITERIA["A1"]["plan_status"])

    def test_safe_typed_result_roundtrip(self):
        payload = ah.build_result(
            criterion="B4",
            code_sha="a" * 40,
            environment_class="github-ci",
            result="PASS",
            evidence_ref="ci:RecoveryGuard#44",
            facts={
                "tree_scan_passed": True,
                "history_scan_passed": True,
                "findings_count": 0,
                "scan_scope": "PUBLIC_REPOSITORY",
            },
        )
        roundtrip = json.loads(ah.serialize_result(payload))
        self.assertEqual(2, roundtrip["schema_version"])
        self.assertEqual("B4", roundtrip["criterion"])
        self.assertEqual(0, roundtrip["facts"]["findings_count"])

    def test_exact_sha_environment_reference_are_mandatory(self):
        with self.assertRaises(ValueError):
            ah.build_result(
                criterion="B4", code_sha="short", environment_class="github-ci",
                result="PASS", evidence_ref="ci:bad",
            )
        with self.assertRaises(ValueError):
            ah.build_result(
                criterion="B4", code_sha="b" * 40, environment_class="bad/path",
                result="PASS", evidence_ref="ci:bad",
            )
        with self.assertRaises(ValueError):
            ah.build_result(
                criterion="B4", code_sha="b" * 40, environment_class="github-ci",
                result="PASS", evidence_ref="https://example.invalid/path?x=y",
            )

    def test_positive_schema_rejects_arbitrary_free_form_keys(self):
        for key in ("detail", "text", "value", "error", "info", "message_body", "file_content"):
            with self.subTest(key=key), self.assertRaises(ValueError):
                ah.build_result(
                    criterion="B4", code_sha="c" * 40, environment_class="synthetic",
                    result="FAIL", evidence_ref="test:privacy", facts={key: "SAFELOOKING"},
                )

    def test_nested_dict_and_unsupported_types_are_rejected(self):
        with self.assertRaises(ValueError):
            ah.build_result(
                criterion="B4", code_sha="d" * 40, environment_class="synthetic",
                result="FAIL", evidence_ref="test:nested", facts={"checks": {"state": "PASS"}},
            )
        with self.assertRaises(ValueError):
            ah.build_result(
                criterion="B4", code_sha="d" * 40, environment_class="synthetic",
                result="FAIL", evidence_ref="test:bytes", facts={"checks": [b"x"]},
            )

    def test_criterion_specific_fact_keys_are_enforced(self):
        with self.assertRaises(ValueError):
            ah.build_result(
                criterion="B4", code_sha="e" * 40, environment_class="synthetic",
                result="PASS", evidence_ref="test:criterion", facts={"rollback_state": "ROLLED_BACK"},
            )
        payload = ah.build_result(
            criterion="J5", code_sha="e" * 40, environment_class="synthetic",
            result="PASS", evidence_ref="test:rollback",
            facts={"rollback_state": "ROLLED_BACK", "previous_sha": "1" * 40, "return_code": 20},
        )
        self.assertEqual("ROLLED_BACK", payload["facts"]["rollback_state"])

    def test_sensitive_content_under_nominally_safe_enum_is_rejected(self):
        pieces = ["TG_", "API_HASH", "=", "synthetic", "Sensitive", "Value123"]
        hidden = "".join(pieces)
        with self.assertRaises(ValueError):
            ah.build_result(
                criterion="B4", code_sha="f" * 40, environment_class="synthetic",
                result="FAIL", evidence_ref="test:secret", facts={"state": hidden.upper()},
            )

    def test_tokenish_value_under_safe_enum_key_is_rejected(self):
        tokenish = "Aa9_" * 12
        with self.assertRaises(ValueError):
            ah.build_result(
                criterion="B4", code_sha="1" * 40, environment_class="synthetic",
                result="FAIL", evidence_ref="test:tokenish", facts={"state": tokenish},
            )

    def test_sensitive_reference_is_rejected_even_without_forbidden_key(self):
        setup_ref = "test:/" + "setup-" + ("Xy9_" * 5)
        with self.assertRaises(ValueError):
            ah.build_result(
                criterion="B4", code_sha="2" * 40, environment_class="synthetic",
                result="FAIL", evidence_ref=setup_ref, facts={"findings_count": 1},
            )

    def test_aggregate_fact_key_and_list_limits(self):
        too_many = {"checks": ["PASS"] * (privacy.MAX_LIST_ITEMS + 1)}
        with self.assertRaises(ValueError):
            ah.build_result(
                criterion="B4", code_sha="3" * 40, environment_class="synthetic",
                result="PASS", evidence_ref="test:listlimit", facts=too_many,
            )
        oversized = {f"x{i}": i for i in range(privacy.MAX_FACT_KEYS + 1)}
        with self.assertRaises(ValueError):
            ah.build_result(
                criterion="B4", code_sha="3" * 40, environment_class="synthetic",
                result="PASS", evidence_ref="test:keylimit", facts=oversized,
            )

    def test_serialize_result_revalidates_mutated_payload(self):
        payload = ah.build_result(
            criterion="B4", code_sha="4" * 40, environment_class="synthetic",
            result="PASS", evidence_ref="test:mutation", facts={"findings_count": 0},
        )
        payload["facts"] = {"detail": "not allowed"}
        with self.assertRaises(ValueError):
            ah.serialize_result(payload)
        payload2 = ah.build_result(
            criterion="B4", code_sha="4" * 40, environment_class="synthetic",
            result="PASS", evidence_ref="test:mutation2", facts={"findings_count": 0},
        )
        payload2["extra"] = "UNREVIEWED"
        with self.assertRaises(ValueError):
            ah.serialize_result(payload2)


class SanitizationTests(unittest.TestCase):
    def test_exception_message_is_never_copied(self):
        secretish = "Bearer" + " " + ("Ab9_" * 10)
        try:
            raise RuntimeError(secretish)
        except RuntimeError as exc:
            facts = privacy.sanitize_exception(exc)
        encoded = json.dumps(facts)
        self.assertNotIn(secretish, encoded)
        self.assertEqual("RUNTIMEERROR", facts["error_type"])

    def test_subprocess_text_is_never_copied(self):
        secretish = "Cookie:" + ("Xy9_" * 10)
        facts = privacy.sanitize_subprocess_result(7, stdout=secretish, stderr=secretish)
        encoded = json.dumps(facts)
        self.assertNotIn(secretish, encoded)
        self.assertEqual({"return_code": 7, "stdout_present": True, "stderr_present": True}, facts)


class TelegramAuthorizationGateTests(unittest.TestCase):
    def test_current_real_planning_state_is_not_yet_required(self):
        gate = ah.current_planning_auth_gate()
        self.assertEqual(ah.AUTH_NOT_YET_REQUIRED, gate["state"])
        self.assertIn("SANITIZED_SOURCE_PENDING", gate["reason_codes"])
        self.assertIn("PASSENGER_RUNTIME_PENDING", gate["reason_codes"])

    def test_gate_requires_all_real_prerequisites_and_first_human_blocker(self):
        gate = ah.evaluate_telegram_auth_gate(
            sanitized_application_source_ready=True,
            passenger_runtime_verified=True,
            server_setup_ready=True,
            setup_session_is_first_human_blocker=True,
        )
        self.assertEqual(ah.AUTH_REQUIRED, gate["state"])
        self.assertEqual(["SERVER_SETUP_FIRST_HUMAN_BLOCKER"], gate["reason_codes"])

    def test_hostiq_or_source_blocker_does_not_demand_login(self):
        gate = ah.evaluate_telegram_auth_gate(
            sanitized_application_source_ready=False,
            passenger_runtime_verified=False,
            server_setup_ready=True,
            setup_session_is_first_human_blocker=True,
        )
        self.assertEqual(ah.AUTH_NOT_YET_REQUIRED, gate["state"])

    def test_synthetic_tests_never_demand_user_credentials(self):
        gate = ah.evaluate_telegram_auth_gate(
            sanitized_application_source_ready=True,
            passenger_runtime_verified=True,
            server_setup_ready=True,
            setup_session_is_first_human_blocker=True,
            synthetic_only=True,
        )
        self.assertEqual(ah.AUTH_NOT_YET_REQUIRED, gate["state"])
        self.assertIn("SYNTHETIC_TEST_ONLY", gate["reason_codes"])

    def test_gate_accepts_only_boolean_control_facts(self):
        with self.assertRaises(ValueError):
            ah.evaluate_telegram_auth_gate(
                sanitized_application_source_ready=True,
                passenger_runtime_verified=True,
                server_setup_ready=True,
                setup_session_is_first_human_blocker="yes",  # type: ignore[arg-type]
            )


if __name__ == "__main__":
    unittest.main()
