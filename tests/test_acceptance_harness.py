# -*- coding: utf-8 -*-
"""Acceptance harness/privacy/auth-gate regressions. Synthetic readiness is never product PASS."""
from __future__ import annotations

import hashlib
import json
import unittest

from ops import acceptance_harness as ah
from ops import evidence_privacy as privacy
from tools import secret_scan

TEST_REF = "test:sha256:" + hashlib.sha256(b"test_acceptance_harness").hexdigest()


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
            criterion="B4", code_sha="a" * 40, environment_class="github-ci",
            result="PASS", evidence_ref="github:run:32461101553",
            facts={"tree_scan_passed": True, "history_scan_passed": True, "findings_count": 0, "scan_scope": "PUBLIC_REPOSITORY"},
        )
        roundtrip = json.loads(ah.serialize_result(payload))
        self.assertEqual(2, roundtrip["schema_version"])
        self.assertEqual("B4", roundtrip["criterion"])
        self.assertEqual(0, roundtrip["facts"]["findings_count"])

    def test_exact_sha_environment_reference_are_mandatory(self):
        bad_cases = [
            dict(code_sha="short", environment_class="github-ci", evidence_ref=TEST_REF),
            dict(code_sha="b" * 40, environment_class="bad/path", evidence_ref=TEST_REF),
            dict(code_sha="b" * 40, environment_class="github-ci", evidence_ref="https://example.invalid/path"),
            dict(code_sha="b" * 40, environment_class="github-ci", evidence_ref="ci:RecoveryGuard#45"),
        ]
        for case in bad_cases:
            with self.subTest(case=case), self.assertRaises(ValueError):
                ah.build_result(criterion="B4", result="PASS", **case)

    def test_semantic_environment_allowlist(self):
        for value in sorted(privacy.ALLOWED_ENVIRONMENT_CLASSES):
            self.assertEqual(value, privacy.validate_environment_class(value))
        for private_label in ("Alice", "PrivateChat", "МійЧат", "github-ci-copy", "prod-user-123"):
            with self.subTest(private_label=private_label), self.assertRaises(ValueError):
                privacy.validate_environment_class(private_label)

    def test_structured_evidence_reference_allowlist(self):
        safe = [
            "github:run:32461101553", "github:job:96708043115", "github:check:123",
            "github:commit:" + "a" * 40, TEST_REF,
            "reference:sha256:" + "b" * 64, "hostiq:sha256:" + "c" * 64,
            "external:sha256:" + "d" * 64,
        ]
        for value in safe:
            with self.subTest(value=value):
                self.assertEqual(value, privacy.validate_evidence_ref(value))
        unsafe = [
            "detail:Alice", "test:PrivateChat", "test:test_private.Alice.Chat",
            "github:run:Alice", "github:job:0", "reference:sha256:short", "ПриватнийЧат",
        ]
        for value in unsafe:
            with self.subTest(value=value), self.assertRaises(ValueError):
                privacy.validate_evidence_ref(value)

    def test_private_identifiers_are_hash_only_and_namespaced(self):
        raw = "Приватний чат Олексій"
        first = privacy.hash_private_identifier(raw, namespace="chat")
        second = privacy.hash_private_identifier(raw, namespace="person")
        self.assertRegex(first, r"^[0-9a-f]{64}$")
        self.assertNotEqual(first, second)
        self.assertNotIn(raw, first)

    def test_positive_schema_rejects_arbitrary_free_form_keys(self):
        for key in ("detail", "text", "value", "error", "info", "message_body", "file_content"):
            with self.subTest(key=key), self.assertRaises(ValueError):
                ah.build_result(
                    criterion="B4", code_sha="c" * 40, environment_class="synthetic",
                    result="FAIL", evidence_ref=TEST_REF, facts={key: "SAFELOOKING"},
                )

    def test_nested_dict_and_unsupported_types_are_rejected(self):
        values = [
            {"checks": {"state": "SUCCESS"}}, {"checks": [b"x"]},
            {"count": 1.5}, {"count": float("nan")}, {"count": object()},
        ]
        for facts in values:
            with self.subTest(facts_type=type(next(iter(facts.values()))).__name__), self.assertRaises(ValueError):
                ah.build_result(
                    criterion="B4", code_sha="d" * 40, environment_class="synthetic",
                    result="FAIL", evidence_ref=TEST_REF, facts=facts,
                )

    def test_criterion_specific_fact_keys_are_enforced(self):
        with self.assertRaises(ValueError):
            ah.build_result(
                criterion="B4", code_sha="e" * 40, environment_class="synthetic",
                result="PASS", evidence_ref=TEST_REF, facts={"rollback_state": "ROLLED_BACK"},
            )
        payload = ah.build_result(
            criterion="J5", code_sha="e" * 40, environment_class="synthetic",
            result="PASS", evidence_ref=TEST_REF,
            facts={"rollback_state": "ROLLED_BACK", "previous_sha": "1" * 40, "return_code": 20},
        )
        self.assertEqual("ROLLED_BACK", payload["facts"]["rollback_state"])

    def test_enum_values_are_semantically_allowlisted(self):
        safe = ah.build_result(
            criterion="B4", code_sha="f" * 40, environment_class="synthetic",
            result="PASS", evidence_ref=TEST_REF,
            facts={"state": "SUCCESS", "checks": ["SECRET_SCAN_PASS"], "scan_scope": "PUBLIC_REPOSITORY"},
        )
        self.assertEqual("SUCCESS", safe["facts"]["state"])
        for private_value in ("ALICE", "PRIVATE_CHAT", "MY_FILE", "CHAT_123"):
            with self.subTest(private_value=private_value), self.assertRaises(ValueError):
                ah.build_result(
                    criterion="B4", code_sha="f" * 40, environment_class="synthetic",
                    result="FAIL", evidence_ref=TEST_REF, facts={"state": private_value},
                )
        for key in ("checks", "capabilities", "coverage_tags"):
            with self.subTest(key=key), self.assertRaises(ValueError):
                ah.build_result(
                    criterion="B4", code_sha="f" * 40, environment_class="synthetic",
                    result="FAIL", evidence_ref=TEST_REF, facts={key: ["PRIVATE_LABEL"]},
                )

    def test_cyrillic_and_control_character_private_metadata_is_rejected(self):
        for value in ("ПРИВАТНИЙ_ЧАТ", "PRIVATE\x00CHAT", "PRIVATE\nCHAT"):
            with self.subTest(value=repr(value)), self.assertRaises(ValueError):
                privacy.validate_fact_value("state", value)
        for ref in ("ПриватнийЧат", "github:run:12\x00", "test:sha256:" + "а" * 64):
            with self.subTest(ref=repr(ref)), self.assertRaises(ValueError):
                privacy.validate_evidence_ref(ref)

    def test_sensitive_content_under_nominally_safe_enum_is_rejected(self):
        hidden = "".join(["TG_", "API_HASH", "=", "synthetic", "Sensitive", "Value123"])
        with self.assertRaises(ValueError):
            ah.build_result(
                criterion="B4", code_sha="f" * 40, environment_class="synthetic",
                result="FAIL", evidence_ref=TEST_REF, facts={"state": hidden.upper()},
            )

    def test_tokenish_value_under_safe_enum_key_is_rejected(self):
        with self.assertRaises(ValueError):
            ah.build_result(
                criterion="B4", code_sha="1" * 40, environment_class="synthetic",
                result="FAIL", evidence_ref=TEST_REF, facts={"state": "Aa9_" * 12},
            )

    def test_aggregate_fact_key_list_integer_and_depth_limits(self):
        with self.assertRaises(ValueError):
            ah.build_result(
                criterion="B4", code_sha="3" * 40, environment_class="synthetic", result="PASS",
                evidence_ref=TEST_REF, facts={"checks": ["SECRET_SCAN_PASS"] * (privacy.MAX_LIST_ITEMS + 1)},
            )
        with self.assertRaises(ValueError):
            ah.build_result(
                criterion="B4", code_sha="3" * 40, environment_class="synthetic", result="PASS",
                evidence_ref=TEST_REF, facts={f"x{i}": i for i in range(privacy.MAX_FACT_KEYS + 1)},
            )
        for value in (privacy.MAX_INT + 1, -(privacy.MAX_INT + 1)):
            with self.subTest(value=value), self.assertRaises(ValueError):
                privacy.validate_fact_value("count", value)
        with self.assertRaises(ValueError):
            privacy.validate_aggregate_payload({"a": {"b": {"c": {"d": {"e": 1}}}}})

    def test_mutable_list_and_tuple_aliases_are_copied(self):
        source = ["SECRET_SCAN_PASS"]
        payload = ah.build_result(
            criterion="B4", code_sha="4" * 40, environment_class="synthetic",
            result="PASS", evidence_ref=TEST_REF, facts={"checks": source},
        )
        source.append("PRIVATE_LABEL")
        self.assertEqual(["SECRET_SCAN_PASS"], payload["facts"]["checks"])
        payload2 = ah.build_result(
            criterion="B4", code_sha="4" * 40, environment_class="synthetic",
            result="PASS", evidence_ref=TEST_REF, facts={"checks": ("SECRET_SCAN_PASS",)},
        )
        self.assertIsInstance(payload2["facts"]["checks"], list)

    def test_serialize_result_revalidates_mutated_payload_and_list(self):
        payload = ah.build_result(
            criterion="B4", code_sha="4" * 40, environment_class="synthetic",
            result="PASS", evidence_ref=TEST_REF, facts={"findings_count": 0, "checks": ["SECRET_SCAN_PASS"]},
        )
        payload["facts"]["checks"].append("PRIVATE_LABEL")
        with self.assertRaises(ValueError):
            ah.serialize_result(payload)
        payload2 = ah.build_result(
            criterion="B4", code_sha="4" * 40, environment_class="synthetic",
            result="PASS", evidence_ref=TEST_REF, facts={"findings_count": 0},
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
        self.assertEqual("RUNTIME_ERROR", facts["error_type"])

    def test_exception_chain_and_subprocess_text_are_never_copied(self):
        canary = "setup-" + ("Xy9_" * 10)
        try:
            try:
                raise ValueError("inner " + canary + "\nprivate multiline")
            except ValueError as inner:
                raise RuntimeError("outer " + canary) from inner
        except RuntimeError as exc:
            facts = privacy.sanitize_exception(exc)
        self.assertNotIn(canary, json.dumps(facts))
        self.assertNotIn("private multiline", json.dumps(facts))
        subprocess_facts = privacy.sanitize_subprocess_result(7, stdout=canary, stderr=canary)
        self.assertNotIn(canary, json.dumps(subprocess_facts))
        self.assertEqual({"return_code": 7, "stdout_present": True, "stderr_present": True}, subprocess_facts)

    def test_privacy_patterns_and_repository_secret_scanner_overlap_on_canaries(self):
        variable = "TG_" + "API_HASH"
        canary = variable + "=" + "SyntheticSensitiveValue123"
        self.assertTrue(secret_scan.scan_text(canary, "synthetic.txt", "test"))
        with self.assertRaises(ValueError):
            privacy.reject_sensitive_text(canary)
        private_key = "-----BEGIN " + "PRIVATE KEY-----"
        self.assertTrue(secret_scan.scan_text(private_key, "synthetic.txt", "test"))
        with self.assertRaises(ValueError):
            privacy.reject_sensitive_text(private_key)
        self.assertEqual([], secret_scan.scan_text("PRIVATE_CHAT", "synthetic.txt", "test"))
        with self.assertRaises(ValueError):
            privacy.validate_fact_value("state", "PRIVATE_CHAT")


class TelegramAuthorizationGateTests(unittest.TestCase):
    def test_current_real_planning_state_is_not_yet_required(self):
        gate = ah.current_planning_auth_gate()
        self.assertEqual(ah.AUTH_NOT_YET_REQUIRED, gate["state"])
        self.assertIn("SANITIZED_SOURCE_PENDING", gate["reason_codes"])
        self.assertIn("PASSENGER_RUNTIME_PENDING", gate["reason_codes"])

    def test_gate_requires_all_real_prerequisites_and_first_human_blocker(self):
        gate = ah.evaluate_telegram_auth_gate(
            sanitized_application_source_ready=True, passenger_runtime_verified=True,
            server_setup_ready=True, setup_session_is_first_human_blocker=True,
        )
        self.assertEqual(ah.AUTH_REQUIRED, gate["state"])
        self.assertEqual(["SERVER_SETUP_FIRST_HUMAN_BLOCKER"], gate["reason_codes"])

    def test_hostiq_or_source_blocker_does_not_demand_login(self):
        gate = ah.evaluate_telegram_auth_gate(
            sanitized_application_source_ready=False, passenger_runtime_verified=False,
            server_setup_ready=True, setup_session_is_first_human_blocker=True,
        )
        self.assertEqual(ah.AUTH_NOT_YET_REQUIRED, gate["state"])

    def test_synthetic_tests_never_demand_user_credentials(self):
        gate = ah.evaluate_telegram_auth_gate(
            sanitized_application_source_ready=True, passenger_runtime_verified=True,
            server_setup_ready=True, setup_session_is_first_human_blocker=True, synthetic_only=True,
        )
        self.assertEqual(ah.AUTH_NOT_YET_REQUIRED, gate["state"])
        self.assertIn("SYNTHETIC_TEST_ONLY", gate["reason_codes"])

    def test_gate_accepts_only_boolean_control_facts(self):
        with self.assertRaises(ValueError):
            ah.evaluate_telegram_auth_gate(
                sanitized_application_source_ready=True, passenger_runtime_verified=True,
                server_setup_ready=True, setup_session_is_first_human_blocker="yes",  # type: ignore[arg-type]
            )


if __name__ == "__main__":
    unittest.main()
