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
                "success": True,
                "tree_scan_passed": True,
                "history_scan_passed": True,
                "findings_count": 0,
                "scan_scope": "PUBLIC_REPOSITORY",
            },
        )
        roundtrip = json.loads(ah.serialize_result(payload))
        self.assertEqual(3, roundtrip["schema_version"])
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
            facts={"success": True, "rollback_state": "ROLLED_BACK", "previous_sha": "1" * 40, "return_code": 20},
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
            result="PASS", evidence_ref="test:mutation", facts={"success": True, "tree_scan_passed": True, "history_scan_passed": True, "findings_count": 0},
        )
        payload["facts"] = {"detail": "not allowed"}
        with self.assertRaises(ValueError):
            ah.serialize_result(payload)
        payload2 = ah.build_result(
            criterion="B4", code_sha="4" * 40, environment_class="synthetic",
            result="PASS", evidence_ref="test:mutation2", facts={"success": True, "tree_scan_passed": True, "history_scan_passed": True, "findings_count": 0},
        )
        payload2["extra"] = "UNREVIEWED"
        with self.assertRaises(ValueError):
            ah.serialize_result(payload2)


class AcceptancePassAuthorityTests(unittest.TestCase):
    sha = "a" * 40
    digest = "b" * 64

    @classmethod
    def ref(cls, provider="LIVE_ENDPOINT"):
        if provider == "GITHUB_ACTIONS":
            return {"provider": provider, "run_id": 123, "suite": "ACCEPTANCE_HARNESS"}
        if provider == "SYNTHETIC_TEST":
            return {"provider": provider, "suite": "ACCEPTANCE_HARNESS"}
        return {"provider": provider, "evidence_sha256": cls.digest}

    @classmethod
    def authority(cls, authority_class, provider):
        return {"authority_class": authority_class, "evidence_ref": cls.ref(provider)}

    def test_synthetic_pass_is_rejected_for_representative_phase_boundaries(self):
        for criterion in ("A3", "C1", "H1", "H2", "I6", "J1", "K5"):
            with self.subTest(criterion=criterion), self.assertRaises(ValueError):
                ah.build_result(
                    criterion=criterion,
                    code_sha=self.sha,
                    environment_class="SYNTHETIC",
                    result="PASS",
                    evidence_ref=self.ref("SYNTHETIC_TEST"),
                    facts={"success": True},
                )

    def test_source_only_b4_positive_control(self):
        payload = ah.build_result(
            criterion="B4",
            code_sha=self.sha,
            environment_class="GITHUB_CI",
            result="PASS",
            evidence_ref=self.ref("GITHUB_ACTIONS"),
            facts={
                "success": True,
                "tree_scan_passed": True,
                "history_scan_passed": True,
                "findings_count": 0,
            },
        )
        self.assertEqual("PASS", payload["result"])
        self.assertEqual("SOURCE_CI", payload["authority_refs"][0]["authority_class"])

    def test_h1_requires_live_and_independent_authority_with_exact_identity(self):
        authorities = [
            self.authority("LIVE_RUNTIME", "LIVE_ENDPOINT"),
            self.authority("INDEPENDENT_AUDITOR", "DRIVE_CONTROL"),
        ]
        payload = ah.build_result(
            criterion="H1",
            code_sha=self.sha,
            environment_class="HOSTIQ_PRODUCTION",
            result="PASS",
            evidence_ref=self.ref("LIVE_ENDPOINT"),
            authority_refs=authorities,
            facts={
                "success": True,
                "schema_valid": True,
                "deployed_sha": self.sha,
                "observed_sha": self.sha,
            },
        )
        self.assertIn('"result":"PASS"', ah.serialize_result(payload))
        for mutation in ("missing_auditor", "wrong_deployed_sha", "synthetic_environment"):
            changed = json.loads(json.dumps(payload))
            if mutation == "missing_auditor":
                changed["authority_refs"] = changed["authority_refs"][:1]
            elif mutation == "wrong_deployed_sha":
                changed["facts"]["deployed_sha"] = "c" * 40
            else:
                changed["environment_class"] = "SYNTHETIC"
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                ah.serialize_result(changed)

        with self.assertRaises(ValueError):
            ah.build_result(
                criterion="H1",
                code_sha=self.sha,
                environment_class="HOSTIQ_PRODUCTION",
                result="PASS",
                evidence_ref=self.ref("LIVE_ENDPOINT"),
                authority_refs=[
                    self.authority("LIVE_RUNTIME", "LIVE_ENDPOINT"),
                    self.authority("INDEPENDENT_AUDITOR", "GITHUB_ACTIONS"),
                ],
                facts={
                    "success": True,
                    "schema_valid": True,
                    "deployed_sha": self.sha,
                    "observed_sha": self.sha,
                },
            )

    def test_human_nvda_pass_cannot_be_created_by_automation(self):
        facts = {
            "success": True,
            "deployed_sha": self.sha,
            "human_verified": True,
            "nvda_verified": True,
        }
        with self.assertRaises(ValueError):
            ah.build_result(
                criterion="I6",
                code_sha=self.sha,
                environment_class="HOSTIQ_PRODUCTION",
                result="PASS",
                evidence_ref=self.ref("LIVE_ENDPOINT"),
                authority_refs=[
                    self.authority("LIVE_RUNTIME", "LIVE_ENDPOINT"),
                    self.authority("INDEPENDENT_HUMAN", "GITHUB_ACTIONS"),
                ],
                facts=facts,
            )
        payload = ah.build_result(
            criterion="I6",
            code_sha=self.sha,
            environment_class="HOSTIQ_PRODUCTION",
            result="PASS",
            evidence_ref=self.ref("DRIVE_CONTROL"),
            authority_refs=[
                self.authority("LIVE_RUNTIME", "LIVE_ENDPOINT"),
                self.authority("INDEPENDENT_HUMAN", "DRIVE_CONTROL"),
            ],
            facts=facts,
        )
        self.assertEqual("PASS", payload["result"])

    def test_k5_requires_every_write_gate_and_replay_fact(self):
        authorities = [
            self.authority("LIVE_RUNTIME", "LIVE_ENDPOINT"),
            self.authority("INDEPENDENT_AUDITOR", "DRIVE_CONTROL"),
            self.authority("USER_CONFIRMATION", "DRIVE_CONTROL"),
        ]
        facts = {
            "success": True,
            "deployed_sha": self.sha,
            "w10_approval_verified": True,
            "safe_destination_verified": True,
            "exact_preview_verified": True,
            "exact_text_verified": True,
            "idempotency_bound": True,
            "fresh_user_confirmation": True,
            "commit_single_use": True,
            "deduplicated": True,
            "operation_kind": "SEND",
            "external_effect_count": 1,
            "replay_duplicate_count": 0,
            "payload_sha256": self.digest,
            "identifier_sha256": "c" * 64,
            "idempotency_sha256": "d" * 64,
            "preview_fingerprint_sha256": "e" * 64,
        }
        payload = ah.build_result(
            criterion="K5",
            code_sha=self.sha,
            environment_class="HOSTIQ_PRODUCTION",
            result="PASS",
            evidence_ref=self.ref("LIVE_ENDPOINT"),
            authority_refs=authorities,
            facts=facts,
        )
        self.assertEqual("PASS", payload["result"])
        missing_cases = [
            "w10_approval_verified",
            "safe_destination_verified",
            "exact_preview_verified",
            "exact_text_verified",
            "idempotency_bound",
            "fresh_user_confirmation",
            "payload_sha256",
            "identifier_sha256",
            "idempotency_sha256",
            "preview_fingerprint_sha256",
        ]
        for key in missing_cases:
            changed = dict(facts)
            changed.pop(key)
            with self.subTest(missing=key), self.assertRaises(ValueError):
                ah.build_result(
                    criterion="K5", code_sha=self.sha,
                    environment_class="HOSTIQ_PRODUCTION", result="PASS",
                    evidence_ref=self.ref("LIVE_ENDPOINT"),
                    authority_refs=authorities, facts=changed,
                )
        for key, value in (("external_effect_count", 2), ("replay_duplicate_count", 1)):
            changed = dict(facts)
            changed[key] = value
            with self.subTest(invalid=key), self.assertRaises(ValueError):
                ah.build_result(
                    criterion="K5", code_sha=self.sha,
                    environment_class="HOSTIQ_PRODUCTION", result="PASS",
                    evidence_ref=self.ref("LIVE_ENDPOINT"),
                    authority_refs=authorities, facts=changed,
                )
        for missing_authority in ("INDEPENDENT_AUDITOR", "USER_CONFIRMATION"):
            changed = [item for item in authorities if item["authority_class"] != missing_authority]
            with self.subTest(missing_authority=missing_authority), self.assertRaises(ValueError):
                ah.build_result(
                    criterion="K5", code_sha=self.sha,
                    environment_class="HOSTIQ_PRODUCTION", result="PASS",
                    evidence_ref=self.ref("LIVE_ENDPOINT"),
                    authority_refs=changed, facts=facts,
                )


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
