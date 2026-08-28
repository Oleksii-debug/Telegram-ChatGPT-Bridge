# -*- coding: utf-8 -*-
from __future__ import annotations

import unittest

from ops.acceptance_harness import AUTH_NOT_YET_REQUIRED, AUTH_REQUIRED
from ops.dev10_accessibility_protocol import (
    ACCESSIBILITY_CRITERIA,
    HUMAN_NVDA_CRITERIA,
    ProtocolError,
    analyze_setup_markup,
    authoritative_accessibility_projection,
    detect_legacy_accessibility_truth_drift,
    evaluate_auth_readiness,
    evaluate_human_nvda_gate,
    human_nvda_step_ids,
    k5_readiness,
    live_scenario_plans,
    operator_bootstrap_contract,
    telegram_setup_stage_plan,
    validate_human_accessibility_evidence,
)

SHA40 = "a" * 40
SHA256 = "b" * 64


class AccessibilityTruthTests(unittest.TestCase):
    def test_authoritative_projection_keeps_human_nvda_live_external(self):
        projection = authoritative_accessibility_projection()
        self.assertEqual(set(projection), set(ACCESSIBILITY_CRITERIA))
        for criterion in HUMAN_NVDA_CRITERIA:
            self.assertEqual(projection[criterion], "LIVE_EXTERNAL_REQUIRED")
        for criterion in ("I2", "I3", "I5", "I7"):
            self.assertEqual(projection[criterion], "REAL_SOURCE_REQUIRED")

    def test_legacy_projection_drift_is_detected_not_silently_trusted(self):
        self.assertEqual(
            detect_legacy_accessibility_truth_drift(),
            ("C1", "I1", "I2", "I3", "I4", "I5", "I6", "I7"),
        )


class SetupMarkupTests(unittest.TestCase):
    GOOD = """<!doctype html>
<html lang="uk"><body><main>
<h1>Private Telegram setup</h1>
<form>
<label for="phone">Phone</label>
<input id="phone" type="tel" aria-describedby="phone-help">
<p id="phone-help">Use the private setup flow.</p>
<button type="button">Continue</button>
<div id="setup-status" role="status" aria-live="polite"></div>
</form></main></body></html>"""

    def test_structural_readiness_never_becomes_human_nvda_pass(self):
        report = analyze_setup_markup(self.GOOD)
        self.assertTrue(report["structural_ready"])
        self.assertTrue(report["labels_present"])
        self.assertTrue(report["accessible_names_present"])
        self.assertTrue(report["heading_structure_valid"])
        self.assertTrue(report["status_region_present"])
        self.assertTrue(report["positive_tabindex_absent"])
        self.assertTrue(report["mouse_only_absent"])
        self.assertFalse(report["human_nvda_pass"])

    def test_missing_label_positive_tabindex_pointer_only_and_bad_aria_fail(self):
        bad = """<main><h1>Setup</h1>
<input id="code" tabindex="2" aria-describedby="missing-error">
<button type="button">Continue</button>
<div onclick="go()">Pointer action</div>
<div role="status"></div></main>"""
        report = analyze_setup_markup(bad)
        self.assertFalse(report["structural_ready"])
        self.assertFalse(report["labels_present"])
        self.assertFalse(report["positive_tabindex_absent"])
        self.assertFalse(report["mouse_only_absent"])
        self.assertFalse(report["aria_references_resolve"])

    def test_missing_status_region_and_heading_jump_fail_structural_readiness(self):
        bad = """<main><h1>Setup</h1><h3>Code</h3>
<label for="code">Code</label><input id="code">
<button>Continue</button></main>"""
        report = analyze_setup_markup(bad)
        self.assertFalse(report["structural_ready"])
        self.assertFalse(report["heading_structure_valid"])
        self.assertFalse(report["status_region_present"])

    def test_markup_input_is_bounded(self):
        with self.assertRaises(ProtocolError):
            analyze_setup_markup("")
        with self.assertRaises(ProtocolError):
            analyze_setup_markup("x" * 1_000_001)


class HumanNvdaGateTests(unittest.TestCase):
    def test_structural_green_alone_cannot_claim_human_pass(self):
        gate = evaluate_human_nvda_gate(
            structural_ready=True,
            audited_deployed_sha_known=False,
            passenger_runtime_verified=False,
            setup_surface_available=False,
            human_run_status="PASS",
        )
        self.assertEqual(gate.state, "BLOCKED")
        self.assertFalse(gate.human_nvda_pass)

    def test_ready_for_human_requires_deployed_prerequisites(self):
        gate = evaluate_human_nvda_gate(
            structural_ready=True,
            audited_deployed_sha_known=True,
            passenger_runtime_verified=True,
            setup_surface_available=True,
        )
        self.assertEqual(gate.state, "READY_FOR_HUMAN")
        self.assertFalse(gate.human_nvda_pass)

    def test_explicit_human_pass_is_distinct_from_structural_readiness(self):
        gate = evaluate_human_nvda_gate(
            structural_ready=True,
            audited_deployed_sha_known=True,
            passenger_runtime_verified=True,
            setup_surface_available=True,
            human_run_status="PASS",
        )
        self.assertEqual(gate.state, "HUMAN_PASS_RECORDED")
        self.assertTrue(gate.human_nvda_pass)

    def test_human_status_is_fail_closed(self):
        with self.assertRaises(ProtocolError):
            evaluate_human_nvda_gate(
                structural_ready=True,
                audited_deployed_sha_known=True,
                passenger_runtime_verified=True,
                setup_surface_available=True,
                human_run_status="SOURCE_PASS",
            )


class TelegramAuthorizationProtocolTests(unittest.TestCase):
    def test_current_external_blockers_keep_auth_not_yet_required(self):
        gate = evaluate_auth_readiness(
            sanitized_application_source_ready=True,
            passenger_runtime_verified=False,
            server_setup_ready=False,
            setup_session_is_first_human_blocker=False,
        )
        self.assertEqual(gate["state"], AUTH_NOT_YET_REQUIRED)
        self.assertIn("PASSENGER_RUNTIME_PENDING", gate["reason_codes"])
        self.assertIn("SERVER_SETUP_NOT_READY", gate["reason_codes"])

    def test_auth_becomes_required_only_when_it_is_first_human_blocker(self):
        gate = evaluate_auth_readiness(
            sanitized_application_source_ready=True,
            passenger_runtime_verified=True,
            server_setup_ready=True,
            setup_session_is_first_human_blocker=True,
        )
        self.assertEqual(gate["state"], AUTH_REQUIRED)

    def test_not_required_stage_plan_requests_no_user_input(self):
        stages = telegram_setup_stage_plan(AUTH_NOT_YET_REQUIRED)
        self.assertTrue(stages)
        self.assertTrue(all(stage["execute_now"] is False for stage in stages))
        self.assertTrue(all(stage["user_input_allowed"] is False for stage in stages))
        self.assertTrue(all(stage["public_secret_value_allowed"] is False for stage in stages))

    def test_required_stage_plan_still_never_allows_public_secret_values(self):
        stages = telegram_setup_stage_plan(AUTH_REQUIRED)
        self.assertTrue(any(stage["user_input_allowed"] for stage in stages))
        self.assertTrue(all(stage["execute_now"] is False for stage in stages))
        self.assertTrue(all(stage["public_secret_value_allowed"] is False for stage in stages))


class LiveScenarioProtocolTests(unittest.TestCase):
    def test_k1_k5_are_ordered_and_never_self_execute(self):
        plans = live_scenario_plans()
        self.assertEqual([plan.criterion for plan in plans], ["K1", "K2", "K3", "K4", "K5"])
        self.assertTrue(all(plan.execute_now is False for plan in plans))
        self.assertEqual([plan.expected_external_effect_count for plan in plans], [0, 0, 0, 0, 1])

    def test_k5_requires_auditor_safe_destination_and_fresh_user_commit(self):
        k5 = live_scenario_plans()[-1]
        gates = set(k5.required_gates)
        self.assertIn("INDEPENDENT_AUDITOR_WRITE_APPROVAL", gates)
        self.assertIn("SAFE_DESTINATION_CONFIRMED", gates)
        self.assertIn("FRESH_EXPLICIT_USER_COMMIT", gates)
        self.assertIn("IDEMPOTENCY_READY", gates)

    def test_k5_safe_destination_requires_hash_only_public_binding(self):
        with self.assertRaises(ProtocolError):
            k5_readiness(
                audited_deployed_sha_known=True,
                passenger_runtime_verified=True,
                private_api_auth_ready=True,
                telegram_authorized=True,
                action_write_schema_verified=True,
                independent_auditor_write_approval=True,
                safe_destination_confirmed=True,
                destination_sha256=None,
                fresh_explicit_user_commit=True,
                idempotency_ready=True,
            )

    def test_k5_can_be_protocol_ready_without_executing(self):
        result = k5_readiness(
            audited_deployed_sha_known=True,
            passenger_runtime_verified=True,
            private_api_auth_ready=True,
            telegram_authorized=True,
            action_write_schema_verified=True,
            independent_auditor_write_approval=True,
            safe_destination_confirmed=True,
            destination_sha256=SHA256,
            fresh_explicit_user_commit=True,
            idempotency_ready=True,
        )
        self.assertEqual(result["state"], "READY_FOR_EXPLICIT_LIVE_EXECUTION")
        self.assertTrue(result["protocol_ready"])
        self.assertFalse(result["execute_now"])
        self.assertEqual(result["expected_external_effect_count"], 1)

    def test_missing_single_k5_gate_stays_blocked(self):
        result = k5_readiness(
            audited_deployed_sha_known=True,
            passenger_runtime_verified=True,
            private_api_auth_ready=True,
            telegram_authorized=True,
            action_write_schema_verified=True,
            independent_auditor_write_approval=False,
            safe_destination_confirmed=True,
            destination_sha256=SHA256,
            fresh_explicit_user_commit=True,
            idempotency_ready=True,
        )
        self.assertEqual(result["state"], "BLOCKED")
        self.assertFalse(result["protocol_ready"])


class HumanEvidenceTests(unittest.TestCase):
    def _payload(self, criterion="C1"):
        return {
            "criterion": criterion,
            "candidate_sha": SHA40,
            "status": "PASS",
            "step_count": 11,
            "finding_count": 0,
            "keyboard_only_verified": True,
            "spoken_name_role_state_verified": True,
            "focus_order_verified": True,
            "status_announcement_verified": True,
            "no_private_content_recorded": True,
        }

    def test_privacy_safe_human_evidence_accepts_only_bounded_facts(self):
        result = validate_human_accessibility_evidence(self._payload())
        self.assertEqual(result["criterion"], "C1")
        self.assertEqual(result["candidate_sha"], SHA40)
        self.assertNotIn("transcript", result)
        self.assertNotIn("message", result)

    def test_free_form_detail_is_rejected(self):
        payload = self._payload()
        payload["detail"] = "must never be public evidence"
        with self.assertRaises(ProtocolError):
            validate_human_accessibility_evidence(payload)

    def test_i6_pass_requires_actual_status_announcement_verification(self):
        payload = self._payload("I6")
        payload["status_announcement_verified"] = False
        with self.assertRaises(ProtocolError):
            validate_human_accessibility_evidence(payload)

    def test_human_evidence_rejects_nonhuman_accessibility_criterion(self):
        payload = self._payload("I2")
        with self.assertRaises(ProtocolError):
            validate_human_accessibility_evidence(payload)


class OperatorAndRecoveryContractTests(unittest.TestCase):
    def test_nvda_steps_are_keyboard_and_privacy_oriented(self):
        steps = human_nvda_step_ids()
        self.assertIn("TAB_FORWARD_THROUGH_EVERY_INTERACTIVE_CONTROL", steps)
        self.assertIn("SHIFT_TAB_BACK_THROUGH_EVERY_INTERACTIVE_CONTROL", steps)
        self.assertIn("VERIFY_STATUS_ANNOUNCEMENT_AFTER_STATE_CHANGE", steps)
        self.assertEqual(steps[-1], "RECORD_ONLY_RESULT_CODES_COUNTS_AND_HASHES")

    def test_bootstrap_contract_eliminates_recurring_cpanel(self):
        contract = operator_bootstrap_contract()
        self.assertEqual(contract["mode"], "ONE_TIME_SUPPORT_MANAGED_BOOTSTRAP")
        self.assertFalse(contract["user_recurring_cpanel_required"])
        self.assertTrue(contract["private_runtime_preserved"])
        self.assertTrue(contract["session_storage_preserved"])
        self.assertTrue(contract["backup_before_change_required"])
        self.assertTrue(contract["rollback_required"])


if __name__ == "__main__":
    unittest.main()
