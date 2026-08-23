# -*- coding: utf-8 -*-
import unittest

from ops.acceptance_harness import AUTH_NOT_YET_REQUIRED, AUTH_REQUIRED
from ops.dev10_human_live_gate import (
    HumanLiveGateError,
    assess_human_receipt_currentness,
    current_source_green_projection,
    deployment_change_invalidates_human_evidence,
    evaluate_human_live_readiness,
    validate_deployed_human_receipt,
    validate_source_identity_kind,
)

SHA_A = "a" * 40
SHA_B = "b" * 40
SURFACE_A = "1" * 64
SURFACE_B = "2" * 64


def ready_kwargs(**overrides):
    data = {
        "source_sha": SHA_A,
        "deployed_sha": SHA_A,
        "source_identity_kind": "EXACT_RELEASE_SHA",
        "setup_surface_sha256": SURFACE_A,
        "source_ci_green": True,
        "nonlive_prepare_verified": True,
        "independent_auditor_release_gate": True,
        "live_manifest_reconciled": True,
        "passenger_application_process_verified": True,
        "running_sha_verified": True,
        "private_setup_surface_ready": True,
        "telegram_auth_state": AUTH_NOT_YET_REQUIRED,
    }
    data.update(overrides)
    return data


def valid_receipt(**overrides):
    data = {
        "criterion": "C1",
        "deployed_sha": SHA_A,
        "setup_surface_sha256": SURFACE_A,
        "status": "PASS",
        "step_count": 11,
        "finding_count": 0,
        "keyboard_only_verified": True,
        "spoken_name_role_state_verified": True,
        "focus_order_verified": True,
        "status_announcement_verified": True,
        "no_private_content_recorded": True,
    }
    data.update(overrides)
    return data


class SourceIdentityTests(unittest.TestCase):
    def test_exact_release_identity_allowed(self):
        self.assertEqual(validate_source_identity_kind("EXACT_RELEASE_SHA"), "EXACT_RELEASE_SHA")

    def test_pr_merge_ref_is_never_deployed_identity(self):
        with self.assertRaises(HumanLiveGateError):
            validate_source_identity_kind("PR_MERGE_REF")

    def test_unknown_identity_fails_closed(self):
        with self.assertRaises(HumanLiveGateError):
            validate_source_identity_kind("CI_SAYS_GREEN")


class HumanLiveReadinessTests(unittest.TestCase):
    def test_source_green_alone_cannot_reach_human_gate(self):
        result = evaluate_human_live_readiness(**ready_kwargs(independent_auditor_release_gate=False))
        self.assertEqual(result.state, "BLOCKED_PRELIVE_GATE")
        self.assertFalse(result.ready_for_human_nvda)
        self.assertFalse(result.human_nvda_pass)
        self.assertFalse(result.live_execution_authorized)

    def test_deployed_sha_must_equal_exact_source_release_sha(self):
        result = evaluate_human_live_readiness(**ready_kwargs(deployed_sha=SHA_B))
        self.assertEqual(result.state, "BLOCKED_DEPLOYED_SHA_MISMATCH")
        self.assertFalse(result.exact_deployment_bound)

    def test_cli_or_generic_runtime_is_not_passenger_application_process_proof(self):
        result = evaluate_human_live_readiness(**ready_kwargs(passenger_application_process_verified=False))
        self.assertEqual(result.state, "BLOCKED_PASSENGER_APPLICATION_PROCESS")
        self.assertFalse(result.ready_for_human_nvda)

    def test_running_sha_is_independent_required_gate(self):
        result = evaluate_human_live_readiness(**ready_kwargs(running_sha_verified=False))
        self.assertEqual(result.state, "BLOCKED_RUNNING_SHA")

    def test_private_setup_surface_is_required(self):
        result = evaluate_human_live_readiness(**ready_kwargs(private_setup_surface_ready=False))
        self.assertEqual(result.state, "BLOCKED_PRIVATE_SETUP_SURFACE")

    def test_human_nvda_can_be_ready_without_requesting_telegram_secrets(self):
        result = evaluate_human_live_readiness(**ready_kwargs())
        self.assertEqual(result.state, "READY_FOR_HUMAN_NVDA")
        self.assertTrue(result.ready_for_human_nvda)
        self.assertFalse(result.telegram_user_input_allowed)
        self.assertFalse(result.human_nvda_pass)

    def test_telegram_user_input_only_after_authoritative_required_state(self):
        result = evaluate_human_live_readiness(**ready_kwargs(telegram_auth_state=AUTH_REQUIRED))
        self.assertTrue(result.ready_for_human_nvda)
        self.assertTrue(result.telegram_user_input_allowed)
        self.assertFalse(result.live_execution_authorized)

    def test_invalid_boolean_and_hash_fail_closed(self):
        with self.assertRaises(HumanLiveGateError):
            evaluate_human_live_readiness(**ready_kwargs(source_ci_green=1))
        with self.assertRaises(HumanLiveGateError):
            evaluate_human_live_readiness(**ready_kwargs(setup_surface_sha256="short"))


class HumanReceiptTests(unittest.TestCase):
    def test_receipt_is_bound_to_current_deployed_sha_and_surface(self):
        result = validate_deployed_human_receipt(
            valid_receipt(),
            expected_deployed_sha=SHA_A,
            expected_setup_surface_sha256=SURFACE_A,
        )
        self.assertEqual(result["deployed_sha"], SHA_A)
        self.assertEqual(result["setup_surface_sha256"], SURFACE_A)

    def test_receipt_from_prior_deployment_is_rejected(self):
        with self.assertRaises(HumanLiveGateError):
            validate_deployed_human_receipt(
                valid_receipt(deployed_sha=SHA_B),
                expected_deployed_sha=SHA_A,
                expected_setup_surface_sha256=SURFACE_A,
            )

    def test_receipt_from_prior_setup_surface_is_rejected(self):
        with self.assertRaises(HumanLiveGateError):
            validate_deployed_human_receipt(
                valid_receipt(setup_surface_sha256=SURFACE_B),
                expected_deployed_sha=SHA_A,
                expected_setup_surface_sha256=SURFACE_A,
            )

    def test_free_form_or_private_detail_field_is_impossible(self):
        payload = valid_receipt()
        payload["transcript"] = "private screen text"
        with self.assertRaises(HumanLiveGateError):
            validate_deployed_human_receipt(
                payload,
                expected_deployed_sha=SHA_A,
                expected_setup_surface_sha256=SURFACE_A,
            )

    def test_pass_requires_criterion_specific_human_fact(self):
        with self.assertRaises(HumanLiveGateError):
            validate_deployed_human_receipt(
                valid_receipt(criterion="I6", status_announcement_verified=False),
                expected_deployed_sha=SHA_A,
                expected_setup_surface_sha256=SURFACE_A,
            )

    def test_fail_receipt_can_record_missing_verified_fact_without_private_content(self):
        result = validate_deployed_human_receipt(
            valid_receipt(status="FAIL", keyboard_only_verified=False, finding_count=1),
            expected_deployed_sha=SHA_A,
            expected_setup_surface_sha256=SURFACE_A,
        )
        self.assertEqual(result["status"], "FAIL")
        self.assertEqual(result["finding_count"], 1)

    def test_private_content_flag_blocks_pass(self):
        with self.assertRaises(HumanLiveGateError):
            validate_deployed_human_receipt(
                valid_receipt(no_private_content_recorded=False),
                expected_deployed_sha=SHA_A,
                expected_setup_surface_sha256=SURFACE_A,
            )

    def test_currentness_distinguishes_deployment_and_surface_change(self):
        receipt = valid_receipt()
        self.assertEqual(
            assess_human_receipt_currentness(receipt, current_deployed_sha=SHA_A, current_setup_surface_sha256=SURFACE_A),
            "CURRENT",
        )
        self.assertEqual(
            assess_human_receipt_currentness(receipt, current_deployed_sha=SHA_B, current_setup_surface_sha256=SURFACE_A),
            "STALE_DEPLOYED_SHA",
        )
        self.assertEqual(
            assess_human_receipt_currentness(receipt, current_deployed_sha=SHA_A, current_setup_surface_sha256=SURFACE_B),
            "STALE_SETUP_SURFACE",
        )

    def test_any_deployment_or_setup_change_invalidates_prior_human_evidence(self):
        self.assertFalse(deployment_change_invalidates_human_evidence(
            previous_deployed_sha=SHA_A,
            current_deployed_sha=SHA_A,
            previous_setup_surface_sha256=SURFACE_A,
            current_setup_surface_sha256=SURFACE_A,
        ))
        self.assertTrue(deployment_change_invalidates_human_evidence(
            previous_deployed_sha=SHA_A,
            current_deployed_sha=SHA_B,
            previous_setup_surface_sha256=SURFACE_A,
            current_setup_surface_sha256=SURFACE_A,
        ))
        self.assertTrue(deployment_change_invalidates_human_evidence(
            previous_deployed_sha=SHA_A,
            current_deployed_sha=SHA_A,
            previous_setup_surface_sha256=SURFACE_A,
            current_setup_surface_sha256=SURFACE_B,
        ))


class CurrentCanonicalProjectionTests(unittest.TestCase):
    def test_green_source_projection_never_claims_human_or_production_pass(self):
        result = current_source_green_projection(
            source_sha=SHA_A,
            recovery_guard_success=True,
            nonlive_prepare_verified=True,
        )
        self.assertTrue(result["source_release_ready"])
        self.assertFalse(result["human_nvda_pass"])
        self.assertFalse(result["telegram_user_input_allowed"])
        self.assertFalse(result["production_pass"])
        self.assertFalse(result["live_execution_authorized"])


if __name__ == "__main__":
    unittest.main()
