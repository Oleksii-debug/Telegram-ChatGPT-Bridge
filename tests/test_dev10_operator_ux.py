# -*- coding: utf-8 -*-
import unittest

from ops.acceptance_harness import AUTH_NOT_YET_REQUIRED, AUTH_REQUIRED
from ops.dev10_operator_ux import (
    BootstrapStep,
    OperatorUxError,
    completion_handoff_contract,
    operator_ux_readiness,
    scan_manual_admin_copy,
    support_managed_bootstrap_plan,
    validate_bootstrap_steps,
)


class ManualAdminCopyTests(unittest.TestCase):
    def test_reference_style_pip_instruction_is_flagged(self):
        findings = scan_manual_admin_copy(
            "У cPanel спочатку виконайте Run Pip Install для requirements.txt."
        )
        self.assertIn("USER_MANUAL_CPANEL_DEPENDENCY_INSTALL", findings)

    def test_reference_style_restart_instruction_is_flagged(self):
        findings = scan_manual_admin_copy(
            "Після цього натисніть Restart для Python App у cPanel."
        )
        self.assertIn("USER_MANUAL_CPANEL_RESTART", findings)

    def test_direct_cpanel_navigation_is_flagged(self):
        findings = scan_manual_admin_copy("Зайдіть у cPanel для наступного кроку.")
        self.assertIn("USER_MANUAL_CPANEL_NAVIGATION", findings)

    def test_neutral_cpanel_reference_without_user_action_is_not_enough(self):
        self.assertEqual(scan_manual_admin_copy("cPanel є частиною HOSTiQ runtime context."), ())

    def test_operator_copy_is_bounded(self):
        with self.assertRaises(OperatorUxError):
            scan_manual_admin_copy("x" * 131073)


class BootstrapPlanTests(unittest.TestCase):
    def test_current_not_required_state_contains_no_user_steps(self):
        plan = support_managed_bootstrap_plan(AUTH_NOT_YET_REQUIRED)
        self.assertFalse(any(step.actor == "USER" for step in plan))
        self.assertFalse(any(step.execute_now for step in plan))

    def test_required_state_limits_user_to_private_auth_interaction(self):
        plan = support_managed_bootstrap_plan(AUTH_REQUIRED)
        user = [step for step in plan if step.actor == "USER"]
        self.assertEqual(
            [step.action for step in user],
            [
                "OPEN_PRIVATE_SETUP",
                "ENTER_PHONE",
                "ENTER_LOGIN_CODE",
                "ENTER_2FA_IF_REQUIRED",
                "CONFIRM_SPOKEN_STATUS",
            ],
        )
        self.assertFalse(any(step.requires_cpanel for step in user))

    def test_user_cpanel_step_fails_closed(self):
        with self.assertRaises(OperatorUxError):
            validate_bootstrap_steps(
                AUTH_REQUIRED,
                [BootstrapStep("USER", "OPEN_PRIVATE_SETUP", requires_cpanel=True)],
            )

    def test_user_server_admin_action_fails_closed(self):
        with self.assertRaises(OperatorUxError):
            validate_bootstrap_steps(
                AUTH_REQUIRED,
                [BootstrapStep("USER", "RESTART_PASSENGER")],
            )

    def test_private_user_input_cannot_be_delegated_to_support(self):
        with self.assertRaises(OperatorUxError):
            validate_bootstrap_steps(
                AUTH_REQUIRED,
                [BootstrapStep("SUPPORT", "VERIFY_PRIVATE_SETUP_GATE", accepts_private_user_input=True)],
            )

    def test_not_required_state_rejects_private_user_input(self):
        with self.assertRaises(OperatorUxError):
            validate_bootstrap_steps(
                AUTH_NOT_YET_REQUIRED,
                [BootstrapStep("USER", "ENTER_PHONE", accepts_private_user_input=True)],
            )

    def test_plan_never_self_executes(self):
        with self.assertRaises(OperatorUxError):
            validate_bootstrap_steps(
                AUTH_REQUIRED,
                [BootstrapStep("SUPPORT", "RESTART_PASSENGER", execute_now=True)],
            )


class CompletionAndReadinessTests(unittest.TestCase):
    def test_completion_handoff_has_no_recurring_manual_server_admin(self):
        contract = completion_handoff_contract()
        self.assertFalse(contract["user_cpanel_required"])
        self.assertFalse(contract["user_terminal_required"])
        self.assertFalse(contract["recurring_manual_server_admin_required"])
        self.assertEqual(contract["restart_owner"], "SUPPORT_OR_AUTOMATION")
        self.assertEqual(contract["dependency_install_owner"], "SUPPORT_OR_AUTOMATION")
        self.assertFalse(contract["execute_now"])

    def test_source_readiness_never_claims_human_or_live_pass(self):
        result = operator_ux_readiness(
            auth_state=AUTH_NOT_YET_REQUIRED,
            setup_copy="Приватне налаштування. Серверні кроки виконує технічна підтримка.",
        )
        self.assertTrue(result["source_operator_copy_ready"])
        self.assertEqual(result["user_step_count"], 0)
        self.assertFalse(result["human_nvda_pass"])
        self.assertFalse(result["live_execution_authorized"])

    def test_manual_restart_copy_blocks_source_operator_copy_readiness(self):
        result = operator_ux_readiness(
            auth_state=AUTH_NOT_YET_REQUIRED,
            setup_copy="Натисніть Restart для Python App у cPanel.",
        )
        self.assertFalse(result["source_operator_copy_ready"])
        self.assertGreater(result["manual_admin_finding_count"], 0)
        self.assertFalse(result["human_nvda_pass"])


if __name__ == "__main__":
    unittest.main()
