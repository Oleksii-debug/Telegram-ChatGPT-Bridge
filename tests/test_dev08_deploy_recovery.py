# -*- coding: utf-8 -*-
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from ops import deploy_release, release_guard
from ops.dev08_deploy_recovery import (
    DeploymentRecoveryClassificationError,
    classify_deployment_recovery,
)
from tests.test_audit_round9 import Round9Layout


def _journal(layout: Round9Layout) -> dict:
    return layout.journal()


class CanonicalDeploymentCrashBoundaryTests(unittest.TestCase):
    """Fault-inject exact canonical transaction boundaries without production I/O."""

    def test_oracle_post_switch_pre_journal_is_currently_escalated_to_ambiguous(self) -> None:
        """Current defect oracle: active candidate is observable but journal is BACKED_UP."""
        with tempfile.TemporaryDirectory() as td:
            layout = Round9Layout(Path(td))
            real_switch = deploy_release.atomic_switch_link

            def switch_then_die(active_link, final):  # type: ignore[no-untyped-def]
                previous = real_switch(active_link, final)
                self.assertEqual(final.resolve(), active_link.resolve())
                self.assertEqual("BACKED_UP", _journal(layout)["state"])
                raise SystemExit("synthetic process loss after atomic switch")

            with mock.patch.object(
                deploy_release, "verify_approved_ref_policy", return_value=layout.new_sha
            ), mock.patch.object(
                deploy_release, "atomic_switch_link", side_effect=switch_then_die
            ):
                with self.assertRaises(SystemExit):
                    deploy_release.execute_prepared_release(**layout.kwargs())

            self.assertEqual("BACKED_UP", _journal(layout)["state"])
            candidate = layout.releases / layout.new_sha
            self.assertEqual(candidate.resolve(), layout.active.resolve())
            self.assertTrue(next((layout.control / "consumed").glob("*.consumed.json"), None))

            # A fresh worker can inspect every local fact, but current canonical
            # reconciliation has no BACKED_UP + active==candidate branch and falls
            # through to CRITICAL_TRANSACTION_AMBIGUOUS.
            with mock.patch.object(
                deploy_release, "verify_approved_ref_policy", return_value=layout.new_sha
            ):
                with self.assertRaises(release_guard.SafetyError):
                    deploy_release.execute_prepared_release(**layout.kwargs())
            self.assertEqual("CRITICAL_TRANSACTION_AMBIGUOUS", _journal(layout)["state"])
            self.assertEqual(candidate.resolve(), layout.active.resolve())

    def test_approval_consumed_before_journal_commit_recovers_previous_release(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            layout = Round9Layout(Path(td))
            real_consume = deploy_release.consume_external_approval

            def consume_then_die(*args, **kwargs):  # type: ignore[no-untyped-def]
                result = real_consume(*args, **kwargs)
                raise SystemExit("synthetic process loss after approval consumption")

            with mock.patch.object(
                deploy_release, "verify_approved_ref_policy", return_value=layout.new_sha
            ), mock.patch.object(
                deploy_release, "consume_external_approval", side_effect=consume_then_die
            ):
                with self.assertRaises(SystemExit):
                    deploy_release.execute_prepared_release(**layout.kwargs())

            self.assertEqual("READY_TO_COMMIT", _journal(layout)["state"])
            self.assertEqual(layout.old.resolve(), layout.active.resolve())
            with mock.patch.object(
                deploy_release, "verify_approved_ref_policy", return_value=layout.new_sha
            ):
                with self.assertRaises(release_guard.SafetyError):
                    deploy_release.execute_prepared_release(**layout.kwargs())
            self.assertEqual("PRELIVE_RECOVERED", _journal(layout)["state"])
            self.assertEqual(layout.old.resolve(), layout.active.resolve())

    def test_quiesce_completed_before_journal_transition_recovers_previous_release(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            layout = Round9Layout(Path(td))
            real_hook = deploy_release.run_private_hook

            def hook_then_die(path, name, **kwargs):  # type: ignore[no-untyped-def]
                result = real_hook(path, name, **kwargs)
                if name == "quiesce":
                    raise SystemExit("synthetic process loss after quiesce")
                return result

            with mock.patch.object(
                deploy_release, "verify_approved_ref_policy", return_value=layout.new_sha
            ), mock.patch.object(deploy_release, "run_private_hook", side_effect=hook_then_die):
                with self.assertRaises(SystemExit):
                    deploy_release.execute_prepared_release(**layout.kwargs())

            self.assertEqual("APPROVAL_COMMITTED", _journal(layout)["state"])
            self.assertEqual(layout.old.resolve(), layout.active.resolve())
            with mock.patch.object(
                deploy_release, "verify_approved_ref_policy", return_value=layout.new_sha
            ):
                with self.assertRaises(release_guard.SafetyError):
                    deploy_release.execute_prepared_release(**layout.kwargs())
            self.assertEqual("PRELIVE_RECOVERED", _journal(layout)["state"])

    def test_post_switch_classifier_narrowly_recovers_only_backed_up_candidate(self) -> None:
        decision = classify_deployment_recovery(
            journal_state="BACKED_UP",
            active_role="candidate",
            approval_marker_valid=True,
            runtime_manifest_matches=True,
            candidate_verified=True,
            previous_release_available=True,
        )
        self.assertEqual("RECOVER_AS_SWITCHED", decision.action)
        self.assertEqual("SWITCHED", decision.journal_transition)
        self.assertEqual("atomic_switch_observed_before_switched_journal", decision.reason_code)


class DeploymentRecoveryClassifierAdversarialTests(unittest.TestCase):
    def classify(self, **overrides):  # type: ignore[no-untyped-def]
        values = dict(
            journal_state="BACKED_UP",
            active_role="candidate",
            approval_marker_valid=True,
            runtime_manifest_matches=True,
            candidate_verified=True,
            previous_release_available=True,
        )
        values.update(overrides)
        return classify_deployment_recovery(**values)

    def test_candidate_active_in_earlier_state_is_ambiguous(self) -> None:
        for state in ("MATERIALIZING", "MATERIALIZED", "READY_TO_COMMIT", "APPROVAL_COMMITTED", "QUIESCED"):
            with self.subTest(state=state):
                self.assertEqual("AMBIGUOUS", self.classify(journal_state=state).action)

    def test_backed_up_candidate_requires_committed_marker(self) -> None:
        decision = self.classify(approval_marker_valid=False)
        self.assertEqual("AMBIGUOUS", decision.action)
        self.assertEqual("committed_marker_missing", decision.reason_code)

    def test_backed_up_candidate_requires_runtime_manifest_match(self) -> None:
        decision = self.classify(runtime_manifest_matches=False)
        self.assertEqual("AMBIGUOUS", decision.action)
        self.assertEqual("runtime_manifest_changed", decision.reason_code)

    def test_backed_up_candidate_failed_reverification_requires_rollback(self) -> None:
        decision = self.classify(candidate_verified=False)
        self.assertEqual("ROLLBACK_REQUIRED", decision.action)
        self.assertEqual("candidate_reverification_failed", decision.reason_code)

    def test_backed_up_candidate_requires_previous_release_for_safe_rollback_path(self) -> None:
        decision = self.classify(previous_release_available=False)
        self.assertEqual("AMBIGUOUS", decision.action)
        self.assertEqual("previous_release_missing", decision.reason_code)

    def test_unrelated_active_target_is_always_ambiguous(self) -> None:
        decision = self.classify(active_role="other")
        self.assertEqual("AMBIGUOUS", decision.action)
        self.assertEqual("active_target_mismatch", decision.reason_code)

    def test_post_switch_candidate_preserves_normal_resume_semantics(self) -> None:
        for state in ("SWITCHED", "VERIFIED"):
            with self.subTest(state=state):
                decision = self.classify(journal_state=state)
                self.assertEqual("RESUME_POST_SWITCH", decision.action)

    def test_post_switch_previous_preserves_rollback_recovery_semantics(self) -> None:
        for state in ("SWITCHED", "VERIFIED"):
            with self.subTest(state=state):
                decision = self.classify(journal_state=state, active_role="previous")
                self.assertEqual("RECOVER_ROLLBACK", decision.action)

    def test_preapproval_previous_aborts_without_claiming_external_effect(self) -> None:
        for state in ("MATERIALIZING", "MATERIALIZED", "READY_TO_COMMIT"):
            with self.subTest(state=state):
                decision = self.classify(
                    journal_state=state,
                    active_role="previous",
                    approval_marker_valid=False,
                )
                self.assertEqual("ABORT_PREAPPROVAL", decision.action)

    def test_committed_pre_switch_previous_requires_recovery(self) -> None:
        for state in ("APPROVAL_COMMITTED", "QUIESCED", "BACKED_UP"):
            with self.subTest(state=state):
                decision = self.classify(journal_state=state, active_role="previous")
                self.assertEqual("RECOVER_PRELIVE", decision.action)

    def test_terminal_state_is_not_reopened(self) -> None:
        for state in ("DEPLOYED", "ROLLED_BACK", "CRITICAL_TRANSACTION_AMBIGUOUS"):
            with self.subTest(state=state):
                decision = self.classify(journal_state=state)
                self.assertEqual("TERMINAL", decision.action)
                self.assertIsNone(decision.journal_transition)

    def test_unknown_or_non_boolean_inputs_fail_closed(self) -> None:
        with self.assertRaises(DeploymentRecoveryClassificationError):
            self.classify(journal_state="NOT_A_STATE")
        with self.assertRaises(DeploymentRecoveryClassificationError):
            self.classify(active_role="mystery")
        with self.assertRaises(DeploymentRecoveryClassificationError):
            self.classify(candidate_verified=1)


if __name__ == "__main__":
    unittest.main()
