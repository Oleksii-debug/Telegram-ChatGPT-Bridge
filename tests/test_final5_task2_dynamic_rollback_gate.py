from __future__ import annotations

import unittest

from ops.final5_task2_dynamic_rollback_gate import assess_approved_candidate_rollback_plan
from ops.finalwave37_rollback_state_compat import RollbackStateContractError


CURRENT_CANDIDATE = "f3e83a35c99d634ff775ee0b5a2a2cc368e1f1a1"
LIVE_PREVIOUS = "00684e834a523f55ea3b61c1a12cb9dc54cfd947"
OTHER_CANDIDATE = "7e061edb2ea2ce718b82d6d7c337ac8008eed4e4"
OTHER_PREVIOUS = "d81ab028059f7aeb1f79c744a800745022f7a23a"


class DynamicRollbackCandidateBindingTests(unittest.TestCase):
    def _decision(self, **overrides):
        values = dict(
            candidate_sha=CURRENT_CANDIDATE,
            approved_candidate_sha=CURRENT_CANDIDATE,
            rollback_target_sha=LIVE_PREVIOUS,
            observed_live_previous_sha=LIVE_PREVIOUS,
            compatibility_reference_sha=LIVE_PREVIOUS,
            target_specific_compatibility_proven=True,
            schema_change_declared=True,
            forced_smoke_passed=True,
            rollback_target_security_regression_cleared=True,
            independent_auditor_gate=False,
        )
        values.update(overrides)
        return assess_approved_candidate_rollback_plan(**values)

    def test_current_candidate_is_bound_to_explicit_exact_approval_not_stale_source_anchor(self):
        decision = self._decision()
        self.assertEqual("AUDITOR_GATE_REQUIRED", decision.action)
        self.assertFalse(decision.production_authorized)

    def test_candidate_different_from_exact_approval_fails_closed(self):
        decision = self._decision(candidate_sha=OTHER_CANDIDATE)
        self.assertEqual("BLOCKED_CANDIDATE_IDENTITY_MISMATCH", decision.action)
        self.assertFalse(decision.production_authorized)

    def test_malformed_approved_candidate_identity_is_rejected(self):
        with self.assertRaises(RollbackStateContractError):
            self._decision(approved_candidate_sha="not-a-sha")

    def test_security_regression_clearance_is_required_for_any_exact_target(self):
        decision = self._decision(
            rollback_target_sha=OTHER_PREVIOUS,
            observed_live_previous_sha=OTHER_PREVIOUS,
            compatibility_reference_sha=OTHER_PREVIOUS,
            rollback_target_security_regression_cleared=False,
        )
        self.assertEqual("BLOCKED_ROLLBACK_TARGET_SECURITY_REGRESSION", decision.action)
        self.assertFalse(decision.production_authorized)

    def test_live_previous_identity_still_must_match_requested_target(self):
        decision = self._decision(observed_live_previous_sha=OTHER_PREVIOUS)
        self.assertEqual("BLOCKED_LKG_IDENTITY_MISMATCH", decision.action)

    def test_all_nonlive_gates_never_authorize_production(self):
        decision = self._decision(independent_auditor_gate=True)
        self.assertEqual("LIVE_ROLLBACK_EVIDENCE_REQUIRED", decision.action)
        self.assertFalse(decision.production_authorized)

    def test_truthy_non_boolean_security_evidence_is_rejected(self):
        with self.assertRaises(RollbackStateContractError):
            self._decision(rollback_target_security_regression_cleared=1)


if __name__ == "__main__":
    unittest.main()
