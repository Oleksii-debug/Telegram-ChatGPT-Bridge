# -*- coding: utf-8 -*-
"""Fail-closed prototype for dynamic exact-SHA rollback candidate binding.

Specialist-only evidence module.  It deliberately does not deploy, authorize a
rollback, or inspect live/private state.  Canonical integration should adapt the
semantics into the authoritative rollback contract rather than merge this file
as a second production authority.
"""
from __future__ import annotations

from ops.finalwave37_rollback_state_compat import (
    FULL_SHA_RE,
    RollbackPlanDecision,
    RollbackStateContractError,
)


def _require_exact_sha(value: object, label: str) -> str:
    if not isinstance(value, str) or not FULL_SHA_RE.fullmatch(value):
        raise RollbackStateContractError(f"{label} must be an exact full Git SHA")
    return value


def assess_approved_candidate_rollback_plan(
    *,
    candidate_sha: str,
    approved_candidate_sha: str,
    rollback_target_sha: str,
    observed_live_previous_sha: str | None,
    compatibility_reference_sha: str,
    target_specific_compatibility_proven: bool,
    schema_change_declared: bool,
    forced_smoke_passed: bool,
    rollback_target_security_regression_cleared: bool,
    independent_auditor_gate: bool,
) -> RollbackPlanDecision:
    """Classify a rollback plan without a stale compile-time candidate anchor.

    ``approved_candidate_sha`` is evidence supplied by the same release-gate
    invocation as ``candidate_sha``.  Exact equality is mandatory.  This keeps
    candidate identity fail-closed while allowing a new frozen canonical SHA to
    be assessed without editing a source constant on every release candidate.

    Security-regression clearance is required for *every* rollback target, not
    only for one historical evidence predecessor.
    """

    bools = (
        target_specific_compatibility_proven,
        schema_change_declared,
        forced_smoke_passed,
        rollback_target_security_regression_cleared,
        independent_auditor_gate,
    )
    if any(type(value) is not bool for value in bools):
        raise RollbackStateContractError("rollback evidence flags must be booleans")

    candidate_sha = _require_exact_sha(candidate_sha, "candidate identity")
    approved_candidate_sha = _require_exact_sha(
        approved_candidate_sha, "approved candidate identity"
    )
    rollback_target_sha = _require_exact_sha(rollback_target_sha, "rollback target identity")
    compatibility_reference_sha = _require_exact_sha(
        compatibility_reference_sha, "compatibility reference identity"
    )

    if candidate_sha != approved_candidate_sha:
        return RollbackPlanDecision(
            "BLOCKED_CANDIDATE_IDENTITY_MISMATCH",
            "candidate_sha_does_not_match_exact_approved_candidate_sha",
        )
    if observed_live_previous_sha is None:
        return RollbackPlanDecision(
            "BLOCKED_LKG_IDENTITY_REQUIRED",
            "live_last_known_good_sha_not_observed",
        )
    observed_live_previous_sha = _require_exact_sha(
        observed_live_previous_sha, "observed live previous identity"
    )
    if rollback_target_sha != observed_live_previous_sha:
        return RollbackPlanDecision(
            "BLOCKED_LKG_IDENTITY_MISMATCH",
            "requested_rollback_target_is_not_observed_live_previous_sha",
        )
    if compatibility_reference_sha != rollback_target_sha and not target_specific_compatibility_proven:
        return RollbackPlanDecision(
            "BLOCKED_TARGET_SPECIFIC_COMPATIBILITY_REQUIRED",
            "compatibility_reference_does_not_prove_the_actual_live_rollback_target",
        )
    if not schema_change_declared:
        return RollbackPlanDecision(
            "BLOCKED_SCHEMA_DECLARATION_REQUIRED",
            "candidate_schema_change_declaration_missing",
        )
    if not target_specific_compatibility_proven:
        return RollbackPlanDecision(
            "BLOCKED_ROLLBACK_COMPATIBILITY_REQUIRED",
            "actual_rollback_target_must_run_against_candidate_mutated_shared_state",
        )
    if not forced_smoke_passed:
        return RollbackPlanDecision(
            "BLOCKED_FORCED_SMOKE_REQUIRED",
            "rollback_forced_smoke_matrix_not_proven",
        )
    if not rollback_target_security_regression_cleared:
        return RollbackPlanDecision(
            "BLOCKED_ROLLBACK_TARGET_SECURITY_REGRESSION",
            "exact_rollback_target_security_regression_not_cleared",
        )
    if not independent_auditor_gate:
        return RollbackPlanDecision(
            "AUDITOR_GATE_REQUIRED",
            "exact_sha_state_compatibility_complete_but_independent_gate_missing",
        )
    return RollbackPlanDecision(
        "LIVE_ROLLBACK_EVIDENCE_REQUIRED",
        "auditor_gate_is_not_a_substitute_for_live_backup_restart_smoke_and_rollback_evidence",
    )


__all__ = ["assess_approved_candidate_rollback_plan"]
