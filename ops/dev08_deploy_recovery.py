# -*- coding: utf-8 -*-
"""DEV08 deterministic deployment crash-classification overlay.

This module does not execute a deployment and does not replace ``ops.deploy_release``.
It isolates one cross-transaction recovery invariant for canonical integration review:
a process can die after the active release symlink has atomically moved to the new
release but before the durable journal moves from ``BACKED_UP`` to ``SWITCHED``.

The active symlink is an inspectable local fact, unlike an uncertain remote side
effect.  If the durable journal is BACKED_UP, the committed approval marker still
exists, the runtime manifest still matches, and the exact candidate can be
re-verified through canonical provenance checks, recovery can deterministically
classify this as "switch happened, SWITCHED journal write was lost".  Every other
unexpected topology remains fail-closed/ambiguous.
"""
from __future__ import annotations

from dataclasses import dataclass


PRE_SWITCH_STATES = frozenset(
    {
        "MATERIALIZING",
        "MATERIALIZED",
        "READY_TO_COMMIT",
        "APPROVAL_COMMITTED",
        "QUIESCED",
        "BACKED_UP",
    }
)
POST_SWITCH_STATES = frozenset({"SWITCHED", "VERIFIED"})
TERMINAL_STATES = frozenset(
    {
        "PREAPPROVAL_ABORTED",
        "PRELIVE_RECOVERED",
        "DEPLOYED",
        "ROLLED_BACK",
        "APPROVAL_COMMIT_FAILED",
        "PRECOMMIT_FAILED",
        "CRITICAL_PRELIVE_RECOVERY_FAILED",
        "CRITICAL_ROLLBACK_FAILED",
        "CRITICAL_TRANSACTION_AMBIGUOUS",
    }
)
KNOWN_STATES = PRE_SWITCH_STATES | POST_SWITCH_STATES | TERMINAL_STATES
ACTIVE_ROLES = frozenset({"previous", "candidate", "other"})


@dataclass(frozen=True)
class DeploymentRecoveryDecision:
    action: str
    reason_code: str
    journal_transition: str | None = None


class DeploymentRecoveryClassificationError(ValueError):
    """Invalid classifier input; never represents deploy permission."""


def classify_deployment_recovery(
    *,
    journal_state: str,
    active_role: str,
    approval_marker_valid: bool,
    runtime_manifest_matches: bool,
    candidate_verified: bool,
    previous_release_available: bool,
) -> DeploymentRecoveryDecision:
    """Classify a durable deployment snapshot without mutating any state.

    ``active_role`` is the already validated active symlink target relative to the
    journal: ``previous``, ``candidate``, or ``other``.  Boolean evidence inputs are
    intentionally explicit; this helper never reads private files or approval data.

    ``RECOVER_AS_SWITCHED`` is deliberately narrow.  BACKED_UP proves the canonical
    engine durably completed both backups before attempting ``atomic_switch_link``.
    If active now resolves to the verified candidate, the observable local switch is
    complete and only the subsequent journal write may have been lost.  The caller
    must still perform the normal canonical SWITCHED recovery (restart, running SHA,
    unauth/auth smoke, resume) or rollback on failure.
    """
    if journal_state not in KNOWN_STATES:
        raise DeploymentRecoveryClassificationError("unknown journal state")
    if active_role not in ACTIVE_ROLES:
        raise DeploymentRecoveryClassificationError("unknown active release role")
    for value in (
        approval_marker_valid,
        runtime_manifest_matches,
        candidate_verified,
        previous_release_available,
    ):
        if type(value) is not bool:  # bool only; reject truthy strings/integers
            raise DeploymentRecoveryClassificationError("recovery evidence must be boolean")

    if journal_state in TERMINAL_STATES:
        return DeploymentRecoveryDecision("TERMINAL", "journal_already_terminal")

    if not runtime_manifest_matches:
        return DeploymentRecoveryDecision("AMBIGUOUS", "runtime_manifest_changed")

    if active_role == "other":
        return DeploymentRecoveryDecision("AMBIGUOUS", "active_target_mismatch")

    if journal_state in POST_SWITCH_STATES:
        if not approval_marker_valid:
            return DeploymentRecoveryDecision("AMBIGUOUS", "committed_marker_missing")
        if active_role == "candidate":
            if not candidate_verified:
                return DeploymentRecoveryDecision("ROLLBACK_REQUIRED", "candidate_reverification_failed")
            return DeploymentRecoveryDecision("RESUME_POST_SWITCH", "journal_and_active_candidate_agree")
        if not previous_release_available:
            return DeploymentRecoveryDecision("AMBIGUOUS", "previous_release_missing")
        return DeploymentRecoveryDecision("RECOVER_ROLLBACK", "previous_already_active")

    if active_role == "previous":
        if journal_state in {"APPROVAL_COMMITTED", "QUIESCED", "BACKED_UP"}:
            if not approval_marker_valid:
                return DeploymentRecoveryDecision("AMBIGUOUS", "committed_marker_missing")
            if not previous_release_available:
                return DeploymentRecoveryDecision("AMBIGUOUS", "previous_release_missing")
            return DeploymentRecoveryDecision("RECOVER_PRELIVE", "committed_before_switch")
        return DeploymentRecoveryDecision("ABORT_PREAPPROVAL", "switch_not_observed")

    # active_role == candidate while journal still claims a pre-switch state.
    # Only BACKED_UP can immediately precede the canonical atomic switch. Earlier
    # states plus candidate-active cannot be derived from the legal execution order.
    if journal_state != "BACKED_UP":
        return DeploymentRecoveryDecision("AMBIGUOUS", "candidate_active_before_backup_boundary")
    if not approval_marker_valid:
        return DeploymentRecoveryDecision("AMBIGUOUS", "committed_marker_missing")
    if not previous_release_available:
        return DeploymentRecoveryDecision("AMBIGUOUS", "previous_release_missing")
    if not candidate_verified:
        return DeploymentRecoveryDecision("ROLLBACK_REQUIRED", "candidate_reverification_failed")
    return DeploymentRecoveryDecision(
        "RECOVER_AS_SWITCHED",
        "atomic_switch_observed_before_switched_journal",
        journal_transition="SWITCHED",
    )


__all__ = [
    "DeploymentRecoveryClassificationError",
    "DeploymentRecoveryDecision",
    "classify_deployment_recovery",
]
