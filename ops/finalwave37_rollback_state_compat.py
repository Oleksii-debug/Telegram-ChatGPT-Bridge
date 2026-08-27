# -*- coding: utf-8 -*-
"""FINALWAVE-37 rollback / persistent-state compatibility contract.

This module is deliberately non-deploying and non-authorizing.  It records the
state that a code rollback must preserve and classifies exact-SHA rollback plans
without reading credentials, Telegram content, or private runtime values.

The compatibility reference below is source evidence only.  It is NOT asserted
to be the production last-known-good release.  A real rollback target must be
resolved from private live deployment evidence and independently gated.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable


# Historical evidence anchor only. It must never be used as the current
# candidate identity. Current rollback adjudication requires an explicit,
# independently approved candidate SHA supplied to the decision function.
CANDIDATE_ANCHOR_SHA = "84691967e5363bc4b88dfae97371d7bf329c105d"
PREDECESSOR_EVIDENCE_SHA = "00684e834a523f55ea3b61c1a12cb9dc54cfd947"
FULL_SHA_RE = re.compile(r"^[0-9a-f]{40}$")


class RollbackStateContractError(ValueError):
    """Invalid or unsafe rollback-plan evidence."""


@dataclass(frozen=True)
class CompatibilityArea:
    domain: str
    location: str
    state_kind: str
    candidate_change: str
    predecessor_basis: str
    rollback_action: str
    loss_risk: str
    forced_smoke: str


@dataclass(frozen=True)
class RollbackPlanDecision:
    action: str
    reason_code: str
    production_authorized: bool = False


# All application-owned persistent state is preserved by ordinary code rollback.
# Targeted data restoration is a separate audited migration operation, never an
# implicit consequence of switching the active release symlink.
COMPATIBILITY_MATRIX = (
    CompatibilityArea(
        domain="files",
        location="state/files.sqlite3 + files/",
        state_kind="sqlite-wal + private payloads",
        candidate_change="files table adds nullable origin_key plus unique partial index",
        predecessor_basis="exact predecessor storage code must open/write the migrated DB",
        rollback_action="PRESERVE_CURRENT",
        loss_risk="registry/payload divergence or loss of download dedupe identity",
        forced_smoke="predecessor_file_store_open_write_after_candidate_migration",
    ),
    CompatibilityArea(
        domain="downloads",
        location="state/downloads.sqlite3 + tmp/downloads/",
        state_kind="sqlite-wal + resumable staging",
        candidate_change="checkpoint payload schema remains schema=1",
        predecessor_basis="predecessor CheckpointStore must load/save candidate-created checkpoint",
        rollback_action="PRESERVE_CURRENT",
        loss_risk="lost resume progress, duplicate backend download, or orphaned private staging",
        forced_smoke="predecessor_checkpoint_load_save_candidate_job",
    ),
    CompatibilityArea(
        domain="writes",
        location="state/writes.sqlite3",
        state_kind="sqlite-wal idempotency transaction state",
        candidate_change="meta schema_version=1; RESERVED/CALLING/COMMITTED/FAILED_SAFE/AMBIGUOUS knowledge",
        predecessor_basis="write_safety source identity plus reopen/no-resend oracle",
        rollback_action="PRESERVE_CURRENT",
        loss_risk="restoring older state can erase COMMITTED/AMBIGUOUS knowledge and duplicate Telegram effects",
        forced_smoke="ambiguous_write_reopen_rejects_retry",
    ),
    CompatibilityArea(
        domain="rate",
        location="state/rate_limit.sqlite3",
        state_kind="sqlite-wal quota + monotonic high-water clock",
        candidate_change="fixed-window quota/high-water schema unchanged at evidence predecessor",
        predecessor_basis="runtime source identity plus backward-clock/high-water oracle",
        rollback_action="PRESERVE_CURRENT",
        loss_risk="restoring older quota/high-water state can weaken abuse protection or reset consumed quota",
        forced_smoke="preserved_high_water_rejects_clock_regression",
    ),
    CompatibilityArea(
        domain="reliability",
        location="private deployment transaction journal + shared persistent roots",
        state_kind="durable control-plane recovery state",
        candidate_change="code rollback restores release identity but intentionally does not rewind shared state",
        predecessor_basis="forced failed-smoke rollback must reverify previous SHA while retaining candidate-mutated shared state",
        rollback_action="PRESERVE_CURRENT",
        loss_risk="rewinding state can resurrect already-consumed side effects or erase recovery evidence",
        forced_smoke="failed_candidate_smoke_rolls_code_back_without_state_restore",
    ),
    CompatibilityArea(
        domain="session",
        location="server-side Telegram session/private config references",
        state_kind="opaque critical secret state",
        candidate_change="deployment must not rewrite session/private configuration",
        predecessor_basis="session-lock source identity; live secret value is never copied into evidence",
        rollback_action="PRESERVE_CURRENT",
        loss_risk="session loss, credential exposure, or competing client corruption",
        forced_smoke="session_state_untouched_and_lock_contract_unchanged",
    ),
    CompatibilityArea(
        domain="audit",
        location="private append-only metadata audit sink",
        state_kind="append-only file",
        candidate_change="hardened nofollow/owner/mode/fsync writer retains line-oriented metadata format",
        predecessor_basis="predecessor writer can append to candidate-created stream, but weaker topology security blocks treating evidence SHA as production LKG",
        rollback_action="PRESERVE_CURRENT",
        loss_risk="truncation/restore erases security evidence; old writer may weaken topology guarantees",
        forced_smoke="append_compatibility_plus_security_regression_gate",
    ),
)

_REQUIRED_DOMAINS = {"files", "downloads", "writes", "rate", "reliability", "session", "audit"}
_CRITICAL_NO_RESTORE = {"writes", "rate", "reliability", "session", "audit"}
_BROAD_RESTORE_ALIASES = {"state", "state/", "private", "private_tree", "persistent_root", "all"}


def matrix_by_domain() -> dict[str, CompatibilityArea]:
    return {area.domain: area for area in COMPATIBILITY_MATRIX}


def validate_matrix() -> None:
    matrix = matrix_by_domain()
    if set(matrix) != _REQUIRED_DOMAINS or len(matrix) != len(COMPATIBILITY_MATRIX):
        raise RollbackStateContractError("rollback matrix domains are incomplete or duplicated")
    for area in matrix.values():
        if area.rollback_action != "PRESERVE_CURRENT":
            raise RollbackStateContractError("ordinary code rollback must preserve current shared state")
        if not area.location or not area.predecessor_basis or not area.forced_smoke:
            raise RollbackStateContractError("rollback matrix evidence is incomplete")


def classify_restore_request(domains: Iterable[str]) -> RollbackPlanDecision:
    requested = tuple(domains)
    if not requested or any(not isinstance(item, str) or not item for item in requested):
        raise RollbackStateContractError("restore domains must be non-empty strings")
    normalized = {item.strip().lower() for item in requested}
    if normalized & _BROAD_RESTORE_ALIASES:
        return RollbackPlanDecision(
            "BLOCKED_UNSAFE_BROAD_STATE_RESTORE",
            "broad_private_state_restore_can_erase_idempotency_quota_session_or_audit_knowledge",
        )
    if normalized & _CRITICAL_NO_RESTORE:
        return RollbackPlanDecision(
            "BLOCKED_UNSAFE_CRITICAL_STATE_RESTORE",
            "writes_rate_reliability_session_and_audit_are_preserve_only_on_code_rollback",
        )
    if normalized - _REQUIRED_DOMAINS:
        return RollbackPlanDecision("BLOCKED_UNKNOWN_STATE_DOMAIN", "restore_domain_not_in_audited_matrix")
    return RollbackPlanDecision(
        "TARGETED_RESTORE_REQUIRES_SEPARATE_AUDIT",
        "files_or_download_state_restore_is_not_part_of_ordinary_code_rollback",
    )


def assess_exact_sha_rollback_plan(
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
    """Fail closed until exact candidate, live predecessor and state contract are proven.

    ``approved_candidate_sha`` must come from the independent source/release gate,
    not from a mutable module constant or caller-selected label. This function
    still never authorizes production: live rollback evidence remains external.
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
    for value in (candidate_sha, approved_candidate_sha, rollback_target_sha, compatibility_reference_sha):
        if not isinstance(value, str) or not FULL_SHA_RE.fullmatch(value):
            raise RollbackStateContractError("candidate/approved/rollback/reference identities must be exact full Git SHAs")
    if candidate_sha != approved_candidate_sha:
        return RollbackPlanDecision(
            "BLOCKED_CANDIDATE_IDENTITY_MISMATCH",
            "plan_candidate_does_not_match_independently_approved_candidate",
        )
    if observed_live_previous_sha is None:
        return RollbackPlanDecision("BLOCKED_LKG_IDENTITY_REQUIRED", "live_last_known_good_sha_not_observed")
    if not isinstance(observed_live_previous_sha, str) or not FULL_SHA_RE.fullmatch(observed_live_previous_sha):
        raise RollbackStateContractError("observed live previous identity must be an exact full Git SHA")
    if rollback_target_sha != observed_live_previous_sha:
        return RollbackPlanDecision("BLOCKED_LKG_IDENTITY_MISMATCH", "requested_rollback_target_is_not_observed_live_previous_sha")
    if compatibility_reference_sha != rollback_target_sha and not target_specific_compatibility_proven:
        return RollbackPlanDecision(
            "BLOCKED_TARGET_SPECIFIC_COMPATIBILITY_REQUIRED",
            "compatibility_reference_does_not_prove_the_actual_live_rollback_target",
        )
    if not schema_change_declared:
        return RollbackPlanDecision(
            "BLOCKED_SCHEMA_DECLARATION_REQUIRED",
            "candidate_files_schema_migration_must_not_be_described_as_no_data_schema_change",
        )
    if not target_specific_compatibility_proven:
        return RollbackPlanDecision(
            "BLOCKED_ROLLBACK_COMPATIBILITY_REQUIRED",
            "actual_rollback_target_must_run_against_candidate_mutated_shared_state",
        )
    if not forced_smoke_passed:
        return RollbackPlanDecision("BLOCKED_FORCED_SMOKE_REQUIRED", "rollback_forced_smoke_matrix_not_proven")
    if not rollback_target_security_regression_cleared:
        return RollbackPlanDecision(
            "BLOCKED_ROLLBACK_TARGET_SECURITY_REGRESSION",
            "actual_rollback_target_must_clear_current_security_regression_gate",
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


validate_matrix()


__all__ = [
    "CANDIDATE_ANCHOR_SHA",
    "PREDECESSOR_EVIDENCE_SHA",
    "COMPATIBILITY_MATRIX",
    "CompatibilityArea",
    "RollbackPlanDecision",
    "RollbackStateContractError",
    "assess_exact_sha_rollback_plan",
    "classify_restore_request",
    "matrix_by_domain",
    "validate_matrix",
]
