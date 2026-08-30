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

import hashlib
import json
import os
import re
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping


CANDIDATE_ANCHOR_SHA = "84691967e5363bc4b88dfae97371d7bf329c105d"
PREDECESSOR_EVIDENCE_SHA = "00684e834a523f55ea3b61c1a12cb9dc54cfd947"
FULL_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_SOURCE_BINDING_KEYS = {
    "schema_version",
    "identity_source",
    "candidate_sha",
    "source_tree_sha",
    "source_tree_listing_sha256",
    "source_gate_status",
    "production_authorized",
    "private_values_recorded",
    "source_binding_sha256",
}


class RollbackStateContractError(ValueError):
    """Invalid or unsafe rollback-plan evidence."""


def _run_git(root: Path, *args: str, text: bool = True) -> str | bytes:
    try:
        completed = subprocess.run(
            ["git", *args],
            cwd=root,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=text,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        raise RollbackStateContractError("source checkout Git unavailable") from None
    if completed.returncode != 0:
        raise RollbackStateContractError("source checkout Git unavailable")
    return completed.stdout


def _execution_root() -> Path:
    try:
        raw = Path(__file__).absolute()
        resolved = raw.resolve(strict=True)
    except OSError:
        raise RollbackStateContractError("source checkout execution root unsafe") from None
    if raw != resolved or not stat.S_ISREG(resolved.stat().st_mode):
        raise RollbackStateContractError("source checkout execution root unsafe")
    return resolved.parents[1]


def _source_root(source_checkout: str | os.PathLike[str] | Path) -> Path:
    try:
        absolute = Path(os.path.abspath(os.fspath(source_checkout)))
        info = absolute.lstat()
        root = absolute.resolve(strict=True)
    except (OSError, TypeError, ValueError):
        raise RollbackStateContractError("source checkout unsafe") from None
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or root != absolute:
        raise RollbackStateContractError("source checkout unsafe")
    top = str(_run_git(root, "rev-parse", "--show-toplevel")).strip()
    try:
        top_root = Path(top).resolve(strict=True)
    except OSError:
        raise RollbackStateContractError("source checkout unsafe") from None
    if top_root != root:
        raise RollbackStateContractError("source checkout is not repository root")
    if root != _execution_root():
        raise RollbackStateContractError("source checkout execution root mismatch")
    return root


def _require_clean_worktree(root: Path) -> None:
    """Reject tracked, staged, and non-ignored untracked checkout influence."""
    status = _run_git(
        root,
        "status",
        "--porcelain=v1",
        "-z",
        "--untracked-files=all",
        text=False,
    )
    if not isinstance(status, bytes):
        raise RollbackStateContractError("source checkout identity invalid")
    if status:
        raise RollbackStateContractError("source checkout worktree dirty")


def _read_source_identity(root: Path) -> tuple[str, str, str]:
    candidate_sha = str(_run_git(root, "rev-parse", "--verify", "HEAD^{commit}")).strip()
    source_tree_sha = str(_run_git(root, "rev-parse", "--verify", "HEAD^{tree}")).strip()
    listing = _run_git(root, "ls-tree", "-r", "-z", "--full-tree", "HEAD", text=False)
    if (
        not isinstance(listing, bytes)
        or not listing
        or FULL_SHA_RE.fullmatch(candidate_sha) is None
        or FULL_SHA_RE.fullmatch(source_tree_sha) is None
    ):
        raise RollbackStateContractError("source checkout identity invalid")
    return candidate_sha, source_tree_sha, hashlib.sha256(listing).hexdigest()


def _canonical_json_sha256(payload: Mapping[str, Any]) -> str:
    try:
        encoded = json.dumps(
            dict(payload), sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError):
        raise RollbackStateContractError("source binding invalid") from None
    return hashlib.sha256(encoded).hexdigest()


def derive_source_checkout_binding(
    source_checkout: str | os.PathLike[str] | Path,
) -> dict[str, Any]:
    """Derive candidate identity only from this module's clean executing checkout."""
    root = _source_root(source_checkout)
    _require_clean_worktree(root)
    first = _read_source_identity(root)
    _require_clean_worktree(root)
    second = _read_source_identity(root)
    _require_clean_worktree(root)
    if first != second:
        raise RollbackStateContractError("source checkout changed during binding")
    candidate_sha, tree_sha, listing_sha256 = second
    base = {
        "schema_version": 1,
        "identity_source": "EXACT_EXECUTING_GIT_CHECKOUT",
        "candidate_sha": candidate_sha,
        "source_tree_sha": tree_sha,
        "source_tree_listing_sha256": listing_sha256,
        "source_gate_status": "IDENTITY_ONLY_INDEPENDENT_GATE_REQUIRED",
        "production_authorized": False,
        "private_values_recorded": False,
    }
    return {**base, "source_binding_sha256": _canonical_json_sha256(base)}


def validate_source_gate_binding(
    binding: Mapping[str, Any],
    source_checkout: str | os.PathLike[str] | Path,
) -> dict[str, Any]:
    """Require a sealed binding to equal the re-derived exact checkout identity."""
    expected = derive_source_checkout_binding(source_checkout)
    if (
        not isinstance(binding, Mapping)
        or set(binding) != _SOURCE_BINDING_KEYS
        or not isinstance(binding.get("source_binding_sha256"), str)
        or SHA256_RE.fullmatch(str(binding.get("source_binding_sha256"))) is None
        or dict(binding) != expected
    ):
        raise RollbackStateContractError("source gate binding mismatch")
    return expected


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
    source_checkout: str | os.PathLike[str] | Path,
    source_gate_binding: Mapping[str, Any],
    rollback_target_sha: str,
    observed_live_previous_sha: str | None,
    compatibility_reference_sha: str,
    target_specific_compatibility_proven: bool,
    schema_change_declared: bool,
    forced_smoke_passed: bool,
    rollback_target_security_regression_cleared: bool,
    independent_auditor_gate: bool,
) -> RollbackPlanDecision:
    """Fail closed until exact source, live predecessor and state are proven.

    Candidate identity is output derived from the same clean checkout that runs
    this module.  ``source_gate_binding`` must exactly match that derivation; it
    is identity evidence, not self-approval.  Independent Auditor approval and
    live deployment evidence remain external gates.
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
    validate_source_gate_binding(source_gate_binding, source_checkout)
    for value in (rollback_target_sha, compatibility_reference_sha):
        if not isinstance(value, str) or not FULL_SHA_RE.fullmatch(value):
            raise RollbackStateContractError("rollback/reference identities must be exact full Git SHAs")
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
    "derive_source_checkout_binding",
    "matrix_by_domain",
    "validate_source_gate_binding",
    "validate_matrix",
]
