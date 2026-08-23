# -*- coding: utf-8 -*-
"""DEV08 persistent-state migration / rollback compatibility contract.

This module is intentionally non-deploying and non-authorizing. It describes
the persistent state touched by the canonical runtime and supplies fail-closed
classification helpers for a later canonical integration. It never reads
credentials or private Telegram content.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class StateMigrationDecision:
    action: str
    reason_code: str
    production_authorized: bool = False


@dataclass(frozen=True)
class PersistentStateArea:
    name: str
    location: str
    medium: str
    startup_behavior: str
    version_contract: str
    rollback_rule: str
    sensitivity: str


class StateMigrationContractError(ValueError):
    """Invalid evidence input; never a deployment authorization."""


# Exact current canonical state classes at anchor 2480d74b...
#
# rollback_rule is deliberately conservative. In particular, restoring the
# write/idempotency store can erase knowledge of an already-started external
# Telegram side effect, and restoring the rate-limit clock/quota can weaken
# abuse protection. Telegram session/config and append-only audit evidence are
# never candidates for a blind whole-tree restore.
PERSISTENT_STATE_INVENTORY = (
    PersistentStateArea(
        "file_registry",
        "state/files.sqlite3",
        "sqlite-wal",
        "create_if_absent_and_add_nullable_origin_key_plus_unique_partial_index",
        "implicit-files-v1-to-v2-no-explicit-user_version",
        "prefer_old_code_compatibility; otherwise targeted audited SQLite restore",
        "private-metadata",
    ),
    PersistentStateArea(
        "download_checkpoints",
        "state/downloads.sqlite3",
        "sqlite-wal",
        "create_if_absent; rows carry payload schema=1",
        "payload-schema-v1; database-schema-implicit",
        "preserve by default; targeted migration only if a future DB/payload schema changes",
        "private-metadata",
    ),
    PersistentStateArea(
        "write_idempotency",
        "state/writes.sqlite3",
        "sqlite-wal",
        "create_if_absent; meta schema_version initialized/validated",
        "meta-schema-version-1-fail-closed",
        "preserve across code rollback; never blind-restore because duplicate-send knowledge may be lost",
        "critical-private-transaction-state",
    ),
    PersistentStateArea(
        "rate_limit",
        "state/rate_limit.sqlite3",
        "sqlite-wal",
        "create_if_absent; fixed-window quota and monotonic clock tables",
        "database-schema-implicit",
        "preserve across code rollback unless a separately audited migration requires otherwise",
        "private-security-state",
    ),
    PersistentStateArea(
        "private_files",
        "files/",
        "filesystem",
        "application-managed file payloads referenced by file_registry",
        "content-addressed-by-recorded-size-and-sha256",
        "preserve; restore only selected artifacts with registry-consistency proof",
        "private-telegram-derived-content",
    ),
    PersistentStateArea(
        "download_staging",
        "tmp/downloads/",
        "filesystem",
        "recoverable staging used with download checkpoints",
        "no-schema",
        "normally preserve/clean by job protocol; not a reason to restore unrelated private state",
        "private-temporary-content",
    ),
    PersistentStateArea(
        "archive_staging",
        "tmp/archives/",
        "filesystem",
        "recoverable generated archive staging",
        "no-schema",
        "normally preserve/clean by archive protocol",
        "private-temporary-content",
    ),
    PersistentStateArea(
        "telegram_session_and_private_config",
        "server environment and protected *.session/private_config/config references",
        "opaque-secret",
        "runtime consumes existing private references; deployment must not rewrite them",
        "externally-managed-secret-state",
        "preserve exactly; never restore from a generic public/code rollback and never copy values to evidence",
        "critical-secret",
    ),
    PersistentStateArea(
        "audit_evidence",
        "optional private metadata audit sink",
        "append-only-file",
        "append and fsync metadata-only events when configured",
        "append-only-event-stream",
        "never roll back merely because code rolls back; erasing evidence is unsafe",
        "private-security-evidence",
    ),
)


def inventory_by_name() -> dict[str, PersistentStateArea]:
    return {area.name: area for area in PERSISTENT_STATE_INVENTORY}


def assess_state_migration(
    *,
    runtime_schema_changed: bool,
    approval_allows_schema_change: bool,
    rollback_restores_persistent_state: bool,
    backward_compatibility_proven: bool,
) -> StateMigrationDecision:
    """Classify a candidate's persistent-state migration boundary.

    This preserves the original R4 four-boolean interface for current callers.
    A declared schema change is not itself authorization: the result remains
    non-authorizing until an exact-SHA audited migration-plan path is integrated
    by the canonical owner.
    """
    values = (
        runtime_schema_changed,
        approval_allows_schema_change,
        rollback_restores_persistent_state,
        backward_compatibility_proven,
    )
    if any(type(value) is not bool for value in values):
        raise StateMigrationContractError("migration evidence must be boolean")

    if not runtime_schema_changed:
        return StateMigrationDecision("NO_SCHEMA_MIGRATION", "runtime_schema_unchanged")

    if not approval_allows_schema_change:
        return StateMigrationDecision(
            "BLOCKED_MIGRATION_PLAN_REQUIRED",
            "runtime_schema_change_not_authorized",
        )

    if not rollback_restores_persistent_state and not backward_compatibility_proven:
        return StateMigrationDecision(
            "BLOCKED_ROLLBACK_COMPATIBILITY_REQUIRED",
            "code_rollback_reuses_migrated_state_without_compatibility_proof",
        )

    if rollback_restores_persistent_state:
        return StateMigrationDecision(
            "AUDITED_MIGRATION_PATH_REQUIRED",
            "state_restore_path_available_but_requires_independent_audit",
        )

    return StateMigrationDecision(
        "AUDITED_MIGRATION_PATH_REQUIRED",
        "backward_compatibility_proven_but_migration_still_requires_independent_audit",
    )


def assess_audited_plan_boundary(
    *,
    runtime_schema_changed: bool,
    approval_declares_schema_change: bool,
    exact_sha_plan_bound: bool,
    backward_compatibility_proven: bool,
    targeted_restore_defined: bool,
    sqlite_snapshot_consistency_proven: bool,
    blind_private_tree_restore_requested: bool,
) -> StateMigrationDecision:
    """Fail-closed checklist for a future canonical audited migration path.

    It intentionally never returns production_authorized=True. Independent
    Auditor approval and canonical deployment wiring remain separate gates.
    """
    values = (
        runtime_schema_changed,
        approval_declares_schema_change,
        exact_sha_plan_bound,
        backward_compatibility_proven,
        targeted_restore_defined,
        sqlite_snapshot_consistency_proven,
        blind_private_tree_restore_requested,
    )
    if any(type(value) is not bool for value in values):
        raise StateMigrationContractError("audited plan evidence must be boolean")

    if blind_private_tree_restore_requested:
        return StateMigrationDecision(
            "BLOCKED_UNSAFE_PRIVATE_TREE_RESTORE",
            "whole_private_tree_restore_would_risk_session_idempotency_rate_limit_or_audit_state",
        )
    if not runtime_schema_changed:
        if approval_declares_schema_change:
            return StateMigrationDecision(
                "BLOCKED_APPROVAL_STATE_MISMATCH",
                "approval_declares_schema_change_but_runtime_contract_says_unchanged",
            )
        return StateMigrationDecision("NO_SCHEMA_MIGRATION", "runtime_schema_unchanged")
    if not approval_declares_schema_change:
        return StateMigrationDecision(
            "BLOCKED_APPROVAL_STATE_MISMATCH",
            "runtime_schema_change_must_not_use_data_schema_change_false",
        )
    if not exact_sha_plan_bound:
        return StateMigrationDecision(
            "BLOCKED_MIGRATION_PLAN_REQUIRED",
            "schema_change_requires_exact_sha_migration_plan",
        )
    if not backward_compatibility_proven and not targeted_restore_defined:
        return StateMigrationDecision(
            "BLOCKED_ROLLBACK_COMPATIBILITY_REQUIRED",
            "old_code_needs_compatibility_proof_or_targeted_restore",
        )
    if targeted_restore_defined and not sqlite_snapshot_consistency_proven:
        return StateMigrationDecision(
            "BLOCKED_SQLITE_SNAPSHOT_CONTRACT_REQUIRED",
            "targeted_sqlite_restore_requires_consistent_db_wal_shm_snapshot_contract",
        )
    return StateMigrationDecision(
        "AUDITOR_GATE_REQUIRED",
        "migration_plan_contract_complete_but_independent_audit_and_canonical_wiring_still_required",
    )


__all__ = [
    "PERSISTENT_STATE_INVENTORY",
    "PersistentStateArea",
    "StateMigrationContractError",
    "StateMigrationDecision",
    "assess_audited_plan_boundary",
    "assess_state_migration",
    "inventory_by_name",
]
