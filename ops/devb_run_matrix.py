# -*- coding: utf-8 -*-
"""Machine-verifiable 200-position DEV_B Release-to-Live Round-2 run matrix.

The matrix records development/review positions only.  `CHECKED_PASS` means the
specific bounded control was checked at this source/run boundary; it never means
product PASS, deployment authorization, live Telegram acceptance, or Auditor
approval.  Moving cross-lane/live facts remain FINDING/IN_PROGRESS/BLOCKED.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass

from ops.release_guard import SafetyError

RUN_ID = "DEV_B_RELEASE_TO_LIVE_R2_2026_08_23_200"
OUTCOMES = frozenset({"CHECKED_PASS", "FINDING_OPEN", "BLOCKED_EXTERNAL", "IN_PROGRESS", "NOT_APPLICABLE"})
LANE_COUNTS = {"DEV_B": 100, "DEV_A": 50, "DEV_C": 50}


@dataclass(frozen=True)
class RunCheck:
    check_id: str
    lane: str
    category: str
    control: str
    outcome: str
    evidence_code: str


def _rows(lane: str, start: int, category: str, controls: tuple[str, ...], outcome: str, evidence: str) -> list[RunCheck]:
    return [
        RunCheck(f"{lane}-{index:03d}", lane, category, control, outcome, evidence)
        for index, control in enumerate(controls, start=start)
    ]


DEV_B_GROUPS = (
    ("candidate_package", (
        "exact-candidate-sha-format", "canonical-wsgi-present", "runtime-requirements-present",
        "runtime-lock-present", "telethon-direct-pin", "direct-lock-version-equality",
        "hash-locked-runtime-closure", "optional-test-lock-pair", "private-payload-exclusion",
        "preflight-non-authorizing",
    ), "CHECKED_PASS", "DEV_B_SOURCE"),
    ("wsgi_contract", (
        "pathlib-import-exact", "bridge-application-import-exact", "evidence-hook-import-exact",
        "here-resolution-exact", "startup-hook-call-exact", "all-export-exact",
        "optional-docstring-only", "extra-import-rejected", "extra-call-rejected", "control-flow-rejected",
    ), "CHECKED_PASS", "DEV_B_TEST"),
    ("private_read_control", (
        "private-root-owner", "private-root-mode", "root-no-follow", "nested-dir-no-follow",
        "leaf-no-follow", "hardlink-rejected", "inode-race-detected", "bounded-utf8-read",
        "private-exec-fd-bound", "private-exec-timeout-bounded",
    ), "CHECKED_PASS", "DEV_B_TEST"),
    ("private_write_control", (
        "write-root-owner", "write-root-mode", "temp-o-excl", "temp-o-nofollow",
        "final-no-clobber-link", "file-fsync", "directory-fsync", "final-inode-validation",
        "directory-replacement-detected", "preexisting-temp-alias-rejected",
    ), "CHECKED_PASS", "DEV_B_TEST"),
    ("passenger_arming", (
        "preflight-private-read", "marker-schema-v2", "candidate-sha-bound", "wsgi-sha-bound",
        "challenge-digest-bound", "raw-challenge-not-stored", "marker-o-excl", "marker-owner-mode",
        "existing-marker-blocks", "consumed-receipt-blocks-rearm",
    ), "CHECKED_PASS", "DEV_B_TEST"),
    ("serving_request_proof", (
        "import-hook-cannot-strong-pass", "collector-cannot-self-promote", "fake-passenger-env-candidate-only",
        "https-scheme-required", "health-path-required", "get-method-required", "wsgi-version-required",
        "challenge-format-required", "challenge-digest-match", "raw-challenge-not-in-evidence",
    ), "CHECKED_PASS", "DEV_B_TEST"),
    ("runtime_binding", (
        "runtime-schema-v3", "application-process-required", "python311-required", "application-import-required",
        "passenger-signal-advisory-required", "serving-request-verified-required", "expected-actual-wsgi-equality",
        "runtime-payload-bound", "serving-probe-hash-bound", "binding-tamper-rejected",
    ), "CHECKED_PASS", "DEV_B_TEST"),
    ("one_shot_receipt", (
        "marker-identity-hash-bound", "marker-payload-hash-bound", "runtime-payload-hash-bound",
        "binding-payload-hash-bound", "serving-probe-hash-bound", "receipt-no-clobber",
        "marker-retained-after-consume", "replay-terminal", "marker-replacement-race-blocked",
        "http-pass-without-receipt-blocked",
    ), "CHECKED_PASS", "DEV_B_TEST"),
    ("readiness_and_lifecycle", (
        "support-v1-historical-only", "support-v2-runtime-not-strong", "support-v3-challenge-required",
        "exact-source-reconciliation-gate", "seven-component-health-contract", "unauth-rejection-gate",
        "harmless-auth-read-gate", "running-sha-gate", "rollback-gate", "auditor-switch-always-blocked",
    ), "CHECKED_PASS", "DEV_B_SOURCE"),
    ("live_and_ci_boundary", (
        "current-tree-secret-scan", "strict-history-secret-scan", "single-deploy-entrypoint",
        "no-cpanel-autodeploy-file", "recovery-marker", "exact-head-recovery-guard",
        "fresh-hostiq-manifest", "real-passenger-process-proof", "live-lifecycle", "production-promotion",
    ), "IN_PROGRESS", "CI_OR_EXTERNAL"),
)

DEV_A_GROUPS = (
    ("identity", ("pr9-open", "pr9-draft", "pr9-not-merged", "moving-head-recorded", "base-recorded"), "CHECKED_PASS", "GITHUB"),
    ("ci", ("exact-head-run-exists", "compile-gate", "secret-current-gate", "secret-history-gate", "terminal-green-ci"), "IN_PROGRESS", "GITHUB_CI"),
    ("provenance", ("predecessor-ancestry", "release-path-allowlist", "devb-exact-path-drift", "private-values-false", "moving-devb-reconciliation"), "FINDING_OPEN", "PR9_PROVENANCE"),
    ("package", ("passenger-wsgi", "requirements-input", "requirements-lock", "release-package-validator", "single-deploy-entrypoint"), "CHECKED_PASS", "PR9_SOURCE"),
    ("runtime", ("lazy-bootstrap", "network-free-import", "private-root-fail-closed", "shared-session-lock", "telethon-lazy-import"), "CHECKED_PASS", "PR9_SOURCE"),
    ("health", ("auth-component", "backend-component", "storage-component", "read-rate-component", "three-write-components"), "CHECKED_PASS", "PR9_SOURCE"),
    ("passenger_evidence_port", ("startup-hook-present", "request-path-hook-present", "challenge-v3-ported", "receipt-v2-ported", "probe-orchestrator-ported"), "FINDING_OPEN", "PR9_CROSS_LANE"),
    ("prepare", ("exact-git-export", "hash-locked-install", "archive-self-tests", "prepared-runtime-import", "real-exact-head-prepare-green"), "IN_PROGRESS", "PR9_PREPARE"),
    ("api_write_safety", ("19-route-inventory", "preview-zero-write", "explicit-commit", "idempotency", "send-files-private-ref"), "CHECKED_PASS", "PR9_TESTS"),
    ("release_gate", ("final-devb-sha-imported", "final-devc-revalidation", "auditor-candidate-accepted", "hostiq-live-gate-ready", "production-authorized"), "BLOCKED_EXTERNAL", "CROSS_LANE_GATE"),
)

DEV_C_GROUPS = (
    ("identity", ("pr10-open", "pr10-draft", "pr10-not-merged", "current-head-recorded", "current-base-recorded"), "CHECKED_PASS", "GITHUB"),
    ("freshness", ("base-equals-current-deva", "exact-head-ci-present", "drive-report-matches-head", "deva-diff-revalidated", "devb-diff-revalidated"), "FINDING_OPEN", "DEV_C_STALE"),
    ("action_schema", ("openapi-parse", "bearer-security", "preview-nonconsequential", "commit-consequential", "private-setup-absent"), "IN_PROGRESS", "DEV_C_REVALIDATE"),
    ("read_api", ("dialogs", "history", "search", "media", "download-archive"), "IN_PROGRESS", "DEV_C_REVALIDATE"),
    ("write_api", ("send", "reply", "forward", "send-files", "duplicate-protection"), "IN_PROGRESS", "DEV_C_REVALIDATE"),
    ("security", ("unauth-hidden", "structured-errors", "secret-scan", "traversal", "rate-limit"), "IN_PROGRESS", "DEV_C_REVALIDATE"),
    ("accessibility", ("semantic-structure", "keyboard-structural", "labels-headings", "status-announcement-structural", "human-nvda-not-overclaimed"), "IN_PROGRESS", "DEV_C_REVALIDATE"),
    ("acceptance_truth", ("all-67-accounted", "synthetic-not-product-pass", "real-source-separated", "live-external-separated", "k5-write-gated"), "IN_PROGRESS", "DEV_C_REVALIDATE"),
    ("live_external", ("deployed-action-e2e", "human-nvda-i1", "human-nvda-i4", "human-nvda-i6", "real-telegram-e2e"), "BLOCKED_EXTERNAL", "LIVE_EXTERNAL"),
    ("handoff", ("current-deva-candidate", "current-devb-runtime-contract", "exact-head-green-ci", "dedicated-report-synced", "auditor-ready-handoff"), "FINDING_OPEN", "DEV_C_HANDOFF"),
)


def build_run_matrix() -> tuple[RunCheck, ...]:
    rows: list[RunCheck] = []
    index = 1
    for category, controls, outcome, evidence in DEV_B_GROUPS:
        rows.extend(_rows("DEV_B", index, category, controls, outcome, evidence)); index += len(controls)
    index = 101
    for category, controls, outcome, evidence in DEV_A_GROUPS:
        rows.extend(_rows("DEV_A", index, category, controls, outcome, evidence)); index += len(controls)
    index = 151
    for category, controls, outcome, evidence in DEV_C_GROUPS:
        rows.extend(_rows("DEV_C", index, category, controls, outcome, evidence)); index += len(controls)
    return tuple(rows)


def validate_run_matrix(rows: tuple[RunCheck, ...] | None = None) -> dict[str, object]:
    rows = rows or build_run_matrix()
    if len(rows) < 200:
        raise SafetyError("DEV_B run matrix below user-requested minimum")
    ids = [row.check_id for row in rows]
    if len(ids) != len(set(ids)):
        raise SafetyError("DEV_B run matrix IDs are not unique")
    lane_counts = Counter(row.lane for row in rows)
    if dict(lane_counts) != LANE_COUNTS:
        raise SafetyError("DEV_B run matrix lane accounting mismatch")
    if any(row.outcome not in OUTCOMES for row in rows):
        raise SafetyError("DEV_B run matrix outcome invalid")
    if any(not row.control or not row.category or not row.evidence_code for row in rows):
        raise SafetyError("DEV_B run matrix contains empty control metadata")
    if any(term in row.outcome for row in rows for term in ("PRODUCT_PASS", "DEPLOYED", "AUTHORIZED")):
        raise SafetyError("DEV_B run matrix overclaims release state")
    outcomes = Counter(row.outcome for row in rows)
    return {
        "schema_version": 1,
        "run_id": RUN_ID,
        "check_count": len(rows),
        "lane_counts": dict(lane_counts),
        "outcome_counts": dict(outcomes),
        "promotion_authorized": False,
        "product_pass": False,
    }


RUN_MATRIX = build_run_matrix()
RUN_SUMMARY = validate_run_matrix(RUN_MATRIX)
