# -*- coding: utf-8 -*-
"""Machine-readable acceptance planning, auth-gate and evidence helpers.

Planning states describe harness readiness only. They are never product PASS.
Real PASS/FAIL/BLOCKED evidence requires an exact code SHA, a semantic environment
class and a structured non-secret evidence reference. Public evidence uses a
positive typed schema; arbitrary prose/private Telegram content is not accepted.
"""
from __future__ import annotations

import json
import re
from typing import Any

from ops import evidence_privacy as privacy

PLAN_STATUSES = {"IMPLEMENTED_TEST", "READY_FOR_REAL_SOURCE", "EXTERNALLY_BLOCKED", "NOT_IMPLEMENTED"}
RESULT_STATUSES = {"PASS", "FAIL", "BLOCKED"}
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
AUTH_NOT_YET_REQUIRED = "USER_TELEGRAM_AUTH_NOT_YET_REQUIRED"
AUTH_REQUIRED = "USER_TELEGRAM_AUTH_REQUIRED"

_ROWS = [
    ("A1", "Python 3.11 compile/import checks pass.", "READY_FOR_REAL_SOURCE"),
    ("A2", "WSGI application imports successfully.", "READY_FOR_REAL_SOURCE"),
    ("A3", "Health endpoint responds within timeout.", "READY_FOR_REAL_SOURCE"),
    ("A4", "Invalid route does not leak stack traces/secrets.", "READY_FOR_REAL_SOURCE"),
    ("A5", "Restart preserves private session/config.", "READY_FOR_REAL_SOURCE"),
    ("B1", "Protected endpoints reject missing bearer/auth.", "READY_FOR_REAL_SOURCE"),
    ("B2", "Wrong token cannot retrieve Telegram content.", "READY_FOR_REAL_SOURCE"),
    ("B3", "Logs do not contain API hash, session, 2FA, bearer token, message bodies or private file contents.", "READY_FOR_REAL_SOURCE"),
    ("B4", "Repository/history/PR/Actions artifacts contain no secrets.", "IMPLEMENTED_TEST"),
    ("B5", "Path traversal attempts are rejected.", "READY_FOR_REAL_SOURCE"),
    ("B6", "File IDs cannot be used to read arbitrary server files.", "READY_FOR_REAL_SOURCE"),
    ("B7", "Malformed JSON/parameters return controlled errors.", "READY_FOR_REAL_SOURCE"),
    ("B8", "Rate limits prevent obvious abuse.", "READY_FOR_REAL_SOURCE"),
    ("C1", "One-time setup is keyboard/NVDA accessible.", "READY_FOR_REAL_SOURCE"),
    ("C2", "Setup route is protected/one-time and disabled/rotated after successful setup as designed.", "READY_FOR_REAL_SOURCE"),
    ("C3", "Code request/auth flow handles Telegram errors safely.", "READY_FOR_REAL_SOURCE"),
    ("C4", "2FA flow works when required.", "READY_FOR_REAL_SOURCE"),
    ("C5", "Restart does not lose the authorized session.", "READY_FOR_REAL_SOURCE"),
    ("C6", "FloodWait/RPC failures are handled without corrupting state.", "READY_FOR_REAL_SOURCE"),
    ("D1", "List dialogs works.", "READY_FOR_REAL_SOURCE"),
    ("D2", "Read history returns correct ordering and pagination.", "READY_FOR_REAL_SOURCE"),
    ("D3", "Global/scoped search works.", "READY_FOR_REAL_SOURCE"),
    ("D4", "Filters by chat/person/text/date behave correctly.", "READY_FOR_REAL_SOURCE"),
    ("D5", "Unicode/Cyrillic text remains intact.", "READY_FOR_REAL_SOURCE"),
    ("D6", "Empty/no-result cases are controlled.", "READY_FOR_REAL_SOURCE"),
    ("E1", "Metadata listing works for documents/media/voice/photo where supported.", "READY_FOR_REAL_SOURCE"),
    ("E2", "Single-file download works and validates expected file.", "READY_FOR_REAL_SOURCE"),
    ("E3", "Bulk download applies requested filters and does not duplicate files.", "READY_FOR_REAL_SOURCE"),
    ("E4", "ZIP generation produces a valid archive.", "READY_FOR_REAL_SOURCE"),
    ("E5", "Interrupted/failed download leaves recoverable state and useful error.", "READY_FOR_REAL_SOURCE"),
    ("E6", "Downloaded private files are not exposed by unauthenticated public URLs.", "READY_FOR_REAL_SOURCE"),
    ("F1", "Send has preview stage.", "READY_FOR_REAL_SOURCE"),
    ("F2", "Reply has preview stage and correct reply target.", "READY_FOR_REAL_SOURCE"),
    ("F3", "Forward has preview stage.", "READY_FOR_REAL_SOURCE"),
    ("F4", "Send-files has preview stage.", "READY_FOR_REAL_SOURCE"),
    ("F5", "Commit requires a valid single-use preview token or equivalent approved mechanism.", "READY_FOR_REAL_SOURCE"),
    ("F6", "Repeating the same commit does not duplicate the action.", "READY_FOR_REAL_SOURCE"),
    ("F7", "Expired/used/invalid preview token fails safely.", "READY_FOR_REAL_SOURCE"),
    ("F8", "Audit metadata records operation without recording private body/secrets.", "READY_FOR_REAL_SOURCE"),
    ("G1", "Idempotency store behaves correctly under retry.", "READY_FOR_REAL_SOURCE"),
    ("G2", "Duplicate protection survives reasonable restart/retry scenarios.", "READY_FOR_REAL_SOURCE"),
    ("G3", "Timeouts are explicit.", "READY_FOR_REAL_SOURCE"),
    ("G4", "Errors do not leave corrupt DB/job state.", "READY_FOR_REAL_SOURCE"),
    ("G5", "Jobs can be resumed/retried safely where designed.", "READY_FOR_REAL_SOURCE"),
    ("H1", "Generated OpenAPI schema matches deployed endpoints.", "READY_FOR_REAL_SOURCE"),
    ("H2", "Read-only Action calls work end-to-end.", "EXTERNALLY_BLOCKED"),
    ("H3", "Unauthorized calls fail without data leakage.", "READY_FOR_REAL_SOURCE"),
    ("H4", "Write operations preserve preview/commit safety.", "READY_FOR_REAL_SOURCE"),
    ("H5", "ChatGPT receives useful structured errors.", "READY_FOR_REAL_SOURCE"),
    ("I1", "Setup page is fully operable with keyboard.", "READY_FOR_REAL_SOURCE"),
    ("I2", "Inputs have explicit labels.", "READY_FOR_REAL_SOURCE"),
    ("I3", "Buttons have accessible names.", "READY_FOR_REAL_SOURCE"),
    ("I4", "Logical Tab order.", "READY_FOR_REAL_SOURCE"),
    ("I5", "Heading structure is meaningful.", "READY_FOR_REAL_SOURCE"),
    ("I6", "Error/status messages are text and readable by NVDA.", "READY_FOR_REAL_SOURCE"),
    ("I7", "No mouse-only control.", "READY_FOR_REAL_SOURCE"),
    ("J1", "Deployed commit SHA is known.", "EXTERNALLY_BLOCKED"),
    ("J2", "Backup is created before production change.", "IMPLEMENTED_TEST"),
    ("J3", "Runtime secrets/session are preserved.", "IMPLEMENTED_TEST"),
    ("J4", "Health/smoke tests run after deploy.", "EXTERNALLY_BLOCKED"),
    ("J5", "Failed deploy can restore last-known-good release.", "IMPLEMENTED_TEST"),
    ("J6", "Main branch and production state are traceable.", "EXTERNALLY_BLOCKED"),
    ("K1", "Ask for list of chats and receive it.", "EXTERNALLY_BLOCKED"),
    ("K2", "Ask for a person's recent messages and receive correct results.", "EXTERNALLY_BLOCKED"),
    ("K3", "Ask for files from a chat/date window and receive correct package.", "EXTERNALLY_BLOCKED"),
    ("K4", "Ask for a draft/preview reply; no message is sent before explicit commit.", "EXTERNALLY_BLOCKED"),
    ("K5", "Explicitly commit a test message to a safe destination and verify exactly one send.", "EXTERNALLY_BLOCKED"),
]
ACCEPTANCE_MATRIX = [{"criterion": c, "description": d, "plan_status": s} for c, d, s in _ROWS]
CRITERIA = {item["criterion"]: item for item in ACCEPTANCE_MATRIX}

COMMON_FACT_KEYS = {
    "success", "count", "duration_ms", "timeout_ms", "retry_count", "attempt",
    "return_code", "http_status", "status_code", "state", "reason_code",
    "reason_codes", "checks", "contract_status", "error_type", "error_present",
    "retry_after_seconds", "raw_text_absent",
}
GROUP_FACT_KEYS = {
    "A": {"observed_sha", "restart_safe", "state_preserved"},
    "B": {"authorized", "findings_count", "tree_scan_passed", "history_scan_passed", "artifact_count", "rate_limit_remaining", "file_count", "scan_scope"},
    "C": {"auth_state", "state_preserved", "restart_safe", "recoverable"},
    "D": {"result_count", "page_count", "identifier_hashes"},
    "E": {"file_count", "file_hashes", "file_sha256", "deduplicated", "recoverable", "private_serving_enforced", "media_kind", "path_sha256"},
    "F": {"preview_only", "commit_single_use", "audit_recorded", "operation_kind", "payload_sha256", "identifier_sha256", "request_sha256", "preview_state", "commit_state", "deduplicated"},
    "G": {"state_preserved", "restart_safe", "recoverable", "job_state", "job_checkpoint", "deduplicated", "request_sha256"},
    "H": {"schema_valid", "authorized", "preview_only", "commit_single_use", "operation_kind", "route_registry_matched", "structured_errors_valid"},
    "I": {"keyboard_operable", "labels_present", "accessible_names_present", "heading_order_valid", "tab_order_valid", "mouse_only_absent", "status_messages_accessible", "error_associations_valid", "focus_reachable", "focusable_count", "findings_count"},
    "J": {"backup_created", "backup_sha256", "state_preserved", "persistent_state_preserved", "persistent_entries_count", "previous_sha", "candidate_sha", "deployed_sha", "observed_sha", "rollback_state", "quiesced", "resumed", "manifest_sha256"},
    "K": {"result_count", "file_count", "preview_only", "commit_single_use", "operation_kind", "identifier_sha256", "success"},
}
CRITERION_FACT_KEYS = {criterion: COMMON_FACT_KEYS | GROUP_FACT_KEYS[criterion[0]] for criterion in CRITERIA}
RESULT_KEYS = {"schema_version", "criterion", "code_sha", "environment_class", "result", "evidence_ref", "facts"}


def validate_matrix() -> None:
    expected_groups = set("ABCDEFGHIJK")
    seen = set()
    for item in ACCEPTANCE_MATRIX:
        criterion = item["criterion"]
        if criterion in seen:
            raise ValueError("duplicate criterion")
        seen.add(criterion)
        if criterion[0] not in expected_groups or not criterion[1:].isdigit():
            raise ValueError("invalid criterion id")
        if item["plan_status"] not in PLAN_STATUSES:
            raise ValueError("invalid planning status")
        if not item["description"].strip():
            raise ValueError("missing criterion description")
    if set(item["criterion"][0] for item in ACCEPTANCE_MATRIX) != expected_groups:
        raise ValueError("A-K groups incomplete")


def validate_result_payload(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict) or set(payload) != RESULT_KEYS:
        raise ValueError("acceptance result schema mismatch")
    if payload.get("schema_version") != 2:
        raise ValueError("acceptance result schema version unsupported")
    criterion = payload.get("criterion")
    if criterion not in CRITERIA:
        raise ValueError("unknown acceptance criterion")
    code_sha = payload.get("code_sha")
    if not isinstance(code_sha, str) or not SHA_RE.fullmatch(code_sha):
        raise ValueError("exact 40-character code SHA required")
    privacy.validate_environment_class(payload.get("environment_class"))
    if payload.get("result") not in RESULT_STATUSES:
        raise ValueError("invalid result status")
    privacy.validate_evidence_ref(payload.get("evidence_ref"))
    payload["facts"] = privacy.validate_facts(payload.get("facts"), allowed_keys=CRITERION_FACT_KEYS[criterion])
    privacy.validate_aggregate_payload(payload)
    return payload


def build_result(*, criterion: str, code_sha: str, environment_class: str,
                 result: str, evidence_ref: str, facts: dict[str, Any] | None = None) -> dict[str, Any]:
    payload = {
        "schema_version": 2,
        "criterion": criterion,
        "code_sha": code_sha,
        "environment_class": environment_class,
        "result": result,
        "evidence_ref": evidence_ref,
        "facts": facts or {},
    }
    return validate_result_payload(payload)


def serialize_result(payload: dict[str, Any]) -> str:
    validated = validate_result_payload(dict(payload))
    return json.dumps(validated, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def evaluate_telegram_auth_gate(*, sanitized_application_source_ready: bool,
                                passenger_runtime_verified: bool,
                                server_setup_ready: bool,
                                setup_session_is_first_human_blocker: bool,
                                synthetic_only: bool = False) -> dict[str, Any]:
    inputs = (sanitized_application_source_ready, passenger_runtime_verified, server_setup_ready,
              setup_session_is_first_human_blocker, synthetic_only)
    if any(not isinstance(item, bool) for item in inputs):
        raise ValueError("Telegram auth gate inputs must be booleans")
    reasons: list[str] = []
    if synthetic_only:
        reasons.append("SYNTHETIC_TEST_ONLY")
    if not sanitized_application_source_ready:
        reasons.append("SANITIZED_SOURCE_PENDING")
    if not passenger_runtime_verified:
        reasons.append("PASSENGER_RUNTIME_PENDING")
    if not server_setup_ready:
        reasons.append("SERVER_SETUP_NOT_READY")
    if not setup_session_is_first_human_blocker:
        reasons.append("HUMAN_INPUT_NOT_FIRST_BLOCKER")
    if reasons:
        return {"state": AUTH_NOT_YET_REQUIRED, "reason_codes": reasons}
    return {"state": AUTH_REQUIRED, "reason_codes": ["SERVER_SETUP_FIRST_HUMAN_BLOCKER"]}


def current_planning_auth_gate() -> dict[str, Any]:
    return evaluate_telegram_auth_gate(
        sanitized_application_source_ready=False,
        passenger_runtime_verified=False,
        server_setup_ready=False,
        setup_session_is_first_human_blocker=False,
        synthetic_only=False,
    )


validate_matrix()
