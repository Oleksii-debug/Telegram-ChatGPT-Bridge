# -*- coding: utf-8 -*-
"""Fail-closed privacy policy for public/non-secret acceptance evidence.

Public evidence is a control-plane record, not a diagnostic transcript.  Only
semantic environment classes, structured evidence references, bounded values,
reviewed enums and hashes are accepted.  External/private identifiers must be
hashed before they cross this boundary.
"""
from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from typing import Any, Iterable

MAX_EVIDENCE_BYTES = 4096
MAX_FACT_KEYS = 20
MAX_LIST_ITEMS = 32
MAX_DEPTH = 4
MAX_INT = 1_000_000_000

SHA40_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SAFE_ENUM_RE = re.compile(r"^[A-Z0-9][A-Z0-9_.:-]{0,79}$")
CONTROL_CHAR_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

ALLOWED_ENVIRONMENT_CLASSES = frozenset({
    "github-ci",
    "synthetic",
    "reference-snapshot",
    "local-test",
    "hostiq-staging",
    "hostiq-production",
    "chatgpt-action-live",
})

# Evidence references are structured and provider-specific.  No free-form chat,
# person, file or note label can be smuggled into a reference field.
EVIDENCE_REF_PATTERNS = (
    re.compile(r"^github:run:[1-9][0-9]{0,19}$"),
    re.compile(r"^github:job:[1-9][0-9]{0,19}$"),
    re.compile(r"^github:check:[1-9][0-9]{0,19}$"),
    re.compile(r"^github:commit:[0-9a-f]{40}$"),
    re.compile(r"^test:sha256:[0-9a-f]{64}$"),
    re.compile(r"^reference:sha256:[0-9a-f]{64}$"),
    re.compile(r"^hostiq:sha256:[0-9a-f]{64}$"),
    re.compile(r"^external:sha256:[0-9a-f]{64}$"),
)

# Defense in depth. The primary protection is the positive schema below.
PRIVATE_KEY_RE = re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", re.I)
SETUP_ROUTE_RE = re.compile(r"(?<![A-Za-z0-9_])/setup-[A-Za-z0-9_-]{12,}(?![A-Za-z0-9_])", re.I)
AUTH_VALUE_RE = re.compile(r"\b(?:authorization|bearer)\b\s*[:= -]?\s*[A-Za-z0-9._~+/-]{8,}", re.I)
COOKIE_VALUE_RE = re.compile(r"\b(?:cookie|set-cookie)\b\s*[:=]\s*\S{8,}", re.I)
JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
SECRET_ASSIGNMENT_RE = re.compile(
    r"\b(?:TG_API_ID|TG_API_HASH|TG_SESSION_STRING|TELEGRAM_2FA_PASSWORD|"
    r"BRIDGE_TOKEN|BRIDGE_ROUTE_KEY|SETUP_ROUTE|SETUP_KEY|HOSTIQ_CPANEL_PASSWORD|"
    r"CPANEL_PASSWORD|SSH_PRIVATE_KEY|GITHUB_TOKEN|GH_TOKEN|GITHUB_PAT|"
    r"GOOGLE_DRIVE_CLIENT_SECRET|GOOGLE_DRIVE_REFRESH_TOKEN|ACCESS_TOKEN|"
    r"REFRESH_TOKEN|CLIENT_SECRET|SESSION_STRING|PASSWORD)\b\s*[:=]\s*\S{4,}",
    re.I,
)

BOOL_FACTS = {
    "success", "backup_created", "state_preserved", "persistent_state_preserved",
    "deduplicated", "authorized", "quiesced", "resumed", "audit_recorded",
    "stdout_present", "stderr_present", "error_present", "tree_scan_passed",
    "history_scan_passed", "private_serving_enforced", "preview_only",
    "commit_single_use", "restart_safe", "recoverable", "schema_valid",
    "keyboard_operable", "labels_present", "accessible_names_present",
    "heading_order_valid", "tab_order_valid", "mouse_only_absent",
    "status_messages_accessible", "error_associations_valid", "focus_reachable",
    "structured_errors_valid", "route_registry_matched", "raw_text_absent",
}
INT_FACTS = {
    "count", "findings_count", "artifact_count", "persistent_entries_count",
    "file_count", "result_count", "page_count", "retry_count", "attempt",
    "duration_ms", "timeout_ms", "return_code", "http_status", "status_code",
    "rate_limit_remaining", "retry_after_seconds", "job_checkpoint", "criteria_count",
    "passed_count", "failed_count", "blocked_count", "test_count", "focusable_count",
}
SHA40_FACTS = {"previous_sha", "candidate_sha", "deployed_sha", "observed_sha"}
SHA256_FACTS = {
    "sha256", "backup_sha256", "manifest_sha256", "identifier_sha256",
    "chat_sha256", "message_sha256", "file_sha256", "payload_sha256",
    "request_sha256", "path_sha256",
}
ENUM_FACTS = {
    "state", "mode", "reason_code", "error_type", "scan_scope",
    "operation_kind", "rollback_state", "result_code", "environment_state",
    "method", "contract_status", "auth_state", "media_kind", "job_state",
    "preview_state", "commit_state", "scope", "error_code",
}
ENUM_LIST_FACTS = {"reason_codes", "checks", "capabilities", "coverage_tags"}
SHA256_LIST_FACTS = {"identifier_hashes", "file_hashes"}
ALL_FACT_KEYS = (
    BOOL_FACTS | INT_FACTS | SHA40_FACTS | SHA256_FACTS |
    ENUM_FACTS | ENUM_LIST_FACTS | SHA256_LIST_FACTS
)

AUTH_REASON_CODES = {
    "SYNTHETIC_TEST_ONLY", "SANITIZED_SOURCE_PENDING", "PASSENGER_RUNTIME_PENDING",
    "SERVER_SETUP_NOT_READY", "HUMAN_INPUT_NOT_FIRST_BLOCKER",
    "SERVER_SETUP_FIRST_HUMAN_BLOCKER",
}
ENUM_VALUE_ALLOWLISTS: dict[str, frozenset[str]] = {
    "state": frozenset({
        "READY", "RUNNING", "RETRYABLE", "COMPLETED", "BLOCKED", "FAILED",
        "CANCELLED", "VERIFIED", "UNVERIFIED", "PENDING", "SUCCESS",
    }),
    "mode": frozenset({
        "SYNTHETIC", "REAL_SOURCE", "LIVE_EXTERNAL", "REFERENCE_ONLY",
        "PROCESS_LOSS_SAME_HOST_V1",
    }),
    "reason_code": frozenset(AUTH_REASON_CODES | {
        "POLICY_REJECTED", "INPUT_REJECTED", "EXTERNAL_BLOCKER", "NOT_APPLICABLE",
    }),
    "error_type": frozenset({
        "EXCEPTION", "RUNTIME_ERROR", "VALUE_ERROR", "TYPE_ERROR", "OS_ERROR",
        "TIMEOUT_ERROR", "CONTRACT_ERROR", "ASSERTION_ERROR",
    }),
    "scan_scope": frozenset({
        "PUBLIC_REPOSITORY", "CURRENT_TREE", "FULL_HISTORY", "REFERENCE_SNAPSHOT",
    }),
    "operation_kind": frozenset({
        "READ", "SEARCH", "DOWNLOAD", "BULK_DOWNLOAD", "ZIP", "SEND", "REPLY",
        "FORWARD", "SEND_FILE", "SEND_FILES", "PREVIEW", "COMMIT",
    }),
    "rollback_state": frozenset({"NOT_REQUIRED", "ROLLED_BACK", "CRITICAL_ROLLBACK_FAILED"}),
    "result_code": frozenset({
        "COMMITTED", "IDEMPOTENCY_CONFLICT", "USED_PREVIEW", "EXPIRED_PREVIEW",
        "INVALID_PREVIEW", "AUTHORIZED", "DENIED", "RATE_LIMITED", "OK",
    }),
    "environment_state": frozenset({"READY", "BLOCKED", "VERIFIED", "UNVERIFIED"}),
    "method": frozenset({"GET", "POST", "PUT", "PATCH", "DELETE"}),
    "contract_status": frozenset({
        "SYNETIC_EXECUTABLE", "SYNTHETIC_EXECUTABLE", "REAL_SOURCE_REQUIRED", "LIVE_EXTERNAL_REQUIRED",
    }),
    "auth_state": frozenset({
        "USER_TELEGRAM_AUTH_NOT_YET_REQUIRED", "USER_TELEGRAM_AUTH_REQUIRED",
        "CODE_REQUESTED", "FLOOD_WAIT", "RPC_ERROR", "INVALID_CODE", "INVALID_2FA",
        "AUTHORIZED", "UNAUTHORIZED", "MISSING_AUTH", "WRONG_AUTH", "MALFORMED_AUTH",
    }),
    "media_kind": frozenset({"DOCUMENT", "VOICE", "PHOTO", "VIDEO", "AUDIO", "OTHER"}),
    "job_state": frozenset({"READY", "RUNNING", "RETRYABLE", "COMPLETED", "FAILED", "CANCELLED"}),
    "preview_state": frozenset({"CREATED", "EXPIRED", "USED", "INVALID"}),
    "commit_state": frozenset({
        "COMMITTED", "IDEMPOTENCY_CONFLICT", "USED_PREVIEW", "EXPIRED_PREVIEW", "INVALID_PREVIEW",
    }),
    "scope": frozenset({"GLOBAL", "DIALOG", "PERSON", "DATE", "FILE", "ACTOR"}),
    "error_code": frozenset({
        "INVALID_JSON", "INVALID_JSON_SHAPE", "PAYLOAD_TOO_LARGE", "INVALID_CONTENT_LENGTH",
        "AUTH_REQUIRED", "AUTH_MALFORMED", "AUTH_INVALID", "IDEMPOTENCY_CONFLICT",
        "RATE_LIMITED", "TELEGRAM_UNAVAILABLE", "FLOOD_WAIT", "RPC_ERROR",
        "TIMEOUT", "CANCELLED", "INTERNAL_ERROR", "FILE_NOT_FOUND", "FILE_ACCESS_DENIED",
    }),
    "reason_codes": frozenset(AUTH_REASON_CODES),
    "checks": frozenset({
        "COMPILE_PASS", "UNIT_TESTS_PASS", "INTEGRATION_TESTS_PASS", "SECRET_SCAN_PASS",
        "HISTORY_SECRET_SCAN_PASS", "RECOVERY_MARKER_PASS", "NO_AUTODEPLOY_PASS",
        "OPENAPI_POLICY_PASS", "ACCESSIBILITY_STRUCTURE_PASS", "COVERAGE_DRIFT_PASS",
        "PY311_PREPARE_VERIFY_PASS", "ROLLBACK_REGRESSION_PASS",
    }),
    "capabilities": frozenset({
        "AUTH", "PATH_TRAVERSAL", "RATE_LIMIT", "IDEMPOTENCY", "ACCESSIBILITY",
        "OPENAPI", "ZIP", "PRIVATE_FILE", "LOG_REDACTION", "TELEGRAM_FAKE", "EVIDENCE_PRIVACY",
    }),
    "coverage_tags": frozenset({
        "SYNTHETIC", "REAL_SOURCE", "LIVE", "SECURITY", "ACCESSIBILITY", "PRIVACY",
        "RELIABILITY", "OPENAPI", "FILES", "WRITES",
    }),
}


def hash_private_identifier(value: str, *, namespace: str = "external") -> str:
    """Return a one-way identifier suitable for public evidence.

    The raw identifier is never returned. Namespaces prevent accidental equality
    between unrelated identifier domains.
    """
    if not isinstance(value, str) or not value:
        raise ValueError("private identifier must be non-empty text")
    if not re.fullmatch(r"[a-z][a-z0-9_-]{0,31}", namespace):
        raise ValueError("invalid hash namespace")
    normalized = unicodedata.normalize("NFC", value)
    return hashlib.sha256((namespace + "\0" + normalized).encode("utf-8")).hexdigest()


def _looks_tokenish(text: str) -> bool:
    if len(text) < 32:
        return False
    compact = re.sub(r"[^A-Za-z0-9_-]", "", text)
    if len(compact) < 32:
        return False
    if re.fullmatch(r"[0-9a-fA-F]{40}|[0-9a-fA-F]{64}", compact):
        return False
    classes = sum(bool(re.search(pattern, compact)) for pattern in (r"[a-z]", r"[A-Z]", r"\d"))
    return classes >= 2


def reject_sensitive_text(text: str, *, label: str = "evidence") -> None:
    if not isinstance(text, str):
        raise ValueError(f"{label} must be text")
    if CONTROL_CHAR_RE.search(text):
        raise ValueError(f"control characters rejected in {label}")
    if any(pattern.search(text) for pattern in (
        PRIVATE_KEY_RE, SETUP_ROUTE_RE, AUTH_VALUE_RE, COOKIE_VALUE_RE,
        JWT_RE, SECRET_ASSIGNMENT_RE,
    )):
        raise ValueError(f"privacy-sensitive content rejected in {label}")
    if _looks_tokenish(text):
        raise ValueError(f"opaque token-like content rejected in {label}")


def validate_environment_class(value: str) -> str:
    if not isinstance(value, str) or value not in ALLOWED_ENVIRONMENT_CLASSES:
        raise ValueError("environment class is not in the semantic allowlist")
    return value


def validate_evidence_ref(value: str) -> str:
    if not isinstance(value, str) or not any(pattern.fullmatch(value) for pattern in EVIDENCE_REF_PATTERNS):
        raise ValueError("evidence reference must use an approved structured form")
    if CONTROL_CHAR_RE.search(value) or any(pattern.search(value) for pattern in (
        PRIVATE_KEY_RE, SETUP_ROUTE_RE, AUTH_VALUE_RE, COOKIE_VALUE_RE, JWT_RE, SECRET_ASSIGNMENT_RE
    )):
        raise ValueError("privacy-sensitive evidence reference rejected")
    return value


def _validate_enum(value: Any, key: str) -> str:
    if not isinstance(value, str) or not SAFE_ENUM_RE.fullmatch(value):
        raise ValueError(f"invalid safe enum fact: {key}")
    allowed = ENUM_VALUE_ALLOWLISTS.get(key)
    if allowed is None or value not in allowed:
        raise ValueError(f"enum fact is not semantically allowlisted: {key}")
    return value


def _validate_int(value: Any, key: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or abs(value) > MAX_INT:
        raise ValueError(f"invalid bounded integer fact: {key}")
    if key == "http_status" and not (100 <= value <= 599):
        raise ValueError("invalid HTTP status evidence")
    if key.endswith("_count") or key in {
        "count", "attempt", "duration_ms", "timeout_ms", "retry_count",
        "rate_limit_remaining", "retry_after_seconds", "job_checkpoint", "criteria_count",
        "test_count", "focusable_count",
    }:
        if value < 0:
            raise ValueError(f"negative count/duration fact: {key}")
    return value


def validate_fact_value(key: str, value: Any) -> None:
    if key in BOOL_FACTS:
        if not isinstance(value, bool):
            raise ValueError(f"invalid boolean fact: {key}")
        return
    if key in INT_FACTS:
        _validate_int(value, key)
        return
    if key in SHA40_FACTS:
        if not isinstance(value, str) or not SHA40_RE.fullmatch(value):
            raise ValueError(f"invalid Git SHA fact: {key}")
        return
    if key in SHA256_FACTS:
        if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
            raise ValueError(f"invalid SHA-256 fact: {key}")
        return
    if key in ENUM_FACTS:
        _validate_enum(value, key)
        return
    if key in ENUM_LIST_FACTS:
        if not isinstance(value, (list, tuple)) or len(value) > MAX_LIST_ITEMS:
            raise ValueError(f"invalid enum-list fact: {key}")
        for item in value:
            _validate_enum(item, key)
        return
    if key in SHA256_LIST_FACTS:
        if not isinstance(value, (list, tuple)) or len(value) > MAX_LIST_ITEMS:
            raise ValueError(f"invalid hash-list fact: {key}")
        for item in value:
            if not isinstance(item, str) or not SHA256_RE.fullmatch(item):
                raise ValueError(f"invalid hash-list item: {key}")
        return
    raise ValueError(f"fact key is not in the positive evidence schema: {key}")


def validate_facts(facts: Any, *, allowed_keys: Iterable[str]) -> dict[str, Any]:
    if facts is None:
        return {}
    if not isinstance(facts, dict):
        raise ValueError("facts must be a dictionary")
    if len(facts) > MAX_FACT_KEYS:
        raise ValueError("too many evidence facts")
    allowed = set(allowed_keys)
    cleaned: dict[str, Any] = {}
    for key, value in facts.items():
        if not isinstance(key, str) or key not in allowed or key not in ALL_FACT_KEYS:
            raise ValueError("evidence fact key not allowed for criterion")
        if isinstance(value, dict):
            raise ValueError("nested evidence dictionaries are forbidden")
        validate_fact_value(key, value)
        cleaned[key] = list(value) if isinstance(value, (list, tuple)) else value
    return cleaned


def _walk_structure(value: Any, *, depth: int = 0) -> None:
    if depth > MAX_DEPTH:
        raise ValueError("evidence nesting depth exceeded")
    if isinstance(value, dict):
        if len(value) > MAX_FACT_KEYS + 12:
            raise ValueError("evidence dictionary too large")
        for key, child in value.items():
            if not isinstance(key, str) or len(key) > 80:
                raise ValueError("invalid evidence key")
            _walk_structure(child, depth=depth + 1)
    elif isinstance(value, list):
        if len(value) > MAX_LIST_ITEMS:
            raise ValueError("evidence list too large")
        for child in value:
            _walk_structure(child, depth=depth + 1)
    elif isinstance(value, str):
        if len(value) > 240:
            raise ValueError("evidence string too large")
        if CONTROL_CHAR_RE.search(value) or any(pattern.search(value) for pattern in (
            PRIVATE_KEY_RE, SETUP_ROUTE_RE, AUTH_VALUE_RE, COOKIE_VALUE_RE, JWT_RE, SECRET_ASSIGNMENT_RE
        )):
            raise ValueError("privacy-sensitive aggregate evidence rejected")
    elif value is None or isinstance(value, (bool, int)):
        return
    else:
        raise ValueError("unsupported evidence object type")


def validate_aggregate_payload(payload: Any) -> None:
    _walk_structure(payload)
    try:
        encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValueError("evidence payload is not safely serializable") from exc
    if len(encoded) > MAX_EVIDENCE_BYTES:
        raise ValueError("aggregate evidence payload exceeds limit")


def sanitize_exception(exc: BaseException) -> dict[str, Any]:
    """Return category-only exception evidence; messages and chained text are discarded."""
    mapping = (
        (TimeoutError, "TIMEOUT_ERROR"),
        (ValueError, "VALUE_ERROR"),
        (TypeError, "TYPE_ERROR"),
        (OSError, "OS_ERROR"),
        (AssertionError, "ASSERTION_ERROR"),
        (RuntimeError, "RUNTIME_ERROR"),
    )
    error_type = "EXCEPTION"
    for klass, label in mapping:
        if isinstance(exc, klass):
            error_type = label
            break
    return {"error_type": error_type, "error_present": True}


def sanitize_subprocess_result(return_code: int, *, stdout: Any = None, stderr: Any = None) -> dict[str, Any]:
    """Record only presence/return code; never serialize subprocess text snippets."""
    return {
        "return_code": _validate_int(return_code, "return_code"),
        "stdout_present": bool(stdout),
        "stderr_present": bool(stderr),
    }
