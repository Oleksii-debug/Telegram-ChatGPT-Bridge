# -*- coding: utf-8 -*-
"""Fail-closed privacy policy for public/non-secret acceptance evidence.

Public evidence is intentionally tiny and semantic. It may contain hashes,
bounded counts and reviewed status identifiers. It must never contain raw
Telegram/server/user content, private labels, filenames, chat/person names,
URLs, query strings, exception text, stdout/stderr or credential material.
"""
from __future__ import annotations

import json
import re
from typing import Any, Iterable, Mapping

MAX_EVIDENCE_BYTES = 4096
MAX_FACT_KEYS = 20
MAX_LIST_ITEMS = 32
MAX_DEPTH = 4
MAX_INT = 1_000_000_000
MAX_REFERENCE_KEYS = 5

SHA40_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
POSITIVE_INT_RE = re.compile(r"^[1-9][0-9]{0,18}$")

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
    r"REFRESH_TOKEN|CLIENT_SECRET|SESSION_STRING|PASSWORD)\b\s*[:=]\s*\S{4,}", re.I,
)
CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

# Align names with the repository scanner where safe; evidence remains stricter.
try:
    from tools.secret_scan import PROJECT_SECRET_VARIABLES as _PROJECT_SECRET_VARIABLES
    from tools.secret_scan import GENERIC_CREDENTIAL_ALIASES as _GENERIC_CREDENTIAL_ALIASES
except Exception:  # pragma: no cover - fail-closed fallback for isolated import contexts
    _PROJECT_SECRET_VARIABLES = ("TG_API_ID", "TG_API_HASH", "TG_SESSION_STRING", "BRIDGE_TOKEN", "SETUP_ROUTE")
    _GENERIC_CREDENTIAL_ALIASES = ("API_ID", "API_HASH", "API_KEY", "SESSION", "PASSWORD", "BEARER_TOKEN", "ACCESS_TOKEN", "REFRESH_TOKEN", "CLIENT_SECRET")
_SHARED_SECRET_ALT = "|".join(re.escape(name) for name in (_PROJECT_SECRET_VARIABLES + _GENERIC_CREDENTIAL_ALIASES))
SHARED_SECRET_ASSIGNMENT_RE = re.compile(rf"\b(?:{_SHARED_SECRET_ALT})\b\s*[:=]\s*\S{{4,}}", re.I)

BASE_ENVIRONMENT_CLASSES = frozenset({
    "SYNTHETIC", "GITHUB_CI", "LOCAL_TEST", "AUDITOR_REPLAY",
    "HOSTIQ_PRIVATE_STAGING", "HOSTIQ_PRODUCTION",
})
# Forward-compatible only by code-reviewed source change; runtime callers cannot extend it.
REVIEWED_ENVIRONMENT_EXTENSIONS = frozenset()
ENVIRONMENT_CLASSES = BASE_ENVIRONMENT_CLASSES | REVIEWED_ENVIRONMENT_EXTENSIONS
ENVIRONMENT_ALIASES = {"synthetic": "SYNTHETIC", "github-ci": "GITHUB_CI", "local-test": "LOCAL_TEST"}
LEGACY_TEST_REF_IDS = {"privacy","nested","bytes","criterion","rollback","secret","tokenish","listlimit","keylimit","mutation","mutation2"}
LEGACY_CI_RE = re.compile(r"^ci:RecoveryGuard#[1-9][0-9]{0,8}$")
LEGACY_TEST_RE = re.compile(r"^test:([a-z0-9-]{1,40})$")
EVIDENCE_PROVIDERS = {
    "GITHUB_ACTIONS", "SYNTHETIC_TEST", "DRIVE_CONTROL",
    "HOSTIQ_PRIVATE", "LIVE_ENDPOINT",
}
TEST_SUITES = {
    "UNIT_SUITE", "CONTRACT_SUITE", "DEPLOYMENT_REGRESSION",
    "SECRET_SCAN", "ACCEPTANCE_HARNESS", "INTEGRATION_SUITE",
}

BOOL_FACTS = {
    "success", "backup_created", "state_preserved", "persistent_state_preserved",
    "deduplicated", "authorized", "quiesced", "resumed", "audit_recorded",
    "stdout_present", "stderr_present", "error_present", "tree_scan_passed",
    "history_scan_passed", "private_serving_enforced", "preview_only",
    "commit_single_use", "restart_safe", "recoverable", "schema_valid",
    "keyboard_operable", "labels_present", "accessible_names_present",
    "heading_order_valid", "tab_order_valid", "mouse_only_absent",
}
INT_FACTS = {
    "count", "findings_count", "artifact_count", "persistent_entries_count",
    "file_count", "result_count", "page_count", "retry_count", "attempt",
    "duration_ms", "timeout_ms", "return_code", "http_status", "status_code",
    "rate_limit_remaining", "retry_after_seconds", "window_seconds",
    "job_checkpoint", "criteria_count",
}
SHA40_FACTS = {"previous_sha", "candidate_sha", "deployed_sha", "observed_sha"}
SHA256_FACTS = {
    "sha256", "backup_sha256", "manifest_sha256", "identifier_sha256",
    "chat_sha256", "message_sha256", "file_sha256", "payload_sha256",
    "operation_sha256", "idempotency_sha256",
}
ENUM_FACTS = {
    "state", "mode", "reason_code", "error_type", "scan_scope",
    "operation_kind", "rollback_state", "result_code", "environment_state",
    "method", "contract_status", "auth_state", "media_kind", "job_state",
    "preview_state", "commit_state", "scope", "error_code",
}
ENUM_LIST_FACTS = {"reason_codes", "checks", "capabilities", "coverage_tags"}
SHA256_LIST_FACTS = {"identifier_hashes", "file_hashes"}
ALL_FACT_KEYS = BOOL_FACTS | INT_FACTS | SHA40_FACTS | SHA256_FACTS | ENUM_FACTS | ENUM_LIST_FACTS | SHA256_LIST_FACTS

ENUM_VALUES = {
    "state": {
        "READY", "RUNNING", "RETRYABLE", "COMPLETED", "FAILED", "BLOCKED",
        "ROLLED_BACK", "DEPLOYED", "PREVIEWED", "COMMITTED", "RESERVED",
        "RECONCILE_REQUIRED", "NOT_YET_REQUIRED", "REQUIRED",
    },
    "mode": {"SYNTHETIC", "READ_ONLY", "PREVIEW", "COMMIT", "ROLLBACK", "RECOVERY"},
    "reason_code": {
        "SYNTHETIC_TEST_ONLY", "SANITIZED_SOURCE_PENDING", "PASSENGER_RUNTIME_PENDING",
        "SERVER_SETUP_NOT_READY", "HUMAN_INPUT_NOT_FIRST_BLOCKER",
        "SERVER_SETUP_FIRST_HUMAN_BLOCKER", "RATE_LIMITED", "IDEMPOTENCY_CONFLICT",
        "RECONCILE_REQUIRED", "EXPIRED", "INVALID", "USED",
    },
    "error_type": {"EXCEPTION", "RUNTIMEERROR", "VALUEERROR", "OSERROR", "TIMEOUTERROR", "SUBPROCESSERROR"},
    "scan_scope": {"PUBLIC_REPOSITORY", "CURRENT_TREE", "FULL_HISTORY", "WORKFLOW_LOGS"},
    "operation_kind": {"SEND", "REPLY", "FORWARD", "SEND_FILE", "READ", "SEARCH", "DOWNLOAD", "ZIP"},
    "rollback_state": {"ROLLED_BACK", "CRITICAL_ROLLBACK_FAILED", "PRELIVE_RECOVERED"},
    "result_code": {"COMMITTED", "IDEMPOTENCY_CONFLICT", "USED_PREVIEW", "EXPIRED_PREVIEW", "INVALID_PREVIEW", "RECONCILE_REQUIRED", "IDEMPOTENCY_RETIRED"},
    "environment_state": {"READY", "BLOCKED", "VERIFIED", "UNVERIFIED"},
    "method": {"UNIT", "INTEGRATION", "SYNTHETIC", "LIVE", "STATIC", "SMOKE"},
    "contract_status": {"SYNTHETIC_EXECUTABLE", "REAL_SOURCE_REQUIRED", "LIVE_EXTERNAL_REQUIRED"},
    "auth_state": {"CODE_REQUESTED", "FLOOD_WAIT", "RPC_ERROR", "INVALID_CODE", "INVALID_2FA", "AUTHORIZED", "USER_TELEGRAM_AUTH_NOT_YET_REQUIRED", "USER_TELEGRAM_AUTH_REQUIRED"},
    "media_kind": {"DOCUMENT", "PHOTO", "VOICE", "VIDEO", "AUDIO", "OTHER"},
    "job_state": {"READY", "RUNNING", "RETRYABLE", "COMPLETED", "FAILED"},
    "preview_state": {"PREVIEWED", "USED", "EXPIRED", "INVALID"},
    "commit_state": {"RESERVED", "COMMITTED", "RECONCILE_REQUIRED", "IDEMPOTENCY_CONFLICT", "RETIRED"},
    "scope": {"GLOBAL", "DIALOG", "PERSON", "DATE_WINDOW", "FILE_SET"},
    "error_code": {"NONE", "CONTROLLED_ERROR", "TIMEOUT", "RATE_LIMITED", "RPC_ERROR", "FLOOD_WAIT", "IDEMPOTENCY_CONFLICT"},
    "reason_codes": {
        "SYNTHETIC_TEST_ONLY", "SANITIZED_SOURCE_PENDING", "PASSENGER_RUNTIME_PENDING",
        "SERVER_SETUP_NOT_READY", "HUMAN_INPUT_NOT_FIRST_BLOCKER", "SERVER_SETUP_FIRST_HUMAN_BLOCKER",
        "RATE_LIMITED", "IDEMPOTENCY_CONFLICT", "RECONCILE_REQUIRED",
    },
    "checks": {
        "COMPILE", "UNIT", "INTEGRATION", "SECRET_SCAN_CURRENT", "SECRET_SCAN_HISTORY",
        "RECOVERY_GUARD", "NO_AUTODEPLOY", "PREPARE_VERIFY", "ROLLBACK", "ACCESSIBILITY",
    },
    "capabilities": {"READ", "SEARCH", "MEDIA", "DOWNLOAD", "ZIP", "PREVIEW", "COMMIT", "OPENAPI", "ACCESSIBILITY"},
    "coverage_tags": {"SYNTHETIC_EXECUTABLE", "REAL_SOURCE_REQUIRED", "LIVE_EXTERNAL_REQUIRED"},
}


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
    if CONTROL_RE.search(text) or "\n" in text or "\r" in text or "\t" in text:
        raise ValueError(f"control/multiline content rejected in {label}")
    if any(ord(ch) > 127 for ch in text):
        raise ValueError(f"non-ASCII private-label risk rejected in {label}")
    if any(pattern.search(text) for pattern in (PRIVATE_KEY_RE, SETUP_ROUTE_RE, AUTH_VALUE_RE, COOKIE_VALUE_RE, JWT_RE, SECRET_ASSIGNMENT_RE, SHARED_SECRET_ASSIGNMENT_RE)):
        raise ValueError(f"privacy-sensitive content rejected in {label}")
    if _looks_tokenish(text):
        raise ValueError(f"opaque token-like content rejected in {label}")


def validate_environment_class(value: str) -> str:
    if not isinstance(value, str): raise ValueError("unreviewed environment class")
    canonical = ENVIRONMENT_ALIASES.get(value, value)
    if canonical not in ENVIRONMENT_CLASSES: raise ValueError("unreviewed environment class")
    return canonical


def _positive_int(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0 or value > 10**18:
        raise ValueError(f"invalid {label}")
    return value


def validate_evidence_ref(value: Any) -> dict[str, Any]:
    """Validate structured refs; accept only a tiny reviewed legacy grammar."""
    if isinstance(value, str):
        if LEGACY_CI_RE.fullmatch(value):
            return {"provider":"GITHUB_ACTIONS","run_id":int(value.rsplit("#",1)[1]),"suite":"ACCEPTANCE_HARNESS"}
        match=LEGACY_TEST_RE.fullmatch(value)
        if match and match.group(1) in LEGACY_TEST_REF_IDS:
            return {"provider":"SYNTHETIC_TEST","suite":"UNIT_SUITE"}
        raise ValueError("unreviewed legacy evidence reference")
    if not isinstance(value, Mapping):
        raise ValueError("evidence_ref must be a structured mapping")
    data = dict(value)
    if len(data) > MAX_REFERENCE_KEYS or set(data) - {"provider", "run_id", "job_id", "suite", "evidence_sha256"}:
        raise ValueError("evidence reference schema mismatch")
    provider = data.get("provider")
    if provider not in EVIDENCE_PROVIDERS:
        raise ValueError("unreviewed evidence provider")
    cleaned: dict[str, Any] = {"provider": provider}
    if provider == "GITHUB_ACTIONS":
        cleaned["run_id"] = _positive_int(data.get("run_id"), "run_id")
        if "job_id" in data:
            cleaned["job_id"] = _positive_int(data["job_id"], "job_id")
        if "suite" in data:
            if data["suite"] not in TEST_SUITES:
                raise ValueError("unreviewed test suite")
            cleaned["suite"] = data["suite"]
        if "evidence_sha256" in data:
            if not isinstance(data["evidence_sha256"], str) or not SHA256_RE.fullmatch(data["evidence_sha256"]):
                raise ValueError("invalid evidence hash")
            cleaned["evidence_sha256"] = data["evidence_sha256"]
    elif provider == "SYNTHETIC_TEST":
        if data.get("suite") not in TEST_SUITES:
            raise ValueError("synthetic evidence requires reviewed suite")
        cleaned["suite"] = data["suite"]
        if set(data) - {"provider", "suite", "evidence_sha256"}:
            raise ValueError("synthetic evidence reference contains unsupported identifiers")
        if "evidence_sha256" in data:
            if not isinstance(data["evidence_sha256"], str) or not SHA256_RE.fullmatch(data["evidence_sha256"]):
                raise ValueError("invalid evidence hash")
            cleaned["evidence_sha256"] = data["evidence_sha256"]
    else:
        if set(data) - {"provider", "evidence_sha256"}:
            raise ValueError("private/control evidence must be hash-addressed only")
        digest = data.get("evidence_sha256")
        if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
            raise ValueError("hash-addressed evidence reference required")
        cleaned["evidence_sha256"] = digest
    return cleaned


def _validate_enum(value: Any, key: str) -> str:
    allowed = ENUM_VALUES.get(key, set())
    if not isinstance(value, str) or value not in allowed:
        raise ValueError(f"unreviewed enum fact: {key}")
    return value


def _validate_int(value: Any, key: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or abs(value) > MAX_INT:
        raise ValueError(f"invalid bounded integer fact: {key}")
    if key == "http_status" and not (100 <= value <= 599):
        raise ValueError("invalid HTTP status evidence")
    nonnegative = {
        "count", "attempt", "duration_ms", "timeout_ms", "retry_count", "rate_limit_remaining",
        "retry_after_seconds", "window_seconds", "job_checkpoint", "criteria_count",
        "findings_count", "artifact_count", "persistent_entries_count", "file_count", "result_count", "page_count",
    }
    if key in nonnegative and value < 0:
        raise ValueError(f"negative count/duration fact: {key}")
    return value


def validate_fact_value(key: str, value: Any) -> None:
    if key in BOOL_FACTS:
        if not isinstance(value, bool): raise ValueError(f"invalid boolean fact: {key}")
        return
    if key in INT_FACTS:
        _validate_int(value, key); return
    if key in SHA40_FACTS:
        if not isinstance(value, str) or not SHA40_RE.fullmatch(value): raise ValueError(f"invalid Git SHA fact: {key}")
        return
    if key in SHA256_FACTS:
        if not isinstance(value, str) or not SHA256_RE.fullmatch(value): raise ValueError(f"invalid SHA-256 fact: {key}")
        return
    if key in ENUM_FACTS:
        _validate_enum(value, key); return
    if key in ENUM_LIST_FACTS:
        if not isinstance(value, (list, tuple)) or len(value) > MAX_LIST_ITEMS: raise ValueError(f"invalid enum-list fact: {key}")
        for item in value: _validate_enum(item, key)
        return
    if key in SHA256_LIST_FACTS:
        if not isinstance(value, (list, tuple)) or len(value) > MAX_LIST_ITEMS: raise ValueError(f"invalid hash-list fact: {key}")
        for item in value:
            if not isinstance(item, str) or not SHA256_RE.fullmatch(item): raise ValueError(f"invalid hash-list item: {key}")
        return
    raise ValueError(f"fact key is not in the positive evidence schema: {key}")


def validate_facts(facts: Any, *, allowed_keys: Iterable[str]) -> dict[str, Any]:
    if facts is None: return {}
    if not isinstance(facts, dict): raise ValueError("facts must be a dictionary")
    if len(facts) > MAX_FACT_KEYS: raise ValueError("too many evidence facts")
    allowed = set(allowed_keys); cleaned: dict[str, Any] = {}
    for key, value in facts.items():
        if not isinstance(key, str) or key not in allowed or key not in ALL_FACT_KEYS:
            raise ValueError("evidence fact key not allowed for criterion")
        if isinstance(value, dict): raise ValueError("nested evidence dictionaries are forbidden")
        validate_fact_value(key, value)
        cleaned[key] = list(value) if isinstance(value, tuple) else value
    return cleaned


def _walk_structure(value: Any, *, depth: int = 0) -> None:
    if depth > MAX_DEPTH: raise ValueError("evidence nesting depth exceeded")
    if isinstance(value, dict):
        if len(value) > MAX_FACT_KEYS + 12: raise ValueError("evidence dictionary too large")
        for key, child in value.items():
            if not isinstance(key, str) or len(key) > 80: raise ValueError("invalid evidence key")
            _walk_structure(child, depth=depth + 1)
    elif isinstance(value, list):
        if len(value) > MAX_LIST_ITEMS: raise ValueError("evidence list too large")
        for child in value: _walk_structure(child, depth=depth + 1)
    elif isinstance(value, str):
        if len(value) > 240: raise ValueError("evidence string too large")
        reject_sensitive_text(value)
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
    if len(encoded) > MAX_EVIDENCE_BYTES: raise ValueError("aggregate evidence payload exceeds limit")


def sanitize_exception(exc: BaseException) -> dict[str, Any]:
    known = {
        "RuntimeError": "RUNTIMEERROR", "ValueError": "VALUEERROR", "OSError": "OSERROR",
        "TimeoutError": "TIMEOUTERROR", "SubprocessError": "SUBPROCESSERROR",
    }
    return {"error_type": known.get(type(exc).__name__, "EXCEPTION"), "error_present": True}


def _subprocess_output_present(value: Any, label: str) -> bool:
    """Return presence without invoking caller-controlled conversion hooks.

    subprocess stdout/stderr are only expected to be exact ``str``/``bytes`` or
    ``None``.  Reject subclasses and arbitrary objects rather than calling
    ``bool()``, ``str()``, ``repr()`` or custom properties that may raise with
    private text and escape the public evidence boundary.
    """
    if value is None:
        return False
    if type(value) is str or type(value) is bytes:
        return len(value) > 0
    raise ValueError(f"unsupported subprocess {label} type")


def sanitize_subprocess_result(return_code: int, *, stdout: Any = None, stderr: Any = None) -> dict[str, Any]:
    return {
        "return_code": _validate_int(return_code, "return_code"),
        "stdout_present": _subprocess_output_present(stdout, "stdout"),
        "stderr_present": _subprocess_output_present(stderr, "stderr"),
    }