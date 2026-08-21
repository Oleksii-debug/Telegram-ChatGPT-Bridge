# -*- coding: utf-8 -*-
"""Machine-readable acceptance planning/evidence helpers for Telegram Bridge.

This module does not claim product PASS. Planning states describe harness readiness only.
Real PASS/FAIL/BLOCKED evidence is emitted separately and must name an exact code SHA,
environment class and non-secret evidence reference.
"""
from __future__ import annotations

import json
import re
from typing import Any

PLAN_STATUSES = {"IMPLEMENTED_TEST", "READY_FOR_REAL_SOURCE", "EXTERNALLY_BLOCKED", "NOT_IMPLEMENTED"}
RESULT_STATUSES = {"PASS", "FAIL", "BLOCKED"}
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
SAFE_ENV_RE = re.compile(r"^[A-Za-z0-9._-]{1,80}$")
SAFE_REF_RE = re.compile(r"^[A-Za-z0-9._:/#-]{1,240}$")
FORBIDDEN_KEYS = {
    "token", "bearer", "authorization", "api_hash", "api_id", "session",
    "session_string", "password", "2fa", "phone", "login_code", "code",
    "nonce", "setup_route", "message_body", "message_text", "file_content",
    "private_content", "media_content", "cookie", "cookies",
}

ACCEPTANCE_MATRIX = [
    {"criterion": "A1", "description": "Python 3.11 compile/import checks pass.", "plan_status": "READY_FOR_REAL_SOURCE"},
    {"criterion": "A2", "description": "WSGI application imports successfully.", "plan_status": "READY_FOR_REAL_SOURCE"},
    {"criterion": "A3", "description": "Health endpoint responds within timeout.", "plan_status": "READY_FOR_REAL_SOURCE"},
    {"criterion": "A4", "description": "Invalid route does not leak stack traces/secrets.", "plan_status": "READY_FOR_REAL_SOURCE"},
    {"criterion": "A5", "description": "Restart preserves private session/config.", "plan_status": "READY_FOR_REAL_SOURCE"},
    {"criterion": "B1", "description": "Protected endpoints reject missing bearer/auth.", "plan_status": "READY_FOR_REAL_SOURCE"},
    {"criterion": "B2", "description": "Wrong token cannot retrieve Telegram content.", "plan_status": "READY_FOR_REAL_SOURCE"},
    {"criterion": "B3", "description": "Logs do not contain API hash, session, 2FA, bearer token, message bodies or private file contents.", "plan_status": "READY_FOR_REAL_SOURCE"},
    {"criterion": "B4", "description": "Repository/history/PR/Actions artifacts contain no secrets.", "plan_status": "IMPLEMENTED_TEST"},
    {"criterion": "B5", "description": "Path traversal attempts are rejected.", "plan_status": "READY_FOR_REAL_SOURCE"},
    {"criterion": "B6", "description": "File IDs cannot be used to read arbitrary server files.", "plan_status": "READY_FOR_REAL_SOURCE"},
    {"criterion": "B7", "description": "Malformed JSON/parameters return controlled errors.", "plan_status": "READY_FOR_REAL_SOURCE"},
    {"criterion": "B8", "description": "Rate limits prevent obvious abuse.", "plan_status": "READY_FOR_REAL_SOURCE"},
    {"criterion": "C1", "description": "One-time setup is keyboard/NVDA accessible.", "plan_status": "READY_FOR_REAL_SOURCE"},
    {"criterion": "C2", "description": "Setup route is protected/one-time and disabled/rotated after successful setup as designed.", "plan_status": "READY_FOR_REAL_SOURCE"},
    {"criterion": "C3", "description": "Code request/auth flow handles Telegram errors safely.", "plan_status": "READY_FOR_REAL_SOURCE"},
    {"criterion": "C4", "description": "2FA flow works when required.", "plan_status": "READY_FOR_REAL_SOURCE"},
    {"criterion": "C5", "description": "Restart does not lose the authorized session.", "plan_status": "READY_FOR_REAL_SOURCE"},
    {"criterion": "C6", "description": "FloodWait/RPC failures are handled without corrupting state.", "plan_status": "READY_FOR_REAL_SOURCE"},
    {"criterion": "D1", "description": "List dialogs works.", "plan_status": "READY_FOR_REAL_SOURCE"},
    {"criterion": "D2", "description": "Read history returns correct ordering and pagination.", "plan_status": "READY_FOR_REAL_SOURCE"},
    {"criterion": "D3", "description": "Global/scoped search works.", "plan_status": "READY_FOR_REAL_SOURCE"},
    {"criterion": "D4", "description": "Filters by chat/person/text/date behave correctly.", "plan_status": "READY_FOR_REAL_SOURCE"},
    {"criterion": "D5", "description": "Unicode/Cyrillic text remains intact.", "plan_status": "READY_FOR_REAL_SOURCE"},
    {"criterion": "D6", "description": "Empty/no-result cases are controlled.", "plan_status": "READY_FOR_REAL_SOURCE"},
    {"criterion": "E1", "description": "Metadata listing works for documents/media/voice/photo where supported.", "plan_status": "READY_FOR_REAL_SOURCE"},
    {"criterion": "E2", "description": "Single-file download works and validates expected file.", "plan_status": "READY_FOR_REAL_SOURCE"},
    {"criterion": "E3", "description": "Bulk download applies requested filters and does not duplicate files.", "plan_status": "READY_FOR_REAL_SOURCE"},
    {"criterion": "E4", "description": "ZIP generation produces a valid archive.", "plan_status": "READY_FOR_REAL_SOURCE"},
    {"criterion": "E5", "description": "Interrupted/failed download leaves recoverable state and useful error.", "plan_status": "READY_FOR_REAL_SOURCE"},
    {"criterion": "E6", "description": "Downloaded private files are not exposed by unauthenticated public URLs.", "plan_status": "READY_FOR_REAL_SOURCE"},
    {"criterion": "F1", "description": "Send has preview stage.", "plan_status": "READY_FOR_REAL_SOURCE"},
    {"criterion": "F2", "description": "Reply has preview stage and correct reply target.", "plan_status": "READY_FOR_REAL_SOURCE"},
    {"criterion": "F3", "description": "Forward has preview stage.", "plan_status": "READY_FOR_REAL_SOURCE"},
    {"criterion": "F4", "description": "Send-files has preview stage.", "plan_status": "READY_FOR_REAL_SOURCE"},
    {"criterion": "F5", "description": "Commit requires a valid single-use preview token or equivalent approved mechanism.", "plan_status": "READY_FOR_REAL_SOURCE"},
    {"criterion": "F6", "description": "Repeating the same commit does not duplicate the action.", "plan_status": "READY_FOR_REAL_SOURCE"},
    {"criterion": "F7", "description": "Expired/used/invalid preview token fails safely.", "plan_status": "READY_FOR_REAL_SOURCE"},
    {"criterion": "F8", "description": "Audit metadata records operation without recording private body/secrets.", "plan_status": "READY_FOR_REAL_SOURCE"},
    {"criterion": "G1", "description": "Idempotency store behaves correctly under retry.", "plan_status": "READY_FOR_REAL_SOURCE"},
    {"criterion": "G2", "description": "Duplicate protection survives reasonable restart/retry scenarios.", "plan_status": "READY_FOR_REAL_SOURCE"},
    {"criterion": "G3", "description": "Timeouts are explicit.", "plan_status": "READY_FOR_REAL_SOURCE"},
    {"criterion": "G4", "description": "Errors do not leave corrupt DB/job state.", "plan_status": "READY_FOR_REAL_SOURCE"},
    {"criterion": "G5", "description": "Jobs can be resumed/retried safely where designed.", "plan_status": "READY_FOR_REAL_SOURCE"},
    {"criterion": "H1", "description": "Generated OpenAPI schema matches deployed endpoints.", "plan_status": "READY_FOR_REAL_SOURCE"},
    {"criterion": "H2", "description": "Read-only Action calls work end-to-end.", "plan_status": "EXTERNALLY_BLOCKED"},
    {"criterion": "H3", "description": "Unauthorized calls fail without data leakage.", "plan_status": "READY_FOR_REAL_SOURCE"},
    {"criterion": "H4", "description": "Write operations preserve preview/commit safety.", "plan_status": "READY_FOR_REAL_SOURCE"},
    {"criterion": "H5", "description": "ChatGPT receives useful structured errors.", "plan_status": "READY_FOR_REAL_SOURCE"},
    {"criterion": "I1", "description": "Setup page is fully operable with keyboard.", "plan_status": "READY_FOR_REAL_SOURCE"},
    {"criterion": "I2", "description": "Inputs have explicit labels.", "plan_status": "READY_FOR_REAL_SOURCE"},
    {"criterion": "I3", "description": "Buttons have accessible names.", "plan_status": "READY_FOR_REAL_SOURCE"},
    {"criterion": "I4", "description": "Logical Tab order.", "plan_status": "READY_FOR_REAL_SOURCE"},
    {"criterion": "I5", "description": "Heading structure is meaningful.", "plan_status": "READY_FOR_REAL_SOURCE"},
    {"criterion": "I6", "description": "Error/status messages are text and readable by NVDA.", "plan_status": "READY_FOR_REAL_SOURCE"},
    {"criterion": "I7", "description": "No mouse-only control.", "plan_status": "READY_FOR_REAL_SOURCE"},
    {"criterion": "J1", "description": "Deployed commit SHA is known.", "plan_status": "EXTERNALLY_BLOCKED"},
    {"criterion": "J2", "description": "Backup is created before production change.", "plan_status": "IMPLEMENTED_TEST"},
    {"criterion": "J3", "description": "Runtime secrets/session are preserved.", "plan_status": "IMPLEMENTED_TEST"},
    {"criterion": "J4", "description": "Health/smoke tests run after deploy.", "plan_status": "EXTERNALLY_BLOCKED"},
    {"criterion": "J5", "description": "Failed deploy can restore last-known-good release.", "plan_status": "IMPLEMENTED_TEST"},
    {"criterion": "J6", "description": "Main branch and production state are traceable.", "plan_status": "EXTERNALLY_BLOCKED"},
    {"criterion": "K1", "description": "Ask for list of chats and receive it.", "plan_status": "EXTERNALLY_BLOCKED"},
    {"criterion": "K2", "description": "Ask for a person's recent messages and receive correct results.", "plan_status": "EXTERNALLY_BLOCKED"},
    {"criterion": "K3", "description": "Ask for files from a chat/date window and receive correct package.", "plan_status": "EXTERNALLY_BLOCKED"},
    {"criterion": "K4", "description": "Ask for a draft/preview reply; no message is sent before explicit commit.", "plan_status": "EXTERNALLY_BLOCKED"},
    {"criterion": "K5", "description": "Explicitly commit a test message to a safe destination and verify exactly one send.", "plan_status": "EXTERNALLY_BLOCKED"},
]

CRITERIA = {item["criterion"]: item for item in ACCEPTANCE_MATRIX}


def _privacy_safe(value: Any, path: str = "root") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            normalized = str(key).strip().lower()
            if normalized in FORBIDDEN_KEYS or any(
                needle in normalized for needle in ("secret", "credential", "private_key")
            ):
                raise ValueError(f"privacy-unsafe evidence field at {path}")
            _privacy_safe(child, f"{path}.{key}")
    elif isinstance(value, (list, tuple)):
        for index, child in enumerate(value):
            _privacy_safe(child, f"{path}[{index}]")
    elif isinstance(value, str):
        if len(value) > 1000:
            raise ValueError("evidence string is unbounded")
        lowered = value.lower()
        if "-----begin " in lowered and "private key-----" in lowered:
            raise ValueError("private key material forbidden")
    elif value is not None and not isinstance(value, (bool, int, float)):
        raise ValueError("unsupported evidence value")


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


def build_result(*, criterion: str, code_sha: str, environment_class: str,
                 result: str, evidence_ref: str, facts: dict[str, Any] | None = None) -> dict[str, Any]:
    if criterion not in CRITERIA:
        raise ValueError("unknown acceptance criterion")
    if not SHA_RE.fullmatch(code_sha):
        raise ValueError("exact 40-character code SHA required")
    if not SAFE_ENV_RE.fullmatch(environment_class):
        raise ValueError("invalid environment class")
    if result not in RESULT_STATUSES:
        raise ValueError("invalid result status")
    if not SAFE_REF_RE.fullmatch(evidence_ref):
        raise ValueError("invalid evidence reference")
    payload = {
        "schema_version": 1,
        "criterion": criterion,
        "code_sha": code_sha,
        "environment_class": environment_class,
        "result": result,
        "evidence_ref": evidence_ref,
        "facts": facts or {},
    }
    _privacy_safe(payload)
    return payload


def serialize_result(payload: dict[str, Any]) -> str:
    _privacy_safe(payload)
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


validate_matrix()
