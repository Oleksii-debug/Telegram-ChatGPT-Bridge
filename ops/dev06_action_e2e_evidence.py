# -*- coding: utf-8 -*-
"""Privacy-safe H2 read-only ChatGPT Action E2E evidence protocol.

This module performs no network, Telegram, HOSTiQ, ChatGPT, credential, or
production mutation. A future private live runner may pass one already-observed
read-only Action response through :func:`build_read_capture` while the private
payload exists only in process memory. The returned capture contains bounded
booleans/status identifiers only.

Neither a caller label nor a structurally valid capture proves that ChatGPT was
the caller. Consequently every public summary keeps ``product_h2_pass`` false
and requires independent Auditor adjudication of the private live provenance.
"""
from __future__ import annotations

import json
import os
import re
import stat
from pathlib import Path
from typing import Any, Mapping

from ops.dev06_api_contracts import ApiOperationClass, canonical_action
from ops.dev06_deployed_action_evidence import (
    PRODUCTION_BASE_URL,
    DeployedActionEvidenceError,
    schema_sha256,
    validate_evidence_summary as validate_h1_summary,
)
from ops.dev06_runtime_conformance import (
    build_compatible_chatgpt_action_openapi,
    validate_action_runtime_response,
)


MAX_H2_EVIDENCE_BYTES = 64 * 1024
_ALLOWED_CAPTURE_SOURCES = {"SOURCE_MOCK", "PRIVATE_LIVE_ACTION_CAPTURE"}
_SHA40_RE = re.compile(r"^[0-9a-f]{40}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class ActionE2EEvidenceError(DeployedActionEvidenceError):
    """Fail-closed H2 protocol/evidence error with stable public codes."""


def _require_sha40(value: Any) -> str:
    if not isinstance(value, str) or _SHA40_RE.fullmatch(value) is None:
        raise ActionE2EEvidenceError("H2_CANDIDATE_SHA_INVALID")
    return value


def _require_sha256(value: Any) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise ActionE2EEvidenceError("H2_SCHEMA_SHA256_INVALID")
    return value


def _require_bool(value: Any, code: str) -> bool:
    if not isinstance(value, bool):
        raise ActionE2EEvidenceError(code)
    return value


def _read_action(operation_id: Any):
    if not isinstance(operation_id, str):
        raise ActionE2EEvidenceError("H2_OPERATION_ID_INVALID")
    try:
        route = canonical_action(operation_id)
    except Exception:
        raise ActionE2EEvidenceError("H2_OPERATION_UNKNOWN") from None
    if route.operation_class is not ApiOperationClass.READ:
        raise ActionE2EEvidenceError("H2_OPERATION_NOT_READ_ONLY")
    return route


def build_read_capture(
    candidate_sha: str,
    operation_id: str,
    status: int,
    headers: Mapping[str, Any],
    payload: Any,
    *,
    source_classification: str = "SOURCE_MOCK",
    bearer_configured_privately: bool = False,
    chatgpt_action_observed: bool = False,
) -> dict[str, Any]:
    """Validate one already-observed read response and emit no response content.

    ``payload`` and ``headers`` are used only for in-memory conformance checking.
    They are never copied to the returned capture. The caller is responsible for
    acquiring them in an authorized private environment; this function never
    performs a request itself.
    """
    sha = _require_sha40(candidate_sha)
    route = _read_action(operation_id)
    if source_classification not in _ALLOWED_CAPTURE_SOURCES:
        raise ActionE2EEvidenceError("H2_SOURCE_CLASSIFICATION_INVALID")
    _require_bool(bearer_configured_privately, "H2_BEARER_ATTESTATION_INVALID")
    _require_bool(chatgpt_action_observed, "H2_CHATGPT_ATTESTATION_INVALID")
    if not isinstance(status, int) or isinstance(status, bool) or not 100 <= status <= 599:
        raise ActionE2EEvidenceError("H2_RESPONSE_STATUS_INVALID")
    if not isinstance(headers, Mapping):
        raise ActionE2EEvidenceError("H2_RESPONSE_HEADERS_INVALID")

    document = build_compatible_chatgpt_action_openapi(PRODUCTION_BASE_URL)
    errors = validate_action_runtime_response(
        document, route.action_operation_id or "", status, headers, payload
    )
    return {
        "schema_version": 1,
        "candidate_sha": sha,
        "source_classification": source_classification,
        "operation_id": route.action_operation_id,
        "action_schema_sha256": schema_sha256(document),
        "response_status": status,
        "response_schema_valid": not errors,
        "response_error_count": len(errors),
        "bearer_configured_privately": bearer_configured_privately,
        "chatgpt_action_observed": chatgpt_action_observed,
        "private_values_recorded": False,
    }


def validate_read_capture(capture: Mapping[str, Any]) -> None:
    required = {
        "schema_version",
        "candidate_sha",
        "source_classification",
        "operation_id",
        "action_schema_sha256",
        "response_status",
        "response_schema_valid",
        "response_error_count",
        "bearer_configured_privately",
        "chatgpt_action_observed",
        "private_values_recorded",
    }
    if not isinstance(capture, Mapping) or set(capture) != required:
        raise ActionE2EEvidenceError("H2_CAPTURE_SHAPE_INVALID")
    if capture.get("schema_version") != 1:
        raise ActionE2EEvidenceError("H2_CAPTURE_SCHEMA_VERSION_INVALID")
    _require_sha40(capture.get("candidate_sha"))
    _require_sha256(capture.get("action_schema_sha256"))
    if capture.get("source_classification") not in _ALLOWED_CAPTURE_SOURCES:
        raise ActionE2EEvidenceError("H2_SOURCE_CLASSIFICATION_INVALID")
    _read_action(capture.get("operation_id"))
    status = capture.get("response_status")
    if not isinstance(status, int) or isinstance(status, bool) or not 100 <= status <= 599:
        raise ActionE2EEvidenceError("H2_RESPONSE_STATUS_INVALID")
    count = capture.get("response_error_count")
    if not isinstance(count, int) or isinstance(count, bool) or not 0 <= count <= 128:
        raise ActionE2EEvidenceError("H2_RESPONSE_ERROR_COUNT_INVALID")
    valid = _require_bool(capture.get("response_schema_valid"), "H2_RESPONSE_VALID_FLAG_INVALID")
    _require_bool(capture.get("bearer_configured_privately"), "H2_BEARER_ATTESTATION_INVALID")
    _require_bool(capture.get("chatgpt_action_observed"), "H2_CHATGPT_ATTESTATION_INVALID")
    private = _require_bool(capture.get("private_values_recorded"), "H2_PRIVATE_FLAG_INVALID")
    if private:
        raise ActionE2EEvidenceError("H2_PRIVATE_VALUES_FORBIDDEN")
    if valid is not (count == 0):
        raise ActionE2EEvidenceError("H2_RESPONSE_VALIDITY_COUNT_DRIFT")


def summarize_h2_candidate(
    candidate_sha: str,
    h1_summary: Mapping[str, Any],
    capture: Mapping[str, Any],
) -> dict[str, Any]:
    """Bind H2 candidate evidence to the exact H1-compatible deployed schema."""
    sha = _require_sha40(candidate_sha)
    try:
        validate_h1_summary(h1_summary)
    except Exception:
        raise ActionE2EEvidenceError("H2_H1_SUMMARY_INVALID") from None
    validate_read_capture(capture)

    if h1_summary.get("candidate_sha") != sha or capture.get("candidate_sha") != sha:
        raise ActionE2EEvidenceError("H2_CANDIDATE_BINDING_MISMATCH")
    if h1_summary.get("source_classification") != "DEPLOYED_CAPTURE":
        h1_deployed_match = False
    else:
        h1_deployed_match = bool(h1_summary.get("schema_match"))

    expected_document = build_compatible_chatgpt_action_openapi(PRODUCTION_BASE_URL)
    expected_schema_digest = schema_sha256(expected_document)
    h1_expected = _require_sha256(h1_summary.get("expected_schema_sha256"))
    h1_observed = _require_sha256(h1_summary.get("observed_schema_sha256"))
    capture_digest = _require_sha256(capture.get("action_schema_sha256"))
    schema_binding_match = (
        h1_expected == expected_schema_digest
        and h1_observed == expected_schema_digest
        and capture_digest == expected_schema_digest
    )
    if h1_deployed_match and not schema_binding_match:
        raise ActionE2EEvidenceError("H2_DEPLOYED_SCHEMA_BINDING_MISMATCH")

    live_capture = capture.get("source_classification") == "PRIVATE_LIVE_ACTION_CAPTURE"
    response_ok = (
        capture.get("response_status") == 200
        and capture.get("response_schema_valid") is True
        and capture.get("response_error_count") == 0
    )
    live_evidence_candidate = bool(
        h1_deployed_match
        and schema_binding_match
        and live_capture
        and response_ok
        and capture.get("bearer_configured_privately") is True
        and capture.get("chatgpt_action_observed") is True
    )

    summary = {
        "schema_version": 1,
        "candidate_sha": sha,
        "operation_id": capture.get("operation_id"),
        "action_schema_sha256": expected_schema_digest,
        "h1_deployed_schema_match": h1_deployed_match,
        "schema_binding_match": schema_binding_match,
        "read_only_operation": True,
        "live_capture_classification": live_capture,
        "response_200_schema_valid": response_ok,
        "bearer_configured_privately": capture.get("bearer_configured_privately"),
        "chatgpt_action_observed": capture.get("chatgpt_action_observed"),
        "live_evidence_candidate": live_evidence_candidate,
        "product_h2_pass": False,
        "auditor_adjudication_required": True,
        "deployment_authorized": False,
        "production_mutated": False,
        "private_values_recorded": False,
    }
    validate_h2_summary(summary)
    return summary


def validate_h2_summary(summary: Mapping[str, Any]) -> None:
    required = {
        "schema_version",
        "candidate_sha",
        "operation_id",
        "action_schema_sha256",
        "h1_deployed_schema_match",
        "schema_binding_match",
        "read_only_operation",
        "live_capture_classification",
        "response_200_schema_valid",
        "bearer_configured_privately",
        "chatgpt_action_observed",
        "live_evidence_candidate",
        "product_h2_pass",
        "auditor_adjudication_required",
        "deployment_authorized",
        "production_mutated",
        "private_values_recorded",
    }
    if not isinstance(summary, Mapping) or set(summary) != required:
        raise ActionE2EEvidenceError("H2_SUMMARY_SHAPE_INVALID")
    if summary.get("schema_version") != 1:
        raise ActionE2EEvidenceError("H2_SUMMARY_SCHEMA_VERSION_INVALID")
    _require_sha40(summary.get("candidate_sha"))
    _require_sha256(summary.get("action_schema_sha256"))
    _read_action(summary.get("operation_id"))
    for key in required - {
        "schema_version", "candidate_sha", "operation_id", "action_schema_sha256"
    }:
        _require_bool(summary.get(key), "H2_SUMMARY_BOOLEAN_INVALID")
    if summary.get("read_only_operation") is not True:
        raise ActionE2EEvidenceError("H2_SUMMARY_MUST_BE_READ_ONLY")
    if summary.get("auditor_adjudication_required") is not True:
        raise ActionE2EEvidenceError("H2_AUDITOR_GATE_REQUIRED")
    if any(
        summary.get(key) is True
        for key in (
            "product_h2_pass",
            "deployment_authorized",
            "production_mutated",
            "private_values_recorded",
        )
    ):
        raise ActionE2EEvidenceError("H2_SUMMARY_MUST_NOT_SELF_AUTHORIZE_OR_RECORD_PRIVATE_VALUES")
    candidate_expected = all(
        summary.get(key) is True
        for key in (
            "h1_deployed_schema_match",
            "schema_binding_match",
            "read_only_operation",
            "live_capture_classification",
            "response_200_schema_valid",
            "bearer_configured_privately",
            "chatgpt_action_observed",
        )
    )
    if summary.get("live_evidence_candidate") is not candidate_expected:
        raise ActionE2EEvidenceError("H2_LIVE_CANDIDATE_STATE_INVALID")


def _load_bounded_json(path: str | Path) -> Mapping[str, Any]:
    raw_path = os.fspath(path)
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(raw_path, flags)
    except OSError:
        raise ActionE2EEvidenceError("H2_EVIDENCE_FILE_UNSAFE") from None
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_size <= 0
            or info.st_size > MAX_H2_EVIDENCE_BYTES
        ):
            raise ActionE2EEvidenceError("H2_EVIDENCE_FILE_UNSAFE")
        data = os.read(fd, MAX_H2_EVIDENCE_BYTES + 1)
        if len(data) > MAX_H2_EVIDENCE_BYTES:
            raise ActionE2EEvidenceError("H2_EVIDENCE_FILE_TOO_LARGE")
    finally:
        os.close(fd)
    try:
        parsed = json.loads(data.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError):
        raise ActionE2EEvidenceError("H2_EVIDENCE_JSON_INVALID") from None
    if not isinstance(parsed, Mapping):
        raise ActionE2EEvidenceError("H2_EVIDENCE_JSON_NOT_OBJECT")
    return parsed


def load_h1_summary(path: str | Path) -> Mapping[str, Any]:
    parsed = _load_bounded_json(path)
    try:
        validate_h1_summary(parsed)
    except Exception:
        raise ActionE2EEvidenceError("H2_H1_SUMMARY_INVALID") from None
    return parsed


def load_h2_capture(path: str | Path) -> Mapping[str, Any]:
    parsed = _load_bounded_json(path)
    validate_read_capture(parsed)
    return parsed
