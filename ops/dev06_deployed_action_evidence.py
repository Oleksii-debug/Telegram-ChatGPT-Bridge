# -*- coding: utf-8 -*-
"""Privacy-safe deployment-bound ChatGPT Action schema comparison for DEV06.

This module performs no network, Telegram, HOSTiQ or production mutation. It
compares an externally captured/sanitized OpenAPI document with the exact DEV06
schema generated for a candidate and emits hashes/counts/stable mismatch codes
only. A matching result is evidence input for H1; it never self-authorizes H1,
deployment, K5, or any live operation.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlsplit

from ops.dev06_api_contracts import CANONICAL_ROUTES, ApiExposure
from ops.dev06_runtime_conformance import (
    ResponseContractError,
    build_compatible_chatgpt_action_openapi,
    validate_action_compatibility,
)


PRODUCTION_BASE_URL = "https://tg-api.rukadopomogy.org.ua"
MAX_SCHEMA_BYTES = 1024 * 1024  # ingestion safety bound, not a ChatGPT platform limit
_ALLOWED_SOURCE_CLASSIFICATIONS = {"SOURCE_MOCK", "DEPLOYED_CAPTURE"}
_ALLOWED_MISMATCH_CODES = frozenset({
    "DOCUMENT_DIGEST_DRIFT",
    "OBSERVED_SCHEMA_VALIDATION_FAILED",
    "OPERATION_CONTRACT_DRIFT",
    "OPERATION_COUNT_DRIFT",
    "PATH_SET_DRIFT",
    "ROOT_SECURITY_DRIFT",
    "SERVER_ORIGIN_DRIFT",
})
_SHA40_RE = re.compile(r"^[0-9a-f]{40}$")


class DeployedActionEvidenceError(ResponseContractError):
    """Fail-closed deployed Action comparison error with stable public codes."""


def _require_candidate_sha(value: str) -> str:
    raw = str(value or "").strip()
    if _SHA40_RE.fullmatch(raw) is None:
        raise DeployedActionEvidenceError("CANDIDATE_SHA_INVALID")
    return raw


def _require_source_classification(value: str) -> str:
    raw = str(value or "").strip().upper()
    if raw not in _ALLOWED_SOURCE_CLASSIFICATIONS:
        raise DeployedActionEvidenceError("SOURCE_CLASSIFICATION_INVALID")
    return raw


def _require_base_url(value: str) -> str:
    raw = str(value or "").strip()
    parts = urlsplit(raw)
    if (
        parts.scheme != "https"
        or not parts.netloc
        or parts.username is not None
        or parts.password is not None
        or parts.query
        or parts.fragment
        or parts.path not in {"", "/"}
    ):
        raise DeployedActionEvidenceError("BASE_URL_INVALID")
    normalized = raw[:-1] if raw.endswith("/") else raw
    # H1 is production-deployment evidence, not a generic HTTPS schema comparator.
    # Letting the caller redefine the expected origin would allow a wrong-host
    # capture to compare cleanly against a schema generated for that same host.
    if normalized != PRODUCTION_BASE_URL:
        raise DeployedActionEvidenceError("BASE_URL_NOT_PRODUCTION")
    return normalized


def canonical_json_bytes(document: Mapping[str, Any]) -> bytes:
    if not isinstance(document, Mapping):
        raise DeployedActionEvidenceError("SCHEMA_DOCUMENT_NOT_OBJECT")
    try:
        encoded = json.dumps(
            document,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError):
        raise DeployedActionEvidenceError("SCHEMA_DOCUMENT_NOT_CANONICAL_JSON") from None
    if not encoded or len(encoded) > MAX_SCHEMA_BYTES:
        raise DeployedActionEvidenceError("SCHEMA_DOCUMENT_SIZE_INVALID")
    return encoded


def schema_sha256(document: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_json_bytes(document)).hexdigest()


def _origin_sha256(base_url: str) -> str:
    return hashlib.sha256(base_url.encode("utf-8")).hexdigest()


def _declared_operation_count(document: Mapping[str, Any]) -> int:
    paths = document.get("paths")
    if not isinstance(paths, Mapping):
        return 0
    count = 0
    for item in paths.values():
        if not isinstance(item, Mapping):
            continue
        for operation in item.values():
            if isinstance(operation, Mapping) and isinstance(operation.get("operationId"), str):
                count += 1
    return count


def _expected_action_routes() -> tuple[Any, ...]:
    return tuple(route for route in CANONICAL_ROUTES if route.exposure is ApiExposure.ACTION)


def _operation_drift_count(expected: Mapping[str, Any], observed: Mapping[str, Any]) -> int:
    expected_paths = expected.get("paths")
    observed_paths = observed.get("paths")
    if not isinstance(expected_paths, Mapping) or not isinstance(observed_paths, Mapping):
        return len(_expected_action_routes())
    drift = 0
    for route in _expected_action_routes():
        exp_item = expected_paths.get(route.path)
        obs_item = observed_paths.get(route.path)
        exp_op = exp_item.get("post") if isinstance(exp_item, Mapping) else None
        obs_op = obs_item.get("post") if isinstance(obs_item, Mapping) else None
        if not isinstance(exp_op, Mapping) or not isinstance(obs_op, Mapping):
            drift += 1
            continue
        try:
            if canonical_json_bytes(exp_op) != canonical_json_bytes(obs_op):
                drift += 1
        except DeployedActionEvidenceError:
            drift += 1
    return drift


def _path_set(document: Mapping[str, Any]) -> set[str] | None:
    paths = document.get("paths")
    if not isinstance(paths, Mapping):
        return None
    return {str(path) for path in paths}


def _server_list(document: Mapping[str, Any]) -> Any:
    return document.get("servers")


def _root_security(document: Mapping[str, Any]) -> Any:
    return document.get("security")


def compare_deployed_action_schema(
    candidate_sha: str,
    observed_document: Mapping[str, Any],
    *,
    base_url: str = PRODUCTION_BASE_URL,
    source_classification: str = "SOURCE_MOCK",
) -> dict[str, Any]:
    """Compare expected vs captured schema and emit privacy-safe bounded evidence.

    ``source_classification`` is a caller-supplied provenance label only. Even a
    ``DEPLOYED_CAPTURE`` match leaves ``product_h1_pass`` and
    ``deployment_authorized`` false; independent audit/live provenance is a
    separate gate.
    """
    sha = _require_candidate_sha(candidate_sha)
    source = _require_source_classification(source_classification)
    origin = _require_base_url(base_url)
    expected = build_compatible_chatgpt_action_openapi(origin)

    expected_bytes = canonical_json_bytes(expected)
    observed_bytes = canonical_json_bytes(observed_document)
    expected_digest = hashlib.sha256(expected_bytes).hexdigest()
    observed_digest = hashlib.sha256(observed_bytes).hexdigest()

    mismatch_codes: list[str] = []
    try:
        observed_validation = validate_action_compatibility(observed_document)
    except Exception:
        observed_validation = ["invalid"]
    if observed_validation:
        mismatch_codes.append("OBSERVED_SCHEMA_VALIDATION_FAILED")

    expected_paths = _path_set(expected)
    observed_paths = _path_set(observed_document)
    if expected_paths != observed_paths:
        mismatch_codes.append("PATH_SET_DRIFT")
    if _server_list(expected) != _server_list(observed_document):
        mismatch_codes.append("SERVER_ORIGIN_DRIFT")
    if _root_security(expected) != _root_security(observed_document):
        mismatch_codes.append("ROOT_SECURITY_DRIFT")

    expected_operation_count = _declared_operation_count(expected)
    observed_operation_count = _declared_operation_count(observed_document)
    if expected_operation_count != observed_operation_count:
        mismatch_codes.append("OPERATION_COUNT_DRIFT")

    operation_drift_count = _operation_drift_count(expected, observed_document)
    if operation_drift_count:
        mismatch_codes.append("OPERATION_CONTRACT_DRIFT")

    if expected_digest != observed_digest:
        mismatch_codes.append("DOCUMENT_DIGEST_DRIFT")

    mismatch_codes = sorted(set(mismatch_codes))
    schema_match = not mismatch_codes and expected_digest == observed_digest
    summary: dict[str, Any] = {
        "schema_version": 1,
        "candidate_sha": sha,
        "source_classification": source,
        "server_origin_sha256": _origin_sha256(origin),
        "expected_schema_sha256": expected_digest,
        "observed_schema_sha256": observed_digest,
        "expected_schema_bytes": len(expected_bytes),
        "observed_schema_bytes": len(observed_bytes),
        "expected_operation_count": expected_operation_count,
        "observed_operation_count": observed_operation_count,
        "operation_drift_count": operation_drift_count,
        "mismatch_count": len(mismatch_codes),
        "mismatch_codes": mismatch_codes,
        "schema_match": schema_match,
        "product_h1_pass": False,
        "deployment_authorized": False,
        "production_mutated": False,
        "private_values_recorded": False,
    }
    validate_evidence_summary(summary)
    return summary


def validate_evidence_summary(summary: Mapping[str, Any]) -> None:
    required = {
        "schema_version", "candidate_sha", "source_classification", "server_origin_sha256",
        "expected_schema_sha256", "observed_schema_sha256", "expected_schema_bytes",
        "observed_schema_bytes", "expected_operation_count", "observed_operation_count",
        "operation_drift_count", "mismatch_count", "mismatch_codes", "schema_match",
        "product_h1_pass", "deployment_authorized", "production_mutated",
        "private_values_recorded",
    }
    if not isinstance(summary, Mapping) or set(summary) != required:
        raise DeployedActionEvidenceError("EVIDENCE_SUMMARY_SHAPE_INVALID")
    if summary.get("schema_version") != 1:
        raise DeployedActionEvidenceError("EVIDENCE_SCHEMA_VERSION_INVALID")
    _require_candidate_sha(summary["candidate_sha"])
    _require_source_classification(summary["source_classification"])
    for key in ("server_origin_sha256", "expected_schema_sha256", "observed_schema_sha256"):
        value = summary.get(key)
        if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
            raise DeployedActionEvidenceError("EVIDENCE_DIGEST_INVALID")
    for key in (
        "expected_schema_bytes", "observed_schema_bytes", "expected_operation_count",
        "observed_operation_count", "operation_drift_count", "mismatch_count",
    ):
        value = summary.get(key)
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise DeployedActionEvidenceError("EVIDENCE_COUNT_INVALID")
    if (
        summary["expected_schema_bytes"] > MAX_SCHEMA_BYTES
        or summary["observed_schema_bytes"] > MAX_SCHEMA_BYTES
        or summary["expected_operation_count"] > 1024
        or summary["observed_operation_count"] > 1024
        or summary["operation_drift_count"] > 1024
        or summary["mismatch_count"] > len(_ALLOWED_MISMATCH_CODES)
    ):
        raise DeployedActionEvidenceError("EVIDENCE_COUNT_INVALID")

    codes = summary.get("mismatch_codes")
    if (
        not isinstance(codes, list)
        or len(codes) > len(_ALLOWED_MISMATCH_CODES)
        or any(code not in _ALLOWED_MISMATCH_CODES for code in codes)
        or codes != sorted(set(codes))
    ):
        raise DeployedActionEvidenceError("EVIDENCE_MISMATCH_CODES_INVALID")
    if summary["mismatch_count"] != len(codes):
        raise DeployedActionEvidenceError("EVIDENCE_MISMATCH_COUNT_INVALID")

    for key in (
        "schema_match", "product_h1_pass", "deployment_authorized",
        "production_mutated", "private_values_recorded",
    ):
        if not isinstance(summary.get(key), bool):
            raise DeployedActionEvidenceError("EVIDENCE_BOOLEAN_INVALID")
    if any(summary[key] for key in (
        "product_h1_pass", "deployment_authorized", "production_mutated", "private_values_recorded"
    )):
        raise DeployedActionEvidenceError("EVIDENCE_MUST_NOT_SELF_AUTHORIZE_OR_RECORD_PRIVATE_VALUES")

    expected_document = build_compatible_chatgpt_action_openapi(PRODUCTION_BASE_URL)
    expected_bytes = canonical_json_bytes(expected_document)
    expected_digest = hashlib.sha256(expected_bytes).hexdigest()
    expected_operation_count = _declared_operation_count(expected_document)
    if summary["server_origin_sha256"] != _origin_sha256(PRODUCTION_BASE_URL):
        raise DeployedActionEvidenceError("EVIDENCE_ORIGIN_BINDING_INVALID")
    if (
        summary["expected_schema_sha256"] != expected_digest
        or summary["expected_schema_bytes"] != len(expected_bytes)
        or summary["expected_operation_count"] != expected_operation_count
    ):
        raise DeployedActionEvidenceError("EVIDENCE_SOURCE_SCHEMA_BINDING_INVALID")

    derived_match = bool(
        summary["mismatch_count"] == 0
        and summary["expected_schema_sha256"] == summary["observed_schema_sha256"]
        and summary["expected_schema_bytes"] == summary["observed_schema_bytes"]
        and summary["expected_operation_count"] == summary["observed_operation_count"]
        and summary["operation_drift_count"] == 0
    )
    if summary["schema_match"] is not derived_match:
        raise DeployedActionEvidenceError("EVIDENCE_MATCH_STATE_INVALID")


def _stat_fingerprint(info: os.stat_result) -> tuple[int, int, int, int, int, int, int]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_nlink,
        info.st_size,
        getattr(info, "st_mtime_ns", int(info.st_mtime * 1_000_000_000)),
        getattr(info, "st_ctime_ns", int(info.st_ctime * 1_000_000_000)),
    )


def load_observed_schema(path: str | Path) -> Mapping[str, Any]:
    """Read one bounded regular no-follow JSON file without exposing its path."""
    raw_path = os.fspath(path)
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(raw_path, flags)
    except OSError:
        raise DeployedActionEvidenceError("OBSERVED_SCHEMA_FILE_UNSAFE") from None
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size <= 0 or before.st_size > MAX_SCHEMA_BYTES:
            raise DeployedActionEvidenceError("OBSERVED_SCHEMA_FILE_UNSAFE")
        chunks: list[bytes] = []
        remaining = MAX_SCHEMA_BYTES + 1
        while remaining > 0:
            chunk = os.read(fd, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        if len(data) > MAX_SCHEMA_BYTES:
            raise DeployedActionEvidenceError("OBSERVED_SCHEMA_FILE_TOO_LARGE")
        after = os.fstat(fd)
        if _stat_fingerprint(before) != _stat_fingerprint(after) or len(data) != before.st_size:
            raise DeployedActionEvidenceError("OBSERVED_SCHEMA_FILE_CHANGED_DURING_READ")
    finally:
        os.close(fd)
    try:
        decoded = data.decode("utf-8")
        parsed = json.loads(decoded)
    except (UnicodeError, json.JSONDecodeError):
        raise DeployedActionEvidenceError("OBSERVED_SCHEMA_JSON_INVALID") from None
    if not isinstance(parsed, Mapping):
        raise DeployedActionEvidenceError("OBSERVED_SCHEMA_JSON_NOT_OBJECT")
    canonical_json_bytes(parsed)
    return parsed
