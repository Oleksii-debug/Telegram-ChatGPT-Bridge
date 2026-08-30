# -*- coding: utf-8 -*-
"""Truthful source-level contracts for the integrated DEV_A release candidate.

This module reports what the current source candidate can prove without turning
synthetic/source evidence into product PASS.  It performs no network, Telegram,
HOSTiQ, filesystem mutation, or credential access.
"""
from __future__ import annotations

from typing import Any

from bridge.routes import READ_ROUTE_REGISTRY
from ops.acceptance_harness import CRITERIA
from ops.acceptance_policy import (
    CRITERION_POLICIES,
    EVIDENCE_CLASSES,
    HUMAN_ACCESSIBILITY_REQUIRED,
    LIVE_EXTERNAL_REQUIRED,
    SYNTHETIC_EXECUTABLE,
)
from ops.openapi_registry import OPERATIONS, OperationClass

def _criterion_sort(value: str) -> tuple[str, int]:
    return value[0], int(value[1:])


def candidate_acceptance_coverage() -> tuple[dict[str, Any], ...]:
    rows: list[dict[str, Any]] = []
    for criterion in sorted(CRITERIA, key=_criterion_sort):
        policy = CRITERION_POLICIES[criterion]
        evidence_class = policy["evidence_class"]
        rows.append({
            "criterion": criterion,
            "evidence_class": evidence_class,
            "human_verification_required": policy["human_verification_required"],
            "explicit_write_approval_required": policy["explicit_write_approval_required"],
            "product_pass": False,
        })
    validate_candidate_acceptance_coverage(rows)
    return tuple(rows)


def validate_candidate_acceptance_coverage(rows: Any) -> dict[str, int]:
    if not isinstance(rows, (list, tuple)) or len(rows) != 67:
        raise ValueError("candidate coverage must contain all 67 criteria exactly once")
    seen: set[str] = set()
    counts = {name: 0 for name in sorted(EVIDENCE_CLASSES)}
    for row in rows:
        if not isinstance(row, dict) or set(row) != {
            "criterion", "evidence_class", "human_verification_required",
            "explicit_write_approval_required", "product_pass",
        }:
            raise ValueError("candidate coverage row schema mismatch")
        criterion = row["criterion"]
        if criterion not in CRITERIA or criterion in seen:
            raise ValueError("candidate coverage criterion mismatch")
        seen.add(criterion)
        evidence_class = row["evidence_class"]
        if evidence_class not in EVIDENCE_CLASSES:
            raise ValueError("candidate evidence class invalid")
        counts[evidence_class] += 1
        if row["human_verification_required"] is not (criterion in HUMAN_ACCESSIBILITY_REQUIRED):
            raise ValueError("candidate human accessibility boundary mismatch")
        if row["explicit_write_approval_required"] is not (criterion == "K5"):
            raise ValueError("candidate K5 approval boundary mismatch")
        if row["product_pass"] is not False:
            raise ValueError("source candidate must not claim product PASS")
    if seen != set(CRITERIA):
        raise ValueError("candidate coverage set mismatch")
    if counts != {
        "LIVE_EXTERNAL_REQUIRED": 17,
        "REAL_SOURCE_REQUIRED": 13,
        "SYNTHETIC_EXECUTABLE": 37,
    }:
        raise ValueError("candidate coverage count mismatch")
    for criterion in ("H1", "I1", "I4", "I6", "K1", "K2", "K3", "K4", "K5"):
        row = next(item for item in rows if item["criterion"] == criterion)
        if row["evidence_class"] != "LIVE_EXTERNAL_REQUIRED":
            raise ValueError("live/human criterion was overpromoted")
    return counts


_PATH_CRITERIA: dict[str, tuple[str, ...]] = {
    "/api/v1/dialogs/list": ("D1",),
    "/api/v1/history/read": ("D2",),
    "/api/v1/search": ("D3", "D4", "D5", "D6"),
    "/api/v1/media/metadata": ("E1",),
    "/api/v1/downloads/single": ("E2",),
    "/api/v1/downloads/bulk": ("E3",),
    "/api/v1/downloads/resume": ("E5", "G5"),
    "/api/v1/archives/create": ("E4",),
    "/api/v1/files/get": ("E6",),
    "/api/v1/messages/send/preview": ("F1", "H4"),
    "/api/v1/messages/send/commit": ("F5", "F6", "F7", "H4"),
    "/api/v1/messages/reply/preview": ("F2", "H4"),
    "/api/v1/messages/reply/commit": ("F5", "F6", "F7", "H4"),
    "/api/v1/messages/forward/preview": ("F3", "H4"),
    "/api/v1/messages/forward/commit": ("F5", "F6", "F7", "H4"),
    "/api/v1/files/send/preview": ("F4", "H4"),
    "/api/v1/files/send/commit": ("F5", "F6", "F7", "H4"),
}


def integrated_api_inventory() -> tuple[dict[str, Any], ...]:
    runtime_by_key: dict[tuple[str, str], Any] = {}
    for route in READ_ROUTE_REGISTRY:
        if route.dynamic_tail:
            continue
        runtime_by_key[(route.method, route.concrete_path("/api/v1"))] = route

    rows: list[dict[str, Any]] = [{
        "method": "GET",
        "path": "/health",
        "runtime_operation_id": "health.get",
        "action_operation_id": None,
        "safety_class": "PUBLIC_HEALTH",
        "auth_policy": "PUBLIC",
        "rate_class": "NONE",
        "audit_policy": "BOUNDED_HEALTH_METADATA",
        "acceptance_criteria": ["A3"],
    }]

    for spec in OPERATIONS:
        key = (spec.method.upper(), spec.path)
        runtime = runtime_by_key.get(key)
        if spec.operation_class is OperationClass.READ:
            safety_class = "PROTECTED_READ"
            rate_class = "AUTHENTICATED_READ_API"
            audit_policy = "METADATA_ONLY"
            runtime_id = runtime.operation_id if runtime is not None else None
        elif spec.operation_class is OperationClass.WRITE_PREVIEW:
            safety_class = "PROTECTED_WRITE_PREVIEW"
            rate_class = "WRITE_OPERATION_SCOPED"
            audit_policy = "HASH_COUNT_STATUS_ONLY"
            runtime_id = spec.operation_id
        else:
            safety_class = "PROTECTED_WRITE_COMMIT"
            rate_class = "WRITE_OPERATION_SCOPED"
            audit_policy = "HASH_COUNT_STATUS_ONLY"
            runtime_id = spec.operation_id
        rows.append({
            "method": spec.method.upper(),
            "path": spec.path,
            "runtime_operation_id": runtime_id,
            "action_operation_id": spec.operation_id,
            "safety_class": safety_class,
            "auth_policy": "BEARER",
            "rate_class": rate_class,
            "audit_policy": audit_policy,
            "acceptance_criteria": list(_PATH_CRITERIA.get(spec.path, ("H1",))),
        })

    rows.append({
        "method": "GET",
        "path": "/api/v1/files/{file_ref}",
        "runtime_operation_id": "files.content",
        "action_operation_id": None,
        "safety_class": "PROTECTED_OR_SIGNED_READ",
        "auth_policy": "BEARER_OR_SIGNED",
        "rate_class": "PRIVATE_FILE_READ",
        "audit_policy": "METADATA_ONLY",
        "acceptance_criteria": ["B6", "E6"],
    })
    validate_integrated_api_inventory(rows)
    return tuple(rows)


def validate_integrated_api_inventory(rows: Any) -> None:
    if not isinstance(rows, (list, tuple)):
        raise ValueError("API inventory must be a sequence")
    expected_action_keys = {(spec.method.upper(), spec.path) for spec in OPERATIONS}
    expected_keys = expected_action_keys | {
        ("GET", "/health"),
        ("GET", "/api/v1/files/{file_ref}"),
    }
    observed: set[tuple[str, str]] = set()
    action_ids: set[str] = set()
    for row in rows:
        if not isinstance(row, dict) or set(row) != {
            "method", "path", "runtime_operation_id", "action_operation_id",
            "safety_class", "auth_policy", "rate_class", "audit_policy",
            "acceptance_criteria",
        }:
            raise ValueError("API inventory row schema mismatch")
        key = (row["method"], row["path"])
        if key in observed:
            raise ValueError("duplicate integrated API route")
        observed.add(key)
        if not isinstance(row["acceptance_criteria"], list) or not row["acceptance_criteria"]:
            raise ValueError("API inventory acceptance mapping missing")
        if any(item not in CRITERIA for item in row["acceptance_criteria"]):
            raise ValueError("API inventory references unknown acceptance criterion")
        action_id = row["action_operation_id"]
        if key in expected_action_keys:
            if not isinstance(action_id, str) or not action_id or action_id in action_ids:
                raise ValueError("Action operation identity mismatch")
            action_ids.add(action_id)
            if row["auth_policy"] != "BEARER":
                raise ValueError("Action operation must require bearer auth")
        elif action_id is not None:
            raise ValueError("non-Action route cannot export operation ID")
        lowered = (str(row["path"]) + " " + str(action_id or "")).casefold()
        if any(word in lowered for word in ("setup-", "login-code", "session-string", "2fa")):
            raise ValueError("private setup surface leaked into API inventory")
    if observed != expected_keys:
        raise ValueError("integrated API route inventory drift")
    if len(action_ids) != len(OPERATIONS):
        raise ValueError("integrated Action operation count mismatch")


# Import-time validation is source-only and deterministic; it has no I/O.
validate_candidate_acceptance_coverage(candidate_acceptance_coverage())
validate_integrated_api_inventory(integrated_api_inventory())
