# -*- coding: utf-8 -*-
"""Fail-closed production-readiness accounting for HOSTiQ evidence.

This module never authorizes deployment. Support-return v4 binds Passenger
runtime evidence to the exact candidate, WSGI, runtime payload, one-time
serving-request probe, and terminal consumed receipt. v1/v2/v3 remain parseable
for historical evidence but can never satisfy the current strong Passenger gate.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from ops.release_guard import SafetyError

SHA40 = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")

EVIDENCE_CLASSES = frozenset({
    "FIRST_HAND_LIVE", "PRIVATE_SERVER_EVIDENCE", "TEST_SIMULATION", "REFERENCE_ONLY",
})
LIVE_ELIGIBLE = frozenset({"FIRST_HAND_LIVE", "PRIVATE_SERVER_EVIDENCE"})
STEP_STATUSES = frozenset({"PASS", "FAIL", "BLOCKED", "NOT_RUN", "NOT_APPLICABLE"})
RECONCILIATION_STATUSES = frozenset({"EXACT_ACCOUNTED", "DIFFERENCES_PENDING", "NOT_RUN"})
RUNTIME_COMPLIANCE = frozenset({
    "PYTHON_3_11_APPLICATION_CONTEXT_CONFIRMED",
    "PYTHON_3_11_CANDIDATE_CONTEXT",
    "NONCOMPLIANT_NOT_PYTHON_3_11",
})
COLLECTOR_CONTEXTS = frozenset({"APPLICATION_PROCESS", "PRIVATE_CLI_CANDIDATE"})
LIFECYCLE_MODES = frozenset({"LIVE_SERVER", "TEST_SIMULATION", "NOT_EXECUTED"})
CHECK_STATUSES = frozenset({"PASS", "BLOCKED_EXTERNAL", "NOT_APPLICABLE"})


def _exact_keys(value: Any, expected: set[str], label: str) -> dict:
    if not isinstance(value, dict) or set(value) != expected:
        raise SafetyError(f"{label} schema mismatch")
    return value


def _sha40(value: Any, label: str) -> str:
    if not isinstance(value, str) or not SHA40.fullmatch(value):
        raise SafetyError(f"{label} SHA-40 invalid")
    return value


def _sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or not SHA256.fullmatch(value):
        raise SafetyError(f"{label} SHA-256 invalid")
    return value


def _bounded_int(value: Any, label: str, *, minimum: int = 0, maximum: int = 100000) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not minimum <= value <= maximum:
        raise SafetyError(f"{label} integer invalid")
    return value


def _enum(value: Any, allowed: frozenset[str], label: str) -> str:
    if not isinstance(value, str) or value not in allowed:
        raise SafetyError(f"{label} status invalid")
    return value


def _bool(value: Any, label: str) -> bool:
    if not isinstance(value, bool):
        raise SafetyError(f"{label} boolean invalid")
    return value


def _probe_sha(candidate_sha: str, wsgi_sha: str, challenge_sha: str, runtime_payload: str) -> str:
    raw = json.dumps({
        "candidate_sha": candidate_sha,
        "expected_wsgi_sha256": wsgi_sha,
        "request_challenge_sha256": challenge_sha,
        "runtime_payload_sha256": runtime_payload,
    }, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    return hashlib.sha256(raw).hexdigest()


def validate_support_return(payload: dict) -> dict:
    if not isinstance(payload, dict):
        raise SafetyError("support return schema mismatch")
    version = payload.get("schema_version")
    common = {
        "schema_version", "candidate_sha", "evidence_classes", "server_manifest",
        "reconciliation", "runtime", "lifecycle", "privacy",
    }
    if version == 1:
        expected_top = common
    elif version in {2, 3}:
        expected_top = common | {"candidate_package", "runtime_binding"}
    elif version == 4:
        expected_top = common | {"candidate_package", "runtime_binding", "consumed_receipt"}
    else:
        raise SafetyError("support return version mismatch")
    top = _exact_keys(payload, expected_top, "support return")
    candidate_sha = _sha40(top["candidate_sha"], "candidate")

    classes = _exact_keys(top["evidence_classes"], {"source", "runtime", "lifecycle"}, "evidence classes")
    for key in ("source", "runtime", "lifecycle"):
        _enum(classes[key], EVIDENCE_CLASSES, f"{key} evidence class")

    server = _exact_keys(top["server_manifest"], {"artifact_sha256", "manifest_sha256", "file_count"}, "server manifest summary")
    _sha256(server["artifact_sha256"], "server artifact")
    _sha256(server["manifest_sha256"], "server manifest")
    server_count = _bounded_int(server["file_count"], "server file count", minimum=1, maximum=500)

    recon = _exact_keys(top["reconciliation"], {
        "artifact_sha256", "status", "server_file_count", "candidate_file_count",
        "unreviewed_difference_count", "startup_accounted",
    }, "reconciliation summary")
    _sha256(recon["artifact_sha256"], "reconciliation artifact")
    recon_status = _enum(recon["status"], RECONCILIATION_STATUSES, "reconciliation")
    recon_server_count = _bounded_int(recon["server_file_count"], "reconciliation server count", minimum=1, maximum=500)
    _bounded_int(recon["candidate_file_count"], "candidate file count", minimum=1, maximum=2000)
    differences = _bounded_int(recon["unreviewed_difference_count"], "unreviewed difference count", maximum=2000)
    startup_accounted = _bool(recon["startup_accounted"], "startup accounted")
    if recon_server_count != server_count:
        raise SafetyError("server manifest and reconciliation counts disagree")
    if recon_status == "EXACT_ACCOUNTED" and (differences != 0 or not startup_accounted):
        raise SafetyError("exact reconciliation claim is not semantically supported")

    runtime_keys = {
        "artifact_sha256", "collector_context", "python_major_minor", "runtime_compliance",
        "application_import_ok", "passenger_context_present", "wsgi_sha256",
    }
    if version >= 2:
        runtime_keys.add("payload_sha256")
    if version >= 3:
        runtime_keys.add("serving_request_verified")
    runtime = _exact_keys(top["runtime"], runtime_keys, "runtime summary")
    _sha256(runtime["artifact_sha256"], "runtime artifact")
    runtime_wsgi = _sha256(runtime["wsgi_sha256"], "WSGI")
    runtime_payload = _sha256(runtime["payload_sha256"], "runtime payload") if version >= 2 else None
    collector = _enum(runtime["collector_context"], COLLECTOR_CONTEXTS, "collector context")
    if runtime["python_major_minor"] not in {"3.6", "3.7", "3.8", "3.9", "3.10", "3.11", "3.12", "3.13", "3.14"}:
        raise SafetyError("runtime Python major/minor invalid")
    compliance = _enum(runtime["runtime_compliance"], RUNTIME_COMPLIANCE, "runtime compliance")
    import_ok = _bool(runtime["application_import_ok"], "application import")
    passenger_present = _bool(runtime["passenger_context_present"], "Passenger context")
    serving_verified = _bool(runtime["serving_request_verified"], "serving request") if version >= 3 else False
    if compliance == "PYTHON_3_11_APPLICATION_CONTEXT_CONFIRMED":
        if collector != "APPLICATION_PROCESS" or runtime["python_major_minor"] != "3.11" or not import_ok or not passenger_present:
            raise SafetyError("strong Passenger runtime claim is not semantically supported")
        if version >= 3 and not serving_verified:
            raise SafetyError("strong Passenger runtime lacks challenged serving request")
    if compliance == "NONCOMPLIANT_NOT_PYTHON_3_11" and runtime["python_major_minor"] == "3.11":
        raise SafetyError("runtime noncompliance contradicts Python version")

    binding_payload = None
    expected_wsgi = None
    probe_sha = None
    if version >= 2:
        package = _exact_keys(top["candidate_package"], {
            "identity_artifact_sha256", "manifest_sha256", "wsgi_sha256",
            "requirements_lock_sha256", "package_preflight_pass",
        }, "candidate package summary")
        _sha256(package["identity_artifact_sha256"], "candidate package identity artifact")
        _sha256(package["manifest_sha256"], "candidate package manifest")
        package_wsgi = _sha256(package["wsgi_sha256"], "candidate package WSGI")
        _sha256(package["requirements_lock_sha256"], "candidate requirements lock")
        if _bool(package["package_preflight_pass"], "candidate package preflight") is not True:
            raise SafetyError("candidate package preflight did not pass")

        if version == 2:
            binding_keys = {
                "artifact_sha256", "candidate_sha", "expected_wsgi_sha256", "actual_wsgi_sha256",
                "runtime_payload_sha256", "binding_valid",
            }
        elif version == 3:
            binding_keys = {
                "artifact_sha256", "candidate_sha", "expected_wsgi_sha256", "actual_wsgi_sha256",
                "request_challenge_sha256", "runtime_payload_sha256", "serving_probe_sha256",
                "serving_request_verified", "binding_valid",
            }
        else:
            binding_keys = {
                "artifact_sha256", "payload_sha256", "candidate_sha", "expected_wsgi_sha256",
                "actual_wsgi_sha256", "request_challenge_sha256", "runtime_payload_sha256",
                "serving_probe_sha256", "serving_request_verified", "binding_valid",
            }
        binding = _exact_keys(top["runtime_binding"], binding_keys, "runtime binding summary")
        _sha256(binding["artifact_sha256"], "runtime binding artifact")
        binding_payload = _sha256(binding["payload_sha256"], "runtime binding payload artifact") if version >= 4 else None
        binding_sha = _sha40(binding["candidate_sha"], "runtime binding candidate")
        expected_wsgi = _sha256(binding["expected_wsgi_sha256"], "runtime binding expected WSGI")
        actual_wsgi = _sha256(binding["actual_wsgi_sha256"], "runtime binding actual WSGI")
        binding_runtime_payload = _sha256(binding["runtime_payload_sha256"], "runtime binding payload")
        if _bool(binding["binding_valid"], "runtime binding valid") is not True:
            raise SafetyError("runtime binding is not positive")
        if binding_sha != candidate_sha:
            raise SafetyError("runtime binding candidate SHA mismatch")
        if not (package_wsgi == runtime_wsgi == expected_wsgi == actual_wsgi):
            raise SafetyError("candidate/runtime Passenger WSGI identity mismatch")
        if binding_runtime_payload != runtime_payload:
            raise SafetyError("runtime binding payload identity mismatch")
        if version >= 3:
            challenge_sha = _sha256(binding["request_challenge_sha256"], "runtime binding challenge")
            probe_sha = _sha256(binding["serving_probe_sha256"], "runtime binding serving probe")
            if _bool(binding["serving_request_verified"], "runtime binding serving request") is not True:
                raise SafetyError("runtime binding serving request not verified")
            if probe_sha != _probe_sha(candidate_sha, expected_wsgi, challenge_sha, binding_runtime_payload):
                raise SafetyError("runtime binding serving probe identity mismatch")
            if serving_verified is not True:
                raise SafetyError("runtime and binding serving-request facts disagree")

    if version >= 4:
        receipt = _exact_keys(top["consumed_receipt"], {
            "artifact_sha256", "payload_sha256", "candidate_sha", "expected_wsgi_sha256",
            "runtime_payload_sha256", "binding_payload_sha256", "serving_probe_sha256",
            "serving_request_verified", "receipt_valid",
        }, "consumed receipt summary")
        _sha256(receipt["artifact_sha256"], "consumed receipt artifact")
        _sha256(receipt["payload_sha256"], "consumed receipt payload")
        receipt_sha = _sha40(receipt["candidate_sha"], "consumed receipt candidate")
        receipt_wsgi = _sha256(receipt["expected_wsgi_sha256"], "consumed receipt expected WSGI")
        receipt_runtime = _sha256(receipt["runtime_payload_sha256"], "consumed receipt runtime payload")
        receipt_binding = _sha256(receipt["binding_payload_sha256"], "consumed receipt binding payload")
        receipt_probe = _sha256(receipt["serving_probe_sha256"], "consumed receipt serving probe")
        if _bool(receipt["serving_request_verified"], "consumed receipt serving request") is not True:
            raise SafetyError("consumed receipt serving request not verified")
        if _bool(receipt["receipt_valid"], "consumed receipt valid") is not True:
            raise SafetyError("consumed receipt is not positive")
        if receipt_sha != candidate_sha:
            raise SafetyError("consumed receipt candidate SHA mismatch")
        if receipt_wsgi != expected_wsgi:
            raise SafetyError("consumed receipt WSGI identity mismatch")
        if receipt_runtime != runtime_payload:
            raise SafetyError("consumed receipt runtime payload mismatch")
        if receipt_binding != binding_payload:
            raise SafetyError("consumed receipt binding payload mismatch")
        if receipt_probe != probe_sha:
            raise SafetyError("consumed receipt serving probe mismatch")

    lifecycle = _exact_keys(top["lifecycle"], {
        "mode", "candidate_sha", "backup", "restart", "running_identity", "health",
        "unauth_smoke", "auth_smoke", "resume", "rollback",
    }, "lifecycle summary")
    mode = _enum(lifecycle["mode"], LIFECYCLE_MODES, "lifecycle mode")
    lifecycle_sha = _sha40(lifecycle["candidate_sha"], "lifecycle candidate")
    if lifecycle_sha != candidate_sha:
        raise SafetyError("lifecycle candidate SHA mismatch")
    for key in ("backup", "restart", "running_identity", "health", "unauth_smoke", "auth_smoke", "resume", "rollback"):
        _enum(lifecycle[key], STEP_STATUSES, key)
    if mode == "NOT_EXECUTED" and any(lifecycle[key] == "PASS" for key in ("restart", "running_identity", "health", "unauth_smoke", "auth_smoke", "resume", "rollback")):
        raise SafetyError("non-executed lifecycle cannot contain PASS execution claims")
    if mode == "TEST_SIMULATION" and classes["lifecycle"] in LIVE_ELIGIBLE:
        raise SafetyError("simulation cannot carry live evidence classification")
    if mode == "LIVE_SERVER" and classes["lifecycle"] not in LIVE_ELIGIBLE:
        raise SafetyError("live lifecycle requires live-eligible evidence classification")

    privacy = _exact_keys(top["privacy"], {"private_values_copied", "raw_response_copied"}, "privacy summary")
    if _bool(privacy["private_values_copied"], "private-values copied") or _bool(privacy["raw_response_copied"], "raw-response copied"):
        raise SafetyError("support return privacy boundary violated")

    try:
        return json.loads(json.dumps(top, sort_keys=True, separators=(",", ":"), ensure_ascii=True))
    except (TypeError, ValueError) as exc:
        raise SafetyError("support return is not canonical JSON") from exc


def _check(status: str, reason_code: str) -> dict:
    _enum(status, CHECK_STATUSES, "readiness check")
    if not isinstance(reason_code, str) or not re.fullmatch(r"[A-Z0-9_]{3,64}", reason_code):
        raise SafetyError("readiness reason code invalid")
    return {"status": status, "reason_code": reason_code}


def build_deployment_readiness(payload: dict) -> dict:
    data = validate_support_return(payload)
    classes = data["evidence_classes"]
    recon = data["reconciliation"]
    runtime = data["runtime"]
    lifecycle = data["lifecycle"]
    exact_binding_ok = data["schema_version"] in {2, 3, 4}
    strong_probe_ok = data["schema_version"] >= 3 and runtime.get("serving_request_verified") is True
    terminal_receipt_ok = data["schema_version"] == 4

    source_ok = (
        classes["source"] in LIVE_ELIGIBLE
        and recon["status"] == "EXACT_ACCOUNTED"
        and recon["unreviewed_difference_count"] == 0
        and recon["startup_accounted"] is True
    )
    runtime_ok = (
        exact_binding_ok
        and strong_probe_ok
        and terminal_receipt_ok
        and classes["runtime"] in LIVE_ELIGIBLE
        and runtime["collector_context"] == "APPLICATION_PROCESS"
        and runtime["python_major_minor"] == "3.11"
        and runtime["runtime_compliance"] == "PYTHON_3_11_APPLICATION_CONTEXT_CONFIRMED"
        and runtime["application_import_ok"] is True
        and runtime["passenger_context_present"] is True
    )
    lifecycle_required = ("backup", "restart", "running_identity", "health", "unauth_smoke", "auth_smoke", "resume")
    lifecycle_ok = (
        classes["lifecycle"] in LIVE_ELIGIBLE
        and lifecycle["mode"] == "LIVE_SERVER"
        and all(lifecycle[key] == "PASS" for key in lifecycle_required)
    )
    rollback_ok = classes["lifecycle"] in LIVE_ELIGIBLE and lifecycle["mode"] == "LIVE_SERVER" and lifecycle["rollback"] == "PASS"

    checks = {
        "source_reconciliation": _check("PASS" if source_ok else "BLOCKED_EXTERNAL", "EXACT_LIVE_SOURCE_ACCOUNTED" if source_ok else "LIVE_SOURCE_EVIDENCE_PENDING"),
        "exact_candidate_runtime_binding": _check("PASS" if exact_binding_ok else "BLOCKED_EXTERNAL", "EXACT_CANDIDATE_RUNTIME_BOUND" if exact_binding_ok else "EXACT_CANDIDATE_RUNTIME_BINDING_REQUIRED"),
        "passenger_python_311": _check("PASS" if runtime_ok else "BLOCKED_EXTERNAL", "PASSENGER_TERMINAL_RECEIPT_CONTEXT_CONFIRMED" if runtime_ok else "PASSENGER_RUNTIME_EVIDENCE_PENDING"),
        "backup_restart_identity_health_smoke_resume": _check("PASS" if lifecycle_ok else "BLOCKED_EXTERNAL", "LIVE_LIFECYCLE_CONFIRMED" if lifecycle_ok else "LIVE_LIFECYCLE_EVIDENCE_PENDING"),
        "rollback": _check("PASS" if rollback_ok else "BLOCKED_EXTERNAL", "LIVE_ROLLBACK_CONFIRMED" if rollback_ok else "LIVE_ROLLBACK_EVIDENCE_PENDING"),
        "telegram_user_authorization": _check("NOT_APPLICABLE", "USER_TELEGRAM_AUTH_NOT_YET_REQUIRED"),
        "independent_auditor_gate": _check("BLOCKED_EXTERNAL", "INDEPENDENT_AUDITOR_APPROVAL_REQUIRED"),
        "production_switch": _check("BLOCKED_EXTERNAL", "DEVELOPER_TOOL_CANNOT_AUTHORIZE_PROMOTION"),
    }
    return {
        "schema_version": 3,
        "candidate_sha": data["candidate_sha"],
        "checks": checks,
        "non_auditor_prerequisites_structurally_present": source_ok and runtime_ok and lifecycle_ok and rollback_ok,
        "promotion_authorized": False,
        "private_values_copied": False,
        "raw_response_copied": False,
    }


def validate_public_readiness(payload: dict) -> dict:
    data = _exact_keys(payload, {
        "schema_version", "candidate_sha", "checks", "non_auditor_prerequisites_structurally_present",
        "promotion_authorized", "private_values_copied", "raw_response_copied",
    }, "public readiness")
    if data["schema_version"] != 3:
        raise SafetyError("public readiness version mismatch")
    _sha40(data["candidate_sha"], "public readiness candidate")
    checks = data["checks"]
    expected = {
        "source_reconciliation", "exact_candidate_runtime_binding", "passenger_python_311",
        "backup_restart_identity_health_smoke_resume", "rollback", "telegram_user_authorization",
        "independent_auditor_gate", "production_switch",
    }
    _exact_keys(checks, expected, "public readiness checks")
    for name, item in checks.items():
        _exact_keys(item, {"status", "reason_code"}, f"{name} check")
        _enum(item["status"], CHECK_STATUSES, f"{name} check")
        if not isinstance(item["reason_code"], str) or not re.fullmatch(r"[A-Z0-9_]{3,64}", item["reason_code"]):
            raise SafetyError("public readiness reason code invalid")
    for key in ("non_auditor_prerequisites_structurally_present", "promotion_authorized", "private_values_copied", "raw_response_copied"):
        _bool(data[key], key)
    if data["promotion_authorized"] is not False or data["private_values_copied"] is not False or data["raw_response_copied"] is not False:
        raise SafetyError("public readiness safety invariant violated")
    if checks["independent_auditor_gate"]["status"] != "BLOCKED_EXTERNAL" or checks["production_switch"]["status"] != "BLOCKED_EXTERNAL":
        raise SafetyError("Developer readiness output cannot self-authorize promotion")
    return dict(data)
