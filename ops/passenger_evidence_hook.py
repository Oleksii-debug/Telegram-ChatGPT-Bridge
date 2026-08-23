# -*- coding: utf-8 -*-
"""Privately armed, exact-candidate Passenger runtime evidence hook.

Import-time observation is deliberately insufficient for STRONG evidence.  A
STRONG report can be finalized only while handling a WSGI request that carries a
one-time raw challenge whose SHA-256 was armed separately.  The raw challenge is
never stored in the marker, report, binding, receipt, public output or logs.

All private writes are descriptor-relative/no-clobber and the accepted marker
inode is re-verified before every state transition.  Completion is represented
by an immutable consumed receipt; the marker is intentionally not pathname-
unlinked after acceptance, removing the former marker replacement race.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
from pathlib import Path
from typing import Any

from ops.private_control import (
    PrivateFileIdentity,
    private_identity_sha256,
    read_private_text,
    read_private_text_with_identity,
    verify_private_file_identity,
    write_private_json_no_clobber,
)
from ops.private_evidence import canonical_json_sha256, validate_runtime_report
from ops.release_guard import SafetyError
from ops.runtime_evidence import collect_runtime_evidence, write_private_report

CONTROL_DIR_NAME = ".telegram_bridge_private_control"
EVIDENCE_DIR_NAME = ".telegram_bridge_private_evidence"
ARM_MARKER_NAME = "collect_passenger_runtime_evidence.once"
CONSUMED_RECEIPT_NAME = "collect_passenger_runtime_evidence.consumed"
REPORT_NAME = "passenger_runtime_evidence.json"
BINDING_REPORT_NAME = "passenger_runtime_binding.json"
STRONG_STATUS = "PYTHON_3_11_APPLICATION_CONTEXT_CONFIRMED"
SHA40_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
CHALLENGE_RE = re.compile(r"^[0-9a-f]{64}$")
HTTP_PROTOCOL_RE = re.compile(r"^HTTP/(?:1\.[01]|2(?:\.0)?)$")
MAX_MARKER_BYTES = 1024
MAX_RECEIPT_BYTES = 2048
CHALLENGE_HEADER_ENV = "HTTP_X_TELEGRAM_BRIDGE_EVIDENCE_CHALLENGE"


def _paths(home: Path | None = None) -> tuple[Path, Path, Path, Path]:
    home = (home or Path.home()).expanduser()
    control = home / CONTROL_DIR_NAME
    marker = control / ARM_MARKER_NAME
    evidence_root = home / EVIDENCE_DIR_NAME
    report = evidence_root / REPORT_NAME
    binding = evidence_root / BINDING_REPORT_NAME
    return control, marker, report, binding


def consumed_receipt_path(home: Path | None = None) -> Path:
    control, _, _, _ = _paths(home)
    return control / CONSUMED_RECEIPT_NAME


def build_arm_marker(candidate_sha: str, expected_wsgi_sha256: str, request_challenge_sha256: str) -> dict:
    if not isinstance(candidate_sha, str) or not SHA40_RE.fullmatch(candidate_sha):
        raise SafetyError("Passenger evidence candidate SHA invalid")
    if not isinstance(expected_wsgi_sha256, str) or not SHA256_RE.fullmatch(expected_wsgi_sha256):
        raise SafetyError("Passenger evidence expected WSGI hash invalid")
    if not isinstance(request_challenge_sha256, str) or not SHA256_RE.fullmatch(request_challenge_sha256):
        raise SafetyError("Passenger evidence request challenge hash invalid")
    return {
        "schema_version": 2,
        "candidate_sha": candidate_sha,
        "expected_wsgi_sha256": expected_wsgi_sha256,
        "request_challenge_sha256": request_challenge_sha256,
    }


def validate_arm_marker(payload: object) -> dict:
    expected = {"schema_version", "candidate_sha", "expected_wsgi_sha256", "request_challenge_sha256"}
    if not isinstance(payload, dict) or set(payload) != expected or payload.get("schema_version") != 2:
        raise SafetyError("Passenger evidence arm marker schema mismatch")
    return build_arm_marker(
        payload.get("candidate_sha"),
        payload.get("expected_wsgi_sha256"),
        payload.get("request_challenge_sha256"),
    )


def _read_arm_marker(control: Path, marker: Path) -> tuple[dict, PrivateFileIdentity]:
    raw, identity = read_private_text_with_identity(control, marker, max_bytes=MAX_MARKER_BYTES)
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SafetyError("Passenger evidence arm marker JSON invalid") from exc
    return validate_arm_marker(payload), identity


def _serving_probe_sha256(marker: dict, runtime_payload_sha256: str) -> str:
    marker = validate_arm_marker(marker)
    if not isinstance(runtime_payload_sha256, str) or not SHA256_RE.fullmatch(runtime_payload_sha256):
        raise SafetyError("Passenger runtime payload identity invalid")
    return canonical_json_sha256({
        "candidate_sha": marker["candidate_sha"],
        "expected_wsgi_sha256": marker["expected_wsgi_sha256"],
        "request_challenge_sha256": marker["request_challenge_sha256"],
        "runtime_payload_sha256": runtime_payload_sha256,
    })


def _promote_runtime_for_verified_request(evidence: dict) -> dict:
    """Promote candidate process facts only after challenge verification.

    The public collector has no serving-request boolean and can never call this
    path by itself.  The report is promoted only inside the WSGI adapter after
    `_verified_serving_request()` has matched the externally held challenge.
    """
    evidence = validate_runtime_report(evidence)
    if evidence["collector_context"] != "APPLICATION_PROCESS":
        raise SafetyError("Passenger candidate evidence is not application-process context")
    if evidence["runtime_compliance"] != "PYTHON_3_11_CANDIDATE_CONTEXT":
        raise SafetyError("Passenger candidate evidence is not promotable")
    if evidence["python_major_minor"] != "3.11":
        raise SafetyError("Passenger candidate Python version is not 3.11")
    if not evidence["application_import_ok"] or not evidence["passenger_context_present"]:
        raise SafetyError("Passenger candidate process signals incomplete")
    if evidence["serving_request_verified"] is not False:
        raise SafetyError("Passenger candidate serving state is already set")

    promoted = dict(evidence)
    promoted["runtime_compliance"] = STRONG_STATUS
    promoted["serving_request_verified"] = True
    promoted.pop("payload_sha256", None)
    promoted["payload_sha256"] = canonical_json_sha256(promoted)
    return validate_runtime_report(promoted)


def build_binding_report(marker: dict, evidence: dict) -> dict:
    marker = validate_arm_marker(marker)
    evidence = validate_runtime_report(evidence)
    actual_wsgi = evidence.get("wsgi_sha256")
    runtime_payload = evidence.get("payload_sha256")
    if actual_wsgi != marker["expected_wsgi_sha256"]:
        raise SafetyError("Passenger WSGI identity does not match armed candidate")
    if evidence.get("serving_request_verified") is not True or evidence.get("runtime_compliance") != STRONG_STATUS:
        raise SafetyError("Passenger runtime evidence lacks verified serving request")
    probe_sha = _serving_probe_sha256(marker, runtime_payload)
    base = {
        "schema_version": 3,
        "candidate_sha": marker["candidate_sha"],
        "expected_wsgi_sha256": marker["expected_wsgi_sha256"],
        "actual_wsgi_sha256": actual_wsgi,
        "request_challenge_sha256": marker["request_challenge_sha256"],
        "runtime_payload_sha256": runtime_payload,
        "serving_probe_sha256": probe_sha,
        "serving_request_verified": True,
        "private_values_copied": False,
    }
    return {**base, "payload_sha256": canonical_json_sha256(base)}


def validate_binding_report(payload: object) -> dict:
    expected = {
        "schema_version", "candidate_sha", "expected_wsgi_sha256", "actual_wsgi_sha256",
        "request_challenge_sha256", "runtime_payload_sha256", "serving_probe_sha256",
        "serving_request_verified", "private_values_copied", "payload_sha256",
    }
    if not isinstance(payload, dict) or set(payload) != expected or payload.get("schema_version") != 3:
        raise SafetyError("Passenger binding report schema mismatch")
    marker = build_arm_marker(
        payload.get("candidate_sha"),
        payload.get("expected_wsgi_sha256"),
        payload.get("request_challenge_sha256"),
    )
    if payload.get("actual_wsgi_sha256") != marker["expected_wsgi_sha256"]:
        raise SafetyError("Passenger binding WSGI mismatch")
    runtime_payload = payload.get("runtime_payload_sha256")
    if not isinstance(runtime_payload, str) or not SHA256_RE.fullmatch(runtime_payload):
        raise SafetyError("Passenger binding runtime payload invalid")
    if payload.get("serving_probe_sha256") != _serving_probe_sha256(marker, runtime_payload):
        raise SafetyError("Passenger binding serving probe identity mismatch")
    if payload.get("serving_request_verified") is not True or payload.get("private_values_copied") is not False:
        raise SafetyError("Passenger binding serving/privacy flags invalid")
    base = dict(payload)
    provided = base.pop("payload_sha256", None)
    if not isinstance(provided, str) or not SHA256_RE.fullmatch(provided) or provided != canonical_json_sha256(base):
        raise SafetyError("Passenger binding report tamper hash mismatch")
    return dict(payload)


def _write_binding_report(path: Path, payload: dict) -> None:
    payload = validate_binding_report(payload)
    write_private_json_no_clobber(path.parent, path, payload)


def build_consumed_receipt(
    marker: dict,
    marker_identity: PrivateFileIdentity,
    evidence: dict,
    binding: dict,
) -> dict:
    marker = validate_arm_marker(marker)
    evidence = validate_runtime_report(evidence)
    binding = validate_binding_report(binding)
    if binding["candidate_sha"] != marker["candidate_sha"]:
        raise SafetyError("Passenger consumed receipt candidate mismatch")
    if binding["runtime_payload_sha256"] != evidence["payload_sha256"]:
        raise SafetyError("Passenger consumed receipt runtime mismatch")
    base = {
        "schema_version": 2,
        "candidate_sha": marker["candidate_sha"],
        "expected_wsgi_sha256": marker["expected_wsgi_sha256"],
        "marker_payload_sha256": canonical_json_sha256(marker),
        "marker_identity_sha256": private_identity_sha256(marker_identity),
        "runtime_payload_sha256": evidence["payload_sha256"],
        "binding_payload_sha256": binding["payload_sha256"],
        "serving_probe_sha256": binding["serving_probe_sha256"],
        "serving_request_verified": True,
        "private_values_copied": False,
    }
    return {**base, "payload_sha256": canonical_json_sha256(base)}


def validate_consumed_receipt(payload: object) -> dict:
    expected = {
        "schema_version", "candidate_sha", "expected_wsgi_sha256", "marker_payload_sha256",
        "marker_identity_sha256", "runtime_payload_sha256", "binding_payload_sha256",
        "serving_probe_sha256", "serving_request_verified", "private_values_copied",
        "payload_sha256",
    }
    if not isinstance(payload, dict) or set(payload) != expected or payload.get("schema_version") != 2:
        raise SafetyError("Passenger consumed receipt schema mismatch")
    if not SHA40_RE.fullmatch(str(payload.get("candidate_sha", ""))):
        raise SafetyError("Passenger consumed receipt candidate invalid")
    for key in (
        "expected_wsgi_sha256", "marker_payload_sha256", "marker_identity_sha256",
        "runtime_payload_sha256", "binding_payload_sha256", "serving_probe_sha256",
        "payload_sha256",
    ):
        if not isinstance(payload.get(key), str) or not SHA256_RE.fullmatch(payload[key]):
            raise SafetyError("Passenger consumed receipt hash invalid")
    if payload.get("serving_request_verified") is not True or payload.get("private_values_copied") is not False:
        raise SafetyError("Passenger consumed receipt flags invalid")
    base = dict(payload)
    provided = base.pop("payload_sha256")
    if provided != canonical_json_sha256(base):
        raise SafetyError("Passenger consumed receipt tamper hash mismatch")
    return dict(payload)


def _receipt_state(control: Path, receipt: Path) -> bool:
    try:
        raw = read_private_text(control, receipt, max_bytes=MAX_RECEIPT_BYTES)
    except FileNotFoundError:
        return False
    except OSError:
        return False
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SafetyError("Passenger consumed receipt JSON invalid") from exc
    validate_consumed_receipt(payload)
    return True


def _verified_serving_request(environ: Any, marker: dict) -> bool:
    marker = validate_arm_marker(marker)
    if not isinstance(environ, dict):
        return False
    if str(environ.get("REQUEST_METHOD") or "").upper() != "GET":
        return False
    if str(environ.get("PATH_INFO") or "") != "/health":
        return False
    if environ.get("wsgi.version") != (1, 0):
        return False
    if str(environ.get("wsgi.url_scheme") or "").casefold() != "https":
        return False
    if not HTTP_PROTOCOL_RE.fullmatch(str(environ.get("SERVER_PROTOCOL") or "")):
        return False
    stream = environ.get("wsgi.input")
    if stream is None or not callable(getattr(stream, "read", None)):
        return False
    challenge = environ.get(CHALLENGE_HEADER_ENV)
    if not isinstance(challenge, str) or not CHALLENGE_RE.fullmatch(challenge):
        return False
    observed = hashlib.sha256(challenge.encode("ascii")).hexdigest()
    return hmac.compare_digest(observed, marker["request_challenge_sha256"])


def _finalize_strong_evidence(
    *,
    app_root: Path,
    wsgi_file: Path,
    control: Path,
    marker_path: Path,
    report: Path,
    binding_path: Path,
    marker: dict,
    marker_identity: PrivateFileIdentity,
) -> str:
    verify_private_file_identity(control, marker_path, marker_identity)
    candidate = collect_runtime_evidence(
        app_root=app_root,
        wsgi_file=wsgi_file,
        application_process=True,
    )
    evidence = _promote_runtime_for_verified_request(candidate)
    bound = build_binding_report(marker, evidence)

    verify_private_file_identity(control, marker_path, marker_identity)
    write_private_report(report, evidence)
    verify_private_file_identity(control, marker_path, marker_identity)
    _write_binding_report(binding_path, bound)
    verify_private_file_identity(control, marker_path, marker_identity)

    receipt = build_consumed_receipt(marker, marker_identity, evidence, bound)
    receipt_path = control / CONSUMED_RECEIPT_NAME
    write_private_json_no_clobber(control, receipt_path, receipt, max_bytes=MAX_RECEIPT_BYTES)
    verify_private_file_identity(control, marker_path, marker_identity)
    return "PASSENGER_EVIDENCE_PRIVATE_REPORT_WRITTEN"


def collect_if_armed(*, app_root: Path, wsgi_file: Path, home: Path | None = None) -> str:
    """Import-time observation; never sufficient to emit STRONG Passenger proof."""
    control, marker_path, _, _ = _paths(home)
    receipt = control / CONSUMED_RECEIPT_NAME
    try:
        if receipt.exists():
            return "PASSENGER_EVIDENCE_ALREADY_CONSUMED" if _receipt_state(control, receipt) else "PASSENGER_EVIDENCE_BLOCKED"
        if not marker_path.exists():
            return "PASSENGER_EVIDENCE_NOT_ARMED"
        _marker, _identity_snapshot = _read_arm_marker(control, marker_path)
        evidence = collect_runtime_evidence(
            app_root=app_root,
            wsgi_file=wsgi_file,
            application_process=True,
        )
        if evidence["runtime_compliance"] == "NONCOMPLIANT_NOT_PYTHON_3_11":
            return "PASSENGER_EVIDENCE_CONTEXT_NOT_CONFIRMED"
        return "PASSENGER_EVIDENCE_AWAITING_SERVING_REQUEST"
    except Exception:
        return "PASSENGER_EVIDENCE_BLOCKED"


def collect_if_armed_from_bridge_app(
    app_module_file: str | Path,
    *,
    environ: dict[str, Any] | None = None,
    home: Path | None = None,
) -> str:
    """Fail-isolated serving-request adapter intended for BridgeApplication.

    A real WSGI ``environ`` is required.  The raw challenge is compared in
    memory and is never serialized or returned.  Any evidence failure remains
    isolated from application availability.
    """
    try:
        app_file = Path(app_module_file).expanduser().resolve(strict=True)
        if app_file.name != "app.py" or app_file.parent.name != "bridge":
            return "PASSENGER_EVIDENCE_APP_TOPOLOGY_BLOCKED"
        app_root = app_file.parent.parent
        wsgi_file = app_root / "passenger_wsgi.py"
        wsgi_stat = os.lstat(wsgi_file)
        if wsgi_file.is_symlink() or not wsgi_file.is_file() or wsgi_stat.st_nlink != 1:
            return "PASSENGER_EVIDENCE_APP_TOPOLOGY_BLOCKED"
        if environ is None:
            return "PASSENGER_EVIDENCE_SERVING_REQUEST_REQUIRED"

        control, marker_path, report, binding = _paths(home)
        receipt = control / CONSUMED_RECEIPT_NAME
        if receipt.exists():
            return "PASSENGER_EVIDENCE_ALREADY_CONSUMED" if _receipt_state(control, receipt) else "PASSENGER_EVIDENCE_BLOCKED"
        if not marker_path.exists():
            return "PASSENGER_EVIDENCE_NOT_ARMED"
        marker, marker_identity = _read_arm_marker(control, marker_path)
        if not _verified_serving_request(environ, marker):
            return "PASSENGER_EVIDENCE_SERVING_REQUEST_NOT_VERIFIED"
        return _finalize_strong_evidence(
            app_root=app_root,
            wsgi_file=wsgi_file,
            control=control,
            marker_path=marker_path,
            report=report,
            binding_path=binding,
            marker=marker,
            marker_identity=marker_identity,
        )
    except Exception:
        return "PASSENGER_EVIDENCE_BLOCKED"
