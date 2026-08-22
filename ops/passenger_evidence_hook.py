# -*- coding: utf-8 -*-
"""Privately armed, exact-candidate Passenger runtime evidence hook.

Public Git cannot activate this collector. HOSTiQ/support creates one owner-private
JSON marker bound to the Auditor-approved candidate SHA and expected
``passenger_wsgi.py`` SHA-256, then restarts that exact Passenger application.
The application process writes bounded private runtime + binding reports only if
Python 3.11, Passenger context, application import and WSGI identity are genuinely
confirmed. Evidence collection is fail-isolated from application availability.

The preferred integration keeps ``passenger_wsgi.py`` call-free: the exported
``bridge.app.application`` may invoke ``collect_if_armed_from_bridge_app`` at the
start of its WSGI ``__call__``. That executes only inside the actual process that
serves a request, remains inert without the owner-private marker, and performs no
Telegram/network operation.
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path

from ops.private_control import read_private_text
from ops.private_evidence import canonical_json_sha256
from ops.release_guard import SafetyError, write_json_atomic
from ops.runtime_evidence import collect_runtime_evidence, write_private_report

CONTROL_DIR_NAME = ".telegram_bridge_private_control"
EVIDENCE_DIR_NAME = ".telegram_bridge_private_evidence"
ARM_MARKER_NAME = "collect_passenger_runtime_evidence.once"
REPORT_NAME = "passenger_runtime_evidence.json"
BINDING_REPORT_NAME = "passenger_runtime_binding.json"
STRONG_STATUS = "PYTHON_3_11_APPLICATION_CONTEXT_CONFIRMED"
SHA40_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
MAX_MARKER_BYTES = 512


def _paths(home: Path | None = None) -> tuple[Path, Path, Path, Path]:
    home = (home or Path.home()).expanduser()
    control = home / CONTROL_DIR_NAME
    marker = control / ARM_MARKER_NAME
    evidence_root = home / EVIDENCE_DIR_NAME
    report = evidence_root / REPORT_NAME
    binding = evidence_root / BINDING_REPORT_NAME
    return control, marker, report, binding


def build_arm_marker(candidate_sha: str, expected_wsgi_sha256: str) -> dict:
    """Build the only accepted non-secret one-time arming payload."""
    if not isinstance(candidate_sha, str) or not SHA40_RE.fullmatch(candidate_sha):
        raise SafetyError("Passenger evidence candidate SHA invalid")
    if not isinstance(expected_wsgi_sha256, str) or not SHA256_RE.fullmatch(expected_wsgi_sha256):
        raise SafetyError("Passenger evidence expected WSGI hash invalid")
    return {
        "schema_version": 1,
        "candidate_sha": candidate_sha,
        "expected_wsgi_sha256": expected_wsgi_sha256,
    }


def validate_arm_marker(payload: object) -> dict:
    if not isinstance(payload, dict) or set(payload) != {"schema_version", "candidate_sha", "expected_wsgi_sha256"}:
        raise SafetyError("Passenger evidence arm marker schema mismatch")
    if payload.get("schema_version") != 1:
        raise SafetyError("Passenger evidence arm marker version mismatch")
    return build_arm_marker(payload.get("candidate_sha"), payload.get("expected_wsgi_sha256"))


def _read_arm_marker(control: Path, marker: Path) -> dict:
    raw = read_private_text(control, marker, max_bytes=MAX_MARKER_BYTES)
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SafetyError("Passenger evidence arm marker JSON invalid") from exc
    return validate_arm_marker(payload)


def build_binding_report(marker: dict, evidence: dict) -> dict:
    marker = validate_arm_marker(marker)
    actual_wsgi = evidence.get("wsgi_sha256")
    runtime_payload = evidence.get("payload_sha256")
    if actual_wsgi != marker["expected_wsgi_sha256"]:
        raise SafetyError("Passenger WSGI identity does not match armed candidate")
    if not isinstance(runtime_payload, str) or not SHA256_RE.fullmatch(runtime_payload):
        raise SafetyError("Passenger runtime payload identity invalid")
    base = {
        "schema_version": 1,
        "candidate_sha": marker["candidate_sha"],
        "expected_wsgi_sha256": marker["expected_wsgi_sha256"],
        "actual_wsgi_sha256": actual_wsgi,
        "runtime_payload_sha256": runtime_payload,
        "private_values_copied": False,
    }
    return {**base, "payload_sha256": canonical_json_sha256(base)}


def validate_binding_report(payload: object) -> dict:
    expected = {
        "schema_version", "candidate_sha", "expected_wsgi_sha256", "actual_wsgi_sha256",
        "runtime_payload_sha256", "private_values_copied", "payload_sha256",
    }
    if not isinstance(payload, dict) or set(payload) != expected or payload.get("schema_version") != 1:
        raise SafetyError("Passenger binding report schema mismatch")
    marker = build_arm_marker(payload.get("candidate_sha"), payload.get("expected_wsgi_sha256"))
    if payload.get("actual_wsgi_sha256") != marker["expected_wsgi_sha256"]:
        raise SafetyError("Passenger binding WSGI mismatch")
    runtime_payload = payload.get("runtime_payload_sha256")
    if not isinstance(runtime_payload, str) or not SHA256_RE.fullmatch(runtime_payload):
        raise SafetyError("Passenger binding runtime payload invalid")
    if payload.get("private_values_copied") is not False:
        raise SafetyError("Passenger binding privacy flag invalid")
    base = dict(payload)
    provided = base.pop("payload_sha256", None)
    if not isinstance(provided, str) or not SHA256_RE.fullmatch(provided) or provided != canonical_json_sha256(base):
        raise SafetyError("Passenger binding report tamper hash mismatch")
    return dict(payload)


def _write_binding_report(path: Path, payload: dict) -> None:
    payload = validate_binding_report(payload)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path.parent, 0o700)
    write_json_atomic(path, payload, mode=0o600)


def collect_if_armed(*, app_root: Path, wsgi_file: Path, home: Path | None = None) -> str:
    """Return a stable non-secret code and never expose evidence values."""
    control, marker, report, binding = _paths(home)
    if not marker.exists():
        return "PASSENGER_EVIDENCE_NOT_ARMED"
    try:
        armed = _read_arm_marker(control, marker)
        evidence = collect_runtime_evidence(
            app_root=app_root,
            wsgi_file=wsgi_file,
            application_process=True,
        )
        if evidence["runtime_compliance"] != STRONG_STATUS:
            return "PASSENGER_EVIDENCE_CONTEXT_NOT_CONFIRMED"
        bound = build_binding_report(armed, evidence)
        # Runtime report + candidate binding must both be durably private before
        # the one-time marker can be consumed.
        write_private_report(report, evidence)
        _write_binding_report(binding, bound)
        marker_stat = os.lstat(marker)
        if marker_stat.st_nlink != 1 or marker_stat.st_uid != os.getuid() or marker_stat.st_size <= 0:
            return "PASSENGER_EVIDENCE_MARKER_CHANGED"
        marker.unlink()
        return "PASSENGER_EVIDENCE_PRIVATE_REPORT_WRITTEN"
    except Exception:
        # Application availability is not coupled to evidence collection.
        # No exception text/path/value is logged or returned.
        return "PASSENGER_EVIDENCE_BLOCKED"


def collect_if_armed_from_bridge_app(app_module_file: str | Path, *, home: Path | None = None) -> str:
    """Call-free-WSGI adapter for ``bridge.app.BridgeApplication.__call__``.

    ``app_module_file`` must be the real ``bridge/app.py`` file inside a normal
    application root. The helper derives the sibling root ``passenger_wsgi.py``
    and delegates to the exact same fail-closed collector. It never raises to the
    request path and returns only a bounded status code.
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
        return collect_if_armed(app_root=app_root, wsgi_file=wsgi_file, home=home)
    except Exception:
        return "PASSENGER_EVIDENCE_APP_TOPOLOGY_BLOCKED"
