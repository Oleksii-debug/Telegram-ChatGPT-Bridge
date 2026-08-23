# -*- coding: utf-8 -*-
"""Independent DEV_C Release-to-Live QA truth gates.

This module is deliberately non-deploying and credential-free.  It validates
public source/package/evidence contracts only; it never reads HOSTiQ private
state, Telegram credentials/sessions, or performs network/Telegram I/O.
"""
from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

SHA40_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
DIRECT_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==([A-Za-z0-9][A-Za-z0-9.+!_-]*)$")
LOCK_RE = re.compile(
    r"^([A-Za-z0-9][A-Za-z0-9._-]*)==([A-Za-z0-9][A-Za-z0-9.+!_-]*)\s+--hash=sha256:([0-9a-f]{64})$"
)
EXPECTED_DIRECT = {"telethon": "1.44.0"}
EXPECTED_LOCK = {
    "telethon": "1.44.0",
    "pyaes": "1.6.1",
    "rsa": "4.9.1",
    "pyasn1": "0.6.4",
}
PRIVATE_PATH_PARTS = frozenset(
    {
        ".env",
        "private",
        "secrets",
        "sessions",
        "credentials",
        "cookies",
        "browser-profile",
        "browser_profiles",
    }
)
PRIVATE_SOURCE_MARKERS = (
    "TG_API_HASH",
    "TG_SESSION_STRING",
    "BRIDGE_TOKEN",
    "HOSTIQ_CPANEL_PASSWORD",
    "SSH_PRIVATE_KEY",
)


@dataclass(frozen=True)
class ReleaseAssessment:
    status: str
    defect_codes: tuple[str, ...]
    direct_requirement_count: int
    locked_requirement_count: int


@dataclass(frozen=True)
class PreLiveProtocol:
    scenario_id: str
    execute_now: bool
    required_gates: tuple[str, ...]
    public_evidence_fields: tuple[str, ...]


def _canonical_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).casefold()


def _logical_lines(text: str) -> list[str]:
    """Return normalized requirement entries, joining backslash continuations."""
    if not isinstance(text, str) or len(text.encode("utf-8")) > 1_000_000:
        return []
    output: list[str] = []
    pending = ""
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.endswith("\\"):
            pending += line[:-1].strip() + " "
            continue
        output.append(" ".join((pending + line).split()))
        pending = ""
    if pending:
        output.append(" ".join(pending.split()))
    return output


def validate_dependency_envelope(requirements_text: str | None, lock_text: str | None) -> tuple[list[str], int, int]:
    defects: set[str] = set()
    direct: dict[str, str] = {}
    locked: dict[str, tuple[str, str]] = {}

    if requirements_text is None:
        defects.add("REQUIREMENTS_INPUT_MISSING")
    else:
        for line in _logical_lines(requirements_text):
            if any(token in line for token in ("://", " @ ", ";")) or line.startswith(("-r ", "--requirement ", "-e ", "--editable ")):
                defects.add("REQUIREMENTS_INPUT_UNSAFE_SOURCE")
                continue
            match = DIRECT_RE.fullmatch(line)
            if not match:
                defects.add("REQUIREMENTS_INPUT_NOT_EXACT_PIN")
                continue
            name = _canonical_name(match.group(1))
            if name in direct:
                defects.add("REQUIREMENTS_INPUT_DUPLICATE")
            direct[name] = match.group(2)
        if not direct:
            defects.add("REQUIREMENTS_INPUT_EMPTY")

    if lock_text is None:
        defects.add("REQUIREMENTS_LOCK_MISSING")
    else:
        for line in _logical_lines(lock_text):
            if any(token in line for token in ("://", " @ ", ";")) or line.startswith(("-r ", "--requirement ", "-e ", "--editable ")):
                defects.add("REQUIREMENTS_LOCK_UNSAFE_SOURCE")
                continue
            match = LOCK_RE.fullmatch(line)
            if not match:
                defects.add("REQUIREMENTS_LOCK_NOT_EXACT_HASH_PIN")
                continue
            name = _canonical_name(match.group(1))
            if name in locked:
                defects.add("REQUIREMENTS_LOCK_DUPLICATE")
            locked[name] = (match.group(2), match.group(3))
        if not locked:
            defects.add("REQUIREMENTS_LOCK_EMPTY")

    if direct != EXPECTED_DIRECT:
        defects.add("DIRECT_RUNTIME_SET_MISMATCH")
    if {name: value[0] for name, value in locked.items()} != EXPECTED_LOCK:
        defects.add("LOCKED_RUNTIME_CLOSURE_MISMATCH")
    for name, version in direct.items():
        if name not in locked:
            defects.add("DIRECT_REQUIREMENT_NOT_LOCKED")
        elif locked[name][0] != version:
            defects.add("DIRECT_LOCK_VERSION_MISMATCH")
    return sorted(defects), len(direct), len(locked)


def _exact_import(node: ast.AST, module: str, name: str) -> bool:
    return (
        isinstance(node, ast.ImportFrom)
        and node.level == 0
        and node.module == module
        and [(alias.name, alias.asname) for alias in node.names] == [(name, None)]
    )


def _valid_here_assignment(node: ast.AST) -> bool:
    if not isinstance(node, ast.Assign) or len(node.targets) != 1:
        return False
    target = node.targets[0]
    value = node.value
    return (
        isinstance(target, ast.Name)
        and target.id == "_here"
        and isinstance(value, ast.Call)
        and not value.args
        and not value.keywords
        and isinstance(value.func, ast.Attribute)
        and value.func.attr == "resolve"
        and isinstance(value.func.value, ast.Call)
        and isinstance(value.func.value.func, ast.Name)
        and value.func.value.func.id == "Path"
        and len(value.func.value.args) == 1
        and isinstance(value.func.value.args[0], ast.Name)
        and value.func.value.args[0].id == "__file__"
        and not value.func.value.keywords
    )


def _valid_evidence_call(node: ast.AST) -> bool:
    if not isinstance(node, ast.Expr) or not isinstance(node.value, ast.Call):
        return False
    call = node.value
    if not isinstance(call.func, ast.Name) or call.func.id != "collect_if_armed" or call.args:
        return False
    if [kw.arg for kw in call.keywords] != ["app_root", "wsgi_file"]:
        return False
    app_root = call.keywords[0].value
    wsgi_file = call.keywords[1].value
    return (
        isinstance(app_root, ast.Attribute)
        and app_root.attr == "parent"
        and isinstance(app_root.value, ast.Name)
        and app_root.value.id == "_here"
        and isinstance(wsgi_file, ast.Name)
        and wsgi_file.id == "_here"
    )


def _valid_all_assignment(node: ast.AST) -> bool:
    if not isinstance(node, ast.Assign) or len(node.targets) != 1:
        return False
    target = node.targets[0]
    if not isinstance(target, ast.Name) or target.id != "__all__":
        return False
    value = node.value
    return (
        isinstance(value, (ast.List, ast.Tuple))
        and len(value.elts) == 1
        and isinstance(value.elts[0], ast.Constant)
        and value.elts[0].value == "application"
    )


def validate_passenger_wsgi_source(source: str | None) -> list[str]:
    """Independently require the exact audited Passenger startup sequence."""
    if source is None:
        return ["PASSENGER_WSGI_MISSING"]
    if not isinstance(source, str) or not source or len(source.encode("utf-8")) > 65_536:
        return ["PASSENGER_WSGI_INVALID"]
    defects: set[str] = set()
    if any(marker in source for marker in PRIVATE_SOURCE_MARKERS):
        defects.add("PASSENGER_WSGI_PRIVATE_MATERIAL")
    try:
        tree = ast.parse(source, filename="passenger_wsgi.py")
    except SyntaxError:
        return sorted(defects | {"PASSENGER_WSGI_SYNTAX_INVALID"})

    body = list(tree.body)
    if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) and isinstance(body[0].value.value, str):
        body = body[1:]
    if len(body) != 6:
        defects.add("PASSENGER_WSGI_STATEMENT_SET_MISMATCH")
        return sorted(defects)
    checks = (
        _exact_import(body[0], "pathlib", "Path"),
        _exact_import(body[1], "bridge.app", "application"),
        _exact_import(body[2], "ops.passenger_evidence_hook", "collect_if_armed"),
        _valid_here_assignment(body[3]),
        _valid_evidence_call(body[4]),
        _valid_all_assignment(body[5]),
    )
    if not checks[0]:
        defects.add("PASSENGER_WSGI_PATH_IMPORT_MISMATCH")
    if not checks[1]:
        defects.add("PASSENGER_WSGI_APPLICATION_IMPORT_MISMATCH")
    if not checks[2]:
        defects.add("PASSENGER_WSGI_EVIDENCE_IMPORT_MISMATCH")
    if not checks[3]:
        defects.add("PASSENGER_WSGI_PATH_BINDING_MISMATCH")
    if not checks[4]:
        defects.add("PASSENGER_WSGI_EVIDENCE_CALL_MISMATCH")
    if not checks[5]:
        defects.add("PASSENGER_WSGI_EXPORT_MISMATCH")
    return sorted(defects)


def _private_release_path(rel: Path) -> bool:
    lowered = tuple(part.casefold() for part in rel.parts)
    if any(part in PRIVATE_PATH_PARTS for part in lowered):
        return True
    return any(
        part.endswith(".session")
        or part.endswith(".session-journal")
        or part.startswith(".env.")
        or part in {"credentials.json", "token.json"}
        for part in lowered
    )


def assess_release_root(root: Path) -> ReleaseAssessment:
    root = Path(root)
    if not root.is_dir():
        return ReleaseAssessment("INTERNAL_RELEASE_BLOCKER", ("RELEASE_ROOT_MISSING",), 0, 0)
    defects: set[str] = set()
    try:
        wsgi = (root / "passenger_wsgi.py").read_text(encoding="utf-8") if (root / "passenger_wsgi.py").is_file() else None
        req = (root / "requirements.txt").read_text(encoding="utf-8") if (root / "requirements.txt").is_file() else None
        lock = (root / "requirements.lock").read_text(encoding="utf-8") if (root / "requirements.lock").is_file() else None
    except (OSError, UnicodeError):
        return ReleaseAssessment("INTERNAL_RELEASE_BLOCKER", ("RELEASE_CONTROL_FILE_UNREADABLE",), 0, 0)
    defects.update(validate_passenger_wsgi_source(wsgi))
    dep_defects, direct_count, lock_count = validate_dependency_envelope(req, lock)
    defects.update(dep_defects)
    for path in root.rglob("*"):
        if ".git" in path.parts or not path.is_file():
            continue
        try:
            rel = path.relative_to(root)
        except ValueError:
            defects.add("RELEASE_PATH_ESCAPE")
            continue
        if _private_release_path(rel):
            defects.add("PRIVATE_RUNTIME_ARTIFACT_IN_RELEASE")
    return ReleaseAssessment(
        "READY_FOR_PREPARE" if not defects else "INTERNAL_RELEASE_BLOCKER",
        tuple(sorted(defects)),
        direct_count,
        lock_count,
    )


def validate_prepared_release_metadata(payload: Mapping[str, Any], expected_sha: str) -> list[str]:
    defects: set[str] = set()
    if not SHA40_RE.fullmatch(expected_sha or ""):
        return ["EXPECTED_SHA_INVALID"]
    expected_keys = {
        "schema_version",
        "repository",
        "approved_ref",
        "sha",
        "configured_python_version",
        "python_version",
        "approved_python_identity",
        "source_manifest_sha256",
        "requirements_lock_sha256",
        "requirements_test_lock_sha256",
        "payload_manifest_sha256",
        "runtime_entries",
        "persistent_state_mode",
        "immutable_permission_policy",
    }
    if not isinstance(payload, Mapping) or set(payload) != expected_keys:
        return ["PREPARED_METADATA_SCHEMA_MISMATCH"]
    if payload.get("schema_version") != 2:
        defects.add("PREPARED_METADATA_VERSION_MISMATCH")
    if payload.get("repository") != "Oleksii-debug/Telegram-ChatGPT-Bridge":
        defects.add("PREPARED_METADATA_REPOSITORY_MISMATCH")
    if payload.get("sha") != expected_sha:
        defects.add("PREPARED_METADATA_STALE_SHA")
    if not str(payload.get("configured_python_version", "")).startswith("3.11."):
        defects.add("PREPARED_METADATA_CONFIGURED_PYTHON_INVALID")
    if not str(payload.get("python_version", "")).startswith("3.11."):
        defects.add("PREPARED_METADATA_BUILT_PYTHON_INVALID")
    for key in ("source_manifest_sha256", "requirements_lock_sha256", "payload_manifest_sha256"):
        if not isinstance(payload.get(key), str) or not SHA256_RE.fullmatch(str(payload.get(key))):
            defects.add("PREPARED_METADATA_HASH_MISSING_OR_INVALID")
    if payload.get("requirements_test_lock_sha256") is not None:
        defects.add("PREPARED_METADATA_UNEXPECTED_TEST_LOCK")
    entries = payload.get("runtime_entries")
    if not isinstance(entries, list) or entries != sorted(set(entries)) or any(not isinstance(value, str) or not value for value in entries):
        defects.add("PREPARED_METADATA_RUNTIME_ENTRIES_INVALID")
    if payload.get("persistent_state_mode") != "shared_external":
        defects.add("PREPARED_METADATA_PERSISTENT_STATE_MODE_INVALID")
    if payload.get("immutable_permission_policy") != "no-write-bits-v1":
        defects.add("PREPARED_METADATA_IMMUTABILITY_POLICY_INVALID")
    ref = payload.get("approved_ref")
    if not isinstance(ref, str) or not re.fullmatch(r"(?:refs/heads/)?[A-Za-z0-9._/-]{1,200}", ref):
        defects.add("PREPARED_METADATA_APPROVED_REF_INVALID")
    identity = payload.get("approved_python_identity")
    if not isinstance(identity, Mapping):
        defects.add("PREPARED_METADATA_APPROVED_PYTHON_IDENTITY_INVALID")
    else:
        if not isinstance(identity.get("version"), str) or not str(identity.get("version")).startswith("3.11."):
            defects.add("PREPARED_METADATA_APPROVED_PYTHON_IDENTITY_INVALID")
        if not isinstance(identity.get("sha256"), str) or not SHA256_RE.fullmatch(str(identity.get("sha256"))):
            defects.add("PREPARED_METADATA_APPROVED_PYTHON_IDENTITY_INVALID")
    return sorted(defects)


def release_live_protocols() -> dict[str, PreLiveProtocol]:
    common = ("AUDITED_DEPLOYED_SHA", "PASSENGER_RUNTIME_VERIFIED", "PRIVATE_API_AUTH_READY")
    telegram = common + ("TELEGRAM_AUTHORIZED",)
    return {
        "H1": PreLiveProtocol("H1", False, common + ("DEPLOYED_SCHEMA_HASH_MATCH",), ("code_sha", "schema_sha256", "result_count")),
        "H2": PreLiveProtocol("H2", False, common + ("CHATGPT_ACTION_CONNECTED_READ_ONLY",), ("operation_sha256", "result_count")),
        "H3": PreLiveProtocol("H3", False, common + ("UNKNOWN_PRIVATE_OPERATION_FAILS_CLOSED",), ("status_code", "error_code")),
        "H4": PreLiveProtocol("H4", False, telegram + ("ACTION_RUNTIME_ROUTE_PARITY",), ("operation_sha256", "result_count")),
        "H5": PreLiveProtocol("H5", False, common + ("PUBLIC_EVIDENCE_PRIVACY_SCAN",), ("artifact_sha256", "finding_count")),
        "K1": PreLiveProtocol("K1", False, telegram + ("SAFE_READ_SCENARIO",), ("operation_sha256", "result_count")),
        "K2": PreLiveProtocol("K2", False, telegram + ("SAFE_MEDIA_SCENARIO",), ("artifact_sha256", "result_count")),
        "K3": PreLiveProtocol("K3", False, telegram + ("SAFE_DOWNLOAD_ZIP_SCENARIO",), ("artifact_sha256", "result_count")),
        "K4": PreLiveProtocol("K4", False, telegram + ("PREVIEW_ONLY_ZERO_EFFECT",), ("operation_sha256", "external_effect_count")),
        "K5": PreLiveProtocol(
            "K5",
            False,
            telegram + ("INDEPENDENT_AUDITOR_WRITE_APPROVAL", "SAFE_DESTINATION_CONFIRMED", "FRESH_EXPLICIT_USER_COMMIT"),
            ("operation_sha256", "external_effect_count", "idempotent_replay_count"),
        ),
    }


def keyboard_nvda_protocol() -> tuple[str, ...]:
    """Human-live protocol only; returning it never constitutes accessibility PASS."""
    return (
        "TAB_FROM_DOCUMENT_START_AND_RECORD_FOCUS_ORDER",
        "VERIFY_EACH_INTERACTIVE_CONTROL_HAS_SPOKEN_NAME_ROLE_STATE",
        "ACTIVATE_SETUP_OR_ACTION_CONTROLS_WITH_KEYBOARD_ONLY",
        "VERIFY_STATUS_AND_ERRORS_ARE_ANNOUNCED_WITHOUT_FOCUS_LOSS",
        "VERIFY_INVALID_FIELDS_HAVE_PROGRAMMATIC_LABEL_AND_ERROR_RELATION",
        "RECOVER_FROM_ERROR_AND_COMPLETE_READ_ONLY_FLOW_WITHOUT_MOUSE",
        "REPEAT_WITH_NVDA_BROWSE_AND_FOCUS_MODES",
        "RECORD_ONLY_PRIVACY_SAFE_RESULT_CODES_AND_COUNTS",
    )


def remaining_gate_classes() -> tuple[str, ...]:
    return (
        "INTERNAL_RELEASE_BLOCKER",
        "HOSTIQ_LIVE",
        "TELEGRAM_AUTH_E2E",
        "DEPLOYED_ACTION",
        "HUMAN_NVDA",
        "K5",
    )
