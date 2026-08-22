# -*- coding: utf-8 -*-
"""DEV_C Release-to-Live QA truth gates.

Credential-free, non-deploying verification only. These helpers are deliberately
independent from DEV_A package validation and DEV_B live evidence accounting so
that cross-lane semantic drift is caught rather than silently inherited.
"""
from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

SHA40_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
REQ_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==([A-Za-z0-9][A-Za-z0-9.+!_-]*)$")
LOCK_RE = re.compile(
    r"^([A-Za-z0-9][A-Za-z0-9._-]*)==([A-Za-z0-9][A-Za-z0-9.+!_-]*)\s+--hash=sha256:([0-9a-f]{64})$"
)
FORBIDDEN_RELEASE_PARTS = frozenset({
    ".env", "var", "private", "secrets", "sessions", "session", "credentials",
    "credentials.json", "token.json", "cookies", "browser-profile", "browser_profiles",
})
SECRET_SOURCE_MARKERS = (
    "TG_API_HASH", "TG_SESSION", "BRIDGE_TOKEN", "SETUP_ROUTE",
    "HOSTIQ_CPANEL_PASSWORD", "SSH_PRIVATE_KEY", "/home/",
)
LIVE_EVIDENCE_CLASSES = frozenset({"FIRST_HAND_LIVE", "PRIVATE_SERVER_EVIDENCE"})
ALL_EVIDENCE_CLASSES = LIVE_EVIDENCE_CLASSES | frozenset({"TEST_SIMULATION", "REFERENCE_ONLY"})
LIVE_STEPS = ("backup", "restart", "running_identity", "health", "unauth_smoke", "auth_smoke", "resume", "rollback")


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
    if not isinstance(text, str) or len(text.encode("utf-8")) > 1_000_000:
        return []
    output: list[str] = []
    current = ""
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.endswith("\\"):
            current += line[:-1].strip() + " "
            continue
        output.append(" ".join((current + line).split()))
        current = ""
    if current:
        output.append(" ".join(current.split()))
    return output


def validate_dependency_envelope(requirements_text: str | None, lock_text: str | None) -> tuple[list[str], int, int]:
    defects: set[str] = set()
    direct: dict[str, str] = {}
    locked: dict[str, tuple[str, str]] = {}

    if requirements_text is None:
        defects.add("REQUIREMENTS_INPUT_MISSING")
    else:
        for line in _logical_lines(requirements_text):
            match = REQ_RE.fullmatch(line)
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

    for name, version in direct.items():
        if name not in locked:
            defects.add("DIRECT_REQUIREMENT_NOT_LOCKED")
        elif locked[name][0] != version:
            defects.add("DIRECT_LOCK_VERSION_MISMATCH")
    if "telethon" not in direct or "telethon" not in locked:
        defects.add("TELETHON_RUNTIME_DEPENDENCY_MISSING")
    return sorted(defects), len(direct), len(locked)


def _is_all_assignment(node: ast.AST) -> bool:
    if not isinstance(node, ast.Assign) or len(node.targets) != 1:
        return False
    target = node.targets[0]
    if not isinstance(target, ast.Name) or target.id != "__all__":
        return False
    if not isinstance(node.value, (ast.List, ast.Tuple)) or len(node.value.elts) != 1:
        return False
    item = node.value.elts[0]
    return isinstance(item, ast.Constant) and item.value == "application"


def validate_passenger_wsgi_source(source: str | None) -> list[str]:
    """Require a minimal bridge.app.application shim and reject symbol rebinding."""
    if source is None:
        return ["PASSENGER_WSGI_MISSING"]
    if not isinstance(source, str) or not source or len(source.encode("utf-8")) > 65536:
        return ["PASSENGER_WSGI_INVALID"]
    defects: set[str] = set()
    if any(marker in source for marker in SECRET_SOURCE_MARKERS):
        defects.add("PASSENGER_WSGI_PRIVATE_MATERIAL")
    try:
        tree = ast.parse(source, filename="passenger_wsgi.py")
    except SyntaxError:
        return sorted(defects | {"PASSENGER_WSGI_SYNTAX_INVALID"})

    canonical_imports = 0
    for index, node in enumerate(tree.body):
        if index == 0 and isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            continue
        if isinstance(node, ast.ImportFrom) and node.level == 0 and node.module == "bridge.app":
            if [(alias.name, alias.asname) for alias in node.names] == [("application", None)]:
                canonical_imports += 1
                continue
        if _is_all_assignment(node):
            continue
        defects.add("PASSENGER_WSGI_UNSAFE_TOP_LEVEL")

    if canonical_imports != 1:
        defects.add("PASSENGER_WSGI_CANONICAL_IMPORT_MISSING")

    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)) and node.id == "application":
            defects.add("PASSENGER_WSGI_APPLICATION_REBOUND")
        if isinstance(node, (ast.Call, ast.Await, ast.AsyncFor, ast.AsyncWith, ast.With, ast.Try)):
            defects.add("PASSENGER_WSGI_IMPORT_SIDE_EFFECT_RISK")
    return sorted(defects)


def _private_release_path(rel: Path) -> bool:
    lowered = tuple(part.casefold() for part in rel.parts)
    if any(part in FORBIDDEN_RELEASE_PARTS for part in lowered):
        return True
    return any(
        part.endswith(".session") or part.endswith(".session-journal") or part.startswith(".env.")
        for part in lowered
    )


def assess_release_root(root: Path) -> ReleaseAssessment:
    root = Path(root)
    if not root.is_dir():
        return ReleaseAssessment("INTERNAL_RELEASE_BLOCKER", ("RELEASE_ROOT_MISSING",), 0, 0)
    defects: set[str] = set()
    wsgi = root / "passenger_wsgi.py"
    req = root / "requirements.txt"
    lock = root / "requirements.lock"
    try:
        wsgi_text = wsgi.read_text(encoding="utf-8") if wsgi.is_file() else None
        req_text = req.read_text(encoding="utf-8") if req.is_file() else None
        lock_text = lock.read_text(encoding="utf-8") if lock.is_file() else None
    except (OSError, UnicodeError):
        return ReleaseAssessment("INTERNAL_RELEASE_BLOCKER", ("RELEASE_CONTROL_FILE_UNREADABLE",), 0, 0)
    defects.update(validate_passenger_wsgi_source(wsgi_text))
    dep_defects, direct_count, lock_count = validate_dependency_envelope(req_text, lock_text)
    defects.update(dep_defects)
    for path in root.rglob("*"):
        if not path.is_file() or ".git" in path.parts:
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
    """Independently validate PREPARED_RELEASE.json semantics.

    runtime_entries are persistent-state bindings, not startup files; startup is
    already bound by the source/payload manifests and package validation.
    """
    defects: set[str] = set()
    if not SHA40_RE.fullmatch(expected_sha or ""):
        return ["EXPECTED_SHA_INVALID"]
    expected_keys = {
        "schema_version", "repository", "approved_ref", "sha", "configured_python_version",
        "python_version", "approved_python_identity", "source_manifest_sha256",
        "requirements_lock_sha256", "requirements_test_lock_sha256", "payload_manifest_sha256",
        "runtime_entries", "persistent_state_mode", "immutable_permission_policy",
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
    if not isinstance(entries, list) or entries != sorted(set(entries)) or any(not isinstance(v, str) or not v for v in entries):
        defects.add("PREPARED_METADATA_RUNTIME_ENTRIES_INVALID")
    if payload.get("persistent_state_mode") != "shared_external":
        defects.add("PREPARED_METADATA_PERSISTENT_STATE_MODE_INVALID")
    if payload.get("immutable_permission_policy") != "no-write-bits-v1":
        defects.add("PREPARED_METADATA_IMMUTABILITY_POLICY_INVALID")
    ref = payload.get("approved_ref")
    if not isinstance(ref, str) or not re.fullmatch(r"(?:refs/heads/)?[A-Za-z0-9._/-]{1,200}", ref):
        defects.add("PREPARED_METADATA_APPROVED_REF_INVALID")
    identity = payload.get("approved_python_identity")
    if not isinstance(identity, Mapping) or not isinstance(identity.get("version"), str) or not str(identity.get("version")).startswith("3.11."):
        defects.add("PREPARED_METADATA_APPROVED_PYTHON_IDENTITY_INVALID")
    return sorted(defects)


def validate_devb_evidence_interface(payload: Mapping[str, Any], expected_sha: str) -> list[str]:
    """Mirror DEV_B live-evidence semantics without accepting simulation as live."""
    defects: set[str] = set()
    top = {
        "schema_version", "candidate_sha", "evidence_classes", "server_manifest",
        "reconciliation", "runtime", "lifecycle", "privacy",
    }
    if not isinstance(payload, Mapping) or set(payload) != top:
        return ["DEVB_EVIDENCE_SCHEMA_MISMATCH"]
    if payload.get("schema_version") != 1 or payload.get("candidate_sha") != expected_sha:
        defects.add("DEVB_EVIDENCE_CANDIDATE_IDENTITY_MISMATCH")
    classes = payload.get("evidence_classes")
    if not isinstance(classes, Mapping) or set(classes) != {"source", "runtime", "lifecycle"}:
        defects.add("DEVB_EVIDENCE_CLASS_SCHEMA_MISMATCH")
        classes = {}
    if any(value not in ALL_EVIDENCE_CLASSES for value in classes.values()):
        defects.add("DEVB_EVIDENCE_CLASS_INVALID")
    runtime = payload.get("runtime")
    lifecycle = payload.get("lifecycle")
    recon = payload.get("reconciliation")
    privacy = payload.get("privacy")
    if not all(isinstance(value, Mapping) for value in (runtime, lifecycle, recon, privacy)):
        return sorted(defects | {"DEVB_EVIDENCE_COMPONENT_SCHEMA_MISMATCH"})
    assert isinstance(runtime, Mapping) and isinstance(lifecycle, Mapping) and isinstance(recon, Mapping) and isinstance(privacy, Mapping)
    if lifecycle.get("candidate_sha") != expected_sha:
        defects.add("DEVB_LIFECYCLE_SHA_MISMATCH")
    mode = lifecycle.get("mode")
    if mode in {"TEST_SIMULATION", "NOT_EXECUTED"} and any(lifecycle.get(step) == "PASS" for step in LIVE_STEPS):
        defects.add("DEVB_SIMULATION_CANNOT_SATISFY_LIVE")
    if mode == "LIVE_SERVER" and classes.get("lifecycle") not in LIVE_EVIDENCE_CLASSES:
        defects.add("DEVB_LIVE_CLASS_REQUIRED")
    strong_runtime = (
        runtime.get("collector_context") == "APPLICATION_PROCESS"
        and runtime.get("python_major_minor") == "3.11"
        and runtime.get("runtime_compliance") == "PYTHON_3_11_APPLICATION_CONTEXT_CONFIRMED"
        and runtime.get("application_import_ok") is True
        and runtime.get("passenger_context_present") is True
    )
    if runtime.get("runtime_compliance") == "PYTHON_3_11_APPLICATION_CONTEXT_CONFIRMED" and not strong_runtime:
        defects.add("DEVB_PASSENGER_CLAIM_UNSUPPORTED")
    if recon.get("status") == "EXACT_ACCOUNTED" and (
        recon.get("unreviewed_difference_count") != 0 or recon.get("startup_accounted") is not True
    ):
        defects.add("DEVB_EXACT_RECONCILIATION_UNSUPPORTED")
    if privacy.get("private_values_copied") is not False or privacy.get("raw_response_copied") is not False:
        defects.add("DEVB_PRIVACY_BOUNDARY_VIOLATION")
    return sorted(defects)


def release_live_protocols() -> dict[str, PreLiveProtocol]:
    common = ("AUDITED_DEPLOYED_SHA", "PASSENGER_RUNTIME_VERIFIED", "PRIVATE_API_AUTH_READY")
    telegram = common + ("TELEGRAM_AUTHORIZED",)
    protocols = {
        "H1": PreLiveProtocol("H1", False, common + ("DEPLOYED_SCHEMA_HASH_MATCH",), ("code_sha", "sha256", "result_count")),
        "H2": PreLiveProtocol("H2", False, common + ("CHATGPT_ACTION_CONNECTED_READ_ONLY",), ("operation_sha256", "result_count")),
        "H3": PreLiveProtocol("H3", False, common + ("CHATGPT_ACTION_CONNECTED",), ("http_status", "result_count")),
        "H4": PreLiveProtocol("H4", False, telegram + ("CHATGPT_ACTION_CONNECTED",), ("operation_sha256", "state")),
        "H5": PreLiveProtocol("H5", False, common + ("CHATGPT_ACTION_CONNECTED",), ("http_status", "operation_sha256")),
        "K1": PreLiveProtocol("K1", False, telegram, ("result_count", "identifier_sha256")),
        "K2": PreLiveProtocol("K2", False, telegram, ("result_count", "identifier_sha256")),
        "K3": PreLiveProtocol("K3", False, telegram, ("file_count", "sha256")),
        "K4": PreLiveProtocol("K4", False, telegram, ("operation_sha256", "state")),
        "K5": PreLiveProtocol(
            "K5", False,
            telegram + ("INDEPENDENT_AUDITOR_WRITE_APPROVAL", "SAFE_DESTINATION_CONFIRMED", "EXPLICIT_USER_COMMIT"),
            ("operation_sha256", "result_count"),
        ),
    }
    return protocols


def keyboard_nvda_protocol() -> tuple[tuple[str, str, str], ...]:
    return (
        ("I1_START", "OPEN_SETUP_WITH_KEYBOARD", "FOCUS_VISIBLE_AND_MEANINGFUL"),
        ("I2_LABELS", "TAB_THROUGH_INPUTS", "NVDA_ANNOUNCES_LABEL_AND_ROLE"),
        ("I4_ORDER", "TAB_FORWARD_AND_SHIFT_TAB_BACK", "ORDER_LOGICAL_NO_TRAP"),
        ("I3_ACTIONS", "ACTIVATE_CONTROLS_WITH_ENTER_OR_SPACE", "NO_MOUSE_REQUIRED"),
        ("I6_STATUS", "TRIGGER_SAFE_VALIDATION_ERROR", "NVDA_ANNOUNCES_TEXT_ERROR"),
        ("I6_PROGRESS", "TRIGGER_SAFE_ASYNC_STATUS", "NVDA_ANNOUNCES_STATUS_CHANGE"),
        ("I7_RECOVERY", "RECOVER_CANCEL_AND_RETRY_BY_KEYBOARD", "FOCUS_RETURNS_PREDICTABLY"),
    )
