# -*- coding: utf-8 -*-
"""DEV_C release-to-live package and pre-live truth gates.

Credential-free, non-deploying verification only. These checks intentionally
fail closed on incomplete startup/dependency envelopes and keep simulated
HOSTiQ/Action/accessibility evidence separate from live acceptance.
"""
from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

SHA40_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
REQ_NAME_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[A-Za-z0-9_,.-]+\])?(?:==([A-Za-z0-9][A-Za-z0-9.+!_-]*))?$")
LOCK_HEAD_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[A-Za-z0-9_,.-]+\])?==([A-Za-z0-9][A-Za-z0-9.+!_-]*)\b")
HASH_TOKEN_RE = re.compile(r"--hash=sha256:([0-9a-f]{64})(?:\s|$)")
ANY_HASH_TOKEN_RE = re.compile(r"--hash=[^\s]+")
FORBIDDEN_RELEASE_NAMES = frozenset({
    ".env", "credentials.json", "token.json", "telegram.session", "session.session",
})
SECRET_OR_PRIVATE_SOURCE_MARKERS = (
    "TG_API_HASH", "TG_SESSION", "BRIDGE_TOKEN", "SETUP_ROUTE",
    "HOSTIQ_CPANEL_PASSWORD", "SSH_PRIVATE_KEY", "/home/",
)
LIVE_EVIDENCE_CLASSES = frozenset({"FIRST_HAND_LIVE", "PRIVATE_SERVER_EVIDENCE"})
ALL_EVIDENCE_CLASSES = LIVE_EVIDENCE_CLASSES | frozenset({"TEST_SIMULATION", "REFERENCE_ONLY"})
LIVE_STEPS = ("backup", "restart", "running_identity", "health", "unauth_smoke", "auth_smoke", "resume", "rollback")


@dataclass(frozen=True)
class ReleasePackageAssessment:
    status: str
    defect_codes: tuple[str, ...]
    app_requirement_count: int
    locked_requirement_count: int


@dataclass(frozen=True)
class PreLiveProtocol:
    scenario_id: str
    execute_now: bool
    required_gates: tuple[str, ...]
    evidence_fields: tuple[str, ...]


def _canonical_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).casefold()


def _logical_lines(text: str) -> list[str]:
    if not isinstance(text, str) or len(text.encode("utf-8")) > 1_000_000:
        return []
    result: list[str] = []
    pending = ""
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.endswith("\\"):
            pending += line[:-1].rstrip() + " "
            continue
        result.append((pending + line).strip())
        pending = ""
    if pending.strip():
        result.append(pending.strip())
    return result


def _parse_input(text: str) -> tuple[dict[str, str | None], set[str]]:
    packages: dict[str, str | None] = {}
    defects: set[str] = set()
    for line in _logical_lines(text):
        if line.startswith("-") or "://" in line or "@" in line or ";" in line:
            defects.add("REQUIREMENTS_INPUT_UNSAFE_LINE")
            continue
        match = REQ_NAME_RE.fullmatch(line)
        if not match:
            defects.add("REQUIREMENTS_INPUT_UNSAFE_LINE")
            continue
        name = _canonical_name(match.group(1))
        if name in packages:
            defects.add("REQUIREMENTS_INPUT_DUPLICATE_PACKAGE")
        packages[name] = match.group(2)
    if not packages:
        defects.add("REQUIREMENTS_INPUT_EMPTY")
    return packages, defects


def _parse_lock(text: str) -> tuple[dict[str, str], set[str]]:
    packages: dict[str, str] = {}
    defects: set[str] = set()
    for line in _logical_lines(text):
        if line.startswith("-") or "://" in line or "@" in line or ";" in line:
            defects.add("REQUIREMENTS_LOCK_UNSAFE_LINE")
            continue
        match = LOCK_HEAD_RE.match(line)
        if not match:
            defects.add("REQUIREMENTS_LOCK_UNPINNED")
            continue
        name = _canonical_name(match.group(1))
        version = match.group(2)
        if name in packages:
            defects.add("REQUIREMENTS_LOCK_DUPLICATE_PACKAGE")
        packages[name] = version
        hashes = HASH_TOKEN_RE.findall(line)
        any_hashes = ANY_HASH_TOKEN_RE.findall(line)
        if not hashes:
            defects.add("REQUIREMENTS_LOCK_MISSING_SHA256")
        if len(any_hashes) != len(hashes):
            defects.add("REQUIREMENTS_LOCK_INVALID_HASH")
    if not packages:
        defects.add("REQUIREMENTS_LOCK_EMPTY")
    return packages, defects


def validate_dependency_envelope(
    requirements_text: str | None,
    lock_text: str | None,
    *,
    required_runtime_packages: tuple[str, ...] = ("telethon",),
) -> tuple[list[str], int, int]:
    defects: set[str] = set()
    if requirements_text is None:
        defects.add("REQUIREMENTS_INPUT_MISSING")
        input_packages: dict[str, str | None] = {}
    else:
        input_packages, found = _parse_input(requirements_text)
        defects.update(found)
    if lock_text is None:
        defects.add("REQUIREMENTS_LOCK_MISSING")
        locked_packages: dict[str, str] = {}
    else:
        locked_packages, found = _parse_lock(lock_text)
        defects.update(found)
    for name in input_packages:
        if name not in locked_packages:
            defects.add("REQUIREMENTS_INPUT_PACKAGE_NOT_LOCKED")
    for required in required_runtime_packages:
        canonical = _canonical_name(required)
        if canonical not in input_packages or canonical not in locked_packages:
            defects.add("REQUIRED_RUNTIME_DEPENDENCY_MISSING")
    return sorted(defects), len(input_packages), len(locked_packages)


def _safe_all_export(node: ast.AST) -> bool:
    if not isinstance(node, ast.Assign) or len(node.targets) != 1:
        return False
    target = node.targets[0]
    if not isinstance(target, ast.Name) or target.id != "__all__":
        return False
    value = node.value
    if not isinstance(value, (ast.List, ast.Tuple)) or len(value.elts) != 1:
        return False
    item = value.elts[0]
    return isinstance(item, ast.Constant) and item.value == "application"


def validate_passenger_wsgi_source(source: str | None) -> list[str]:
    if source is None:
        return ["PASSENGER_WSGI_MISSING"]
    if not isinstance(source, str) or not source or len(source.encode("utf-8")) > 65536:
        return ["PASSENGER_WSGI_INVALID"]
    defects: set[str] = set()
    if any(marker in source for marker in SECRET_OR_PRIVATE_SOURCE_MARKERS):
        defects.add("PASSENGER_WSGI_PRIVATE_MATERIAL")
    try:
        tree = ast.parse(source, filename="passenger_wsgi.py")
    except SyntaxError:
        return sorted(defects | {"PASSENGER_WSGI_SYNTAX_INVALID"})
    body = list(tree.body)
    if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) and isinstance(body[0].value.value, str):
        body = body[1:]
    canonical_imports = 0
    for node in body:
        if isinstance(node, ast.ImportFrom) and node.module == "bridge.app" and node.level == 0:
            for alias in node.names:
                if alias.name == "application" and alias.asname in (None, "application"):
                    canonical_imports += 1
            if len(node.names) != 1:
                defects.add("PASSENGER_WSGI_UNSAFE_TOP_LEVEL")
            continue
        if _safe_all_export(node):
            continue
        defects.add("PASSENGER_WSGI_UNSAFE_TOP_LEVEL")
    if canonical_imports != 1:
        defects.add("PASSENGER_WSGI_CANONICAL_IMPORT_MISSING")
    for node in ast.walk(tree):
        if isinstance(node, (ast.Call, ast.AnnAssign, ast.AugAssign, ast.With, ast.AsyncWith, ast.Try)):
            defects.add("PASSENGER_WSGI_IMPORT_SIDE_EFFECT_RISK")
            break
        if isinstance(node, ast.Assign) and not _safe_all_export(node):
            defects.add("PASSENGER_WSGI_IMPORT_SIDE_EFFECT_RISK")
            break
    return sorted(defects)


def _private_path(path: Path) -> bool:
    name = path.name.casefold()
    if name in FORBIDDEN_RELEASE_NAMES:
        return True
    if name.endswith(".session") or name.endswith(".sqlite") or name.endswith(".db"):
        return True
    return any(part.casefold() in {"var", "private", "secrets", "credentials"} for part in path.parts)


def assess_release_package_root(root: Path) -> ReleasePackageAssessment:
    defects: set[str] = set()
    root = Path(root)
    if not root.is_dir():
        return ReleasePackageAssessment("INTERNAL_RELEASE_BLOCKER", ("RELEASE_ROOT_MISSING",), 0, 0)
    wsgi = root / "passenger_wsgi.py"
    req = root / "requirements.txt"
    lock = root / "requirements.lock"
    defects.update(validate_passenger_wsgi_source(wsgi.read_text(encoding="utf-8") if wsgi.is_file() else None))
    dep_defects, input_count, lock_count = validate_dependency_envelope(
        req.read_text(encoding="utf-8") if req.is_file() else None,
        lock.read_text(encoding="utf-8") if lock.is_file() else None,
    )
    defects.update(dep_defects)
    for path in root.rglob("*"):
        if ".git" in path.parts or not path.is_file():
            continue
        try:
            rel = path.relative_to(root)
        except ValueError:
            defects.add("RELEASE_PATH_ESCAPE")
            continue
        if _private_path(rel):
            defects.add("PRIVATE_FILE_IN_RELEASE")
    status = "READY_FOR_PREPARE" if not defects else "INTERNAL_RELEASE_BLOCKER"
    return ReleasePackageAssessment(status, tuple(sorted(defects)), input_count, lock_count)


def validate_prepared_release_metadata(payload: Mapping[str, Any], expected_sha: str) -> list[str]:
    defects: set[str] = set()
    if not SHA40_RE.fullmatch(expected_sha or ""):
        return ["EXPECTED_SHA_INVALID"]
    required = {
        "schema_version", "approved_ref", "sha", "configured_python_version", "python_version",
        "source_manifest_sha256", "requirements_lock_sha256", "payload_manifest_sha256",
        "runtime_entries", "persistent_state_mode", "immutable_permission_policy",
    }
    if not isinstance(payload, Mapping) or not required.issubset(payload):
        return ["PREPARED_METADATA_SCHEMA_MISMATCH"]
    if payload.get("schema_version") != 2:
        defects.add("PREPARED_METADATA_VERSION_MISMATCH")
    if payload.get("sha") != expected_sha:
        defects.add("PREPARED_METADATA_STALE_SHA")
    if not str(payload.get("configured_python_version", "")).startswith("3.11."):
        defects.add("PREPARED_METADATA_CONFIGURED_PYTHON_INVALID")
    if not str(payload.get("python_version", "")).startswith("3.11."):
        defects.add("PREPARED_METADATA_BUILT_PYTHON_INVALID")
    for key in ("source_manifest_sha256", "requirements_lock_sha256", "payload_manifest_sha256"):
        if not isinstance(payload.get(key), str) or not SHA256_RE.fullmatch(str(payload.get(key))):
            defects.add("PREPARED_METADATA_HASH_MISSING_OR_INVALID")
    entries = payload.get("runtime_entries")
    if not isinstance(entries, list) or "passenger_wsgi.py" not in entries:
        defects.add("PREPARED_METADATA_STARTUP_UNACCOUNTED")
    if payload.get("persistent_state_mode") != "shared_external":
        defects.add("PREPARED_METADATA_PERSISTENT_STATE_MODE_INVALID")
    if payload.get("immutable_permission_policy") != "no-write-bits-v1":
        defects.add("PREPARED_METADATA_IMMUTABILITY_POLICY_INVALID")
    ref = payload.get("approved_ref")
    if not isinstance(ref, str) or not re.fullmatch(r"(?:refs/heads/)?[A-Za-z0-9._/-]{1,200}", ref):
        defects.add("PREPARED_METADATA_APPROVED_REF_INVALID")
    return sorted(defects)


def validate_devb_evidence_interface(payload: Mapping[str, Any], expected_sha: str) -> list[str]:
    """Independent semantic gate for DEV_B's documented support-return contract."""
    defects: set[str] = set()
    expected_top = {
        "schema_version", "candidate_sha", "evidence_classes", "server_manifest",
        "reconciliation", "runtime", "lifecycle", "privacy",
    }
    if not isinstance(payload, Mapping) or set(payload) != expected_top:
        return ["DEVB_EVIDENCE_SCHEMA_MISMATCH"]
    if payload.get("schema_version") != 1 or payload.get("candidate_sha") != expected_sha:
        defects.add("DEVB_EVIDENCE_CANDIDATE_IDENTITY_MISMATCH")
    classes = payload.get("evidence_classes")
    if not isinstance(classes, Mapping) or set(classes) != {"source", "runtime", "lifecycle"}:
        defects.add("DEVB_EVIDENCE_CLASS_SCHEMA_MISMATCH")
        classes = {}
    for value in classes.values():
        if value not in ALL_EVIDENCE_CLASSES:
            defects.add("DEVB_EVIDENCE_CLASS_INVALID")
    runtime = payload.get("runtime")
    lifecycle = payload.get("lifecycle")
    privacy = payload.get("privacy")
    recon = payload.get("reconciliation")
    if not isinstance(runtime, Mapping) or not isinstance(lifecycle, Mapping) or not isinstance(privacy, Mapping) or not isinstance(recon, Mapping):
        return sorted(defects | {"DEVB_EVIDENCE_COMPONENT_SCHEMA_MISMATCH"})
    if lifecycle.get("candidate_sha") != expected_sha:
        defects.add("DEVB_LIFECYCLE_SHA_MISMATCH")
    live_claim = lifecycle.get("mode") == "LIVE_SERVER"
    simulation = lifecycle.get("mode") in {"TEST_SIMULATION", "NOT_EXECUTED"}
    if simulation and any(lifecycle.get(step) == "PASS" for step in LIVE_STEPS):
        defects.add("DEVB_SIMULATION_CANNOT_SATISFY_LIVE")
    if live_claim and classes.get("lifecycle") not in LIVE_EVIDENCE_CLASSES:
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
    return {
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


def keyboard_nvda_protocol() -> tuple[tuple[str, str, str], ...]:
    """Privacy-safe human protocol; execution remains external."""
    return (
        ("I1_START", "OPEN_SETUP_WITH_KEYBOARD", "FOCUS_VISIBLE_AND_MEANINGFUL"),
        ("I2_LABELS", "TAB_THROUGH_INPUTS", "NVDA_ANNOUNCES_LABEL_AND_ROLE"),
        ("I4_ORDER", "TAB_FORWARD_AND_SHIFT_TAB_BACK", "ORDER_LOGICAL_NO_TRAP"),
        ("I3_ACTIONS", "ACTIVATE_CONTROLS_WITH_ENTER_OR_SPACE", "NO_MOUSE_REQUIRED"),
        ("I6_STATUS", "TRIGGER_SAFE_VALIDATION_ERROR", "NVDA_ANNOUNCES_TEXT_ERROR"),
        ("I6_PROGRESS", "TRIGGER_SAFE_ASYNC_STATUS", "NVDA_ANNOUNCES_STATUS_CHANGE"),
        ("I7_RECOVERY", "RECOVER_CANCEL_AND_RETRY_BY_KEYBOARD", "FOCUS_RETURNS_PREDICTABLY"),
    )
