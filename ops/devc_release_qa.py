# -*- coding: utf-8 -*-
"""Independent DEV_C Release-to-Live QA truth gates.

Non-deploying, credential-free validation of public package/evidence contracts.
No HOSTiQ private state, Telegram credential/session, network or Telegram I/O.
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
LOCK_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==([A-Za-z0-9][A-Za-z0-9.+!_-]*)\s+--hash=sha256:([0-9a-f]{64})$")
EXPECTED_DIRECT = {"telethon": "1.44.0"}
EXPECTED_LOCK = {"telethon": "1.44.0", "pyaes": "1.6.1", "rsa": "4.9.1", "pyasn1": "0.6.4"}
PRIVATE_SOURCE_MARKERS = ("TG_API_HASH", "TG_SESSION_STRING", "BRIDGE_TOKEN", "HOSTIQ_CPANEL_PASSWORD", "SSH_PRIVATE_KEY")


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


def _name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).casefold()


def _logical_lines(text: str) -> list[str]:
    if not isinstance(text, str) or len(text.encode("utf-8")) > 1_000_000:
        return []
    out, pending = [], ""
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.endswith("\\"):
            pending += line[:-1].strip() + " "
            continue
        out.append(" ".join((pending + line).split()))
        pending = ""
    if pending:
        out.append(" ".join(pending.split()))
    return out


def validate_dependency_envelope(requirements_text: str | None, lock_text: str | None) -> tuple[list[str], int, int]:
    defects: set[str] = set()
    direct: dict[str, str] = {}
    locked: dict[str, tuple[str, str]] = {}
    if requirements_text is None:
        defects.add("REQUIREMENTS_INPUT_MISSING")
    else:
        for line in _logical_lines(requirements_text):
            if any(t in line for t in ("://", " @ ", ";")) or line.startswith(("-r ", "--requirement ", "-e ", "--editable ")):
                defects.add("REQUIREMENTS_INPUT_UNSAFE_SOURCE"); continue
            m = DIRECT_RE.fullmatch(line)
            if not m:
                defects.add("REQUIREMENTS_INPUT_NOT_EXACT_PIN"); continue
            n = _name(m.group(1))
            if n in direct: defects.add("REQUIREMENTS_INPUT_DUPLICATE")
            direct[n] = m.group(2)
        if not direct: defects.add("REQUIREMENTS_INPUT_EMPTY")
    if lock_text is None:
        defects.add("REQUIREMENTS_LOCK_MISSING")
    else:
        for line in _logical_lines(lock_text):
            if any(t in line for t in ("://", " @ ", ";")) or line.startswith(("-r ", "--requirement ", "-e ", "--editable ")):
                defects.add("REQUIREMENTS_LOCK_UNSAFE_SOURCE"); continue
            m = LOCK_RE.fullmatch(line)
            if not m:
                defects.add("REQUIREMENTS_LOCK_NOT_EXACT_HASH_PIN"); continue
            n = _name(m.group(1))
            if n in locked: defects.add("REQUIREMENTS_LOCK_DUPLICATE")
            locked[n] = (m.group(2), m.group(3))
        if not locked: defects.add("REQUIREMENTS_LOCK_EMPTY")
    if direct != EXPECTED_DIRECT: defects.add("DIRECT_RUNTIME_SET_MISMATCH")
    if {n: v[0] for n, v in locked.items()} != EXPECTED_LOCK: defects.add("LOCKED_RUNTIME_CLOSURE_MISMATCH")
    for n, version in direct.items():
        if n not in locked: defects.add("DIRECT_REQUIREMENT_NOT_LOCKED")
        elif locked[n][0] != version: defects.add("DIRECT_LOCK_VERSION_MISMATCH")
    return sorted(defects), len(direct), len(locked)


def _exact_import(node: ast.AST, module: str, name: str) -> bool:
    return isinstance(node, ast.ImportFrom) and node.level == 0 and node.module == module and [(a.name, a.asname) for a in node.names] == [(name, None)]


def _valid_here(node: ast.AST) -> bool:
    if not isinstance(node, ast.Assign) or len(node.targets) != 1 or not isinstance(node.targets[0], ast.Name) or node.targets[0].id != "_here": return False
    v = node.value
    return isinstance(v, ast.Call) and not v.args and not v.keywords and isinstance(v.func, ast.Attribute) and v.func.attr == "resolve" and isinstance(v.func.value, ast.Call) and isinstance(v.func.value.func, ast.Name) and v.func.value.func.id == "Path" and len(v.func.value.args) == 1 and isinstance(v.func.value.args[0], ast.Name) and v.func.value.args[0].id == "__file__" and not v.func.value.keywords


def _valid_call(node: ast.AST) -> bool:
    if not isinstance(node, ast.Expr) or not isinstance(node.value, ast.Call): return False
    c = node.value
    if not isinstance(c.func, ast.Name) or c.func.id != "collect_if_armed" or c.args or [k.arg for k in c.keywords] != ["app_root", "wsgi_file"]: return False
    a, w = c.keywords[0].value, c.keywords[1].value
    return isinstance(a, ast.Attribute) and a.attr == "parent" and isinstance(a.value, ast.Name) and a.value.id == "_here" and isinstance(w, ast.Name) and w.id == "_here"


def _valid_all(node: ast.AST) -> bool:
    if not isinstance(node, ast.Assign) or len(node.targets) != 1 or not isinstance(node.targets[0], ast.Name) or node.targets[0].id != "__all__": return False
    v = node.value
    return isinstance(v, (ast.List, ast.Tuple)) and len(v.elts) == 1 and isinstance(v.elts[0], ast.Constant) and v.elts[0].value == "application"


def validate_passenger_wsgi_source(source: str | None) -> list[str]:
    if source is None: return ["PASSENGER_WSGI_MISSING"]
    if not isinstance(source, str) or not source or len(source.encode("utf-8")) > 65536: return ["PASSENGER_WSGI_INVALID"]
    defects: set[str] = set()
    if any(m in source for m in PRIVATE_SOURCE_MARKERS): defects.add("PASSENGER_WSGI_PRIVATE_MATERIAL")
    try: tree = ast.parse(source, filename="passenger_wsgi.py")
    except SyntaxError: return sorted(defects | {"PASSENGER_WSGI_SYNTAX_INVALID"})
    body = list(tree.body)
    if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) and isinstance(body[0].value.value, str): body = body[1:]
    if len(body) != 6: return sorted(defects | {"PASSENGER_WSGI_STATEMENT_SET_MISMATCH"})
    checks = [
        (_exact_import(body[0], "pathlib", "Path"), "PASSENGER_WSGI_PATH_IMPORT_MISMATCH"),
        (_exact_import(body[1], "bridge.app", "application"), "PASSENGER_WSGI_APPLICATION_IMPORT_MISMATCH"),
        (_exact_import(body[2], "ops.passenger_evidence_hook", "collect_if_armed"), "PASSENGER_WSGI_EVIDENCE_IMPORT_MISMATCH"),
        (_valid_here(body[3]), "PASSENGER_WSGI_PATH_BINDING_MISMATCH"),
        (_valid_call(body[4]), "PASSENGER_WSGI_EVIDENCE_CALL_MISMATCH"),
        (_valid_all(body[5]), "PASSENGER_WSGI_EXPORT_MISMATCH"),
    ]
    defects.update(code for ok, code in checks if not ok)
    return sorted(defects)


def _private_path(rel: Path) -> bool:
    parts = tuple(p.casefold() for p in rel.parts)
    if any(p in {".env", "private", "secrets", "sessions", "credentials", "cookies", "browser-profile", "browser_profiles"} for p in parts): return True
    return any(p.endswith(".session") or p.endswith(".session-journal") or p.startswith(".env.") or p in {"credentials.json", "token.json"} for p in parts)


def assess_release_root(root: Path) -> ReleaseAssessment:
    root = Path(root)
    if not root.is_dir(): return ReleaseAssessment("INTERNAL_RELEASE_BLOCKER", ("RELEASE_ROOT_MISSING",), 0, 0)
    try:
        wsgi = (root / "passenger_wsgi.py").read_text(encoding="utf-8") if (root / "passenger_wsgi.py").is_file() else None
        req = (root / "requirements.txt").read_text(encoding="utf-8") if (root / "requirements.txt").is_file() else None
        lock = (root / "requirements.lock").read_text(encoding="utf-8") if (root / "requirements.lock").is_file() else None
    except (OSError, UnicodeError): return ReleaseAssessment("INTERNAL_RELEASE_BLOCKER", ("RELEASE_CONTROL_FILE_UNREADABLE",), 0, 0)
    defects = set(validate_passenger_wsgi_source(wsgi))
    d, direct, locked = validate_dependency_envelope(req, lock); defects.update(d)
    for path in root.rglob("*"):
        if ".git" in path.parts or not path.is_file(): continue
        try: rel = path.relative_to(root)
        except ValueError: defects.add("RELEASE_PATH_ESCAPE"); continue
        if _private_path(rel): defects.add("PRIVATE_RUNTIME_ARTIFACT_IN_RELEASE")
    return ReleaseAssessment("READY_FOR_PREPARE" if not defects else "INTERNAL_RELEASE_BLOCKER", tuple(sorted(defects)), direct, locked)


def validate_prepared_release_metadata(payload: Mapping[str, Any], expected_sha: str) -> list[str]:
    if not SHA40_RE.fullmatch(expected_sha or ""): return ["EXPECTED_SHA_INVALID"]
    expected = {"schema_version","repository","approved_ref","sha","configured_python_version","python_version","approved_python_identity","source_manifest_sha256","requirements_lock_sha256","requirements_test_lock_sha256","payload_manifest_sha256","runtime_entries","persistent_state_mode","immutable_permission_policy"}
    if not isinstance(payload, Mapping) or set(payload) != expected: return ["PREPARED_METADATA_SCHEMA_MISMATCH"]
    defects: set[str] = set()
    if payload.get("schema_version") != 2: defects.add("PREPARED_METADATA_VERSION_MISMATCH")
    if payload.get("repository") != "Oleksii-debug/Telegram-ChatGPT-Bridge": defects.add("PREPARED_METADATA_REPOSITORY_MISMATCH")
    if payload.get("sha") != expected_sha: defects.add("PREPARED_METADATA_STALE_SHA")
    if not str(payload.get("configured_python_version", "")).startswith("3.11."): defects.add("PREPARED_METADATA_CONFIGURED_PYTHON_INVALID")
    if not str(payload.get("python_version", "")).startswith("3.11."): defects.add("PREPARED_METADATA_BUILT_PYTHON_INVALID")
    for key in ("source_manifest_sha256","requirements_lock_sha256","payload_manifest_sha256"):
        if not isinstance(payload.get(key), str) or not SHA256_RE.fullmatch(str(payload.get(key))): defects.add("PREPARED_METADATA_HASH_MISSING_OR_INVALID")
    if payload.get("requirements_test_lock_sha256") is not None: defects.add("PREPARED_METADATA_UNEXPECTED_TEST_LOCK")
    entries = payload.get("runtime_entries")
    if not isinstance(entries, list) or entries != sorted(set(entries)) or any(not isinstance(v, str) or not v for v in entries): defects.add("PREPARED_METADATA_RUNTIME_ENTRIES_INVALID")
    if payload.get("persistent_state_mode") != "shared_external": defects.add("PREPARED_METADATA_PERSISTENT_STATE_MODE_INVALID")
    if payload.get("immutable_permission_policy") != "no-write-bits-v1": defects.add("PREPARED_METADATA_IMMUTABILITY_POLICY_INVALID")
    ref = payload.get("approved_ref")
    if not isinstance(ref, str) or not re.fullmatch(r"(?:refs/heads/)?[A-Za-z0-9._/-]{1,200}", ref): defects.add("PREPARED_METADATA_APPROVED_REF_INVALID")
    identity = payload.get("approved_python_identity")
    if not isinstance(identity, Mapping) or not str(identity.get("version", "")).startswith("3.11.") or not SHA256_RE.fullmatch(str(identity.get("sha256", ""))): defects.add("PREPARED_METADATA_APPROVED_PYTHON_IDENTITY_INVALID")
    return sorted(defects)


def release_live_protocols() -> dict[str, PreLiveProtocol]:
    common = ("AUDITED_DEPLOYED_SHA", "PASSENGER_RUNTIME_VERIFIED", "PRIVATE_API_AUTH_READY")
    telegram = common + ("TELEGRAM_AUTHORIZED",)
    return {
        "H1": PreLiveProtocol("H1", False, common + ("DEPLOYED_SCHEMA_HASH_MATCH",), ("code_sha","schema_sha256","result_count")),
        "H2": PreLiveProtocol("H2", False, common + ("CHATGPT_ACTION_CONNECTED_READ_ONLY",), ("operation_sha256","result_count")),
        "H3": PreLiveProtocol("H3", False, common + ("UNKNOWN_PRIVATE_OPERATION_FAILS_CLOSED",), ("status_code","error_code")),
        "H4": PreLiveProtocol("H4", False, telegram + ("ACTION_RUNTIME_ROUTE_PARITY",), ("operation_sha256","result_count")),
        "H5": PreLiveProtocol("H5", False, common + ("PUBLIC_EVIDENCE_PRIVACY_SCAN",), ("artifact_sha256","finding_count")),
        "K1": PreLiveProtocol("K1", False, telegram + ("SAFE_READ_SCENARIO",), ("operation_sha256","result_count")),
        "K2": PreLiveProtocol("K2", False, telegram + ("SAFE_MEDIA_SCENARIO",), ("artifact_sha256","result_count")),
        "K3": PreLiveProtocol("K3", False, telegram + ("SAFE_DOWNLOAD_ZIP_SCENARIO",), ("artifact_sha256","result_count")),
        "K4": PreLiveProtocol("K4", False, telegram + ("PREVIEW_ONLY_ZERO_EFFECT",), ("operation_sha256","external_effect_count")),
        "K5": PreLiveProtocol("K5", False, telegram + ("INDEPENDENT_AUDITOR_WRITE_APPROVAL","SAFE_DESTINATION_CONFIRMED","FRESH_EXPLICIT_USER_COMMIT"), ("operation_sha256","external_effect_count","idempotent_replay_count")),
    }


def keyboard_nvda_protocol() -> tuple[str, ...]:
    return ("TAB_FROM_DOCUMENT_START_AND_RECORD_FOCUS_ORDER","VERIFY_EACH_INTERACTIVE_CONTROL_HAS_SPOKEN_NAME_ROLE_STATE","ACTIVATE_SETUP_OR_ACTION_CONTROLS_WITH_KEYBOARD_ONLY","VERIFY_STATUS_AND_ERRORS_ARE_ANNOUNCED_WITHOUT_FOCUS_LOSS","VERIFY_INVALID_FIELDS_HAVE_PROGRAMMATIC_LABEL_AND_ERROR_RELATION","RECOVER_FROM_ERROR_AND_COMPLETE_READ_ONLY_FLOW_WITHOUT_MOUSE","REPEAT_WITH_NVDA_BROWSE_AND_FOCUS_MODES","RECORD_ONLY_PRIVACY_SAFE_RESULT_CODES_AND_COUNTS")


def remaining_gate_classes() -> tuple[str, ...]:
    return ("INTERNAL_RELEASE_BLOCKER","HOSTIQ_LIVE","TELEGRAM_AUTH_E2E","DEPLOYED_ACTION","HUMAN_NVDA","K5")
