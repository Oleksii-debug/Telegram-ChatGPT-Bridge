# -*- coding: utf-8 -*-
"""Strict validation for future private HOSTiQ evidence artifacts.

Raw private evidence is validated locally/private-side.  Public output is only a
bounded hash/count/status summary and never copies arbitrary text fields.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path, PurePosixPath
from typing import Any

try:
    from ops.release_guard import SafetyError
except ImportError:
    class SafetyError(RuntimeError):
        pass

SHA40 = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
SAFE_STATUS = {"PASS", "FAIL", "BLOCKED", "READY", "NONCOMPLIANT", "UNKNOWN"}
MAX_BYTES = 64 * 1024
MAX_FILES = 500
MAX_STRING = 512
FORBIDDEN_KEYS = {
    "token", "password", "secret", "session", "cookie", "authorization",
    "api_hash", "api_id", "setup_route", "login_code", "message", "body",
    "content", "stdout", "stderr", "environment", "env",
}
SECRETISH = re.compile(
    r"(?i)(?:-----BEGIN .*PRIVATE KEY-----|authorization\s*[:=]|bearer\s+[A-Za-z0-9._~-]{12,}|"
    r"(?:TG_API_HASH|TG_SESSION_STRING|BRIDGE_TOKEN|SETUP_ROUTE|PASSWORD)\s*[:=])"
)


def _key_safe(key: str) -> bool:
    folded = key.casefold()
    return not any(part in folded for part in FORBIDDEN_KEYS)


def _walk_shape(value: Any, depth: int = 0, *, enforce_keys: bool = True) -> None:
    if depth > 5:
        raise SafetyError("private evidence nesting limit exceeded")
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, int) and not isinstance(value, bool):
        if abs(value) > 10**12:
            raise SafetyError("private evidence integer out of bounds")
        return
    if isinstance(value, str):
        if len(value) > MAX_STRING or SECRETISH.search(value):
            raise SafetyError("private evidence string policy failed")
        return
    if isinstance(value, list):
        if len(value) > MAX_FILES:
            raise SafetyError("private evidence list limit exceeded")
        for item in value:
            _walk_shape(item, depth + 1, enforce_keys=enforce_keys)
        return
    if isinstance(value, dict):
        if len(value) > 64:
            raise SafetyError("private evidence dictionary limit exceeded")
        for key, item in value.items():
            if not isinstance(key, str) or (enforce_keys and not _key_safe(key)):
                raise SafetyError("private evidence key policy failed")
            _walk_shape(item, depth + 1, enforce_keys=enforce_keys)
        return
    raise SafetyError("unsupported private evidence type")


def canonical_manifest_path(path: str) -> str:
    if not isinstance(path, str) or not path or "\\" in path:
        raise SafetyError("invalid manifest path")
    p = PurePosixPath(path)
    if p.is_absolute() or ".." in p.parts or p.as_posix() != path:
        raise SafetyError("unsafe manifest path")
    return path


def validate_server_manifest(payload: dict) -> dict:
    if set(payload) != {"schema_version", "files"} or payload["schema_version"] != 1:
        raise SafetyError("server manifest schema mismatch")
    files = payload["files"]
    if not isinstance(files, list) or not 0 < len(files) <= MAX_FILES:
        raise SafetyError("server manifest file list invalid")
    seen: set[str] = set(); folded: set[str] = set()
    safe_files = []
    for item in files:
        if not isinstance(item, dict) or set(item) != {"path", "sha256", "size", "category"}:
            raise SafetyError("server manifest entry schema mismatch")
        path = canonical_manifest_path(item["path"])
        if path in seen or path.casefold() in folded:
            raise SafetyError("server manifest duplicate/case collision")
        seen.add(path); folded.add(path.casefold())
        digest = item["sha256"]
        if not isinstance(digest, str) or not SHA256.fullmatch(digest):
            raise SafetyError("server manifest digest invalid")
        size = item["size"]
        if not isinstance(size, int) or isinstance(size, bool) or size < 0 or size > 100_000_000:
            raise SafetyError("server manifest size invalid")
        category = item["category"]
        if category not in {
            "application_source", "wsgi_startup", "tests", "tooling",
            "dependency_input", "empty_extra", "documentation_metadata",
            "tooling_metadata", "sanitized_metadata", "other_nonsecret",
        }:
            raise SafetyError("server manifest category invalid")
        safe_files.append(dict(item))
    return {"schema_version": 1, "files": safe_files}


def canonical_json_sha256(payload: dict) -> str:
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def validate_runtime_report(payload: dict) -> dict:
    # Strict top-level schema; no arbitrary expansion.
    required = {
        "schema_version", "collector_context", "python_version", "python_major_minor",
        "python_implementation", "runtime_compliance", "python_executable_sha256",
        "python_executable_owner_uid", "python_executable_mode", "python_executable_nlink",
        "sys_prefix_sha256", "sys_base_prefix_sha256", "virtual_environment_active",
        "wsgi_relative_path", "wsgi_sha256", "application_import_target",
        "application_import_ok", "process_cwd_inside_app_root", "passenger_context_present",
        "package_evidence", "environment_values_recorded", "request_data_recorded",
        "secret_values_recorded", "payload_sha256",
    }
    if set(payload) != required or payload.get("schema_version") != 2:
        raise SafetyError("runtime report schema mismatch")
    _walk_shape(payload, enforce_keys=False)
    if payload["collector_context"] not in {"PRIVATE_CLI_CANDIDATE", "APPLICATION_PROCESS"}:
        raise SafetyError("collector context invalid")
    if payload["runtime_compliance"] not in {
        "PYTHON_3_11_APPLICATION_CONTEXT_CONFIRMED", "PYTHON_3_11_CANDIDATE_CONTEXT",
        "NONCOMPLIANT_NOT_PYTHON_3_11",
    }:
        raise SafetyError("runtime compliance status invalid")
    for key in ("python_executable_sha256", "sys_prefix_sha256", "sys_base_prefix_sha256", "wsgi_sha256"):
        if not isinstance(payload[key], str) or not SHA256.fullmatch(payload[key]):
            raise SafetyError("runtime report hash invalid")
    if payload["python_executable_owner_uid"] < 0 or payload["python_executable_owner_uid"] > 2**31 - 1:
        raise SafetyError("runtime interpreter owner invalid")
    if payload["python_executable_mode"] < 0 or payload["python_executable_mode"] > 0o7777:
        raise SafetyError("runtime interpreter mode invalid")
    if payload["python_executable_nlink"] < 1 or payload["python_executable_nlink"] > 1024:
        raise SafetyError("runtime interpreter link count invalid")
    if payload["application_import_target"] != "bridge.app.application":
        raise SafetyError("runtime application import target invalid")
    if payload["wsgi_relative_path"] != "passenger_wsgi.py":
        raise SafetyError("runtime WSGI path invalid")
    if not isinstance(payload["python_version"], str) or not re.fullmatch(r"[0-9]+(?:\.[0-9]+){1,3}(?:[A-Za-z0-9.+_-]*)?", payload["python_version"]):
        raise SafetyError("runtime Python version invalid")
    if payload["python_major_minor"] not in {"3.11", "3.6", "3.7", "3.8", "3.9", "3.10", "3.12", "3.13", "3.14"}:
        raise SafetyError("runtime Python major/minor invalid")
    version_parts = payload["python_version"].split(".")
    if len(version_parts) < 2 or ".".join(version_parts[:2]) != payload["python_major_minor"]:
        raise SafetyError("runtime Python version fields disagree")
    if payload["python_implementation"] not in {"CPython", "PyPy"}:
        raise SafetyError("runtime Python implementation invalid")
    for key in ("application_import_ok", "process_cwd_inside_app_root", "passenger_context_present",
                "virtual_environment_active", "environment_values_recorded", "request_data_recorded",
                "secret_values_recorded"):
        if not isinstance(payload[key], bool):
            raise SafetyError("runtime report boolean field invalid")
    packages = payload["package_evidence"]
    if not isinstance(packages, list) or len(packages) > 8:
        raise SafetyError("runtime package evidence invalid")
    seen_packages = set()
    for item in packages:
        if not isinstance(item, dict) or set(item) != {"name", "present", "version", "metadata_sha256"}:
            raise SafetyError("runtime package evidence schema invalid")
        if item["name"] not in {"telethon", "pypdf"} or item["name"] in seen_packages:
            raise SafetyError("runtime package name invalid")
        seen_packages.add(item["name"])
        if not isinstance(item["present"], bool):
            raise SafetyError("runtime package presence invalid")
        if not isinstance(item["version"], str) or not re.fullmatch(r"[A-Za-z0-9.+_-]{1,64}", item["version"]):
            raise SafetyError("runtime package version invalid")
        if not isinstance(item["metadata_sha256"], str) or not SHA256.fullmatch(item["metadata_sha256"]):
            raise SafetyError("runtime package metadata hash invalid")
    if set(seen_packages) != {"telethon", "pypdf"}:
        raise SafetyError("runtime reviewed package set incomplete")
    if payload["runtime_compliance"] == "PYTHON_3_11_APPLICATION_CONTEXT_CONFIRMED":
        if payload["collector_context"] != "APPLICATION_PROCESS" or payload["python_major_minor"] != "3.11" or not payload["passenger_context_present"] or not payload["application_import_ok"]:
            raise SafetyError("strong Passenger runtime status is not semantically supported")
    if payload["runtime_compliance"] == "NONCOMPLIANT_NOT_PYTHON_3_11" and payload["python_major_minor"] == "3.11":
        raise SafetyError("runtime noncompliance status contradicts Python version")
    if not all(payload[k] is False for k in ("environment_values_recorded", "request_data_recorded", "secret_values_recorded")):
        raise SafetyError("runtime report privacy flags invalid")
    provided = payload["payload_sha256"]
    base = dict(payload); base.pop("payload_sha256")
    if provided != canonical_json_sha256(base):
        raise SafetyError("runtime report tamper hash mismatch")
    return dict(payload)


def ingest_private_evidence_file(path: Path, kind: str) -> dict:
    path = path.resolve(strict=True)
    data = path.read_bytes()
    if len(data) > MAX_BYTES:
        raise SafetyError("private evidence file too large")
    try:
        payload = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SafetyError("private evidence JSON invalid") from exc
    if not isinstance(payload, dict):
        raise SafetyError("private evidence root must be object")
    if kind == "runtime":
        validated = validate_runtime_report(payload)
        return {
            "schema_version": 1,
            "kind": "runtime",
            "artifact_sha256": hashlib.sha256(data).hexdigest(),
            "runtime_compliance": validated["runtime_compliance"],
            "application_import_ok": validated["application_import_ok"],
            "passenger_context_present": validated["passenger_context_present"],
            "private_values_copied": False,
        }
    if kind == "server_manifest":
        validated = validate_server_manifest(payload)
        return {
            "schema_version": 1,
            "kind": "server_manifest",
            "artifact_sha256": hashlib.sha256(data).hexdigest(),
            "file_count": len(validated["files"]),
            "manifest_sha256": canonical_json_sha256(validated),
            "private_values_copied": False,
        }
    raise SafetyError("unsupported private evidence kind")
