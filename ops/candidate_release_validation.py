# -*- coding: utf-8 -*-
"""Fail-closed validation of a deployable Telegram Bridge candidate package.

This validates only non-secret release-package structure.  It does not authorize
promotion and it does not replace ``prepare_versioned_release``: the real PREPARE
pipeline must still create a clean Python 3.11 environment and execute
``pip --require-hashes`` plus compile/import/tests for the exact candidate SHA.
"""
from __future__ import annotations

import ast
import hashlib
import os
import re
import stat
from pathlib import Path

from ops.release_guard import SafetyError

SHA40_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.!+_-]{0,127}$")
PIN_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==([A-Za-z0-9][A-Za-z0-9.!+_-]{0,127})(.*)$")
HASH_TOKEN_RE = re.compile(r"^--hash=sha256:([0-9a-f]{64})$")
MAX_CONTROL_BYTES = 256 * 1024
MAX_REQUIREMENT_RECORDS = 512

REQUIRED_FILES = ("passenger_wsgi.py", "requirements.txt", "requirements.lock")
OPTIONAL_TEST_PAIR = ("requirements-test.txt", "requirements-test.lock")
FORBIDDEN_DIR_PARTS = frozenset({
    ".git", "var", "runtime", "session", "sessions", "private", "backup", "backups",
})
FORBIDDEN_ROOT_FILES = frozenset({
    "private_config.json", "connection_info.txt", "credentials.json", "token.json",
    "bootstrap.json", "setup_state.json",
})
FORBIDDEN_SUFFIXES = (".session", ".session-journal", ".sqlite", ".sqlite3", ".db", ".pem", ".key")


def _normalise_name(name: str) -> str:
    if not NAME_RE.fullmatch(name):
        raise SafetyError("requirement package name invalid")
    return re.sub(r"[-_.]+", "-", name).casefold()


def _regular_file(root: Path, name: str, *, allow_empty: bool = False) -> Path:
    path = root / name
    try:
        st = os.lstat(path)
    except OSError as exc:
        raise SafetyError(f"required release file missing: {name}") from exc
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
        raise SafetyError(f"release file topology invalid: {name}")
    if not allow_empty and st.st_size <= 0:
        raise SafetyError(f"release file empty: {name}")
    if st.st_size > MAX_CONTROL_BYTES:
        raise SafetyError(f"release file too large: {name}")
    return path


def _read_text(path: Path) -> str:
    data = path.read_bytes()
    if len(data) > MAX_CONTROL_BYTES:
        raise SafetyError("release control file too large")
    try:
        return data.decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        raise SafetyError("release control file must be strict UTF-8") from exc


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _logical_records(text: str) -> list[str]:
    records: list[str] = []
    pending = ""
    for raw in text.splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.endswith("\\"):
            pending += stripped[:-1].strip() + " "
            continue
        record = (pending + stripped).strip()
        pending = ""
        if record:
            records.append(record)
        if len(records) > MAX_REQUIREMENT_RECORDS:
            raise SafetyError("requirement record limit exceeded")
    if pending:
        raise SafetyError("unterminated requirement continuation")
    if not records:
        raise SafetyError("requirements input is empty")
    return records


def _parse_direct_requirements(text: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for record in _logical_records(text):
        if record.startswith("-") or ";" in record or " @ " in record or "://" in record:
            raise SafetyError("runtime requirement must be an unconditional exact pin")
        match = PIN_RE.fullmatch(record)
        if not match or match.group(3).strip():
            raise SafetyError("runtime requirement must use canonical name==version")
        name = _normalise_name(match.group(1))
        version = match.group(2)
        if not VERSION_RE.fullmatch(version) or name in result:
            raise SafetyError("runtime requirement pin invalid or duplicate")
        result[name] = version
    if "telethon" not in result:
        raise SafetyError("canonical runtime dependencies must directly pin Telethon")
    return result


def _parse_lock(text: str) -> dict[str, tuple[str, tuple[str, ...]]]:
    result: dict[str, tuple[str, tuple[str, ...]]] = {}
    for record in _logical_records(text):
        if record.startswith("-") or ";" in record or " @ " in record or "://" in record:
            raise SafetyError("locked requirement must be an unconditional exact hash pin")
        match = PIN_RE.fullmatch(record)
        if not match:
            raise SafetyError("locked requirement pin invalid")
        name = _normalise_name(match.group(1))
        version = match.group(2)
        if not VERSION_RE.fullmatch(version) or name in result:
            raise SafetyError("locked requirement version invalid or duplicate")
        tail = match.group(3).strip()
        tokens = tuple(tail.split()) if tail else ()
        hashes: list[str] = []
        for token in tokens:
            hash_match = HASH_TOKEN_RE.fullmatch(token)
            if not hash_match:
                raise SafetyError("locked requirement contains non-hash option or malformed hash")
            hashes.append(hash_match.group(1))
        if not hashes or len(set(hashes)) != len(hashes):
            raise SafetyError("every locked requirement needs unique sha256 hashes")
        result[name] = (version, tuple(hashes))
    return result


def _verify_lock_covers_direct(direct: dict[str, str], locked: dict[str, tuple[str, tuple[str, ...]]]) -> None:
    for name, version in direct.items():
        item = locked.get(name)
        if item is None or item[0] != version:
            raise SafetyError("requirements lock does not exactly cover direct runtime pin")


def _validate_wsgi(text: str) -> None:
    try:
        tree = ast.parse(text, filename="passenger_wsgi.py")
    except SyntaxError as exc:
        raise SafetyError("passenger WSGI syntax invalid") from exc
    matched = False
    for node in tree.body:
        if isinstance(node, ast.ImportFrom) and node.module == "bridge.app" and node.level == 0:
            for alias in node.names:
                if alias.name == "application" and alias.asname in {None, "application"}:
                    matched = True
    if not matched:
        raise SafetyError("passenger WSGI must expose `from bridge.app import application`")


def _reject_private_payload(root: Path) -> None:
    for current_root, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        current = Path(current_root)
        for dirname in list(dirnames):
            path = current / dirname
            st = os.lstat(path)
            if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
                raise SafetyError("candidate directory topology invalid")
            if dirname.casefold() in FORBIDDEN_DIR_PARTS:
                raise SafetyError("candidate contains forbidden private/runtime directory")
        for filename in filenames:
            path = current / filename
            st = os.lstat(path)
            if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
                raise SafetyError("candidate file topology invalid")
            rel = path.relative_to(root)
            folded = filename.casefold()
            if len(rel.parts) == 1 and (folded in FORBIDDEN_ROOT_FILES or folded.startswith(".env")):
                raise SafetyError("candidate contains forbidden private/runtime file")
            if folded.endswith(FORBIDDEN_SUFFIXES):
                raise SafetyError("candidate contains forbidden private/runtime file")


def validate_candidate_release(candidate_root: Path, candidate_sha: str) -> dict:
    """Validate pre-PREPARE package semantics and return bounded hash-only identity."""
    if not isinstance(candidate_sha, str) or not SHA40_RE.fullmatch(candidate_sha):
        raise SafetyError("candidate SHA invalid")
    root = Path(os.path.abspath(os.fspath(candidate_root.expanduser())))
    try:
        root_stat = os.lstat(root)
    except OSError as exc:
        raise SafetyError("candidate root unavailable") from exc
    if stat.S_ISLNK(root_stat.st_mode) or not stat.S_ISDIR(root_stat.st_mode):
        raise SafetyError("candidate root topology invalid")

    _reject_private_payload(root)
    wsgi = _regular_file(root, "passenger_wsgi.py")
    requirements = _regular_file(root, "requirements.txt")
    lock = _regular_file(root, "requirements.lock")
    _validate_wsgi(_read_text(wsgi))
    direct = _parse_direct_requirements(_read_text(requirements))
    locked = _parse_lock(_read_text(lock))
    _verify_lock_covers_direct(direct, locked)

    test_input = root / OPTIONAL_TEST_PAIR[0]
    test_lock = root / OPTIONAL_TEST_PAIR[1]
    test_present = test_input.exists() or test_lock.exists()
    test_summary = {
        "present": False,
        "requirements_sha256": "0" * 64,
        "requirements_lock_sha256": "0" * 64,
        "direct_dependency_count": 0,
        "locked_dependency_count": 0,
    }
    if test_present:
        if not test_input.exists() or not test_lock.exists():
            raise SafetyError("test requirements input/lock must appear as an exact pair")
        test_input = _regular_file(root, OPTIONAL_TEST_PAIR[0])
        test_lock = _regular_file(root, OPTIONAL_TEST_PAIR[1])
        test_direct = _parse_direct_requirements_without_telethon(_read_text(test_input))
        test_locked = _parse_lock(_read_text(test_lock))
        _verify_lock_covers_direct(test_direct, test_locked)
        test_summary = {
            "present": True,
            "requirements_sha256": _sha256(test_input),
            "requirements_lock_sha256": _sha256(test_lock),
            "direct_dependency_count": len(test_direct),
            "locked_dependency_count": len(test_locked),
        }

    result = {
        "schema_version": 1,
        "candidate_sha": candidate_sha,
        "startup_import_target": "bridge.app.application",
        "wsgi_sha256": _sha256(wsgi),
        "requirements_sha256": _sha256(requirements),
        "requirements_lock_sha256": _sha256(lock),
        "direct_dependency_count": len(direct),
        "locked_dependency_count": len(locked),
        "telethon_pinned": True,
        "test_dependencies": test_summary,
        "private_runtime_payload_present": False,
        "package_preflight_pass": True,
        "promotion_authorized": False,
    }
    for key in ("wsgi_sha256", "requirements_sha256", "requirements_lock_sha256"):
        if not SHA256_RE.fullmatch(result[key]):
            raise SafetyError("candidate package hash invalid")
    return result


def _parse_direct_requirements_without_telethon(text: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for record in _logical_records(text):
        if record.startswith("-") or ";" in record or " @ " in record or "://" in record:
            raise SafetyError("test requirement must be an unconditional exact pin")
        match = PIN_RE.fullmatch(record)
        if not match or match.group(3).strip():
            raise SafetyError("test requirement must use canonical name==version")
        name = _normalise_name(match.group(1))
        version = match.group(2)
        if not VERSION_RE.fullmatch(version) or name in result:
            raise SafetyError("test requirement pin invalid or duplicate")
        result[name] = version
    return result
