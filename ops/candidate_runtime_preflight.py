# -*- coding: utf-8 -*-
"""Fail-closed non-live preflight for a canonical HOSTiQ release candidate.

This validator is deliberately narrower than deployment itself. It proves that
an exact candidate contains the startup/dependency envelope required before
``prepare_versioned_release`` can be treated as meaningful release evidence.
It never authorizes deployment and never reads runtime/private state.
"""
from __future__ import annotations

import ast
import hashlib
import os
import re
import stat
from pathlib import Path

from ops.release_guard import SafetyError

_SHA40 = re.compile(r"^[0-9a-f]{40}$")
_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*(?:\[[A-Za-z0-9_,.-]+\])?$")
_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+!_-]*$")
_HASH = re.compile(r"^--hash=sha256:[0-9a-f]{64}$")
_MAX_TEXT_BYTES = 1024 * 1024
_PRIVATE_DIRS = frozenset({"var", "runtime", "session", "sessions", "private", "backup", "backups"})
_PRIVATE_ROOT_FILES = frozenset({
    "private_config.json", "connection_info.txt", "credentials.json", "token.json",
    "bootstrap.json", "setup_state.json",
})
_PRIVATE_SUFFIXES = (".session", ".session-journal", ".sqlite", ".sqlite3", ".db", ".pem", ".key")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _regular_owner_file(root: Path, name: str) -> Path:
    path = root / name
    try:
        st = path.lstat()
    except OSError as exc:
        raise SafetyError(f"required release file missing: {name}") from exc
    if not stat.S_ISREG(st.st_mode) or path.is_symlink() or st.st_nlink != 1:
        raise SafetyError(f"required release file topology unsafe: {name}")
    if hasattr(os, "getuid") and st.st_uid != os.getuid():
        raise SafetyError(f"required release file owner unsafe: {name}")
    if st.st_size <= 0 or st.st_size > _MAX_TEXT_BYTES:
        raise SafetyError(f"required release file size unsafe: {name}")
    return path


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise SafetyError("release input is not safe UTF-8 text") from exc


def _logical_lines(text: str) -> list[str]:
    """Return requirement logical lines with continuations/comments normalized."""
    lines: list[str] = []
    current = ""
    for raw in text.splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        # Requirement URLs/fragments are intentionally unsupported in this
        # canonical lock format, so a '#' starts a comment here.
        if "#" in stripped:
            stripped = stripped.split("#", 1)[0].rstrip()
        continued = stripped.endswith("\\")
        if continued:
            stripped = stripped[:-1].rstrip()
        current = (current + " " + stripped).strip()
        if not continued:
            if current:
                lines.append(current)
            current = ""
    if current:
        raise SafetyError("requirements input has unterminated continuation")
    return lines


def _canonical_name(name: str) -> str:
    base = name.split("[", 1)[0]
    return re.sub(r"[-_.]+", "-", base).lower()


def _parse_pinned_spec(token: str, label: str) -> tuple[str, str]:
    if token.count("==") != 1:
        raise SafetyError(f"{label} entry is not exactly pinned")
    name, version = token.split("==", 1)
    if not _NAME.fullmatch(name) or not _VERSION.fullmatch(version):
        raise SafetyError(f"{label} pinned requirement invalid")
    return _canonical_name(name), version


def _parse_direct_requirements(text: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in _logical_lines(text):
        if line.startswith("-") or "://" in line or " @ " in line:
            raise SafetyError("requirements input contains non-canonical dependency input")
        if ";" in line or any(ch.isspace() for ch in line):
            raise SafetyError("requirements input must contain exact direct pins only")
        name, version = _parse_pinned_spec(line, "direct requirement")
        if name in result:
            raise SafetyError("requirements input contains duplicate package")
        result[name] = version
    if not result:
        raise SafetyError("requirements input contains no direct dependencies")
    return result


def _parse_lock(text: str) -> dict[str, tuple[str, tuple[str, ...]]]:
    result: dict[str, tuple[str, tuple[str, ...]]] = {}
    for line in _logical_lines(text):
        if line.startswith("-") or "://" in line or " @ " in line:
            raise SafetyError("requirements lock contains non-canonical dependency input")
        tokens = line.split()
        if not tokens:
            continue
        if ";" in tokens[0] or ";" in line:
            raise SafetyError("requirements lock contains environment marker")
        name, version = _parse_pinned_spec(tokens[0], "locked requirement")
        hashes = tuple(tokens[1:])
        if not hashes or any(not _HASH.fullmatch(item) for item in hashes):
            raise SafetyError("requirements lock entry is not fully SHA-256 hash locked")
        if len(set(hashes)) != len(hashes):
            raise SafetyError("requirements lock contains duplicate hash")
        if name in result:
            raise SafetyError("requirements lock contains duplicate package")
        result[name] = (version, tuple(sorted(hashes)))
    if not result:
        raise SafetyError("requirements lock contains no locked dependencies")
    return result


def _verify_direct_lock(direct: dict[str, str], locked: dict[str, tuple[str, tuple[str, ...]]]) -> None:
    for name, version in direct.items():
        locked_entry = locked.get(name)
        if locked_entry is None or locked_entry[0] != version:
            raise SafetyError("direct dependency is absent or version-mismatched in lock")


def _validate_wsgi(text: str) -> None:
    try:
        tree = ast.parse(text, filename="passenger_wsgi.py")
    except SyntaxError as exc:
        raise SafetyError("passenger_wsgi.py syntax invalid") from exc
    found = False
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == "bridge.app" and node.level == 0:
            for alias in node.names:
                if alias.name == "application" and alias.asname in (None, "application"):
                    found = True
    if not found:
        raise SafetyError("passenger_wsgi.py does not expose bridge.app.application")


def _reject_private_payload(root: Path) -> None:
    """Reject private/runtime material that must never enter the immutable code artifact."""
    for current_root, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        current = Path(current_root)
        kept: list[str] = []
        for dirname in dirnames:
            path = current / dirname
            st = path.lstat()
            if path.is_symlink() or not stat.S_ISDIR(st.st_mode):
                raise SafetyError("candidate directory topology unsafe")
            if dirname == ".git":
                # A working checkout may be validated; git metadata is not part
                # of git-archive/PREPARE payload and is never traversed here.
                continue
            if dirname.casefold() in _PRIVATE_DIRS:
                raise SafetyError("candidate contains forbidden private/runtime directory")
            kept.append(dirname)
        dirnames[:] = kept
        for filename in filenames:
            path = current / filename
            st = path.lstat()
            if path.is_symlink() or not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
                raise SafetyError("candidate file topology unsafe")
            rel = path.relative_to(root)
            folded = filename.casefold()
            if len(rel.parts) == 1 and (folded in _PRIVATE_ROOT_FILES or folded.startswith(".env")):
                raise SafetyError("candidate contains forbidden private/runtime file")
            if folded.endswith(_PRIVATE_SUFFIXES):
                raise SafetyError("candidate contains forbidden private/runtime file")


def _optional_dependency_pair(root: Path) -> dict:
    input_path = root / "requirements-test.txt"
    lock_path = root / "requirements-test.lock"
    present = input_path.exists() or lock_path.exists()
    if not present:
        return {
            "present": False,
            "requirements_sha256": "0" * 64,
            "requirements_lock_sha256": "0" * 64,
            "direct_package_count": 0,
            "locked_package_count": 0,
        }
    if not input_path.exists() or not lock_path.exists():
        raise SafetyError("test dependency input and lock must be present as an exact pair")
    input_path = _regular_owner_file(root, "requirements-test.txt")
    lock_path = _regular_owner_file(root, "requirements-test.lock")
    direct = _parse_direct_requirements(_read_text(input_path))
    locked = _parse_lock(_read_text(lock_path))
    _verify_direct_lock(direct, locked)
    return {
        "present": True,
        "requirements_sha256": _sha256(input_path),
        "requirements_lock_sha256": _sha256(lock_path),
        "direct_package_count": len(direct),
        "locked_package_count": len(locked),
    }


def validate_candidate_release_envelope(
    root: Path,
    *,
    candidate_sha: str,
    required_direct_packages: tuple[str, ...] = ("telethon",),
) -> dict:
    """Validate the exact non-secret startup/dependency envelope.

    The returned projection is intentionally safe for CI/Drive reporting: it
    contains only hashes, counts and booleans, never requirement text or paths
    outside the candidate root. Actual transitive completeness is proven later
    by the real Python 3.11 PREPARE ``pip --require-hashes`` installation.
    """
    if not isinstance(candidate_sha, str) or not _SHA40.fullmatch(candidate_sha):
        raise SafetyError("candidate SHA is not an exact full Git SHA")
    try:
        resolved_root = root.resolve(strict=True)
        root_stat = resolved_root.lstat()
    except OSError as exc:
        raise SafetyError("candidate root missing or unsafe") from exc
    if root.is_symlink() or not stat.S_ISDIR(root_stat.st_mode):
        raise SafetyError("candidate root missing or unsafe")

    _reject_private_payload(resolved_root)
    wsgi = _regular_owner_file(resolved_root, "passenger_wsgi.py")
    requirements = _regular_owner_file(resolved_root, "requirements.txt")
    lock = _regular_owner_file(resolved_root, "requirements.lock")

    _validate_wsgi(_read_text(wsgi))
    direct = _parse_direct_requirements(_read_text(requirements))
    locked = _parse_lock(_read_text(lock))
    _verify_direct_lock(direct, locked)

    required = {_canonical_name(name) for name in required_direct_packages}
    if not required.issubset(direct):
        raise SafetyError("required runtime dependency missing from canonical direct requirements")

    test_dependencies = _optional_dependency_pair(resolved_root)
    return {
        "schema_version": 2,
        "candidate_sha": candidate_sha,
        "wsgi_sha256": _sha256(wsgi),
        "requirements_sha256": _sha256(requirements),
        "requirements_lock_sha256": _sha256(lock),
        "direct_package_count": len(direct),
        "locked_package_count": len(locked),
        "required_packages_present": True,
        "startup_import_contract_ok": True,
        "fully_hash_locked": True,
        "test_dependencies": test_dependencies,
        "private_runtime_payload_present": False,
        "preflight_pass": True,
        "promotion_authorized": False,
    }
