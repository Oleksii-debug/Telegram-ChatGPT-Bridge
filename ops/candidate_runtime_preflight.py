# -*- coding: utf-8 -*-
"""Fail-closed non-live preflight for a canonical HOSTiQ release candidate.

This validator is deliberately narrower than deployment itself.  It proves that
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
            raise SafetyError("requirements.txt contains non-canonical dependency input")
        if ";" in line or any(ch.isspace() for ch in line):
            raise SafetyError("requirements.txt must contain exact direct pins only")
        name, version = _parse_pinned_spec(line, "direct requirement")
        if name in result:
            raise SafetyError("requirements.txt contains duplicate package")
        result[name] = version
    if not result:
        raise SafetyError("requirements.txt contains no direct runtime dependencies")
    return result


def _parse_lock(text: str) -> dict[str, tuple[str, tuple[str, ...]]]:
    result: dict[str, tuple[str, tuple[str, ...]]] = {}
    for line in _logical_lines(text):
        if line.startswith("-") or "://" in line or " @ " in line:
            raise SafetyError("requirements.lock contains non-canonical dependency input")
        tokens = line.split()
        if not tokens:
            continue
        # Environment markers would make one artifact resolve differently by
        # host.  The HOSTiQ artifact is intentionally one Python 3.11/Linux
        # lock, so the deployment lock is marker-free and deterministic.
        if ";" in tokens[0] or ";" in line:
            raise SafetyError("requirements.lock contains environment marker")
        name, version = _parse_pinned_spec(tokens[0], "locked requirement")
        hashes = tuple(tokens[1:])
        if not hashes or any(not _HASH.fullmatch(item) for item in hashes):
            raise SafetyError("requirements.lock entry is not fully SHA-256 hash locked")
        if len(set(hashes)) != len(hashes):
            raise SafetyError("requirements.lock contains duplicate hash")
        if name in result:
            raise SafetyError("requirements.lock contains duplicate package")
        result[name] = (version, tuple(sorted(hashes)))
    if not result:
        raise SafetyError("requirements.lock contains no locked runtime dependencies")
    return result


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


def validate_candidate_release_envelope(
    root: Path,
    *,
    candidate_sha: str,
    required_direct_packages: tuple[str, ...] = ("telethon",),
) -> dict:
    """Validate the exact non-secret startup/dependency envelope.

    The returned projection is intentionally safe for CI/Drive reporting: it
    contains only hashes, counts and booleans, never requirement text or paths
    outside the candidate root.
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

    wsgi = _regular_owner_file(resolved_root, "passenger_wsgi.py")
    requirements = _regular_owner_file(resolved_root, "requirements.txt")
    lock = _regular_owner_file(resolved_root, "requirements.lock")

    _validate_wsgi(_read_text(wsgi))
    direct = _parse_direct_requirements(_read_text(requirements))
    locked = _parse_lock(_read_text(lock))

    for name, version in direct.items():
        locked_entry = locked.get(name)
        if locked_entry is None or locked_entry[0] != version:
            raise SafetyError("direct runtime dependency is absent or version-mismatched in lock")

    required = {_canonical_name(name) for name in required_direct_packages}
    if not required.issubset(direct):
        raise SafetyError("required runtime dependency missing from canonical direct requirements")

    return {
        "schema_version": 1,
        "candidate_sha": candidate_sha,
        "wsgi_sha256": _sha256(wsgi),
        "requirements_sha256": _sha256(requirements),
        "requirements_lock_sha256": _sha256(lock),
        "direct_package_count": len(direct),
        "locked_package_count": len(locked),
        "required_packages_present": True,
        "startup_import_contract_ok": True,
        "fully_hash_locked": True,
        "preflight_pass": True,
        "promotion_authorized": False,
    }
