# -*- coding: utf-8 -*-
"""Collect a bounded hash-only manifest from the actual HOSTiQ application root.

The collector never serializes file contents. Private/runtime paths and unknown
file classes fail closed so support must review new topology instead of silently
publishing it as source evidence.
"""
from __future__ import annotations

import hashlib
import os
import stat
import unicodedata
from pathlib import Path

from ops.baseline_reconcile import SAFE_CATEGORIES, canonical_posix_path, normalize_nonsecret_manifest
from ops.release_guard import SafetyError

MAX_FILES = 500
MAX_FILE_BYTES = 100_000_000
MAX_TOTAL_BYTES = 250_000_000
PRIVATE_PARTS = frozenset({"var", "runtime", "session", "sessions", "private", "cache", "tmp", "temp", "backup", "backups", ".git"})
PRIVATE_NAMES = frozenset({"private_config.json", "connection_info.txt", "credentials.json", "token.json", "bootstrap.json", "setup_state.json"})
PRIVATE_SUFFIXES = (".session", ".session-journal", ".sqlite", ".sqlite3", ".db", ".log", ".pem", ".key")


def _category(path: str, size: int) -> str:
    p = Path(path)
    parts = tuple(part.casefold() for part in p.parts)
    name = p.name.casefold()
    if set(parts) & PRIVATE_PARTS or name in PRIVATE_NAMES or name.startswith(".env") or name.endswith(PRIVATE_SUFFIXES):
        raise SafetyError("private/runtime path rejected")
    if path == "passenger_wsgi.py":
        return "wsgi_startup"
    if path == "install_server.sh":
        if size != 0:
            raise SafetyError("install_server.sh is only reviewed as empty extra")
        return "empty_extra"
    if parts and parts[0] == "bridge" and name.endswith(".py"):
        return "application_source"
    if parts and parts[0] == "tests" and name.endswith(".py"):
        return "tests"
    if parts and parts[0] in {"ops", "tools"} and name.endswith((".py", ".sh")):
        return "tooling"
    if name in {"requirements.txt", "requirements.lock", "requirements-dev.txt", "constraints.txt", "pyproject.toml", "poetry.lock"}:
        return "dependency_input"
    if parts and parts[0] == "docs" and name.endswith((".md", ".txt", ".json")):
        return "documentation_metadata"
    if name in {"readme.md", "recovery_baseline.md", ".gitignore", ".secret-scan-allowlist.json"}:
        return "sanitized_metadata"
    raise SafetyError("unreviewed application-root file class")


def _hash_regular(path: Path, expected: os.stat_result) -> tuple[str, int]:
    flags = os.O_RDONLY | int(getattr(os, "O_NOFOLLOW", 0)) | int(getattr(os, "O_CLOEXEC", 0))
    fd = os.open(path, flags)
    try:
        current = os.fstat(fd)
        if not stat.S_ISREG(current.st_mode) or current.st_dev != expected.st_dev or current.st_ino != expected.st_ino:
            raise SafetyError("manifest file changed during open")
        if current.st_size != expected.st_size or not 0 <= current.st_size <= MAX_FILE_BYTES:
            raise SafetyError("manifest file size changed/out of bounds")
        digest = hashlib.sha256()
        read_total = 0
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            read_total += len(chunk)
            if read_total > MAX_FILE_BYTES:
                raise SafetyError("manifest file exceeded size bound")
            digest.update(chunk)
        after = os.fstat(fd)
        if after.st_dev != current.st_dev or after.st_ino != current.st_ino or after.st_size != current.st_size or after.st_mtime_ns != current.st_mtime_ns:
            raise SafetyError("manifest file changed during hashing")
        return digest.hexdigest(), read_total
    finally:
        os.close(fd)


def collect_server_manifest(app_root: Path) -> dict:
    root = Path(os.path.abspath(os.fspath(app_root.expanduser())))
    root_stat = os.lstat(root)
    if stat.S_ISLNK(root_stat.st_mode) or not stat.S_ISDIR(root_stat.st_mode):
        raise SafetyError("application root topology invalid")
    rows = []
    folded = set()
    total_bytes = 0
    for current_root, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        current = Path(current_root)
        rel_dir = current.relative_to(root)
        kept_dirs = []
        for dirname in sorted(dirnames):
            absolute = current / dirname
            st = os.lstat(absolute)
            if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
                raise SafetyError("application-root directory topology invalid")
            rel = (rel_dir / dirname).as_posix()
            if dirname.casefold() in PRIVATE_PARTS:
                # Deliberately do not enter known private/runtime directories.
                continue
            canonical_posix_path(rel)
            kept_dirs.append(dirname)
        dirnames[:] = kept_dirs
        for filename in sorted(filenames):
            absolute = current / filename
            st = os.lstat(absolute)
            if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
                raise SafetyError("application-root file topology invalid")
            rel = (rel_dir / filename).as_posix()
            canonical_posix_path(rel)
            if rel != unicodedata.normalize("NFC", rel) or rel.casefold() in folded:
                raise SafetyError("application-root path collision")
            folded.add(rel.casefold())
            category = _category(rel, st.st_size)
            digest, size = _hash_regular(absolute, st)
            total_bytes += size
            if total_bytes > MAX_TOTAL_BYTES:
                raise SafetyError("application-root aggregate size bound exceeded")
            rows.append({"path": rel, "sha256": digest, "size": size, "category": category})
            if len(rows) > MAX_FILES:
                raise SafetyError("application-root file count bound exceeded")
    rows.sort(key=lambda item: item["path"])
    if not rows:
        raise SafetyError("application-root manifest empty")
    # Reuse the strict reconciliation schema as a final independent validator.
    return normalize_nonsecret_manifest({"schema_version": 1, "files": rows})
