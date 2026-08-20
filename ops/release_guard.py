# -*- coding: utf-8 -*-
"""Safety primitives shared by Telegram Bridge recovery and deployment tooling."""
from __future__ import annotations

import hashlib
import json
import os
import shutil
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

PROTECTED_DIR_COMPONENTS = {
    "var", "runtime", "private", "secrets", "sessions", "data", "uploads",
    "downloads", "media", "logs", "log", "tmp", "cache", "venv", ".venv",
    "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache",
}
PROTECTED_EXACT_NAMES = {
    ".env", "credentials.json", "token.json", "private_config.json",
    "connection_info.txt", "setup_state.json", "bootstrap.json",
    "bridge_keys_secret.txt", "tg_session_string_secret.txt",
}
PROTECTED_SUFFIXES = {
    ".session", ".session-journal", ".sqlite", ".sqlite3", ".db",
    ".db-journal", ".db-wal", ".db-shm", ".pem", ".key", ".p12", ".pfx",
}

class SafetyError(RuntimeError):
    pass

def normalize_relative(path: str | Path) -> str:
    text = str(path).replace("\\", "/")
    pure = PurePosixPath(text)
    if pure.is_absolute() or ".." in pure.parts or text in {"", "."}:
        raise SafetyError("unsafe relative path")
    return pure.as_posix()

def is_protected_relative(path: str | Path) -> bool:
    rel = normalize_relative(path)
    pure = PurePosixPath(rel)
    parts = [part.casefold() for part in pure.parts]
    name = pure.name.casefold()
    if any(part in PROTECTED_DIR_COMPONENTS for part in parts[:-1]):
        return True
    if name.startswith(".env") or name in PROTECTED_EXACT_NAMES:
        return True
    return any(name.endswith(suffix) for suffix in PROTECTED_SUFFIXES)

def iter_regular_files(root: Path):
    root = root.resolve()
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise SafetyError(f"symlink encountered: {path.relative_to(root).as_posix()}")
        if path.is_file():
            yield path

def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()

def copy_source_without_protected(source: Path, destination: Path) -> None:
    source = source.resolve(); destination.mkdir(parents=True, exist_ok=True)
    for path in iter_regular_files(source):
        rel = path.relative_to(source).as_posix()
        if is_protected_relative(rel):
            continue
        target = destination / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, target)

def copy_protected_state(live_root: Path, destination: Path) -> list[str]:
    live_root = live_root.resolve(); copied: list[str] = []
    if not live_root.exists():
        return copied
    for path in iter_regular_files(live_root):
        rel = path.relative_to(live_root).as_posix()
        if not is_protected_relative(rel):
            continue
        target = destination / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, target); copied.append(rel)
    return copied

def build_manifest(root: Path) -> dict:
    files = []
    for path in iter_regular_files(root):
        rel = path.relative_to(root).as_posix()
        files.append({"path": rel, "size": path.stat().st_size, "sha256": sha256_file(path)})
    return {"files": files, "count": len(files)}

def write_json_atomic(path: Path, payload: dict, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(path.name + ".tmp")
    temp.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(temp, mode); os.replace(temp, path)

def load_external_approval(path: Path, expected_sha: str) -> dict:
    if not path.is_file() or path.is_symlink():
        raise SafetyError("external approval file missing or unsafe")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SafetyError("external approval file is invalid") from exc
    if payload.get("approved") is not True or str(payload.get("approved_sha", "")).strip() != expected_sha:
        raise SafetyError("release SHA is not externally approved")
    if not payload.get("approval_id"):
        raise SafetyError("approval_id missing")
    return payload

def atomic_switch_link(link: Path, new_target: Path) -> Path | None:
    link.parent.mkdir(parents=True, exist_ok=True); previous = None
    if link.exists() or link.is_symlink():
        if not link.is_symlink():
            raise SafetyError("active application path is not a symlink")
        previous = link.resolve(strict=True)
    temp = link.with_name(link.name + ".next")
    if temp.exists() or temp.is_symlink(): temp.unlink()
    temp.symlink_to(new_target); os.replace(temp, link)
    return previous

def restore_link(link: Path, previous_target: Path | None) -> None:
    if previous_target is None:
        if link.is_symlink() or link.exists(): link.unlink()
        return
    temp = link.with_name(link.name + ".rollback")
    if temp.exists() or temp.is_symlink(): temp.unlink()
    temp.symlink_to(previous_target); os.replace(temp, link)

def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def retention_candidates(paths: list[Path], *, active: Path | None, last_known_good: Path | None, keep_newest: int = 5) -> list[Path]:
    existing = [p for p in paths if p.exists()]
    newest = sorted(existing, key=lambda p: p.stat().st_mtime, reverse=True)
    protected = {p.resolve() for p in newest[:keep_newest]}
    if active is not None: protected.add(active.resolve())
    if last_known_good is not None: protected.add(last_known_good.resolve())
    return [p for p in newest[keep_newest:] if p.resolve() not in protected]

def apply_retention(paths: list[Path], *, active: Path | None, last_known_good: Path | None, keep_newest: int = 5) -> list[str]:
    removed: list[str] = []
    for path in retention_candidates(paths, active=active, last_known_good=last_known_good, keep_newest=keep_newest):
        if path.is_symlink(): raise SafetyError("retention refuses symlink artifact")
        if path.is_dir(): shutil.rmtree(path)
        else: path.unlink(missing_ok=True)
        removed.append(str(path))
    return removed
