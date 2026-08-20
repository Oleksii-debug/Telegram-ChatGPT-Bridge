# -*- coding: utf-8 -*-
"""Safety primitives shared by Telegram Bridge recovery and deployment tooling."""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath

PROTECTED_DIR_COMPONENTS = {
    "var", "runtime", "private", "secrets", "sessions", "data", "uploads",
    "downloads", "media", "logs", "log", "tmp", "cache", "browser",
    "browser_profile", "browser_profiles", "profiles", "cookies", "cookie",
    "venv", ".venv", "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache",
}
PERSISTENT_DIR_COMPONENTS = {
    "var", "runtime", "private", "secrets", "sessions", "data", "uploads",
    "downloads", "media", "logs", "log", "browser", "browser_profile",
    "browser_profiles", "profiles", "cookies", "cookie",
}
PROTECTED_EXACT_NAMES = {
    ".env", "credentials.json", "token.json", "private_config.json",
    "connection_info.txt", "setup_state.json", "bootstrap.json",
    "bridge_keys_secret.txt", "tg_session_string_secret.txt", "cookies.txt",
    "cookies.json",
}
PROTECTED_SUFFIXES = {
    ".session", ".session-journal", ".sqlite", ".sqlite3", ".db",
    ".db-journal", ".db-wal", ".db-shm", ".pem", ".key", ".p12", ".pfx",
    ".log", ".cookie", ".cookies",
}


class SafetyError(RuntimeError):
    pass


def normalize_relative(path: str | Path) -> str:
    text = str(path).replace("\\", "/")
    pure = PurePosixPath(text)
    if pure.is_absolute() or ".." in pure.parts or text in {"", "."}:
        raise SafetyError("unsafe relative path")
    return pure.as_posix()


def _parts_and_name(path: str | Path) -> tuple[list[str], str]:
    rel = normalize_relative(path)
    pure = PurePosixPath(rel)
    parts = [part.casefold() for part in pure.parts]
    return parts, pure.name.casefold()


def is_protected_relative(path: str | Path) -> bool:
    parts, name = _parts_and_name(path)
    if any(part in PROTECTED_DIR_COMPONENTS for part in parts):
        return True
    if name.startswith(".env") or name in PROTECTED_EXACT_NAMES:
        return True
    return any(name.endswith(suffix) for suffix in PROTECTED_SUFFIXES)


def is_persistent_relative(path: str | Path) -> bool:
    parts, name = _parts_and_name(path)
    if any(part in PERSISTENT_DIR_COMPONENTS for part in parts):
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


def sha256_json(payload: dict) -> str:
    data = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def copy_source_without_protected(source: Path, destination: Path) -> None:
    source = source.resolve()
    destination.mkdir(parents=True, exist_ok=True)
    for path in iter_regular_files(source):
        rel = path.relative_to(source).as_posix()
        if is_protected_relative(rel):
            continue
        target = destination / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, target)


def copy_protected_state(*_args, **_kwargs):
    raise SafetyError("mutable protected state must not be copied into versioned releases")


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
    os.chmod(temp, mode)
    os.replace(temp, path)


def _lexical_absolute(path: Path) -> Path:
    return Path(os.path.abspath(os.path.expanduser(str(path))))


def _canonical_no_alias(path: Path, label: str, *, must_exist: bool = False) -> Path:
    lexical = _lexical_absolute(path)
    if must_exist and not lexical.exists():
        raise SafetyError(f"{label} does not exist")
    real = Path(os.path.realpath(lexical))
    if real != lexical:
        raise SafetyError(f"{label} uses a symlink/alias path")
    if lexical.is_symlink():
        raise SafetyError(f"{label} must not be a symlink")
    return lexical


def _overlap(a: Path, b: Path) -> bool:
    if a == b:
        return True
    try:
        a.relative_to(b)
        return True
    except ValueError:
        pass
    try:
        b.relative_to(a)
        return True
    except ValueError:
        return False


def validate_disjoint_topology(
    named_roots: dict[str, Path],
    forbidden_pairs: list[tuple[str, str]],
    *,
    must_exist: set[str] | None = None,
) -> dict[str, Path]:
    must_exist = must_exist or set()
    canonical: dict[str, Path] = {}
    for name, path in named_roots.items():
        canonical[name] = _canonical_no_alias(path, name, must_exist=name in must_exist)
    for left, right in forbidden_pairs:
        if _overlap(canonical[left], canonical[right]):
            raise SafetyError(f"unsafe path topology overlap: {left} / {right}")
    return canonical


def validate_recovery_topology(
    app_root: Path,
    recovery_root: Path,
    *,
    repo_root: Path | None = None,
    public_root: Path | None = None,
) -> dict[str, Path]:
    roots = {"app_root": app_root, "recovery_root": recovery_root}
    pairs = [("app_root", "recovery_root")]
    if repo_root is not None:
        roots["repo_root"] = repo_root
        pairs.append(("recovery_root", "repo_root"))
    if public_root is not None:
        roots["public_root"] = public_root
        pairs.append(("recovery_root", "public_root"))
    return validate_disjoint_topology(roots, pairs, must_exist={"app_root"})


def _lexical_link_path(path: Path, label: str) -> Path:
    lexical = _lexical_absolute(path)
    parent = lexical.parent
    if Path(os.path.realpath(parent)) != parent:
        raise SafetyError(f"{label} parent uses a symlink/alias path")
    return lexical


def validate_deployment_topology(
    *,
    repo: Path,
    active_link: Path,
    releases_root: Path,
    backup_root: Path,
    persistent_state_root: Path,
    control_root: Path,
    public_root: Path | None = None,
) -> dict[str, Path]:
    roots = {
        "repo": repo,
        "releases_root": releases_root,
        "backup_root": backup_root,
        "persistent_state_root": persistent_state_root,
        "control_root": control_root,
    }
    pairs = []
    root_names = list(roots)
    for index, left in enumerate(root_names):
        for right in root_names[index + 1 :]:
            pairs.append((left, right))
    if public_root is not None:
        roots["public_root"] = public_root
        for name in ("repo", "releases_root", "backup_root", "persistent_state_root", "control_root"):
            pairs.append((name, "public_root"))
    canonical = validate_disjoint_topology(roots, pairs, must_exist={"repo"})
    active_lexical = _lexical_link_path(active_link, "active_link")
    for name in ("repo", "releases_root", "backup_root", "persistent_state_root", "control_root"):
        if _overlap(active_lexical, canonical[name]):
            raise SafetyError(f"unsafe path topology overlap: active_link / {name}")
    canonical["active_link"] = active_lexical
    return canonical


def require_under_control_root(path: Path, control_root: Path, label: str) -> Path:
    control = _canonical_no_alias(control_root, "control_root")
    lexical = _lexical_absolute(path)
    if Path(os.path.realpath(lexical.parent)) != lexical.parent:
        raise SafetyError(f"{label} parent uses a symlink/alias path")
    try:
        lexical.relative_to(control)
    except ValueError as exc:
        raise SafetyError(f"{label} must live under private control_root") from exc
    return lexical


def load_runtime_manifest(path: Path) -> list[str]:
    if not path.is_file() or path.is_symlink():
        raise SafetyError("runtime manifest missing or unsafe")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SafetyError("runtime manifest is invalid") from exc
    raw_paths = payload.get("paths") if isinstance(payload, dict) else None
    if not isinstance(raw_paths, list) or not raw_paths:
        raise SafetyError("runtime manifest must contain protected paths")
    result: list[str] = []
    for raw in raw_paths:
        rel = normalize_relative(str(raw))
        if not is_persistent_relative(rel):
            raise SafetyError("runtime manifest contains a non-persistent path")
        if rel not in result:
            result.append(rel)
    return result


def attach_persistent_state(release_root: Path, state_root: Path, entries: list[str]) -> None:
    release_root = release_root.resolve()
    state_root = _canonical_no_alias(state_root, "persistent_state_root", must_exist=True)
    for rel in entries:
        if not is_persistent_relative(rel):
            raise SafetyError("attempt to attach non-persistent path")
        source = state_root / rel
        if not source.exists() or source.is_symlink():
            raise SafetyError("persistent state entry missing or unsafe")
        target = release_root / rel
        if target.exists() or target.is_symlink():
            raise SafetyError("release already contains protected mutable state")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.symlink_to(source, target_is_directory=source.is_dir())


def validate_persistent_bindings(release_root: Path, state_root: Path, entries: list[str]) -> None:
    release_root = release_root.resolve(strict=True)
    state_root = _canonical_no_alias(state_root, "persistent_state_root", must_exist=True)
    for rel in entries:
        target = release_root / rel
        expected = (state_root / rel).resolve(strict=True)
        if not target.is_symlink():
            raise SafetyError("active release does not use shared persistent state")
        if target.resolve(strict=True) != expected:
            raise SafetyError("persistent state binding points to unexpected target")


def _parse_iso(value: object, label: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError as exc:
        raise SafetyError(f"{label} is invalid") from exc
    if parsed.tzinfo is None:
        raise SafetyError(f"{label} must include timezone")
    return parsed.astimezone(timezone.utc)


def load_external_approval(
    path: Path,
    *,
    expected_sha: str,
    expected_repository: str,
    expected_ref: str,
    expected_manifest_sha256: str,
    expected_ci_run_id: str,
    expected_audit_id: str,
    now: datetime | None = None,
) -> dict:
    if not path.is_file() or path.is_symlink():
        raise SafetyError("external approval file missing or unsafe")
    st = path.stat()
    if stat.S_IMODE(st.st_mode) & 0o077:
        raise SafetyError("external approval permissions are too broad")
    if hasattr(os, "getuid") and st.st_uid != os.getuid():
        raise SafetyError("external approval owner is unexpected")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SafetyError("external approval file is invalid") from exc
    expected = {
        "approved_sha": expected_sha,
        "repository": expected_repository,
        "approved_ref": expected_ref,
        "release_manifest_sha256": expected_manifest_sha256,
        "ci_run_id": str(expected_ci_run_id),
        "audit_id": str(expected_audit_id),
    }
    if payload.get("approved") is not True:
        raise SafetyError("release is not externally approved")
    for key, value in expected.items():
        if str(payload.get(key, "")).strip() != str(value):
            raise SafetyError(f"external approval provenance mismatch: {key}")
    if payload.get("data_schema_change") is not False:
        raise SafetyError("schema-changing deployment requires a separate audited migration plan")
    if not payload.get("approval_id") or not payload.get("nonce"):
        raise SafetyError("approval_id/nonce missing")
    issued = _parse_iso(payload.get("issued_at"), "issued_at")
    expires = _parse_iso(payload.get("expires_at"), "expires_at")
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    if expires <= issued or expires - issued > timedelta(hours=24):
        raise SafetyError("external approval lifetime is invalid")
    if issued > current + timedelta(minutes=5) or current > expires:
        raise SafetyError("external approval is not fresh")
    return payload


def consume_external_approval(payload: dict, consumption_root: Path) -> Path:
    consumption_root = _canonical_no_alias(consumption_root, "approval_consumption_root")
    consumption_root.mkdir(parents=True, exist_ok=True)
    token = hashlib.sha256(
        (str(payload["approval_id"]) + "\0" + str(payload["nonce"])).encode("utf-8")
    ).hexdigest()
    marker = consumption_root / (token + ".consumed.json")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    try:
        fd = os.open(marker, flags, 0o600)
    except FileExistsError as exc:
        raise SafetyError("external approval was already consumed") from exc
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump({"approval_id": payload["approval_id"], "consumed_at": utc_now_iso()}, handle)
        handle.write("\n")
    return marker


def atomic_switch_link(link: Path, new_target: Path) -> Path | None:
    link.parent.mkdir(parents=True, exist_ok=True)
    previous = None
    if link.exists() or link.is_symlink():
        if not link.is_symlink():
            raise SafetyError("active application path is not a symlink")
        previous = link.resolve(strict=True)
    temp = link.with_name(link.name + ".next")
    if temp.exists() or temp.is_symlink():
        temp.unlink()
    temp.symlink_to(new_target)
    os.replace(temp, link)
    return previous


def restore_link(link: Path, previous_target: Path | None) -> None:
    if previous_target is None:
        if link.is_symlink() or link.exists():
            link.unlink()
        return
    temp = link.with_name(link.name + ".rollback")
    if temp.exists() or temp.is_symlink():
        temp.unlink()
    temp.symlink_to(previous_target)
    os.replace(temp, link)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def retention_candidates(
    paths: list[Path],
    *,
    active: Path | None,
    last_known_good: Path | None,
    keep_newest: int = 5,
) -> list[Path]:
    existing = [p for p in paths if p.exists()]
    newest = sorted(existing, key=lambda p: p.stat().st_mtime, reverse=True)
    protected = {p.resolve() for p in newest[:keep_newest]}
    if active is not None:
        protected.add(active.resolve())
    if last_known_good is not None:
        protected.add(last_known_good.resolve())
    return [p for p in newest[keep_newest:] if p.resolve() not in protected]


def apply_retention(
    paths: list[Path],
    *,
    active: Path | None,
    last_known_good: Path | None,
    keep_newest: int = 5,
) -> list[str]:
    removed: list[str] = []
    for path in retention_candidates(
        paths, active=active, last_known_good=last_known_good, keep_newest=keep_newest
    ):
        if path.is_symlink():
            raise SafetyError("retention refuses symlink artifact")
        if path.is_dir():
            shutil.rmtree(path)
        else:
            path.unlink(missing_ok=True)
        removed.append(str(path))
    return removed


def apply_backup_retention(
    backup_root: Path,
    *,
    last_known_good: Path | None,
    keep_newest: int = 5,
) -> list[str]:
    backups = sorted(backup_root.glob("*.tar.gz"))
    removable = retention_candidates(
        backups, active=None, last_known_good=last_known_good, keep_newest=keep_newest
    )
    removed: list[str] = []
    for backup in removable:
        if backup.is_symlink():
            raise SafetyError("retention refuses symlink backup")
        hash_path = Path(str(backup) + ".sha256")
        backup.unlink(missing_ok=True)
        hash_path.unlink(missing_ok=True)
        removed.append(str(backup))
    return removed


def cleanup_stale_staging(
    releases_root: Path,
    *,
    older_than_seconds: int = 86400,
    now_timestamp: float | None = None,
) -> list[str]:
    if not releases_root.exists():
        return []
    now_value = now_timestamp if now_timestamp is not None else datetime.now().timestamp()
    removed: list[str] = []
    for path in releases_root.iterdir():
        if not path.name.startswith(".stage_"):
            continue
        if path.is_symlink():
            raise SafetyError("staging cleanup refuses symlink")
        if not path.is_dir() or (path / "ACTIVE_LOCK").exists():
            continue
        if now_value - path.stat().st_mtime < older_than_seconds:
            continue
        shutil.rmtree(path)
        removed.append(str(path))
    return removed
