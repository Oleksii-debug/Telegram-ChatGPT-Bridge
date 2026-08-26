# -*- coding: utf-8 -*-
"""Fail-closed cleanup for private Telegram Bridge state.

Retention is deliberately narrower than "delete old files". A destructive
operation is allowed only when age, terminality, references, topology and the
live serialization boundary can all be proven at deletion time.

Authoritative knowledge is never space-pruned here: write idempotency rows,
COMMITTED/AMBIGUOUS tombstones, referenced previews, rate-limit/retention high
water, audit history, retryable/non-terminal checkpoints, and unleased staging.
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import hmac
import json
import os
import re
import sqlite3
import stat
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

_RETENTION_TABLE = "retention_high_water"
_LEASE_SCHEMA = 1
_MAX_RETENTION_SECONDS = 10 * 365 * 24 * 60 * 60
_MAX_BATCH = 10_000
_JOB_ID_RE = re.compile(r"^[A-Za-z0-9_-]{16,128}$")
_ITEM_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
_CODE_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_FILE_REF_RE = re.compile(r"^[A-Za-z0-9_-]{16,128}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_CHECKPOINT_KEYS = {"schema", "job_id", "status", "items", "results", "failures"}
_ITEM_KEYS = {
    "item_id",
    "chat",
    "message_id",
    "source_file_ref",
    "name",
    "mime_type",
    "expected_size",
    "expected_sha256",
}
_FAILURE_KEYS = {"code", "status", "retryable"}


class RetentionSafetyError(RuntimeError):
    """Cleanup cannot prove a destructive operation safe."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class CleanupResult:
    deleted: int
    busy: int = 0
    protected: int = 0
    corrupt: int = 0

    def as_dict(self) -> dict[str, int]:
        return {
            "deleted": self.deleted,
            "busy": self.busy,
            "protected": self.protected,
            "corrupt": self.corrupt,
        }


@dataclass(frozen=True)
class StagingLease:
    marker_path: Path
    part_path: Path
    created_at: int
    fd: int

    def close(self, *, remove_marker: bool = True) -> None:
        try:
            if remove_marker:
                _unlink_if_same_inode(self.marker_path, self.fd)
        finally:
            try:
                fcntl.flock(self.fd, fcntl.LOCK_UN)
            except OSError:
                pass
            os.close(self.fd)


def retention_policy() -> dict[str, str]:
    return {
        "download_checkpoint_nonterminal": "AUTHORITATIVE_PROTECTED",
        "download_checkpoint_terminal_aged": "EPHEMERAL_AFTER_LOCK_AND_RECHECK",
        "download_job_lock_active": "EPHEMERAL_PROTECTED_WHILE_LOCKED",
        "download_job_lock_terminal_deleted": "EPHEMERAL_RECLAIMABLE",
        "archive_staging_leased_aged": "EPHEMERAL_AFTER_LEASE_LOCK",
        "archive_staging_unleased": "AMBIGUOUS_PROTECTED",
        "write_preview_unreferenced_expired": "EPHEMERAL_AFTER_DB_RECHECK",
        "write_preview_referenced": "AUTHORITATIVE_PROTECTED",
        "write_idempotency": "AUTHORITATIVE_PROTECTED",
        "write_committed_tombstone": "AUTHORITATIVE_PROTECTED",
        "write_ambiguous_tombstone": "AUTHORITATIVE_PROTECTED",
        "rate_limit_high_water": "AUTHORITATIVE_PROTECTED",
        "retention_high_water": "AUTHORITATIVE_PROTECTED",
        "audit_history": "AUTHORITATIVE_PROTECTED",
    }


def audit_disk_policy(path: str | Path) -> dict[str, Any]:
    """Inventory audit disk use without truncating authoritative history."""
    candidate = Path(path)
    exists = candidate.exists() or candidate.is_symlink()
    size = 0
    if exists:
        info = os.lstat(candidate)
        if (
            stat.S_ISLNK(info.st_mode)
            or not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or (hasattr(os, "geteuid") and info.st_uid != os.geteuid())
        ):
            raise RetentionSafetyError("unsafe_audit_topology")
        size = int(info.st_size)
    return {
        "exists": exists,
        "bytes": size,
        "classification": "AUTHORITATIVE_PROTECTED",
        "automatic_delete": False,
    }


def _validate_now(now: int | None) -> int:
    try:
        value = int(time.time() if now is None else now)
    except (TypeError, ValueError) as exc:
        raise RetentionSafetyError("invalid_retention_clock") from exc
    if isinstance(now, bool) or value < 0:
        raise RetentionSafetyError("invalid_retention_clock")
    return value


def _validate_age(seconds: int) -> int:
    if isinstance(seconds, bool):
        raise RetentionSafetyError("invalid_retention_age")
    try:
        value = int(seconds)
    except (TypeError, ValueError) as exc:
        raise RetentionSafetyError("invalid_retention_age") from exc
    if value < 0 or value > _MAX_RETENTION_SECONDS:
        raise RetentionSafetyError("invalid_retention_age")
    return value


def _validate_batch(limit: int) -> int:
    if isinstance(limit, bool):
        raise RetentionSafetyError("invalid_retention_batch")
    try:
        value = int(limit)
    except (TypeError, ValueError) as exc:
        raise RetentionSafetyError("invalid_retention_batch") from exc
    if not 1 <= value <= _MAX_BATCH:
        raise RetentionSafetyError("invalid_retention_batch")
    return value


def _private_dir(path: Path, *, create: bool) -> Path:
    lexical = Path(os.path.abspath(os.path.expanduser(str(path))))
    if not lexical.exists():
        if not create:
            raise RetentionSafetyError("retention_directory_missing")
        try:
            lexical.mkdir(parents=True, mode=0o700, exist_ok=False)
            os.chmod(lexical, 0o700)
        except FileExistsError:
            pass
        except OSError as exc:
            raise RetentionSafetyError("retention_directory_create_failed") from exc
    try:
        info = os.lstat(lexical)
    except OSError as exc:
        raise RetentionSafetyError("retention_directory_unavailable") from exc
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISDIR(info.st_mode)
        or Path(os.path.realpath(lexical)) != lexical
        or stat.S_IMODE(info.st_mode) != 0o700
        or (hasattr(os, "geteuid") and info.st_uid != os.geteuid())
    ):
        raise RetentionSafetyError("unsafe_retention_directory")
    return lexical


def _validate_database_leaf(path: Path) -> None:
    if not (path.exists() or path.is_symlink()):
        return
    info = os.lstat(path)
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or (hasattr(os, "geteuid") and info.st_uid != os.geteuid())
    ):
        raise RetentionSafetyError("unsafe_retention_database")


def _prepare_sqlite_path(path: Path) -> Path:
    lexical = Path(os.path.abspath(os.path.expanduser(str(path))))
    parent = _private_dir(lexical.parent, create=True)
    if lexical.parent != parent:
        raise RetentionSafetyError("unsafe_retention_database_path")
    if lexical.exists() or lexical.is_symlink():
        _validate_database_leaf(lexical)
        return lexical
    flags = (
        os.O_CREAT
        | os.O_EXCL
        | os.O_RDWR
        | int(getattr(os, "O_NOFOLLOW", 0))
        | int(getattr(os, "O_CLOEXEC", 0))
    )
    try:
        fd = os.open(lexical, flags, 0o600)
    except FileExistsError:
        _validate_database_leaf(lexical)
        return lexical
    except OSError as exc:
        raise RetentionSafetyError("retention_database_create_failed") from exc
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or (hasattr(os, "geteuid") and info.st_uid != os.geteuid())
        ):
            raise RetentionSafetyError("unsafe_retention_database")
    finally:
        os.close(fd)
    return lexical


def _validate_sqlite_sidecars(database: Path) -> None:
    for suffix in ("-wal", "-shm"):
        _validate_database_leaf(Path(str(database) + suffix))


@contextmanager
def _sqlite(path: str | Path) -> Iterator[sqlite3.Connection]:
    database = _prepare_sqlite_path(Path(path))
    _validate_sqlite_sidecars(database)
    try:
        con = sqlite3.connect(str(database), timeout=8.0, isolation_level=None)
    except sqlite3.Error as exc:
        raise RetentionSafetyError("retention_database_unavailable") from exc
    try:
        con.execute("PRAGMA foreign_keys=ON")
        con.execute("PRAGMA journal_mode=WAL")
        con.execute("PRAGMA synchronous=FULL")
        con.execute("PRAGMA busy_timeout=8000")
        _validate_sqlite_sidecars(database)
        yield con
    except sqlite3.Error as exc:
        raise RetentionSafetyError("retention_database_unavailable") from exc
    finally:
        con.close()
        _validate_sqlite_sidecars(database)


def _require_tables(con: sqlite3.Connection, *names: str) -> None:
    existing = {
        str(row[0])
        for row in con.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
    }
    if any(name not in existing for name in names):
        raise RetentionSafetyError("retention_schema_mismatch")


def _ensure_retention_table(con: sqlite3.Connection) -> None:
    con.execute(
        f"CREATE TABLE IF NOT EXISTS {_RETENTION_TABLE}("
        "namespace TEXT PRIMARY KEY,high_water INTEGER NOT NULL CHECK(high_water>=0))"
    )


def _advance_high_water(con: sqlite3.Connection, *, namespace: str, now: int) -> None:
    _ensure_retention_table(con)
    row = con.execute(
        f"SELECT high_water FROM {_RETENTION_TABLE} WHERE namespace=?", (namespace,)
    ).fetchone()
    if row is not None and now < int(row[0]):
        raise RetentionSafetyError("retention_clock_moved_backward")
    if row is None:
        con.execute(
            f"INSERT INTO {_RETENTION_TABLE}(namespace,high_water) VALUES(?,?)",
            (namespace, now),
        )
    elif now > int(row[0]):
        con.execute(
            f"UPDATE {_RETENTION_TABLE} SET high_water=? WHERE namespace=?",
            (now, namespace),
        )


def cleanup_write_previews(
    db_path: str | Path,
    *,
    now: int | None = None,
    expired_grace_seconds: int = 86_400,
) -> CleanupResult:
    """Delete only old unconsumed previews with zero idempotency references."""
    ts = _validate_now(now)
    cutoff = ts - _validate_age(expired_grace_seconds)
    with _sqlite(db_path) as con:
        con.execute("BEGIN IMMEDIATE")
        try:
            _require_tables(con, "previews", "idempotency")
            _advance_high_water(con, namespace="write_preview_cleanup", now=ts)
            idem_before = int(con.execute("SELECT COUNT(*) FROM idempotency").fetchone()[0])
            protected = int(
                con.execute(
                    "SELECT COUNT(*) FROM previews p WHERE EXISTS("
                    "SELECT 1 FROM idempotency i WHERE i.preview_id=p.preview_id)"
                ).fetchone()[0]
            )
            cur = con.execute(
                "DELETE FROM previews WHERE expires_at < ? AND consumed_at IS NULL "
                "AND NOT EXISTS(SELECT 1 FROM idempotency i WHERE i.preview_id=previews.preview_id)",
                (cutoff,),
            )
            if int(con.execute("SELECT COUNT(*) FROM idempotency").fetchone()[0]) != idem_before:
                raise RetentionSafetyError("idempotency_retention_violation")
            con.execute("COMMIT")
            return CleanupResult(deleted=max(0, int(cur.rowcount)), protected=protected)
        except Exception:
            if con.in_transaction:
                con.execute("ROLLBACK")
            raise


def _decode_checkpoint(raw_text: str, stored_digest: str) -> dict[str, Any]:
    actual = hashlib.sha256(raw_text.encode("utf-8", "strict")).hexdigest()
    if not hmac.compare_digest(actual, stored_digest):
        raise RetentionSafetyError("checkpoint_integrity_mismatch")
    try:
        payload = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        raise RetentionSafetyError("checkpoint_json_corrupt") from exc
    if not isinstance(payload, dict):
        raise RetentionSafetyError("checkpoint_json_corrupt")
    return payload


def _valid_file_ref(value: Any) -> bool:
    return isinstance(value, str) and _FILE_REF_RE.fullmatch(value) is not None


def _checkpoint_terminal(payload: dict[str, Any]) -> bool:
    """Mirror CheckpointStore validation before evaluating retention terminality."""
    if set(payload) != _CHECKPOINT_KEYS or payload.get("schema") != 1:
        raise RetentionSafetyError("checkpoint_shape_corrupt")
    job_id = payload.get("job_id")
    status_value = payload.get("status")
    items = payload.get("items")
    results = payload.get("results")
    failures = payload.get("failures")
    if not isinstance(job_id, str) or _JOB_ID_RE.fullmatch(job_id) is None:
        raise RetentionSafetyError("checkpoint_shape_corrupt")
    if status_value not in {"pending", "running", "partial", "complete", "failed"}:
        raise RetentionSafetyError("checkpoint_shape_corrupt")
    if not isinstance(items, list) or not 1 <= len(items) <= 500:
        raise RetentionSafetyError("checkpoint_shape_corrupt")
    if not isinstance(results, dict) or not isinstance(failures, dict):
        raise RetentionSafetyError("checkpoint_shape_corrupt")

    item_ids: set[str] = set()
    for raw in items:
        if not isinstance(raw, dict) or set(raw) != _ITEM_KEYS:
            raise RetentionSafetyError("checkpoint_shape_corrupt")
        item_id = raw.get("item_id")
        message_id = raw.get("message_id")
        expected_size = raw.get("expected_size")
        expected_sha = raw.get("expected_sha256")
        if (
            not isinstance(item_id, str)
            or _ITEM_ID_RE.fullmatch(item_id) is None
            or item_id in item_ids
            or not isinstance(raw.get("chat"), str)
            or not raw.get("chat")
            or isinstance(message_id, bool)
            or not isinstance(message_id, int)
            or message_id <= 0
            or not _valid_file_ref(raw.get("source_file_ref"))
            or not isinstance(raw.get("name"), str)
            or not isinstance(raw.get("mime_type"), str)
            or (
                expected_size is not None
                and (
                    isinstance(expected_size, bool)
                    or not isinstance(expected_size, int)
                    or expected_size < 0
                )
            )
            or (
                expected_sha is not None
                and (not isinstance(expected_sha, str) or _SHA256_RE.fullmatch(expected_sha) is None)
            )
        ):
            raise RetentionSafetyError("checkpoint_shape_corrupt")
        item_ids.add(item_id)

    if (
        not set(results).issubset(item_ids)
        or not set(failures).issubset(item_ids)
        or set(results).intersection(failures)
    ):
        raise RetentionSafetyError("checkpoint_shape_corrupt")
    if any(not _valid_file_ref(value) for value in results.values()):
        raise RetentionSafetyError("checkpoint_shape_corrupt")
    for info in failures.values():
        if not isinstance(info, dict) or set(info) != _FAILURE_KEYS:
            raise RetentionSafetyError("checkpoint_shape_corrupt")
        code = info.get("code")
        status_code = info.get("status")
        retryable = info.get("retryable")
        if (
            not isinstance(code, str)
            or _CODE_RE.fullmatch(code) is None
            or isinstance(status_code, bool)
            or not isinstance(status_code, int)
            or not 400 <= status_code <= 599
            or not isinstance(retryable, bool)
        ):
            raise RetentionSafetyError("checkpoint_shape_corrupt")

    if status_value == "complete":
        if set(results) != item_ids or failures:
            raise RetentionSafetyError("checkpoint_shape_corrupt")
        return True
    if status_value not in {"partial", "failed"}:
        return False
    unresolved = item_ids - set(results)
    if not unresolved:
        return False
    return all(
        isinstance(failures.get(item_id), dict)
        and failures[item_id].get("retryable") is False
        for item_id in unresolved
    )


def _checkpoint_candidates(
    db_path: str | Path,
    *,
    now: int,
    min_age_seconds: int,
    limit: int,
) -> tuple[list[str], int, int]:
    cutoff = now - min_age_seconds
    terminal: list[str] = []
    protected = corrupt = 0
    with _sqlite(db_path) as con:
        con.execute("BEGIN IMMEDIATE")
        try:
            _require_tables(con, "download_jobs")
            _advance_high_water(con, namespace="download_checkpoint_cleanup", now=now)
            rows = con.execute(
                "SELECT job_id,payload_json,payload_sha256 FROM download_jobs "
                "WHERE updated_at < ? ORDER BY updated_at,job_id LIMIT ?",
                (cutoff, limit),
            ).fetchall()
            for job_id, raw, digest in rows:
                try:
                    payload = _decode_checkpoint(str(raw), str(digest))
                    if str(payload.get("job_id")) != str(job_id):
                        raise RetentionSafetyError("checkpoint_identity_mismatch")
                    if _checkpoint_terminal(payload):
                        terminal.append(str(job_id))
                    else:
                        protected += 1
                except RetentionSafetyError:
                    corrupt += 1
            con.execute("COMMIT")
        except Exception:
            if con.in_transaction:
                con.execute("ROLLBACK")
            raise
    return terminal, protected, corrupt


def _safe_lock_dir(path: str | Path) -> Path:
    return _private_dir(Path(path), create=True)


def _job_lock_name(job_id: str) -> str:
    return hashlib.sha256(job_id.encode("utf-8", "strict")).hexdigest() + ".lock"


@contextmanager
def _cleanup_job_lock(lock_dir: Path, job_id: str) -> Iterator[tuple[int, Path, bool]]:
    lock_path = lock_dir / _job_lock_name(job_id)
    nofollow = int(getattr(os, "O_NOFOLLOW", 0))
    cloexec = int(getattr(os, "O_CLOEXEC", 0))
    created = False
    try:
        fd = os.open(
            lock_path,
            os.O_CREAT | os.O_EXCL | os.O_RDWR | nofollow | cloexec,
            0o600,
        )
        created = True
    except FileExistsError:
        try:
            fd = os.open(lock_path, os.O_RDWR | nofollow | cloexec)
        except OSError as exc:
            raise RetentionSafetyError("job_lock_unavailable") from exc
    except OSError as exc:
        raise RetentionSafetyError("job_lock_unavailable") from exc
    acquired = False
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_size != 0
            or stat.S_IMODE(info.st_mode) != 0o600
            or (hasattr(os, "geteuid") and info.st_uid != os.geteuid())
        ):
            raise RetentionSafetyError("unsafe_job_lock_topology")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            acquired = True
        except BlockingIOError as exc:
            raise RetentionSafetyError("job_lock_busy") from exc
        yield fd, lock_path, created
    finally:
        if acquired:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            except OSError:
                pass
        os.close(fd)


def _delete_checkpoint_if_terminal(
    db_path: str | Path,
    *,
    job_id: str,
    now: int,
    min_age_seconds: int,
) -> bool:
    cutoff = now - min_age_seconds
    with _sqlite(db_path) as con:
        con.row_factory = sqlite3.Row
        con.execute("BEGIN IMMEDIATE")
        try:
            _require_tables(con, "download_jobs")
            _advance_high_water(con, namespace="download_checkpoint_cleanup", now=now)
            row = con.execute(
                "SELECT payload_json,payload_sha256,updated_at FROM download_jobs WHERE job_id=?",
                (job_id,),
            ).fetchone()
            if row is None or int(row["updated_at"]) >= cutoff:
                con.execute("COMMIT")
                return False
            payload = _decode_checkpoint(str(row["payload_json"]), str(row["payload_sha256"]))
            if str(payload.get("job_id")) != job_id or not _checkpoint_terminal(payload):
                con.execute("COMMIT")
                return False
            cur = con.execute("DELETE FROM download_jobs WHERE job_id=?", (job_id,))
            con.execute("COMMIT")
            return int(cur.rowcount) == 1
        except Exception:
            if con.in_transaction:
                con.execute("ROLLBACK")
            raise


def _unlink_if_same_inode(path: Path, fd: int) -> None:
    try:
        current = os.lstat(path)
    except FileNotFoundError:
        return
    held = os.fstat(fd)
    if (current.st_dev, current.st_ino) != (held.st_dev, held.st_ino):
        raise RetentionSafetyError("retention_leaf_replaced")
    if not stat.S_ISREG(current.st_mode) or current.st_nlink != 1:
        raise RetentionSafetyError("unsafe_retention_leaf_topology")
    os.unlink(path)


def cleanup_download_checkpoints(
    checkpoint_db_path: str | Path,
    lock_dir: str | Path,
    *,
    now: int | None = None,
    min_age_seconds: int = 7 * 24 * 60 * 60,
    max_jobs: int = 256,
) -> CleanupResult:
    """Delete aged terminal jobs only while holding their live resume lock."""
    ts = _validate_now(now)
    age = _validate_age(min_age_seconds)
    limit = _validate_batch(max_jobs)
    directory = _safe_lock_dir(lock_dir)
    candidates, protected, corrupt = _checkpoint_candidates(
        checkpoint_db_path,
        now=ts,
        min_age_seconds=age,
        limit=limit,
    )
    deleted = busy = 0
    for job_id in candidates:
        try:
            with _cleanup_job_lock(directory, job_id) as (fd, lock_path, created):
                try:
                    removed = _delete_checkpoint_if_terminal(
                        checkpoint_db_path,
                        job_id=job_id,
                        now=ts,
                        min_age_seconds=age,
                    )
                except RetentionSafetyError:
                    corrupt += 1
                    if created:
                        _unlink_if_same_inode(lock_path, fd)
                    continue
                if not removed:
                    protected += 1
                    if created:
                        _unlink_if_same_inode(lock_path, fd)
                    continue
                _unlink_if_same_inode(lock_path, fd)
                deleted += 1
        except RetentionSafetyError as exc:
            if exc.code == "job_lock_busy":
                busy += 1
                continue
            raise
    return CleanupResult(deleted=deleted, busy=busy, protected=protected, corrupt=corrupt)


def _safe_stage_name(name: str) -> bool:
    return (
        name.startswith("archive_")
        and name.endswith(".zip.part")
        and all(ch.isalnum() or ch in {"_", ".", "-"} for ch in name)
    )


def _write_all(fd: int, payload: bytes) -> None:
    view = memoryview(payload)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise RetentionSafetyError("staging_lease_write_failed")
        view = view[written:]


def create_staging_lease(part_path: str | Path, *, now: int | None = None) -> StagingLease:
    ts = _validate_now(now)
    part = Path(os.path.abspath(os.path.expanduser(str(part_path))))
    if not _safe_stage_name(part.name):
        raise RetentionSafetyError("invalid_staging_name")
    parent = _private_dir(part.parent, create=True)
    if part.parent != parent:
        raise RetentionSafetyError("unsafe_staging_path")
    marker = part.with_name(part.name + ".lease")
    flags = (
        os.O_CREAT
        | os.O_EXCL
        | os.O_RDWR
        | int(getattr(os, "O_NOFOLLOW", 0))
        | int(getattr(os, "O_CLOEXEC", 0))
    )
    try:
        fd = os.open(marker, flags, 0o600)
    except OSError as exc:
        raise RetentionSafetyError("staging_lease_create_failed") from exc
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        payload = json.dumps(
            {"schema": _LEASE_SCHEMA, "part": part.name, "created_at": ts},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
        _write_all(fd, payload)
        os.fsync(fd)
        return StagingLease(marker_path=marker, part_path=part, created_at=ts, fd=fd)
    except Exception:
        try:
            os.close(fd)
        finally:
            try:
                marker.unlink(missing_ok=True)
            except OSError:
                pass
        raise


def _read_lease(fd: int, marker: Path) -> tuple[Path, int]:
    info = os.fstat(fd)
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or stat.S_IMODE(info.st_mode) != 0o600
        or info.st_size > 512
        or (hasattr(os, "geteuid") and info.st_uid != os.geteuid())
    ):
        raise RetentionSafetyError("unsafe_staging_lease")
    os.lseek(fd, 0, os.SEEK_SET)
    raw = os.read(fd, 513)
    try:
        payload = json.loads(raw.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RetentionSafetyError("staging_lease_corrupt") from exc
    if not isinstance(payload, dict) or set(payload) != {"schema", "part", "created_at"}:
        raise RetentionSafetyError("staging_lease_corrupt")
    part_name = payload["part"]
    created = payload["created_at"]
    if (
        payload["schema"] != _LEASE_SCHEMA
        or not isinstance(part_name, str)
        or not _safe_stage_name(part_name)
        or marker.name != part_name + ".lease"
        or isinstance(created, bool)
        or not isinstance(created, int)
        or created < 0
    ):
        raise RetentionSafetyError("staging_lease_corrupt")
    return marker.parent / part_name, created


def _unlink_stage_part(path: Path) -> None:
    flags = (
        os.O_RDONLY
        | int(getattr(os, "O_NOFOLLOW", 0))
        | int(getattr(os, "O_CLOEXEC", 0))
    )
    try:
        fd = os.open(path, flags)
    except FileNotFoundError:
        return
    except OSError as exc:
        raise RetentionSafetyError("staging_part_unavailable") from exc
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or (hasattr(os, "geteuid") and info.st_uid != os.geteuid())
        ):
            raise RetentionSafetyError("unsafe_staging_part")
        _unlink_if_same_inode(path, fd)
    finally:
        os.close(fd)


def cleanup_leased_archive_staging(
    staging_dir: str | Path,
    ledger_db_path: str | Path,
    *,
    now: int | None = None,
    min_age_seconds: int = 24 * 60 * 60,
    max_markers: int = 256,
) -> CleanupResult:
    """Delete only aged valid unlocked archive leases and their exact part inode."""
    ts = _validate_now(now)
    age = _validate_age(min_age_seconds)
    limit = _validate_batch(max_markers)
    directory = Path(os.path.abspath(os.path.expanduser(str(staging_dir))))
    if not directory.exists():
        return CleanupResult(deleted=0)
    directory = _private_dir(directory, create=False)
    with _sqlite(ledger_db_path) as con:
        con.execute("BEGIN IMMEDIATE")
        try:
            _advance_high_water(con, namespace="archive_staging_cleanup", now=ts)
            con.execute("COMMIT")
        except Exception:
            if con.in_transaction:
                con.execute("ROLLBACK")
            raise
    cutoff = ts - age
    deleted = busy = protected = corrupt = 0
    for marker in sorted(directory.glob("archive_*.zip.part.lease"))[:limit]:
        flags = os.O_RDWR | int(getattr(os, "O_NOFOLLOW", 0)) | int(getattr(os, "O_CLOEXEC", 0))
        try:
            fd = os.open(marker, flags)
        except OSError:
            corrupt += 1
            continue
        acquired = False
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                acquired = True
            except BlockingIOError:
                busy += 1
                continue
            try:
                part, created = _read_lease(fd, marker)
                if created > ts:
                    raise RetentionSafetyError("staging_lease_future_clock")
            except RetentionSafetyError:
                corrupt += 1
                continue
            if created >= cutoff:
                protected += 1
                continue
            try:
                _unlink_stage_part(part)
                _unlink_if_same_inode(marker, fd)
            except RetentionSafetyError:
                corrupt += 1
                continue
            deleted += 1
        finally:
            if acquired:
                try:
                    fcntl.flock(fd, fcntl.LOCK_UN)
                except OSError:
                    pass
            os.close(fd)
    return CleanupResult(deleted=deleted, busy=busy, protected=protected, corrupt=corrupt)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Fail-closed Telegram Bridge state retention")
    parser.add_argument("--now", type=int, default=None)
    sub = parser.add_subparsers(dest="command", required=True)
    writes = sub.add_parser("writes")
    writes.add_argument("db")
    writes.add_argument("--grace", type=int, default=86_400)
    downloads = sub.add_parser("downloads")
    downloads.add_argument("db")
    downloads.add_argument("lock_dir")
    downloads.add_argument("--age", type=int, default=7 * 24 * 60 * 60)
    downloads.add_argument("--limit", type=int, default=256)
    staging = sub.add_parser("staging")
    staging.add_argument("directory")
    staging.add_argument("ledger_db")
    staging.add_argument("--age", type=int, default=24 * 60 * 60)
    staging.add_argument("--limit", type=int, default=256)
    sub.add_parser("policy")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "writes":
        result: Any = cleanup_write_previews(
            args.db,
            now=args.now,
            expired_grace_seconds=args.grace,
        ).as_dict()
    elif args.command == "downloads":
        result = cleanup_download_checkpoints(
            args.db,
            args.lock_dir,
            now=args.now,
            min_age_seconds=args.age,
            max_jobs=args.limit,
        ).as_dict()
    elif args.command == "staging":
        result = cleanup_leased_archive_staging(
            args.directory,
            args.ledger_db,
            now=args.now,
            min_age_seconds=args.age,
            max_markers=args.limit,
        ).as_dict()
    else:
        result = retention_policy()
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
