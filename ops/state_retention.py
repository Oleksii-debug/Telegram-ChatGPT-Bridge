# -*- coding: utf-8 -*-
"""Crash-safe, fail-closed retention primitives for private bridge state.

The cleaner deliberately distinguishes ephemeral storage from authoritative
security/recovery knowledge.  It may reclaim only state whose terminality and
lack of references can be proven while holding the same serialization boundary
used by the live operation.

Never reclaimed by this module:
- write idempotency rows (including COMMITTED/AMBIGUOUS tombstones),
- consumed previews referenced by idempotency rows,
- rate-limit/high-water knowledge,
- audit history,
- non-terminal or retryable download checkpoints,
- unleased archive staging files whose ownership/liveness is ambiguous.
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
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


class RetentionSafetyError(RuntimeError):
    """Retention could not prove that a destructive action was safe."""

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
        """Release a live lease; normal builders remove the marker on completion."""
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
    """Machine-readable classification used by tests/docs/maintenance tooling."""
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
    """Inventory an audit sink without deleting/truncating authoritative history."""
    candidate = Path(path)
    size = 0
    exists = candidate.exists()
    if exists:
        info = os.lstat(candidate)
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise RetentionSafetyError("unsafe_audit_topology")
        size = int(info.st_size)
    return {
        "exists": exists,
        "bytes": size,
        "classification": "AUTHORITATIVE_PROTECTED",
        "automatic_delete": False,
    }


def _validate_now(now: int | None) -> int:
    value = int(time.time() if now is None else now)
    if value < 0:
        raise RetentionSafetyError("invalid_retention_clock")
    return value


def _validate_age(seconds: int) -> int:
    if isinstance(seconds, bool):
        raise RetentionSafetyError("invalid_retention_age")
    value = int(seconds)
    if value < 0 or value > _MAX_RETENTION_SECONDS:
        raise RetentionSafetyError("invalid_retention_age")
    return value


def _validate_batch(limit: int) -> int:
    if isinstance(limit, bool):
        raise RetentionSafetyError("invalid_retention_batch")
    value = int(limit)
    if not 1 <= value <= _MAX_BATCH:
        raise RetentionSafetyError("invalid_retention_batch")
    return value


def _ensure_retention_table(con: sqlite3.Connection) -> None:
    con.execute(
        f"CREATE TABLE IF NOT EXISTS {_RETENTION_TABLE} ("
        "namespace TEXT PRIMARY KEY, high_water INTEGER NOT NULL CHECK(high_water>=0))"
    )


def _advance_high_water(con: sqlite3.Connection, *, namespace: str, now: int) -> None:
    """Persist wall-clock high water in the same transaction as cleanup decisions."""
    _ensure_retention_table(con)
    row = con.execute(
        f"SELECT high_water FROM {_RETENTION_TABLE} WHERE namespace=?",
        (namespace,),
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


@contextmanager
def _sqlite(path: str | Path) -> Iterator[sqlite3.Connection]:
    con = sqlite3.connect(str(Path(path)), timeout=8.0, isolation_level=None)
    try:
        con.execute("PRAGMA foreign_keys=ON")
        con.execute("PRAGMA journal_mode=WAL")
        con.execute("PRAGMA synchronous=FULL")
        con.execute("PRAGMA busy_timeout=8000")
        yield con
    finally:
        con.close()


def _require_tables(con: sqlite3.Connection, *names: str) -> None:
    existing = {
        str(row[0])
        for row in con.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
    }
    if any(name not in existing for name in names):
        raise RetentionSafetyError("retention_schema_mismatch")


def cleanup_write_previews(
    db_path: str | Path,
    *,
    now: int | None = None,
    expired_grace_seconds: int = 86_400,
) -> CleanupResult:
    """Delete only expired, unconsumed previews with zero idempotency references.

    BEGIN IMMEDIATE races safely with preview/commit.  No idempotency row is ever
    deleted or modified by this operation.  A persistent high-water record makes
    clock rollback explicit rather than silently changing retention decisions.
    """
    ts = _validate_now(now)
    grace = _validate_age(expired_grace_seconds)
    cutoff = ts - grace
    with _sqlite(db_path) as con:
        con.execute("BEGIN IMMEDIATE")
        try:
            _require_tables(con, "previews", "idempotency")
            _advance_high_water(con, namespace="write_preview_cleanup", now=ts)
            before_idempotency = int(con.execute("SELECT COUNT(*) FROM idempotency").fetchone()[0])
            before_protected = int(
                con.execute(
                    "SELECT COUNT(*) FROM previews p WHERE EXISTS "
                    "(SELECT 1 FROM idempotency i WHERE i.preview_id=p.preview_id)"
                ).fetchone()[0]
            )
            cur = con.execute(
                "DELETE FROM previews "
                "WHERE expires_at < ? AND consumed_at IS NULL "
                "AND NOT EXISTS (SELECT 1 FROM idempotency i WHERE i.preview_id=previews.preview_id)",
                (cutoff,),
            )
            after_idempotency = int(con.execute("SELECT COUNT(*) FROM idempotency").fetchone()[0])
            if before_idempotency != after_idempotency:
                raise RetentionSafetyError("idempotency_retention_violation")
            con.execute("COMMIT")
            return CleanupResult(deleted=max(0, int(cur.rowcount)), protected=before_protected)
        except Exception:
            if con.in_transaction:
                con.execute("ROLLBACK")
            raise


def _checkpoint_payload(row: sqlite3.Row | tuple[Any, ...]) -> dict[str, Any]:
    raw_text = str(row[0])
    stored_digest = str(row[1])
    actual = hashlib.sha256(raw_text.encode("utf-8")).hexdigest()
    if not secrets_compare(actual, stored_digest):
        raise RetentionSafetyError("checkpoint_integrity_mismatch")
    try:
        payload = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        raise RetentionSafetyError("checkpoint_json_corrupt") from exc
    if not isinstance(payload, dict):
        raise RetentionSafetyError("checkpoint_json_corrupt")
    return payload


def secrets_compare(left: str, right: str) -> bool:
    # Avoid importing application modules or secret-bearing state into maintenance tooling.
    import hmac

    return hmac.compare_digest(left, right)


def _checkpoint_terminal(payload: dict[str, Any]) -> bool:
    """True only when resume cannot legitimately make additional progress."""
    required = {"job_id", "status", "items", "results", "failures"}
    if not required.issubset(payload):
        raise RetentionSafetyError("checkpoint_shape_corrupt")
    items = payload.get("items")
    results = payload.get("results")
    failures = payload.get("failures")
    if not isinstance(items, list) or not isinstance(results, dict) or not isinstance(failures, dict):
        raise RetentionSafetyError("checkpoint_shape_corrupt")
    item_ids: set[str] = set()
    for raw in items:
        if not isinstance(raw, dict) or not isinstance(raw.get("item_id"), str) or not raw["item_id"]:
            raise RetentionSafetyError("checkpoint_shape_corrupt")
        if raw["item_id"] in item_ids:
            raise RetentionSafetyError("checkpoint_shape_corrupt")
        item_ids.add(raw["item_id"])
    if not item_ids or not set(results).issubset(item_ids) or not set(failures).issubset(item_ids):
        raise RetentionSafetyError("checkpoint_shape_corrupt")
    status = payload.get("status")
    if status == "complete":
        return set(results) == item_ids and not failures
    if status not in {"partial", "failed"}:
        return False
    unresolved = item_ids - set(results)
    if not unresolved:
        return False
    for item_id in unresolved:
        info = failures.get(item_id)
        if not isinstance(info, dict) or info.get("retryable") is not False:
            return False
    return True


def _safe_lock_dir(path: str | Path) -> Path:
    directory = Path(path)
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    info = os.lstat(directory)
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise RetentionSafetyError("unsafe_lock_directory")
    if hasattr(os, "geteuid") and info.st_uid != os.geteuid():
        raise RetentionSafetyError("unsafe_lock_directory_owner")
    if stat.S_IMODE(info.st_mode) != 0o700:
        raise RetentionSafetyError("unsafe_lock_directory_mode")
    return directory


def _job_lock_name(job_id: str) -> str:
    return hashlib.sha256(job_id.encode("utf-8", "strict")).hexdigest() + ".lock"


@contextmanager
def _cleanup_job_lock(lock_dir: Path, job_id: str) -> Iterator[tuple[int, Path]]:
    lock_path = lock_dir / _job_lock_name(job_id)
    flags = os.O_CREAT | os.O_RDWR | int(getattr(os, "O_NOFOLLOW", 0)) | int(getattr(os, "O_CLOEXEC", 0))
    try:
        fd = os.open(lock_path, flags, 0o600)
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
        yield fd, lock_path
    finally:
        if acquired:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            except OSError:
                pass
        os.close(fd)


def _unlink_if_same_inode(path: Path, fd: int) -> None:
    """Unlink only the exact descriptor-bound leaf; replacement is fail-closed."""
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


def _checkpoint_candidates(
    db_path: str | Path,
    *,
    now: int,
    min_age_seconds: int,
    limit: int,
) -> list[str]:
    cutoff = now - min_age_seconds
    with _sqlite(db_path) as con:
        con.execute("BEGIN IMMEDIATE")
        try:
            _require_tables(con, "download_jobs")
            _advance_high_water(con, namespace="download_checkpoint_cleanup", now=now)
            rows = con.execute(
                "SELECT job_id FROM download_jobs WHERE updated_at < ? ORDER BY updated_at,job_id LIMIT ?",
                (cutoff, limit),
            ).fetchall()
            con.execute("COMMIT")
            return [str(row[0]) for row in rows]
        except Exception:
            if con.in_transaction:
                con.execute("ROLLBACK")
            raise


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
            payload = _checkpoint_payload((row["payload_json"], row["payload_sha256"]))
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


def cleanup_download_checkpoints(
    checkpoint_db_path: str | Path,
    lock_dir: str | Path,
    *,
    now: int | None = None,
    min_age_seconds: int = 7 * 24 * 60 * 60,
    max_jobs: int = 256,
) -> CleanupResult:
    """Reclaim semantically terminal download checkpoints under their job locks.

    A job is protected if it is pending/running, has any unresolved retryable
    failure, is too young, or cannot be locked without blocking.  On successful
    deletion its now-useless empty lock leaf is unlinked while still held.
    """
    ts = _validate_now(now)
    age = _validate_age(min_age_seconds)
    limit = _validate_batch(max_jobs)
    directory = _safe_lock_dir(lock_dir)
    candidates = _checkpoint_candidates(checkpoint_db_path, now=ts, min_age_seconds=age, limit=limit)
    deleted = busy = protected = corrupt = 0
    for job_id in candidates:
        try:
            with _cleanup_job_lock(directory, job_id) as (fd, lock_path):
                try:
                    removed = _delete_checkpoint_if_terminal(
                        checkpoint_db_path,
                        job_id=job_id,
                        now=ts,
                        min_age_seconds=age,
                    )
                except RetentionSafetyError:
                    corrupt += 1
                    continue
                if not removed:
                    protected += 1
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
    return name.startswith("archive_") and name.endswith(".zip.part") and all(
        ch.isalnum() or ch in {"_", ".", "-"} for ch in name
    )


def create_staging_lease(part_path: str | Path, *, now: int | None = None) -> StagingLease:
    """Create and exclusively hold a crash-releasable lease for a staging part."""
    ts = _validate_now(now)
    part = Path(part_path)
    if not _safe_stage_name(part.name):
        raise RetentionSafetyError("invalid_staging_name")
    part.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    marker = part.with_name(part.name + ".lease")
    flags = os.O_CREAT | os.O_EXCL | os.O_RDWR | int(getattr(os, "O_NOFOLLOW", 0)) | int(getattr(os, "O_CLOEXEC", 0))
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
        os.write(fd, payload)
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
    if payload["schema"] != _LEASE_SCHEMA or not isinstance(payload["part"], str) or not _safe_stage_name(payload["part"]):
        raise RetentionSafetyError("staging_lease_corrupt")
    created = payload["created_at"]
    if isinstance(created, bool) or not isinstance(created, int) or created < 0:
        raise RetentionSafetyError("staging_lease_corrupt")
    return marker.parent / payload["part"], created


def cleanup_leased_archive_staging(
    staging_dir: str | Path,
    ledger_db_path: str | Path,
    *,
    now: int | None = None,
    min_age_seconds: int = 24 * 60 * 60,
    max_markers: int = 256,
) -> CleanupResult:
    """Delete only old archive parts carrying a valid, unlocked lease marker.

    Legacy/unleased ``*.part`` files are deliberately untouched: without a lease
    there is no race-proof evidence that another process is not actively writing.
    """
    ts = _validate_now(now)
    age = _validate_age(min_age_seconds)
    limit = _validate_batch(max_markers)
    directory = Path(staging_dir)
    if not directory.exists():
        return CleanupResult(deleted=0)
    dir_info = os.lstat(directory)
    if stat.S_ISLNK(dir_info.st_mode) or not stat.S_ISDIR(dir_info.st_mode):
        raise RetentionSafetyError("unsafe_staging_directory")
    with _sqlite(ledger_db_path) as con:
        con.execute("BEGIN IMMEDIATE")
        try:
            _advance_high_water(con, namespace="archive_staging_cleanup", now=ts)
            con.execute("COMMIT")
        except Exception:
            if con.in_transaction:
                con.execute("ROLLBACK")
            raise

    markers = sorted(directory.glob("archive_*.zip.part.lease"))[:limit]
    deleted = busy = protected = corrupt = 0
    cutoff = ts - age
    for marker in markers:
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
            except RetentionSafetyError:
                corrupt += 1
                continue
            if created > ts:
                corrupt += 1
                continue
            if created >= cutoff:
                protected += 1
                continue
            if part.exists() or part.is_symlink():
                try:
                    info = os.lstat(part)
                except OSError:
                    corrupt += 1
                    continue
                if (
                    stat.S_ISLNK(info.st_mode)
                    or not stat.S_ISREG(info.st_mode)
                    or info.st_nlink != 1
                    or (hasattr(os, "geteuid") and info.st_uid != os.geteuid())
                ):
                    corrupt += 1
                    continue
                os.unlink(part)
            _unlink_if_same_inode(marker, fd)
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
    parser.add_argument("--now", type=int, default=None, help="test/controlled wall clock; defaults to current time")
    sub = parser.add_subparsers(dest="command", required=True)

    writes = sub.add_parser("writes", help="delete only expired unreferenced preview rows")
    writes.add_argument("db")
    writes.add_argument("--grace", type=int, default=86_400)

    downloads = sub.add_parser("downloads", help="delete aged terminal checkpoints under job locks")
    downloads.add_argument("db")
    downloads.add_argument("lock_dir")
    downloads.add_argument("--age", type=int, default=7 * 24 * 60 * 60)
    downloads.add_argument("--limit", type=int, default=256)

    staging = sub.add_parser("staging", help="delete only aged lease-managed archive staging")
    staging.add_argument("directory")
    staging.add_argument("ledger_db")
    staging.add_argument("--age", type=int, default=24 * 60 * 60)
    staging.add_argument("--limit", type=int, default=256)

    policy = sub.add_parser("policy", help="print immutable retention classifications")
    del policy
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "writes":
        result: Any = cleanup_write_previews(args.db, now=args.now, expired_grace_seconds=args.grace).as_dict()
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


if __name__ == "__main__":  # pragma: no cover - exercised through module/CLI smoke
    raise SystemExit(main())
