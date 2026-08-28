# -*- coding: utf-8 -*-
"""Process-loss hardening candidate for Telegram write idempotency state.

This isolated specialist layer composes the canonical PersistentWriteStore without
performing Telegram I/O. It adds serialized first-use schema bootstrap, a persistent
wall-clock high-water guard, a hash-only process-shared commit marker/flock held
across the external effect boundary, guarded dead-owner CALLING recovery, and
monotonic terminal-state handling after late local persistence failures.

Only hashes, protocol labels and integer timestamps are persisted by this layer.
It never stores credentials, Telegram content, preview tokens, idempotency keys or
private file contents in guard metadata.
"""
from __future__ import annotations

import fcntl
import json
import os
import sqlite3
import stat
import time
from pathlib import Path
from typing import Any, Callable, Mapping

from ops.write_safety import (
    CommitResult,
    PersistentWriteStore,
    PreviewEnvelope,
    ReconciliationRequired,
    TransactionState,
    WriteSafetyError,
)


_PROTOCOL = "v1"
_CLOCK_KEY = "fault_hardened_write_clock_high_water"
_MARKER_PREFIX = "fault_hardened_calling_guard:"


def _owned_by_current_user(st: os.stat_result) -> bool:
    return not hasattr(os, "geteuid") or st.st_uid == os.geteuid()


def _validate_lock_root(path: Path) -> None:
    try:
        st = os.lstat(path)
    except OSError as exc:
        raise WriteSafetyError("write_guard_lock_root_unavailable", status=503) from exc
    if (
        stat.S_ISLNK(st.st_mode)
        or not stat.S_ISDIR(st.st_mode)
        or not _owned_by_current_user(st)
        or stat.S_IMODE(st.st_mode) != 0o700
    ):
        raise WriteSafetyError("write_guard_lock_root_unsafe", status=503)


def _ensure_lock_root(path: Path) -> None:
    try:
        path.mkdir(mode=0o700, parents=False, exist_ok=False)
    except FileExistsError:
        pass
    except OSError as exc:
        raise WriteSafetyError("write_guard_lock_root_unavailable", status=503) from exc
    _validate_lock_root(path)


def _open_lock(path: Path, *, nonblocking: bool) -> int | None:
    flags = os.O_RDWR | os.O_CREAT
    flags |= int(getattr(os, "O_CLOEXEC", 0))
    flags |= int(getattr(os, "O_NOFOLLOW", 0))
    try:
        fd = os.open(path, flags, 0o600)
    except OSError as exc:
        raise WriteSafetyError("write_guard_lock_unavailable", status=503) from exc
    try:
        st = os.fstat(fd)
        if (
            not stat.S_ISREG(st.st_mode)
            or not _owned_by_current_user(st)
            or st.st_nlink != 1
            or stat.S_IMODE(st.st_mode) != 0o600
            or st.st_size != 0
        ):
            raise WriteSafetyError("write_guard_lock_unsafe", status=503)
        mode = fcntl.LOCK_EX | (fcntl.LOCK_NB if nonblocking else 0)
        try:
            fcntl.flock(fd, mode)
        except BlockingIOError:
            os.close(fd)
            return None
        return fd
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        raise


def _close_lock(fd: int | None) -> None:
    if fd is None:
        return
    try:
        fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


class FaultHardenedPersistentWriteStore(PersistentWriteStore):
    """PersistentWriteStore with process-loss and clock guards.

    This is an isolated integration candidate, not a production deployment switch.
    Canonical payload/action semantics remain in the parent class.
    """

    def __init__(
        self,
        db_path: str | Path,
        *,
        preview_ttl_seconds: int = 300,
        busy_timeout_ms: int = 5000,
        backward_skew_seconds: int = 2,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if isinstance(backward_skew_seconds, bool) or not 0 <= backward_skew_seconds <= 30:
            raise ValueError("bounded write clock skew required")
        path = Path(db_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        self._clock = clock
        self._backward_skew_seconds = int(backward_skew_seconds)
        self._schema_lock_path = path.parent / f".{path.name}.schema.lock"
        self._commit_lock_root = path.parent / ".write-commit-locks"

        # Serialize the canonical SELECT->INSERT schema-version decision without
        # changing the persisted table schema. Kernel flock ownership dies with the
        # process; the empty lock inode may safely remain.
        schema_fd = _open_lock(self._schema_lock_path, nonblocking=False)
        try:
            super().__init__(
                path,
                preview_ttl_seconds=preview_ttl_seconds,
                busy_timeout_ms=busy_timeout_ms,
            )
        finally:
            _close_lock(schema_fd)
        _ensure_lock_root(self._commit_lock_root)

    @staticmethod
    def _marker_key(key_hash: str) -> str:
        if len(key_hash) != 64 or any(ch not in "0123456789abcdef" for ch in key_hash):
            raise WriteSafetyError("invalid_write_guard_key", status=503)
        return f"{_MARKER_PREFIX}{key_hash}"

    def _lock_path(self, key_hash: str) -> Path:
        self._marker_key(key_hash)
        return self._commit_lock_root / f"{key_hash}.lock"

    def _observe_clock(self, now: int | None, *, recovery: bool = False) -> int:
        ts = int(self._clock() if now is None else now)
        if ts < 0:
            raise WriteSafetyError("invalid_write_clock", status=503)
        with self._connect() as con:
            con.execute("BEGIN IMMEDIATE")
            try:
                row = con.execute("SELECT value FROM meta WHERE key=?", (_CLOCK_KEY,)).fetchone()
                if row is None:
                    con.execute("INSERT INTO meta(key,value) VALUES(?,?)", (_CLOCK_KEY, str(ts)))
                    high_water = ts
                else:
                    try:
                        high_water = int(row["value"])
                    except (TypeError, ValueError) as exc:
                        raise WriteSafetyError("write_clock_state_corrupt", status=503) from exc
                    if high_water < 0:
                        raise WriteSafetyError("write_clock_state_corrupt", status=503)
                    if not recovery and ts + self._backward_skew_seconds < high_water:
                        raise WriteSafetyError("write_clock_moved_backward", status=503)
                    if ts > high_water:
                        high_water = ts
                        con.execute("UPDATE meta SET value=? WHERE key=?", (str(ts), _CLOCK_KEY))
                con.commit()
                return max(ts, high_water) if recovery else ts
            except Exception:
                if con.in_transaction:
                    con.rollback()
                raise

    def create_preview(
        self,
        action: Any,
        payload: Mapping[str, Any],
        *,
        now: int | None = None,
        ttl_seconds: int | None = None,
    ) -> PreviewEnvelope:
        ts = self._observe_clock(now)
        return super().create_preview(action, payload, now=ts, ttl_seconds=ttl_seconds)

    def _state_and_marker(self, con: sqlite3.Connection, key_hash: str) -> tuple[str | None, bool]:
        state_row = con.execute(
            "SELECT state FROM idempotency WHERE key_hash=?", (key_hash,)
        ).fetchone()
        marker_row = con.execute(
            "SELECT value FROM meta WHERE key=?", (self._marker_key(key_hash),)
        ).fetchone()
        state = str(state_row["state"]) if state_row is not None else None
        return state, marker_row is not None

    def _reconcile_dead_owner_before_commit(self, key_hash: str, *, now: int) -> None:
        """Classify only a marker whose cooperating flock owner is provably gone."""
        marker_key = self._marker_key(key_hash)
        with self._connect() as con:
            con.execute("BEGIN IMMEDIATE")
            try:
                state, marker = self._state_and_marker(con, key_hash)
                if not marker:
                    con.commit()
                    return
                if state == TransactionState.CALLING.value:
                    con.execute(
                        "UPDATE idempotency SET state=?,updated_at=? "
                        "WHERE key_hash=? AND state=?",
                        (
                            TransactionState.AMBIGUOUS.value,
                            now,
                            key_hash,
                            TransactionState.CALLING.value,
                        ),
                    )
                    con.execute("DELETE FROM meta WHERE key=?", (marker_key,))
                    con.commit()
                    raise ReconciliationRequired()
                # Dead owner before CALLING is retry-safe; terminal rows only need
                # marker cleanup. Idempotency tombstones are never deleted here.
                con.execute("DELETE FROM meta WHERE key=?", (marker_key,))
                con.commit()
            except ReconciliationRequired:
                raise
            except Exception:
                if con.in_transaction:
                    con.rollback()
                raise

    def _arm_marker(self, key_hash: str, *, now: int) -> None:
        with self._connect() as con:
            con.execute("BEGIN IMMEDIATE")
            try:
                con.execute(
                    "INSERT INTO meta(key,value) VALUES(?,?) "
                    "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                    (self._marker_key(key_hash), f"{_PROTOCOL}:{now}"),
                )
                con.commit()
            except Exception:
                if con.in_transaction:
                    con.rollback()
                raise

    def _clear_marker_if_terminal(self, key_hash: str) -> None:
        marker_key = self._marker_key(key_hash)
        with self._connect() as con:
            con.execute("BEGIN IMMEDIATE")
            try:
                state, marker = self._state_and_marker(con, key_hash)
                if marker and state != TransactionState.CALLING.value:
                    con.execute("DELETE FROM meta WHERE key=?", (marker_key,))
                con.commit()
            except Exception:
                if con.in_transaction:
                    con.rollback()
                raise

    def _record_ambiguous(self, idempotency_key: str, fingerprint: str, *, now: int) -> None:
        """Never downgrade a durable terminal state after a late local failure."""
        key_hash = self._idempotency_hash(idempotency_key)
        with self._connect() as con:
            con.execute("BEGIN IMMEDIATE")
            try:
                row = con.execute("SELECT * FROM idempotency WHERE key_hash=?", (key_hash,)).fetchone()
                if row is None or row["request_fingerprint"] != fingerprint:
                    raise WriteSafetyError("idempotency_state_missing", status=409)
                state = str(row["state"])
                if state == TransactionState.COMMITTED.value:
                    # A local fault may happen after SQLite durably commits. Preserve
                    # the cached result so exact replay cannot become a resend.
                    if not row["result_json"]:
                        raise ReconciliationRequired()
                    try:
                        parsed = json.loads(row["result_json"])
                    except Exception as exc:
                        raise ReconciliationRequired() from exc
                    if not isinstance(parsed, dict):
                        raise ReconciliationRequired()
                    con.commit()
                    return
                if state in {TransactionState.AMBIGUOUS.value, TransactionState.FAILED_SAFE.value}:
                    con.commit()
                    return
                con.execute(
                    "UPDATE idempotency SET state=?,updated_at=? WHERE key_hash=?",
                    (TransactionState.AMBIGUOUS.value, now, key_hash),
                )
                con.commit()
            except Exception:
                if con.in_transaction:
                    con.rollback()
                raise

    def commit(
        self,
        preview_token: str,
        *,
        expected_action: Any,
        idempotency_key: str,
        external_write: Callable[[dict[str, Any]], Mapping[str, Any]],
        now: int | None = None,
    ) -> CommitResult:
        ts = self._observe_clock(now)
        key_hash = self._idempotency_hash(idempotency_key)
        fd = _open_lock(self._lock_path(key_hash), nonblocking=True)
        if fd is None:
            raise WriteSafetyError("write_in_progress", status=409)
        try:
            self._reconcile_dead_owner_before_commit(key_hash, now=ts)
            self._arm_marker(key_hash, now=ts)
            try:
                return super().commit(
                    preview_token,
                    expected_action=expected_action,
                    idempotency_key=idempotency_key,
                    external_write=external_write,
                    now=ts,
                )
            finally:
                # Process death skips this block and leaves a durable hash-only
                # crash witness. Ordinary terminal outcomes clear it.
                self._clear_marker_if_terminal(key_hash)
        finally:
            _close_lock(fd)

    def recover_orphaned_calling(self, *, now: int | None = None) -> dict[str, int]:
        """Recover only marker-owned CALLING rows whose process flock is free."""
        ts = self._observe_clock(now, recovery=True)
        with self._connect() as con:
            rows = con.execute(
                "SELECT key FROM meta WHERE key LIKE ? ORDER BY key",
                (f"{_MARKER_PREFIX}%",),
            ).fetchall()
        scanned = recovered = active = cleared = 0
        for row in rows:
            marker_key = str(row["key"])
            key_hash = marker_key[len(_MARKER_PREFIX) :]
            self._marker_key(key_hash)
            scanned += 1
            fd = _open_lock(self._lock_path(key_hash), nonblocking=True)
            if fd is None:
                active += 1
                continue
            try:
                with self._connect() as con:
                    con.execute("BEGIN IMMEDIATE")
                    try:
                        state, marker = self._state_and_marker(con, key_hash)
                        if not marker:
                            con.commit()
                            continue
                        if state == TransactionState.CALLING.value:
                            con.execute(
                                "UPDATE idempotency SET state=?,updated_at=? "
                                "WHERE key_hash=? AND state=?",
                                (
                                    TransactionState.AMBIGUOUS.value,
                                    ts,
                                    key_hash,
                                    TransactionState.CALLING.value,
                                ),
                            )
                            recovered += 1
                        else:
                            cleared += 1
                        con.execute("DELETE FROM meta WHERE key=?", (marker_key,))
                        con.commit()
                    except Exception:
                        if con.in_transaction:
                            con.rollback()
                        raise
            finally:
                _close_lock(fd)
        return {
            "markers_scanned": scanned,
            "calling_recovered": recovered,
            "active_busy": active,
            "stale_markers_cleared": cleared,
        }


__all__ = ["FaultHardenedPersistentWriteStore"]
