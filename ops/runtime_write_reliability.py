# -*- coding: utf-8 -*-
"""Process-shared write reliability primitives for production runtime composition.

The proxy wraps the secure canonical write store without replacing its preview or
idempotency semantics.  A per-idempotency flock spans the external effect,
a hash-only durable marker witnesses process death, and a persistent wall-clock
high-water protects expiry decisions across workers/restarts.
"""
from __future__ import annotations

import fcntl
import os
import sqlite3
import stat
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping

from ops.write_safety import CommitResult, PersistentWriteStore, PreviewEnvelope, ReconciliationRequired, WriteSafetyError

_PROTOCOL_VERSION = 1
_REQUIRED_IDEMPOTENCY_COLUMNS = {
    "key_hash", "request_fingerprint", "preview_id", "state", "result_json", "created_at", "updated_at",
}


@dataclass(frozen=True)
class RecoveryReport:
    markers_scanned: int
    calling_recovered: int
    active_busy: int
    stale_markers_cleared: int
    reserved_released: int


class PersistentWriteClock:
    def __init__(self, store: PersistentWriteStore, *, clock: Callable[[], float] = time.time, backward_skew_seconds: int = 2) -> None:
        if isinstance(backward_skew_seconds, bool) or not 0 <= backward_skew_seconds <= 30:
            raise ValueError("bounded write clock skew required")
        self.store = store
        self.clock = clock
        self.backward_skew_seconds = int(backward_skew_seconds)
        self._ensure_schema()

    def _ensure_schema(self) -> None:
        with self.store._connect() as con:
            con.execute("BEGIN IMMEDIATE")
            try:
                con.execute(
                    "CREATE TABLE IF NOT EXISTS runtime_write_clock ("
                    "singleton INTEGER PRIMARY KEY CHECK(singleton=1),"
                    "high_water INTEGER NOT NULL CHECK(high_water>=0))"
                )
                con.commit()
            except Exception:
                if con.in_transaction:
                    con.rollback()
                raise

    def observe(self, now: int | None = None) -> int:
        try:
            ts = int(self.clock() if now is None else now)
        except (TypeError, ValueError, OverflowError) as exc:
            raise WriteSafetyError("invalid_write_clock", status=503) from exc
        if ts < 0:
            raise WriteSafetyError("invalid_write_clock", status=503)
        with self.store._connect() as con:
            con.execute("BEGIN IMMEDIATE")
            try:
                row = con.execute("SELECT high_water FROM runtime_write_clock WHERE singleton=1").fetchone()
                if row is None:
                    con.execute("INSERT INTO runtime_write_clock(singleton,high_water) VALUES(1,?)", (ts,))
                else:
                    high_water = int(row["high_water"])
                    if ts + self.backward_skew_seconds < high_water:
                        raise WriteSafetyError("write_clock_moved_backward", status=503)
                    if ts > high_water:
                        con.execute("UPDATE runtime_write_clock SET high_water=? WHERE singleton=1", (ts,))
                con.commit()
                return ts
            except Exception:
                if con.in_transaction:
                    con.rollback()
                raise

    def recovery_timestamp(self, now: int | None = None) -> int:
        try:
            ts = int(self.clock() if now is None else now)
        except (TypeError, ValueError, OverflowError) as exc:
            raise WriteSafetyError("invalid_write_clock", status=503) from exc
        if ts < 0:
            raise WriteSafetyError("invalid_write_clock", status=503)
        with self.store._connect() as con:
            con.execute("BEGIN IMMEDIATE")
            try:
                row = con.execute("SELECT high_water FROM runtime_write_clock WHERE singleton=1").fetchone()
                if row is None:
                    con.execute("INSERT INTO runtime_write_clock(singleton,high_water) VALUES(1,?)", (ts,))
                    result = ts
                else:
                    high_water = int(row["high_water"])
                    result = max(ts, high_water)
                    if ts > high_water:
                        con.execute("UPDATE runtime_write_clock SET high_water=? WHERE singleton=1", (ts,))
                con.commit()
                return result
            except Exception:
                if con.in_transaction:
                    con.rollback()
                raise


class ProcessSharedCommitGuard:
    def __init__(self, store: PersistentWriteStore, *, lock_root: str | Path | None = None) -> None:
        self.store = store
        self.lock_root = Path(lock_root) if lock_root is not None else store.db_path.parent / ".write-operation-locks"
        self._lock_root_identity: tuple[int, int] | None = None
        self._prepare_lock_root()
        self._ensure_schema()

    def _prepare_lock_root(self) -> None:
        try:
            self.lock_root.mkdir(mode=0o700, parents=False, exist_ok=False)
        except FileExistsError:
            pass
        except OSError as exc:
            raise WriteSafetyError("write_guard_lock_root_unavailable", status=503) from exc
        try:
            st = os.lstat(self.lock_root)
        except OSError as exc:
            raise WriteSafetyError("write_guard_lock_root_unavailable", status=503) from exc
        if (
            stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode)
            or (hasattr(os, "geteuid") and st.st_uid != os.geteuid())
            or stat.S_IMODE(st.st_mode) != 0o700
        ):
            raise WriteSafetyError("write_guard_lock_root_unsafe", status=503)
        self._lock_root_identity = (int(st.st_dev), int(st.st_ino))

    def _open_lock_root(self) -> int:
        nofollow = getattr(os, "O_NOFOLLOW", None)
        directory = getattr(os, "O_DIRECTORY", None)
        if nofollow is None or directory is None or self._lock_root_identity is None:
            raise WriteSafetyError("write_guard_lock_root_unsafe", status=503)
        flags = os.O_RDONLY | int(directory) | int(nofollow) | int(getattr(os, "O_CLOEXEC", 0))
        try:
            fd = os.open(self.lock_root, flags)
        except OSError as exc:
            raise WriteSafetyError("write_guard_lock_root_unavailable", status=503) from exc
        try:
            st = os.fstat(fd)
            if (
                not stat.S_ISDIR(st.st_mode)
                or (hasattr(os, "geteuid") and st.st_uid != os.geteuid())
                or stat.S_IMODE(st.st_mode) != 0o700
                or (int(st.st_dev), int(st.st_ino)) != self._lock_root_identity
            ):
                raise WriteSafetyError("write_guard_lock_root_unsafe", status=503)
            return fd
        except Exception:
            try:
                os.close(fd)
            except OSError:
                pass
            raise

    def _ensure_schema(self) -> None:
        with self.store._connect() as con:
            con.execute("BEGIN IMMEDIATE")
            try:
                columns = {str(row[1]) for row in con.execute("PRAGMA table_info(idempotency)").fetchall()}
                if not _REQUIRED_IDEMPOTENCY_COLUMNS.issubset(columns):
                    raise WriteSafetyError("write_guard_schema_mismatch", status=503)
                con.execute(
                    "CREATE TABLE IF NOT EXISTS runtime_commit_guard ("
                    "key_hash TEXT PRIMARY KEY,protocol INTEGER NOT NULL,"
                    "armed_at INTEGER NOT NULL CHECK(armed_at>=0))"
                )
                con.commit()
            except Exception:
                if con.in_transaction:
                    con.rollback()
                raise

    @staticmethod
    def _validate_key_hash(key_hash: str) -> str:
        if len(key_hash) != 64 or any(ch not in "0123456789abcdef" for ch in key_hash):
            raise WriteSafetyError("invalid_write_guard_key", status=503)
        return key_hash

    def _key_hash(self, idempotency_key: str) -> str:
        return self._validate_key_hash(self.store._idempotency_hash(idempotency_key))

    def _open_lock(self, key_hash: str, *, fail_busy: bool) -> int | None:
        key_hash = self._validate_key_hash(key_hash)
        root_fd = self._open_lock_root()
        nofollow = getattr(os, "O_NOFOLLOW", None)
        if nofollow is None:
            os.close(root_fd)
            raise WriteSafetyError("write_guard_lock_unsafe", status=503)
        flags = os.O_RDWR | os.O_CREAT | int(getattr(os, "O_CLOEXEC", 0)) | int(nofollow)
        try:
            fd = os.open(f"{key_hash}.lock", flags, 0o600, dir_fd=root_fd)
        except OSError as exc:
            raise WriteSafetyError("write_guard_lock_unavailable", status=503) from exc
        finally:
            os.close(root_fd)
        try:
            st = os.fstat(fd)
            if (
                not stat.S_ISREG(st.st_mode)
                or (hasattr(os, "geteuid") and st.st_uid != os.geteuid())
                or st.st_nlink != 1 or stat.S_IMODE(st.st_mode) != 0o600 or st.st_size != 0
            ):
                raise WriteSafetyError("write_guard_lock_unsafe", status=503)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                os.close(fd)
                if fail_busy:
                    raise WriteSafetyError("write_in_progress", status=409) from None
                return None
            return fd
        except Exception:
            try:
                os.close(fd)
            except OSError:
                pass
            raise

    @staticmethod
    def _close_lock(fd: int | None) -> None:
        if fd is None:
            return
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)

    def _state_and_marker(self, con: sqlite3.Connection, key_hash: str) -> tuple[str | None, bool]:
        row = con.execute("SELECT state FROM idempotency WHERE key_hash=?", (key_hash,)).fetchone()
        marker = con.execute("SELECT protocol FROM runtime_commit_guard WHERE key_hash=?", (key_hash,)).fetchone()
        return (str(row["state"]) if row is not None else None, marker is not None)

    def _arm(self, key_hash: str, *, now: int) -> None:
        with self.store._connect() as con:
            con.execute("BEGIN IMMEDIATE")
            try:
                state, marker = self._state_and_marker(con, key_hash)
                if state == "CALLING":
                    if marker:
                        con.execute(
                            "UPDATE idempotency SET state='AMBIGUOUS',updated_at=? WHERE key_hash=? AND state='CALLING'",
                            (now, key_hash),
                        )
                        con.execute("DELETE FROM runtime_commit_guard WHERE key_hash=?", (key_hash,))
                        con.commit()
                        raise ReconciliationRequired()
                    con.commit()
                    raise ReconciliationRequired()
                if state in {"COMMITTED", "FAILED_SAFE", "AMBIGUOUS"}:
                    if marker:
                        con.execute("DELETE FROM runtime_commit_guard WHERE key_hash=?", (key_hash,))
                    con.commit()
                    return
                con.execute(
                    "INSERT INTO runtime_commit_guard(key_hash,protocol,armed_at) VALUES(?,?,?) "
                    "ON CONFLICT(key_hash) DO UPDATE SET protocol=excluded.protocol,armed_at=excluded.armed_at",
                    (key_hash, _PROTOCOL_VERSION, now),
                )
                con.commit()
            except ReconciliationRequired:
                raise
            except Exception:
                if con.in_transaction:
                    con.rollback()
                raise

    def _clear_terminal_marker(self, key_hash: str) -> None:
        with self.store._connect() as con:
            con.execute("BEGIN IMMEDIATE")
            try:
                state, marker = self._state_and_marker(con, key_hash)
                if marker and state != "CALLING":
                    con.execute("DELETE FROM runtime_commit_guard WHERE key_hash=?", (key_hash,))
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
        now: int,
    ) -> CommitResult:
        key_hash = self._key_hash(idempotency_key)
        fd = self._open_lock(key_hash, fail_busy=True)
        try:
            self._arm(key_hash, now=now)
            try:
                return self.store.commit(
                    preview_token,
                    expected_action=expected_action,
                    idempotency_key=idempotency_key,
                    external_write=external_write,
                    now=now,
                )
            finally:
                self._clear_terminal_marker(key_hash)
        finally:
            self._close_lock(fd)

    def recover_orphaned_calling(self, *, now: int) -> RecoveryReport:
        if isinstance(now, bool) or int(now) < 0:
            raise WriteSafetyError("invalid_write_clock", status=503)
        ts = int(now)
        with self.store._connect() as con:
            rows = con.execute("SELECT key_hash FROM runtime_commit_guard ORDER BY key_hash").fetchall()
        recovered = busy = cleared = reserved = 0
        for raw in rows:
            key_hash = self._validate_key_hash(str(raw["key_hash"]))
            fd = self._open_lock(key_hash, fail_busy=False)
            if fd is None:
                busy += 1
                continue
            try:
                with self.store._connect() as con:
                    con.execute("BEGIN IMMEDIATE")
                    try:
                        state, marker = self._state_and_marker(con, key_hash)
                        if not marker:
                            con.commit()
                            continue
                        if state == "CALLING":
                            con.execute(
                                "UPDATE idempotency SET state='AMBIGUOUS',updated_at=? WHERE key_hash=? AND state='CALLING'",
                                (ts, key_hash),
                            )
                            recovered += 1
                        elif state == "RESERVED":
                            reserved += 1
                        else:
                            cleared += 1
                        con.execute("DELETE FROM runtime_commit_guard WHERE key_hash=?", (key_hash,))
                        con.commit()
                    except Exception:
                        if con.in_transaction:
                            con.rollback()
                        raise
            finally:
                self._close_lock(fd)
        return RecoveryReport(len(rows), recovered, busy, cleared, reserved)


class RollbackSafeReliableWriteStoreProxy:
    def __init__(
        self,
        store: PersistentWriteStore,
        *,
        lock_root: str | Path | None = None,
        clock: Callable[[], float] = time.time,
        backward_skew_seconds: int = 2,
    ) -> None:
        self.store = store
        self.clock_guard = PersistentWriteClock(store, clock=clock, backward_skew_seconds=backward_skew_seconds)
        self.commit_guard = ProcessSharedCommitGuard(store, lock_root=lock_root)

    def create_preview(self, action: Any, payload: Mapping[str, Any], *, now: int | None = None, ttl_seconds: int | None = None) -> PreviewEnvelope:
        ts = self.clock_guard.observe(now)
        return self.store.create_preview(action, payload, now=ts, ttl_seconds=ttl_seconds)

    def commit(
        self,
        preview_token: str,
        *,
        expected_action: Any,
        idempotency_key: str,
        external_write: Callable[[dict[str, Any]], Mapping[str, Any]],
        now: int | None = None,
    ) -> CommitResult:
        ts = self.clock_guard.observe(now)
        return self.commit_guard.commit(
            preview_token,
            expected_action=expected_action,
            idempotency_key=idempotency_key,
            external_write=external_write,
            now=ts,
        )

    def recover_on_startup(self, *, now: int | None = None) -> RecoveryReport:
        return self.commit_guard.recover_orphaned_calling(now=self.clock_guard.recovery_timestamp(now))

    def __getattr__(self, name: str) -> Any:
        return getattr(self.store, name)


__all__ = [
    "PersistentWriteClock", "ProcessSharedCommitGuard", "RecoveryReport",
    "RollbackSafeReliableWriteStoreProxy",
]
