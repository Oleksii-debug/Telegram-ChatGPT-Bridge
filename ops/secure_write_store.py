# -*- coding: utf-8 -*-
"""Owner-private, concurrency-safe persistent write state.

This runtime-facing store retains the canonical PersistentWriteStore semantics,
adds fail-closed POSIX SQLite topology validation from the reviewed DEV05 line,
and serializes both schema bootstrap and SQLite sidecar lifecycle across Passenger
workers. The process-shared lock is state-local, owner-private and never stores
private content.
"""
from __future__ import annotations

import fcntl
import os
import sqlite3
import stat
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from ops.write_safety import PersistentWriteStore


class WriteStateSecurityError(RuntimeError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _lexical(path: Path) -> Path:
    return Path(os.path.abspath(os.path.expanduser(str(path))))


def _owned_by_current_user(st: os.stat_result) -> bool:
    return not hasattr(os, "geteuid") or st.st_uid == os.geteuid()


def _validate_private_directory(path: Path) -> Path:
    path = _lexical(path)
    if not path.exists() or path.is_symlink():
        raise WriteStateSecurityError("write_state_parent_missing_or_unsafe")
    try:
        st = os.lstat(path)
    except OSError as exc:
        raise WriteStateSecurityError("write_state_parent_unavailable") from exc
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        raise WriteStateSecurityError("write_state_parent_not_directory")
    if Path(os.path.realpath(path)) != path:
        raise WriteStateSecurityError("write_state_parent_alias_unsafe")
    if not _owned_by_current_user(st):
        raise WriteStateSecurityError("write_state_parent_wrong_owner")
    if stat.S_IMODE(st.st_mode) != 0o700:
        raise WriteStateSecurityError("write_state_parent_mode_unsafe")
    return path


def _validate_private_regular(path: Path, *, code_prefix: str) -> os.stat_result:
    try:
        st = os.lstat(path)
    except OSError as exc:
        raise WriteStateSecurityError(f"{code_prefix}_unavailable") from exc
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
        raise WriteStateSecurityError(f"{code_prefix}_type_unsafe")
    if not _owned_by_current_user(st):
        raise WriteStateSecurityError(f"{code_prefix}_wrong_owner")
    if st.st_nlink != 1:
        raise WriteStateSecurityError(f"{code_prefix}_hardlink_unsafe")
    if stat.S_IMODE(st.st_mode) != 0o600:
        raise WriteStateSecurityError(f"{code_prefix}_mode_unsafe")
    return st


def _secure_create_database(path: Path) -> None:
    if path.exists() or path.is_symlink():
        _validate_private_regular(path, code_prefix="write_state_database")
        return
    flags = os.O_RDWR | os.O_CREAT | os.O_EXCL
    flags |= int(getattr(os, "O_NOFOLLOW", 0))
    flags |= int(getattr(os, "O_CLOEXEC", 0))
    try:
        fd = os.open(path, flags, 0o600)
    except FileExistsError:
        _validate_private_regular(path, code_prefix="write_state_database")
        return
    except OSError as exc:
        raise WriteStateSecurityError("write_state_database_create_failed") from exc
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
            raise WriteStateSecurityError("write_state_database_type_unsafe")
        if not _owned_by_current_user(st):
            raise WriteStateSecurityError("write_state_database_wrong_owner")
        if stat.S_IMODE(st.st_mode) != 0o600:
            raise WriteStateSecurityError("write_state_database_mode_unsafe")
    finally:
        os.close(fd)
    _validate_private_regular(path, code_prefix="write_state_database")


class SecurePersistentWriteStore(PersistentWriteStore):
    _SIDECAR_SUFFIXES = ("-wal", "-shm")

    def __init__(self, db_path: str | Path, **kwargs):
        path = _lexical(Path(db_path))
        parent = _validate_private_directory(path.parent)
        if path.parent != parent:
            raise WriteStateSecurityError("write_state_database_path_unsafe")
        _secure_create_database(path)
        self._secure_database_path = path
        self._runtime_lock_path = Path(str(path) + ".runtime.lock")
        super().__init__(path, **kwargs)
        self._validate_database_and_sidecars(strict_existing=True)

    def _sidecar_paths(self) -> tuple[Path, ...]:
        return tuple(Path(str(self.db_path) + suffix) for suffix in self._SIDECAR_SUFFIXES)

    @contextmanager
    def _runtime_connection_lock(self) -> Iterator[None]:
        """Serialize SQLite connection/sidecar lifecycle across Passenger workers.

        WAL/SHM files are created and removed by SQLite itself. Validating those
        paths concurrently with another process opening/closing the same database
        creates a TOCTOU window. A separate descriptor-bound flock closes that
        window without trusting pathnames after lock acquisition.
        """
        _validate_private_directory(self.db_path.parent)
        flags = os.O_RDWR | os.O_CREAT
        flags |= int(getattr(os, "O_NOFOLLOW", 0))
        flags |= int(getattr(os, "O_CLOEXEC", 0))
        try:
            fd = os.open(self._runtime_lock_path, flags, 0o600)
        except OSError as exc:
            raise WriteStateSecurityError("write_state_runtime_lock_unavailable") from exc
        locked = False
        try:
            before = os.fstat(fd)
            if (
                not stat.S_ISREG(before.st_mode)
                or not _owned_by_current_user(before)
                or before.st_nlink != 1
                or stat.S_IMODE(before.st_mode) != 0o600
                or before.st_size != 0
            ):
                raise WriteStateSecurityError("write_state_runtime_lock_unsafe")
            fcntl.flock(fd, fcntl.LOCK_EX)
            locked = True
            after = os.fstat(fd)
            path_st = os.lstat(self._runtime_lock_path)
            if (
                after.st_dev != before.st_dev
                or after.st_ino != before.st_ino
                or path_st.st_dev != after.st_dev
                or path_st.st_ino != after.st_ino
                or stat.S_ISLNK(path_st.st_mode)
                or not stat.S_ISREG(path_st.st_mode)
                or not _owned_by_current_user(path_st)
                or path_st.st_nlink != 1
                or stat.S_IMODE(path_st.st_mode) != 0o600
                or path_st.st_size != 0
            ):
                raise WriteStateSecurityError("write_state_runtime_lock_binding_unsafe")
            yield
        except WriteStateSecurityError:
            raise
        except OSError as exc:
            raise WriteStateSecurityError("write_state_runtime_lock_unavailable") from exc
        finally:
            if locked:
                try:
                    fcntl.flock(fd, fcntl.LOCK_UN)
                except OSError:
                    pass
            os.close(fd)

    def _validate_database_and_sidecars(self, *, strict_existing: bool) -> None:
        _validate_private_directory(self.db_path.parent)
        _validate_private_regular(self.db_path, code_prefix="write_state_database")
        for sidecar in self._sidecar_paths():
            if not (sidecar.exists() or sidecar.is_symlink()):
                continue
            try:
                st = os.lstat(sidecar)
            except FileNotFoundError:
                # SQLite may remove a sidecar as the last connection closes.
                # Under _runtime_connection_lock no other managed worker can race
                # this validation, so disappearance here is an allowed no-object
                # state rather than a reason to weaken topology checks.
                continue
            except OSError as exc:
                raise WriteStateSecurityError("write_state_sidecar_unavailable") from exc
            if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
                raise WriteStateSecurityError("write_state_sidecar_type_unsafe")
            if not _owned_by_current_user(st):
                raise WriteStateSecurityError("write_state_sidecar_wrong_owner")
            if st.st_nlink != 1:
                raise WriteStateSecurityError("write_state_sidecar_hardlink_unsafe")
            if stat.S_IMODE(st.st_mode) != 0o600:
                if strict_existing:
                    raise WriteStateSecurityError("write_state_sidecar_mode_unsafe")
                try:
                    os.chmod(sidecar, 0o600)
                except OSError as exc:
                    raise WriteStateSecurityError("write_state_sidecar_mode_unsafe") from exc
                _validate_private_regular(sidecar, code_prefix="write_state_sidecar")

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        with self._runtime_connection_lock():
            self._validate_database_and_sidecars(strict_existing=True)
            try:
                con = sqlite3.connect(
                    str(self.db_path),
                    timeout=self.busy_timeout_ms / 1000.0,
                    isolation_level=None,
                )
            except sqlite3.Error as exc:
                raise WriteStateSecurityError("write_state_database_unavailable") from exc
            try:
                con.row_factory = sqlite3.Row
                con.execute("PRAGMA foreign_keys=ON")
                con.execute("PRAGMA journal_mode=WAL")
                con.execute("PRAGMA synchronous=FULL")
                con.execute(f"PRAGMA busy_timeout={self.busy_timeout_ms}")
                self._validate_database_and_sidecars(strict_existing=False)
                yield con
            except WriteStateSecurityError:
                raise
            except sqlite3.Error as exc:
                raise WriteStateSecurityError("write_state_database_unavailable") from exc
            finally:
                con.close()
                self._validate_database_and_sidecars(strict_existing=False)

    def _init_schema(self) -> None:
        """Serialize bootstrap and never adopt unversioned managed state."""
        statements = (
            "CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY,value TEXT NOT NULL)",
            "CREATE TABLE IF NOT EXISTS previews (preview_id TEXT PRIMARY KEY,token_hash TEXT NOT NULL UNIQUE,action TEXT NOT NULL,request_fingerprint TEXT NOT NULL,payload_json TEXT NOT NULL,created_at INTEGER NOT NULL,expires_at INTEGER NOT NULL,consumed_at INTEGER)",
            "CREATE TABLE IF NOT EXISTS idempotency (key_hash TEXT PRIMARY KEY,request_fingerprint TEXT NOT NULL,preview_id TEXT NOT NULL,state TEXT NOT NULL,result_json TEXT,created_at INTEGER NOT NULL,updated_at INTEGER NOT NULL,FOREIGN KEY(preview_id) REFERENCES previews(preview_id))",
            "CREATE INDEX IF NOT EXISTS idx_previews_expires ON previews(expires_at)",
            "CREATE INDEX IF NOT EXISTS idx_idempotency_state ON idempotency(state)",
        )
        managed_tables = {"meta", "previews", "idempotency"}
        with self._connect() as con:
            con.execute("BEGIN IMMEDIATE")
            try:
                existing = {
                    str(row["name"])
                    for row in con.execute(
                        "SELECT name FROM sqlite_master WHERE type='table' AND name IN ('meta','previews','idempotency')"
                    )
                }
                if "meta" in existing:
                    row = con.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()
                    if row is None or str(row["value"]) != str(self.SCHEMA_VERSION):
                        raise RuntimeError("unsupported write-store schema")
                elif existing & (managed_tables - {"meta"}):
                    # A non-empty managed schema without authoritative version
                    # metadata may be stale, partially restored or from another
                    # implementation. Never bless it as current by inserting a
                    # new version marker after the fact.
                    raise RuntimeError("unsupported write-store schema")

                for statement in statements:
                    con.execute(statement)
                if "meta" not in existing:
                    con.execute(
                        "INSERT INTO meta(key,value) VALUES('schema_version',?)",
                        (str(self.SCHEMA_VERSION),),
                    )
                con.commit()
            except Exception:
                if con.in_transaction:
                    con.rollback()
                raise


__all__ = ["SecurePersistentWriteStore", "WriteStateSecurityError"]