# -*- coding: utf-8 -*-
"""Descriptor-bound POSIX process lock for the personal Telegram session.

The lock contains no session material. Its namespace is bound to an already
opened owner-private parent directory; every path component is opened with
O_NOFOLLOW. Public parent/leaf bindings are rechecked after flock acquisition,
on explicit ``assert_intact()``, and before release.
"""
from __future__ import annotations

import os
import stat
import time
from pathlib import Path
from typing import Callable

from ops.posix_fs import (
    FilesystemSafetyError,
    open_directory_fd,
    open_regular_at,
    verify_directory_binding,
    verify_leaf_binding,
)

try:
    import fcntl
except ImportError:  # pragma: no cover - HOSTiQ production is POSIX
    fcntl = None


class SessionLockError(RuntimeError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


class TelegramSessionLock:
    def __init__(
        self,
        lock_path: str | Path,
        *,
        timeout_seconds: float = 5.0,
        poll_interval_seconds: float = 0.05,
        monotonic: Callable[[], float] = time.monotonic,
        sleeper: Callable[[float], None] = time.sleep,
    ):
        self.path = Path(os.path.abspath(os.path.expanduser(os.fspath(lock_path))))
        if timeout_seconds < 0 or timeout_seconds > 60:
            raise ValueError("bounded session-lock timeout required")
        if poll_interval_seconds <= 0 or poll_interval_seconds > 1:
            raise ValueError("bounded session-lock poll interval required")
        self.timeout_seconds = float(timeout_seconds)
        self.poll_interval_seconds = float(poll_interval_seconds)
        self.monotonic = monotonic
        self.sleeper = sleeper
        self._fd: int | None = None
        self._parent_fd: int | None = None
        self._parent_stat: os.stat_result | None = None

    def _open_private_parent(self) -> tuple[int, os.stat_result]:
        try:
            return open_directory_fd(
                self.path.parent,
                create_missing=True,
                create_mode=0o700,
                final_exact_mode=0o700,
            )
        except FilesystemSafetyError as exc:
            text = str(exc)
            if "mode" in text or "permissions" in text:
                raise SessionLockError("unsafe_session_lock_parent_mode") from exc
            if "owner" in text:
                raise SessionLockError("unsafe_session_lock_parent") from exc
            raise SessionLockError("unsafe_session_lock_parent") from exc

    @staticmethod
    def _map_leaf_error(exc: FilesystemSafetyError) -> SessionLockError:
        text = str(exc)
        if "hardlink" in text:
            return SessionLockError("unsafe_session_lock_hardlink")
        if "mode" in text:
            return SessionLockError("unsafe_session_lock_mode")
        if "empty" in text:
            return SessionLockError("unsafe_session_lock_nonempty")
        if "owner" in text or "regular" in text:
            return SessionLockError("unsafe_session_lock_file")
        return SessionLockError("unsafe_session_lock_topology")

    def assert_intact(self) -> None:
        """Fail closed if the public lock namespace no longer names our inode."""
        if self._fd is None or self._parent_fd is None or self._parent_stat is None:
            raise SessionLockError("session_lock_not_acquired")
        try:
            verify_directory_binding(
                self.path.parent,
                self._parent_stat,
                final_exact_mode=0o700,
            )
            verify_leaf_binding(self._parent_fd, self.path.name, self._fd)
            info = os.fstat(self._fd)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.geteuid()
                or info.st_nlink != 1
                or info.st_size != 0
                or stat.S_IMODE(info.st_mode) != 0o600
            ):
                raise FilesystemSafetyError("held session lock inode became unsafe")
        except (FilesystemSafetyError, OSError) as exc:
            raise SessionLockError("session_lock_namespace_changed") from exc

    def acquire(self) -> "TelegramSessionLock":
        if fcntl is None:
            raise SessionLockError("session_lock_posix_unavailable")
        if self._fd is not None or self._parent_fd is not None:
            raise SessionLockError("session_lock_already_acquired")

        parent_fd, parent_stat = self._open_private_parent()
        fd: int | None = None
        try:
            try:
                fd, _ = open_regular_at(
                    parent_fd,
                    self.path.name,
                    os.O_RDWR | os.O_CREAT,
                    mode=0o600,
                    exact_mode=0o600,
                    require_single_link=True,
                    require_empty=True,
                )
            except FilesystemSafetyError as exc:
                raise self._map_leaf_error(exc) from exc

            started = self.monotonic()
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if self.monotonic() - started >= self.timeout_seconds:
                        raise SessionLockError("session_lock_timeout")
                    self.sleeper(self.poll_interval_seconds)
                except OSError as exc:
                    raise SessionLockError("session_lock_acquire_failed") from exc

            self._fd = fd
            self._parent_fd = parent_fd
            self._parent_stat = parent_stat
            fd = None
            parent_fd = -1
            try:
                self.assert_intact()
            except Exception:
                self.release(_suppress_continuity=True)
                raise
            return self
        finally:
            if fd is not None:
                os.close(fd)
            if parent_fd >= 0:
                os.close(parent_fd)

    def release(self, _suppress_continuity: bool = False) -> None:
        fd = self._fd
        parent_fd = self._parent_fd
        if fd is None:
            if parent_fd is not None:
                os.close(parent_fd)
                self._parent_fd = None
                self._parent_stat = None
            return

        continuity_error: BaseException | None = None
        if not _suppress_continuity:
            try:
                self.assert_intact()
            except BaseException as exc:
                continuity_error = exc
        try:
            if fcntl is not None:
                try:
                    fcntl.flock(fd, fcntl.LOCK_UN)
                except OSError:
                    pass
        finally:
            os.close(fd)
            self._fd = None
            if parent_fd is not None:
                os.close(parent_fd)
            self._parent_fd = None
            self._parent_stat = None
        if continuity_error is not None:
            raise continuity_error

    def __enter__(self) -> "TelegramSessionLock":
        return self.acquire()

    def __exit__(self, exc_type, exc, tb) -> None:
        try:
            self.release()
        except SessionLockError:
            if exc_type is None:
                raise
