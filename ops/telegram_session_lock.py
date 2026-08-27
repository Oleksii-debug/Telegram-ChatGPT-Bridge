# -*- coding: utf-8 -*-
"""Strict POSIX process lock for a personal Telegram session.

The lock contains no session material. It is expected to live in an owner-controlled
private runtime directory outside Git. Lock acquisition is descriptor-relative so
symlinked/replaced parent directories cannot redirect the leaf open after validation.
"""
from __future__ import annotations

import errno
import fcntl
import os
import stat
import time
from pathlib import Path
from typing import Callable


class SessionLockError(RuntimeError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _same_inode(left: os.stat_result, right: os.stat_result) -> bool:
    return left.st_dev == right.st_dev and left.st_ino == right.st_ino


class TelegramSessionLock:
    def __init__(self, lock_path: str | Path, *, timeout_seconds: float = 5.0,
                 poll_interval_seconds: float = 0.05,
                 monotonic: Callable[[], float] = time.monotonic,
                 sleeper: Callable[[float], None] = time.sleep):
        self.path = Path(os.path.abspath(os.fspath(Path(lock_path).expanduser())))
        if timeout_seconds < 0 or timeout_seconds > 60:
            raise ValueError("bounded session-lock timeout required")
        if poll_interval_seconds <= 0 or poll_interval_seconds > 1:
            raise ValueError("bounded session-lock poll interval required")
        if not self.path.name or self.path.name in {".", ".."}:
            raise ValueError("session-lock filename required")
        self.timeout_seconds = float(timeout_seconds)
        self.poll_interval_seconds = float(poll_interval_seconds)
        self.monotonic = monotonic
        self.sleeper = sleeper
        self._fd: int | None = None

    @staticmethod
    def _directory_flags() -> int:
        if os.name != "posix" or not hasattr(os, "O_DIRECTORY") or not hasattr(os, "O_NOFOLLOW"):
            raise SessionLockError("session_lock_safe_primitives_unavailable")
        return os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)

    def _open_parent_fd(self, *, create: bool) -> tuple[int, os.stat_result]:
        """Walk to the parent without following any pathname symlink component."""
        parent = self.path.parent
        parts = parent.parts
        if not parts or parts[0] != os.sep:
            raise SessionLockError("unsafe_session_lock_parent")

        flags = self._directory_flags()
        try:
            current_fd = os.open(os.sep, flags)
        except OSError:
            raise SessionLockError("session_lock_parent_open_failed") from None
        opened = [current_fd]
        try:
            for index, component in enumerate(parts[1:], start=1):
                is_leaf_parent = index == len(parts) - 1
                try:
                    before = os.stat(component, dir_fd=current_fd, follow_symlinks=False)
                except FileNotFoundError:
                    if not create or not is_leaf_parent:
                        raise SessionLockError("unsafe_session_lock_parent") from None
                    try:
                        os.mkdir(component, 0o700, dir_fd=current_fd)
                    except OSError:
                        raise SessionLockError("session_lock_parent_create_failed") from None
                    try:
                        before = os.stat(component, dir_fd=current_fd, follow_symlinks=False)
                    except OSError:
                        raise SessionLockError("session_lock_parent_metadata_failed") from None
                except OSError:
                    raise SessionLockError("session_lock_parent_metadata_failed") from None

                if stat.S_ISLNK(before.st_mode) or not stat.S_ISDIR(before.st_mode):
                    raise SessionLockError("unsafe_session_lock_parent_topology")
                try:
                    next_fd = os.open(component, flags, dir_fd=current_fd)
                except OSError:
                    raise SessionLockError("session_lock_parent_open_failed") from None
                after = os.fstat(next_fd)
                if not stat.S_ISDIR(after.st_mode) or not _same_inode(before, after):
                    os.close(next_fd)
                    raise SessionLockError("session_lock_parent_changed")
                opened.append(next_fd)
                current_fd = next_fd

            parent_stat = os.fstat(current_fd)
            mode = stat.S_IMODE(parent_stat.st_mode)
            if (
                not stat.S_ISDIR(parent_stat.st_mode)
                or parent_stat.st_uid != os.geteuid()
                or mode & 0o077
                or not (mode & stat.S_IWUSR)
                or not (mode & stat.S_IXUSR)
            ):
                raise SessionLockError("unsafe_session_lock_parent_mode")

            retained = os.dup(current_fd)
            retained_stat = os.fstat(retained)
            return retained, retained_stat
        finally:
            for directory_fd in reversed(opened):
                try:
                    os.close(directory_fd)
                except OSError:
                    pass

    def _verify_parent_binding(self, expected: os.stat_result) -> None:
        verify_fd, observed = self._open_parent_fd(create=False)
        try:
            if not _same_inode(expected, observed):
                raise SessionLockError("session_lock_parent_changed")
        finally:
            os.close(verify_fd)

    def acquire(self) -> "TelegramSessionLock":
        if self._fd is not None:
            raise SessionLockError("session_lock_already_acquired")
        parent_fd, parent_stat = self._open_parent_fd(create=True)
        fd: int | None = None
        try:
            flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0)
            if not hasattr(os, "O_NOFOLLOW"):
                raise SessionLockError("session_lock_safe_primitives_unavailable")
            flags |= os.O_NOFOLLOW
            try:
                fd = os.open(self.path.name, flags, 0o600, dir_fd=parent_fd)
            except OSError as exc:
                if exc.errno in {errno.ELOOP, errno.EMLINK}:
                    raise SessionLockError("unsafe_session_lock_topology") from None
                raise SessionLockError("session_lock_open_failed") from None
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid():
                raise SessionLockError("unsafe_session_lock_file")
            if st.st_nlink != 1:
                raise SessionLockError("unsafe_session_lock_hardlink")
            if st.st_size != 0:
                raise SessionLockError("unsafe_session_lock_nonempty")
            if stat.S_IMODE(st.st_mode) != 0o600:
                raise SessionLockError("unsafe_session_lock_mode")
            started = self.monotonic()
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if self.monotonic() - started >= self.timeout_seconds:
                        raise SessionLockError("session_lock_timeout")
                    self.sleeper(self.poll_interval_seconds)

            self._verify_parent_binding(parent_stat)
            try:
                named = os.stat(self.path.name, dir_fd=parent_fd, follow_symlinks=False)
            except OSError:
                raise SessionLockError("session_lock_leaf_changed") from None
            current = os.fstat(fd)
            if stat.S_ISLNK(named.st_mode) or not _same_inode(named, current):
                raise SessionLockError("session_lock_leaf_changed")
            self._fd = fd
            fd = None
            return self
        finally:
            os.close(parent_fd)
            if fd is not None:
                try:
                    fcntl.flock(fd, fcntl.LOCK_UN)
                except OSError:
                    pass
                os.close(fd)

    def release(self) -> None:
        fd, self._fd = self._fd, None
        if fd is None:
            return
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)

    def __enter__(self) -> "TelegramSessionLock":
        return self.acquire()

    def __exit__(self, exc_type, exc, tb) -> None:
        self.release()
