# -*- coding: utf-8 -*-
"""Strict POSIX process lock for a personal Telegram session.

The lock contains no session material. It is expected to live in an owner-controlled
private runtime directory outside Git. Existing unsafe topology fails closed.
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


class TelegramSessionLock:
    def __init__(self, lock_path: str | Path, *, timeout_seconds: float = 5.0,
                 poll_interval_seconds: float = 0.05,
                 monotonic: Callable[[], float] = time.monotonic,
                 sleeper: Callable[[float], None] = time.sleep):
        self.path = Path(lock_path)
        if timeout_seconds < 0 or timeout_seconds > 60:
            raise ValueError("bounded session-lock timeout required")
        if poll_interval_seconds <= 0 or poll_interval_seconds > 1:
            raise ValueError("bounded session-lock poll interval required")
        self.timeout_seconds = float(timeout_seconds)
        self.poll_interval_seconds = float(poll_interval_seconds)
        self.monotonic = monotonic
        self.sleeper = sleeper
        self._fd: int | None = None

    def _validate_parent(self) -> None:
        parent = self.path.parent
        parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        st = parent.stat()
        if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.geteuid():
            raise SessionLockError("unsafe_session_lock_parent")
        # Private session-control root must not be group/world accessible.
        if stat.S_IMODE(st.st_mode) & 0o077:
            raise SessionLockError("unsafe_session_lock_parent_mode")

    def acquire(self) -> "TelegramSessionLock":
        if self._fd is not None:
            raise SessionLockError("session_lock_already_acquired")
        self._validate_parent()
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(self.path, flags, 0o600)
        except OSError as exc:
            if exc.errno in {errno.ELOOP, errno.EMLINK}:
                raise SessionLockError("unsafe_session_lock_topology") from None
            raise SessionLockError("session_lock_open_failed") from None
        try:
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
                    self._fd = fd
                    return self
                except BlockingIOError:
                    if self.monotonic() - started >= self.timeout_seconds:
                        raise SessionLockError("session_lock_timeout")
                    self.sleeper(self.poll_interval_seconds)
        except Exception:
            os.close(fd)
            raise

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
