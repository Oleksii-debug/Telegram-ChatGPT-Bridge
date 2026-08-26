"""Metadata-only audit sink with fail-closed private-file topology."""

from __future__ import annotations

import fcntl
import json
import os
import stat
import time
from pathlib import Path
from typing import Any


_ALLOWED_FIELDS = {
    "request_id",
    "status",
    "count",
    "scanned",
    "route",
    "method",
    "job_id",
    "file_count",
    "byte_count",
    "error_code",
    "retry_after_seconds",
}
_MAX_TORN_TAIL_BYTES = 8192


class AuditSecurityError(RuntimeError):
    """Audit persistence cannot prove its private topology safely."""


class AuditLog:
    def __init__(self, path: Path | None = None) -> None:
        self.path = Path(path) if path is not None else None
        self.events: list[dict[str, Any]] = []
        self._parent_identity: tuple[int, int] | None = None
        self._leaf_name: str | None = None
        if self.path is not None:
            parent = self.path.parent
            if not parent.exists():
                try:
                    parent.mkdir(mode=0o700, parents=True, exist_ok=False)
                except FileExistsError:
                    pass
                except OSError as exc:
                    raise AuditSecurityError("audit parent cannot be created safely") from exc
            self._leaf_name = self.path.name
            if not self._leaf_name or self._leaf_name in {".", ".."}:
                raise AuditSecurityError("audit filename is invalid")
            fd = self._open_parent(expected=None)
            try:
                info = os.fstat(fd)
                self._parent_identity = (info.st_dev, info.st_ino)
            finally:
                os.close(fd)

    def _open_parent(self, expected: tuple[int, int] | None) -> int:
        assert self.path is not None
        flags = os.O_RDONLY
        if not hasattr(os, "O_DIRECTORY") or not hasattr(os, "O_NOFOLLOW"):
            raise AuditSecurityError("platform lacks safe audit directory primitives")
        flags |= os.O_DIRECTORY | os.O_NOFOLLOW
        try:
            fd = os.open(self.path.parent, flags)
        except OSError as exc:
            raise AuditSecurityError("audit parent is unavailable") from exc
        try:
            info = os.fstat(fd)
            identity = (info.st_dev, info.st_ino)
            if (
                not stat.S_ISDIR(info.st_mode)
                or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o700
                or (expected is not None and identity != expected)
            ):
                raise AuditSecurityError("audit parent topology/ownership/permissions are unsafe")
            return fd
        except Exception:
            os.close(fd)
            raise

    @staticmethod
    def _recover_torn_tail(fd: int) -> None:
        """Drop only a bounded incomplete JSONL tail left by process loss.

        Complete records end in a newline and are never rewritten. If the file is
        too large to prove the previous newline within a bounded tail window, fail
        closed instead of truncating an unknown amount of audit history.
        """
        if not hasattr(os, "pread") or not hasattr(os, "ftruncate"):
            raise AuditSecurityError("platform lacks audit tail recovery primitives")
        try:
            size = os.fstat(fd).st_size
        except OSError as exc:
            raise AuditSecurityError("audit file state unavailable") from exc
        if size <= 0:
            return
        try:
            last = os.pread(fd, 1, size - 1)
        except OSError as exc:
            raise AuditSecurityError("audit tail cannot be read safely") from exc
        if last == b"\n":
            return
        length = min(size, _MAX_TORN_TAIL_BYTES)
        start = size - length
        try:
            tail = os.pread(fd, length, start)
        except OSError as exc:
            raise AuditSecurityError("audit tail cannot be read safely") from exc
        newline = tail.rfind(b"\n")
        if newline < 0 and size > _MAX_TORN_TAIL_BYTES:
            raise AuditSecurityError("audit torn tail exceeds recovery bound")
        truncate_to = 0 if newline < 0 else start + newline + 1
        try:
            os.ftruncate(fd, truncate_to)
            os.fsync(fd)
        except OSError as exc:
            raise AuditSecurityError("audit torn tail recovery failed") from exc

    def _append_private_line(self, line: bytes) -> None:
        if self.path is None or self._leaf_name is None or self._parent_identity is None:
            raise AuditSecurityError("audit path state is incomplete")
        parent_fd = self._open_parent(expected=self._parent_identity)
        fd: int | None = None
        locked = False
        try:
            flags = os.O_RDWR | os.O_APPEND | os.O_CREAT | os.O_NONBLOCK
            if not hasattr(os, "O_NOFOLLOW"):
                raise AuditSecurityError("platform lacks O_NOFOLLOW for audit file")
            flags |= os.O_NOFOLLOW
            try:
                fd = os.open(self._leaf_name, flags, 0o600, dir_fd=parent_fd)
            except OSError as exc:
                raise AuditSecurityError("audit file cannot be opened safely") from exc
            info = os.fstat(fd)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.getuid()
                or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o600
            ):
                raise AuditSecurityError("audit file topology/ownership/permissions are unsafe")
            # O_APPEND makes each individual write position+write atomic, but one
            # logical JSONL record can require multiple os.write() calls after a
            # short write. Serialize the complete record so Passenger processes
            # cannot interleave fragments into corrupt audit evidence. Kernel flock
            # ownership also releases automatically if a worker dies mid-record.
            try:
                fcntl.flock(fd, fcntl.LOCK_EX)
                locked = True
            except OSError as exc:
                raise AuditSecurityError("audit file lock failed") from exc
            self._recover_torn_tail(fd)
            view = memoryview(line)
            while view:
                try:
                    written = os.write(fd, view)
                except OSError as exc:
                    raise AuditSecurityError("audit file write failed") from exc
                if written <= 0:
                    raise AuditSecurityError("audit file write made no progress")
                view = view[written:]
            try:
                os.fsync(fd)
            except OSError as exc:
                raise AuditSecurityError("audit file sync failed") from exc
        finally:
            if fd is not None:
                if locked:
                    try:
                        fcntl.flock(fd, fcntl.LOCK_UN)
                    except OSError:
                        pass
                os.close(fd)
            os.close(parent_fd)

    @staticmethod
    def _safe_event(event: str, fields: dict[str, Any]) -> dict[str, Any]:
        safe: dict[str, Any] = {"ts": int(time.time()), "event": str(event)[:64]}
        for key, value in fields.items():
            if key not in _ALLOWED_FIELDS:
                continue
            if isinstance(value, bool):
                safe[key] = value
            elif isinstance(value, int) and -(2**31) <= value <= 2**31 - 1:
                safe[key] = value
            elif isinstance(value, str) and len(value) <= 128 and value.isascii() and all(ord(ch) >= 32 for ch in value):
                safe[key] = value
        return safe

    def write(self, event: str, **fields: Any) -> None:
        safe = self._safe_event(event, fields)
        if self.path is not None:
            line = (json.dumps(safe, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
            self._append_private_line(line)
        self.events.append(dict(safe))