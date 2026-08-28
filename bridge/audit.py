"""Metadata-only audit sink with fail-closed private-file topology."""

from __future__ import annotations

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


class AuditSecurityError(RuntimeError):
    """Audit persistence cannot prove its private topology safely."""


class AuditLog:
    DEFAULT_MEMORY_EVENT_LIMIT = 2048
    MAX_MEMORY_EVENT_LIMIT = 100_000

    def __init__(self, path: Path | None = None, *, memory_event_limit: int = DEFAULT_MEMORY_EVENT_LIMIT) -> None:
        if (
            isinstance(memory_event_limit, bool)
            or not isinstance(memory_event_limit, int)
            or not 1 <= memory_event_limit <= self.MAX_MEMORY_EVENT_LIMIT
        ):
            raise ValueError("memory_event_limit is outside the safe range")
        self.path = Path(path) if path is not None else None
        self.memory_event_limit = memory_event_limit
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

    def _append_private_line(self, line: bytes) -> None:
        if self.path is None or self._leaf_name is None or self._parent_identity is None:
            raise AuditSecurityError("audit path state is incomplete")
        parent_fd = self._open_parent(expected=self._parent_identity)
        fd: int | None = None
        try:
            flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NONBLOCK
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
        overflow = len(self.events) - self.memory_event_limit
        if overflow > 0:
            del self.events[:overflow]
