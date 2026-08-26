"""Metadata-only audit sink with descriptor-bound private-file topology."""
from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any

from ops.posix_fs import (
    FilesystemSafetyError,
    open_directory_fd,
    open_regular_at,
    verify_directory_binding,
    verify_leaf_binding,
)

_ALLOWED_FIELDS = {
    "request_id", "status", "count", "scanned", "route", "method", "job_id",
    "file_count", "byte_count", "error_code", "retry_after_seconds",
}


class AuditSecurityError(RuntimeError):
    """Audit persistence cannot prove its private topology safely."""


class AuditLog:
    def __init__(self, path: Path | None = None) -> None:
        self.path = (
            Path(os.path.abspath(os.path.expanduser(os.fspath(path))))
            if path is not None
            else None
        )
        self.events: list[dict[str, Any]] = []
        self._parent_identity: os.stat_result | None = None
        self._leaf_name: str | None = None
        if self.path is not None:
            self._leaf_name = self.path.name
            if not self._leaf_name or self._leaf_name in {".", ".."}:
                raise AuditSecurityError("audit filename is invalid")
            try:
                fd, info = open_directory_fd(
                    self.path.parent,
                    create_missing=True,
                    create_mode=0o700,
                    final_exact_mode=0o700,
                )
            except FilesystemSafetyError as exc:
                raise AuditSecurityError("audit parent topology/ownership/permissions are unsafe") from exc
            try:
                self._parent_identity = info
            finally:
                os.close(fd)

    def _open_parent(self) -> tuple[int, os.stat_result]:
        if self.path is None or self._parent_identity is None:
            raise AuditSecurityError("audit path state is incomplete")
        try:
            fd, info = open_directory_fd(
                self.path.parent,
                final_exact_mode=0o700,
            )
            if (
                info.st_dev != self._parent_identity.st_dev
                or info.st_ino != self._parent_identity.st_ino
            ):
                os.close(fd)
                raise AuditSecurityError("audit parent pathname binding changed")
            return fd, info
        except FilesystemSafetyError as exc:
            raise AuditSecurityError("audit parent is unavailable or unsafe") from exc

    def _append_private_line(self, line: bytes) -> None:
        if self.path is None or self._leaf_name is None or self._parent_identity is None:
            raise AuditSecurityError("audit path state is incomplete")
        parent_fd, parent_info = self._open_parent()
        fd: int | None = None
        try:
            try:
                fd, _ = open_regular_at(
                    parent_fd,
                    self._leaf_name,
                    os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_NONBLOCK", 0),
                    mode=0o600,
                    exact_mode=0o600,
                    require_single_link=True,
                )
            except FilesystemSafetyError as exc:
                raise AuditSecurityError("audit file cannot be opened safely") from exc

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
                verify_leaf_binding(parent_fd, self._leaf_name, fd)
                verify_directory_binding(
                    self.path.parent,
                    parent_info,
                    final_exact_mode=0o700,
                )
            except (OSError, FilesystemSafetyError) as exc:
                raise AuditSecurityError("audit filesystem binding changed during append") from exc
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
            elif (
                isinstance(value, str)
                and len(value) <= 128
                and value.isascii()
                and all(ord(ch) >= 32 for ch in value)
            ):
                safe[key] = value
        return safe

    def write(self, event: str, **fields: Any) -> None:
        safe = self._safe_event(event, fields)
        if self.path is not None:
            line = (
                json.dumps(safe, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
                + "\n"
            ).encode("ascii")
            self._append_private_line(line)
        self.events.append(dict(safe))
