"""Metadata-only audit sink with durable, descriptor-bound retention."""

from __future__ import annotations

import errno
import json
import os
import re
import stat
import time
from pathlib import Path
from typing import Any

try:
    import fcntl
except ImportError:  # pragma: no cover - production target is POSIX/Linux
    fcntl = None  # type: ignore[assignment]


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
_SAFE_EVENT_RE = re.compile(r"[A-Za-z][A-Za-z0-9_.:-]{0,63}\Z")
_SAFE_TEXT_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_./:@+-]{0,127}\Z")
_ARCHIVE_DIGITS = 20


class AuditSecurityError(RuntimeError):
    """Audit persistence cannot prove its private topology or durability safely."""


class AuditLog:
    DEFAULT_MEMORY_EVENT_LIMIT = 2048
    MAX_MEMORY_EVENT_LIMIT = 100_000
    DEFAULT_MAX_FILE_BYTES = 8 * 1024 * 1024
    MAX_FILE_BYTES = 1024 * 1024 * 1024
    DEFAULT_RETENTION_FILES = 16
    MAX_RETENTION_FILES = 64

    def __init__(
        self,
        path: Path | None = None,
        *,
        memory_event_limit: int = DEFAULT_MEMORY_EVENT_LIMIT,
        max_file_bytes: int | None = DEFAULT_MAX_FILE_BYTES,
        retention_files: int = DEFAULT_RETENTION_FILES,
    ) -> None:
        if (
            isinstance(memory_event_limit, bool)
            or not isinstance(memory_event_limit, int)
            or not 1 <= memory_event_limit <= self.MAX_MEMORY_EVENT_LIMIT
        ):
            raise ValueError("memory_event_limit is outside the safe range")
        if max_file_bytes is not None and (
            isinstance(max_file_bytes, bool)
            or not isinstance(max_file_bytes, int)
            or not 512 <= max_file_bytes <= self.MAX_FILE_BYTES
        ):
            raise ValueError("max_file_bytes is outside the safe range")
        if (
            isinstance(retention_files, bool)
            or not isinstance(retention_files, int)
            or not 1 <= retention_files <= self.MAX_RETENTION_FILES
        ):
            raise ValueError("retention_files is outside the safe range")

        self.path = Path(path) if path is not None else None
        self.memory_event_limit = memory_event_limit
        self.max_file_bytes = max_file_bytes
        self.retention_files = retention_files
        self.events: list[dict[str, Any]] = []
        self._parent_identity: tuple[int, int] | None = None
        self._leaf_identity: tuple[int, int] | None = None
        self._leaf_name: str | None = None
        self._lock_name: str | None = None
        self._lock_identity: tuple[int, int] | None = None
        self._pending_rotation: tuple[tuple[int, int], str] | None = None

        if self.path is not None:
            if fcntl is None:
                raise AuditSecurityError("platform lacks POSIX audit locking")
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
            self._lock_name = f".{self._leaf_name}.lock"
            parent_fd = self._open_parent(expected=None)
            try:
                info = os.fstat(parent_fd)
                self._parent_identity = (info.st_dev, info.st_ino)
                lock_fd = self._open_lock(parent_fd, create=True, expected=None)
                try:
                    lock_info = os.fstat(lock_fd)
                    self._lock_identity = (lock_info.st_dev, lock_info.st_ino)
                    os.fsync(lock_fd)
                    os.fsync(parent_fd)
                    assert fcntl is not None
                    try:
                        fcntl.flock(lock_fd, fcntl.LOCK_EX)
                    except OSError as exc:
                        raise AuditSecurityError("audit initialization lock cannot be acquired") from exc
                finally:
                    try:
                        assert fcntl is not None
                        fcntl.flock(lock_fd, fcntl.LOCK_UN)
                    except OSError:
                        pass
                    os.close(lock_fd)
            finally:
                os.close(parent_fd)

    def _open_parent(self, expected: tuple[int, int] | None) -> int:
        assert self.path is not None
        if not hasattr(os, "O_DIRECTORY") or not hasattr(os, "O_NOFOLLOW"):
            raise AuditSecurityError("platform lacks safe audit directory primitives")
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
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
    def _validate_private_regular(info: os.stat_result, *, what: str) -> tuple[int, int]:
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != 0o600
        ):
            raise AuditSecurityError(f"{what} topology/ownership/permissions are unsafe")
        return (info.st_dev, info.st_ino)

    def _open_lock(
        self,
        parent_fd: int,
        *,
        create: bool,
        expected: tuple[int, int] | None,
    ) -> int:
        assert self._lock_name is not None
        flags = os.O_RDWR
        if create:
            flags |= os.O_CREAT
        if not hasattr(os, "O_NOFOLLOW"):
            raise AuditSecurityError("platform lacks O_NOFOLLOW for audit lock")
        flags |= os.O_NOFOLLOW
        try:
            fd = os.open(self._lock_name, flags, 0o600, dir_fd=parent_fd)
        except OSError as exc:
            raise AuditSecurityError("audit lock cannot be opened safely") from exc
        try:
            identity = self._validate_private_regular(os.fstat(fd), what="audit lock")
            if expected is not None and identity != expected:
                raise AuditSecurityError("audit lock continuity changed unexpectedly")
            return fd
        except Exception:
            os.close(fd)
            raise

    def _open_existing_leaf(self, parent_fd: int) -> int:
        assert self._leaf_name is not None
        flags = os.O_WRONLY | os.O_APPEND | os.O_NONBLOCK
        if not hasattr(os, "O_NOFOLLOW"):
            raise AuditSecurityError("platform lacks O_NOFOLLOW for audit file")
        flags |= os.O_NOFOLLOW
        try:
            fd = os.open(self._leaf_name, flags, dir_fd=parent_fd)
        except FileNotFoundError:
            raise
        except OSError as exc:
            raise AuditSecurityError("audit file cannot be opened safely") from exc
        try:
            self._validate_private_regular(os.fstat(fd), what="audit file")
            return fd
        except Exception:
            os.close(fd)
            raise

    def _create_leaf(self, parent_fd: int) -> int:
        assert self._leaf_name is not None
        flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_EXCL | os.O_NONBLOCK | os.O_NOFOLLOW
        try:
            fd = os.open(self._leaf_name, flags, 0o600, dir_fd=parent_fd)
        except OSError as exc:
            raise AuditSecurityError("audit file cannot be created safely") from exc
        try:
            identity = self._validate_private_regular(os.fstat(fd), what="audit file")
            self._leaf_identity = identity
            os.fsync(fd)
            os.fsync(parent_fd)
            self._pending_rotation = None
            return fd
        except Exception:
            os.close(fd)
            raise

    def _archive_prefix(self) -> str:
        assert self._leaf_name is not None
        return f"{self._leaf_name}.r"

    def _archive_entries(self, parent_fd: int) -> list[tuple[int, str, tuple[int, int]]]:
        prefix = self._archive_prefix()
        entries: list[tuple[int, str, tuple[int, int]]] = []
        try:
            names = os.listdir(parent_fd)
        except OSError as exc:
            raise AuditSecurityError("audit archive directory cannot be enumerated safely") from exc
        for name in names:
            if not name.startswith(prefix):
                continue
            suffix = name[len(prefix):]
            if len(suffix) != _ARCHIVE_DIGITS or not suffix.isdigit():
                raise AuditSecurityError("audit archive namespace contains an invalid entry")
            try:
                fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent_fd)
            except OSError as exc:
                raise AuditSecurityError("audit archive cannot be opened safely") from exc
            try:
                identity = self._validate_private_regular(os.fstat(fd), what="audit archive")
            finally:
                os.close(fd)
            entries.append((int(suffix), name, identity))
        entries.sort(key=lambda item: item[0])
        return entries

    def _can_adopt_peer_rotation(self, parent_fd: int, expected: tuple[int, int]) -> bool:
        return any(identity == expected for _, _, identity in self._archive_entries(parent_fd))

    def _open_current_leaf(self, parent_fd: int) -> int:
        assert self._leaf_name is not None
        exists = True
        try:
            info = os.stat(self._leaf_name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            exists = False
            info = None
        except OSError as exc:
            raise AuditSecurityError("audit file topology cannot be inspected safely") from exc

        if not exists:
            if self._leaf_identity is None:
                return self._create_leaf(parent_fd)
            if self._pending_rotation is not None:
                old_identity, archive_name = self._pending_rotation
                if old_identity != self._leaf_identity:
                    raise AuditSecurityError("audit rotation continuity state is inconsistent")
                entries = {name: identity for _, name, identity in self._archive_entries(parent_fd)}
                if entries.get(archive_name) != old_identity:
                    raise AuditSecurityError("audit rotation archive continuity is missing")
                return self._create_leaf(parent_fd)
            raise AuditSecurityError("audit leaf disappeared after continuity was established")

        assert info is not None
        self._validate_private_regular(info, what="audit file")
        fd = self._open_existing_leaf(parent_fd)
        try:
            identity = self._validate_private_regular(os.fstat(fd), what="audit file")
            if self._leaf_identity is None:
                self._leaf_identity = identity
            elif identity != self._leaf_identity:
                if not self._can_adopt_peer_rotation(parent_fd, self._leaf_identity):
                    raise AuditSecurityError("audit leaf continuity changed unexpectedly")
                self._leaf_identity = identity
                self._pending_rotation = None
            return fd
        except Exception:
            os.close(fd)
            raise

    def _next_archive_name(self, parent_fd: int) -> str:
        entries = self._archive_entries(parent_fd)
        sequence = (entries[-1][0] + 1) if entries else 1
        if sequence >= 10**_ARCHIVE_DIGITS:
            raise AuditSecurityError("audit archive generation space is exhausted")
        return f"{self._archive_prefix()}{sequence:0{_ARCHIVE_DIGITS}d}"

    def _rotate_locked(self, parent_fd: int, fd: int) -> int:
        assert self._leaf_name is not None
        current_identity = self._validate_private_regular(os.fstat(fd), what="audit file")
        if self._leaf_identity != current_identity:
            raise AuditSecurityError("audit leaf changed before rotation")
        try:
            os.fsync(fd)
        except OSError as exc:
            raise AuditSecurityError("audit file cannot be synced before rotation") from exc
        archive_name = self._next_archive_name(parent_fd)
        try:
            os.rename(
                self._leaf_name,
                archive_name,
                src_dir_fd=parent_fd,
                dst_dir_fd=parent_fd,
            )
            self._pending_rotation = (current_identity, archive_name)
            os.fsync(parent_fd)
        except OSError as exc:
            raise AuditSecurityError("audit rotation rename could not be made durable") from exc
        try:
            new_fd = self._create_leaf(parent_fd)
        except Exception:
            # The durable archive remains the evidence source. A later retry in
            # this process, or a restart, may safely recreate the current leaf.
            raise
        return new_fd

    def _verify_live_paths(self, parent_fd: int, leaf_fd: int) -> None:
        assert self._leaf_name is not None
        leaf_identity = self._validate_private_regular(os.fstat(leaf_fd), what="audit file")
        try:
            path_info = os.stat(self._leaf_name, dir_fd=parent_fd, follow_symlinks=False)
        except OSError as exc:
            raise AuditSecurityError("audit leaf continuity cannot be revalidated") from exc
        path_identity = self._validate_private_regular(path_info, what="audit file")
        if path_identity != leaf_identity or path_identity != self._leaf_identity:
            raise AuditSecurityError("audit leaf was replaced during append")
        check_parent = self._open_parent(expected=self._parent_identity)
        os.close(check_parent)

    @staticmethod
    def _rollback_partial_append(fd: int, original_size: int) -> bool:
        try:
            os.ftruncate(fd, original_size)
            os.fsync(fd)
            return os.fstat(fd).st_size == original_size
        except OSError:
            return False

    def _write_line_locked(self, parent_fd: int, fd: int, line: bytes) -> None:
        original_size = os.fstat(fd).st_size
        view = memoryview(line)
        try:
            while view:
                written = os.write(fd, view)
                if written <= 0:
                    raise OSError(errno.EIO, "audit write made no progress")
                view = view[written:]
            os.fsync(fd)
            self._verify_live_paths(parent_fd, fd)
        except Exception as exc:
            if not self._rollback_partial_append(fd, original_size):
                raise AuditSecurityError("audit write failed and prior evidence rollback is unproven") from exc
            raise AuditSecurityError("audit file write failed without committing the record") from exc

    def _prune_archives_locked(self, parent_fd: int) -> None:
        try:
            entries = self._archive_entries(parent_fd)
        except AuditSecurityError:
            # Retention cleanup never overrides successful evidence persistence.
            # Unsafe archive topology degrades to retention hold, not deletion.
            return
        excess = len(entries) - self.retention_files
        if excess <= 0:
            return
        deleted = False
        for _, name, _ in entries[:excess]:
            try:
                os.unlink(name, dir_fd=parent_fd)
                deleted = True
            except OSError:
                break
        if deleted:
            try:
                os.fsync(parent_fd)
            except OSError:
                # Deletion durability uncertainty cannot erase the current event;
                # the safe outcome is simply that some old archive may remain.
                pass

    def _append_private_line(self, line: bytes) -> None:
        if (
            self.path is None
            or self._leaf_name is None
            or self._parent_identity is None
            or self._lock_name is None
            or self._lock_identity is None
        ):
            raise AuditSecurityError("audit path state is incomplete")
        if self.max_file_bytes is not None and len(line) > self.max_file_bytes:
            raise AuditSecurityError("audit record exceeds the configured segment size")
        parent_fd = self._open_parent(expected=self._parent_identity)
        lock_fd: int | None = None
        leaf_fd: int | None = None
        try:
            lock_fd = self._open_lock(parent_fd, create=False, expected=self._lock_identity)
            assert fcntl is not None
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_EX)
            except OSError as exc:
                raise AuditSecurityError("audit append lock cannot be acquired") from exc
            # Revalidate after waiting: another process may have rotated safely.
            os.close(parent_fd)
            parent_fd = -1
            parent_fd = self._open_parent(expected=self._parent_identity)
            check_lock_fd = self._open_lock(parent_fd, create=False, expected=self._lock_identity)
            os.close(check_lock_fd)
            leaf_fd = self._open_current_leaf(parent_fd)
            if self.max_file_bytes is not None:
                size = os.fstat(leaf_fd).st_size
                if size > 0 and size + len(line) > self.max_file_bytes:
                    new_fd = self._rotate_locked(parent_fd, leaf_fd)
                    os.close(leaf_fd)
                    leaf_fd = new_fd
            self._write_line_locked(parent_fd, leaf_fd, line)
            self._prune_archives_locked(parent_fd)
        finally:
            if leaf_fd is not None:
                os.close(leaf_fd)
            if lock_fd is not None:
                try:
                    assert fcntl is not None
                    fcntl.flock(lock_fd, fcntl.LOCK_UN)
                except OSError:
                    pass
                os.close(lock_fd)
            if parent_fd >= 0:
                os.close(parent_fd)

    @staticmethod
    def _safe_event(event: str, fields: dict[str, Any]) -> dict[str, Any]:
        raw_event = str(event)
        event_name = raw_event if _SAFE_EVENT_RE.fullmatch(raw_event) else "invalid_event"
        safe: dict[str, Any] = {"ts": int(time.time()), "event": event_name}
        for key, value in fields.items():
            if key not in _ALLOWED_FIELDS:
                continue
            if isinstance(value, bool):
                safe[key] = value
            elif isinstance(value, int) and -(2**31) <= value <= 2**31 - 1:
                safe[key] = value
            elif isinstance(value, str) and _SAFE_TEXT_RE.fullmatch(value):
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
