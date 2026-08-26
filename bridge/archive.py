"""Traversal-safe ZIP creation for files already in private storage."""

from __future__ import annotations

import fcntl
import hashlib
import os
import re
import secrets
import sqlite3
import stat
import zipfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator

from .errors import BridgeError
from .filenames import filename_collision_key, safe_filename
from .storage import FileRecord, FileRecordStore

_PENDING_RE = re.compile(r"^\.archive_([0-9a-f]{40})\.pending$")


def safe_archive_name(name: str) -> str:
    return safe_filename(name, "file", limit=180)


def _collision_key(name: str) -> str:
    return filename_collision_key(name)


def unique_name(name: str, used: set[str]) -> str:
    """Return a safe member name unique under Unicode-NFC + casefold.

    ZIP consumers differ in case sensitivity and Unicode normalization. The
    archive therefore resolves those collisions deterministically instead of
    emitting two visually/equivalently named members.
    """
    base = safe_archive_name(name)
    stem = Path(base).stem or "file"
    suffix = Path(base).suffix
    candidate = base
    index = 2
    while _collision_key(candidate) in used:
        candidate = safe_archive_name(f"{stem} ({index}){suffix}")
        index += 1
    used.add(_collision_key(candidate))
    return candidate


@dataclass(frozen=True)
class ArchiveLimits:
    max_members: int = 200
    max_total_bytes: int = 750 * 1024 * 1024
    compression: int = zipfile.ZIP_DEFLATED

    def __post_init__(self) -> None:
        if (
            isinstance(self.max_members, bool)
            or isinstance(self.max_total_bytes, bool)
            or not 1 <= self.max_members <= 500
            or self.max_total_bytes <= 0
            or self.compression not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED, zipfile.ZIP_BZIP2, zipfile.ZIP_LZMA}
        ):
            raise ValueError("invalid archive limits")


class ArchiveBuilder:
    """Build private ZIPs with process-loss reconciliation.

    A small owner-private marker is durably created before archive materialization.
    The marker token deterministically names both staging and final leaves. Builds
    are serialized with a POSIX flock, so a later worker may safely reconcile a
    marker left by a dead process without racing a live archive builder.
    """

    def __init__(self, *, files: FileRecordStore, output_dir: Path, limits: ArchiveLimits | None = None) -> None:
        self.files = files
        self.output_dir = output_dir.resolve()
        self.limits = limits or ArchiveLimits()
        self.output_dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.output_dir, 0o700)
        except OSError:
            pass
        self.lock_path = self.output_dir / ".archive.lock"

    @contextmanager
    def _archive_lock(self) -> Iterator[None]:
        flags = os.O_CREAT | os.O_RDWR
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            fd = os.open(self.lock_path, flags, 0o600)
        except OSError as exc:
            raise BridgeError("Archive lock is unavailable", status=503, code="archive_lock_unavailable") from exc
        try:
            info = os.fstat(fd)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_size != 0
                or (hasattr(os, "getuid") and info.st_uid != os.getuid())
            ):
                raise BridgeError("Unsafe archive lock topology", status=500, code="archive_lock_unsafe")
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise BridgeError(
                    "Archive builder is already running",
                    status=409,
                    code="archive_busy",
                    details={"retryable": True},
                ) from exc
            yield
        finally:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            except OSError:
                pass
            os.close(fd)

    @staticmethod
    def _owned_leaf_info(path: Path) -> os.stat_result | None:
        try:
            info = os.lstat(path)
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise BridgeError("Archive recovery path is unavailable", status=500, code="archive_recovery_unsafe") from exc
        if (
            not (stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode))
            or info.st_nlink != 1
            or (hasattr(os, "getuid") and info.st_uid != os.getuid())
        ):
            raise BridgeError("Unsafe archive recovery topology", status=500, code="archive_recovery_unsafe")
        return info

    def _unlink_owned_leaf(self, path: Path, *, parent: Path) -> None:
        try:
            actual_parent = path.parent.resolve(strict=True)
        except OSError as exc:
            raise BridgeError("Archive recovery parent is unavailable", status=500, code="archive_recovery_unsafe") from exc
        if actual_parent != parent:
            raise BridgeError("Archive recovery path escaped private storage", status=500, code="archive_recovery_unsafe")
        if self._owned_leaf_info(path) is None:
            return
        try:
            path.unlink()
        except OSError as exc:
            raise BridgeError("Archive recovery cleanup failed", status=500, code="archive_recovery_failed") from exc

    def _create_pending_marker(self, token: str) -> Path:
        marker = self.output_dir / f".archive_{token}.pending"
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            fd = os.open(marker, flags, 0o600)
        except OSError as exc:
            raise BridgeError("Archive recovery marker cannot be created", status=500, code="archive_marker_failed") from exc
        try:
            info = os.fstat(fd)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_size != 0
                or (hasattr(os, "getuid") and info.st_uid != os.getuid())
            ):
                raise BridgeError("Unsafe archive recovery marker", status=500, code="archive_recovery_unsafe")
            os.fsync(fd)
        except Exception:
            try:
                marker.unlink()
            except OSError:
                pass
            raise
        finally:
            os.close(fd)
        return marker

    def _final_is_registered(self, final: Path) -> bool:
        try:
            relative = final.relative_to(self.files.root).as_posix()
        except ValueError as exc:
            raise BridgeError("Archive final path escaped private storage", status=500, code="archive_recovery_unsafe") from exc
        try:
            with self.files._connect() as connection:
                row = connection.execute(
                    "SELECT 1 FROM files WHERE rel_path=? LIMIT 1",
                    (relative,),
                ).fetchone()
        except sqlite3.Error as exc:
            raise BridgeError("Archive registry is unavailable for recovery", status=503, code="archive_registry_unavailable") from exc
        return row is not None

    def _validate_marker(self, marker: Path) -> str:
        match = _PENDING_RE.fullmatch(marker.name)
        if match is None:
            raise BridgeError("Invalid archive recovery marker", status=500, code="archive_recovery_unsafe")
        try:
            info = os.lstat(marker)
        except OSError as exc:
            raise BridgeError("Archive recovery marker is unavailable", status=500, code="archive_recovery_unsafe") from exc
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_size != 0
            or (hasattr(os, "getuid") and info.st_uid != os.getuid())
        ):
            raise BridgeError("Unsafe archive recovery marker", status=500, code="archive_recovery_unsafe")
        return match.group(1)

    def _reconcile_pending(self) -> None:
        """Clean process-loss artifacts while holding the global archive lock."""
        try:
            markers = [path for path in self.output_dir.iterdir() if _PENDING_RE.fullmatch(path.name)]
        except OSError as exc:
            raise BridgeError("Archive staging cannot be inspected", status=500, code="archive_recovery_failed") from exc
        for marker in markers:
            token = self._validate_marker(marker)
            target = self.output_dir / f"archive_{token}.zip.part"
            final = self.files.root / f".archive_{token}.zip"
            registered = self._final_is_registered(final)
            self._unlink_owned_leaf(target, parent=self.output_dir)
            if not registered:
                self._unlink_owned_leaf(final, parent=self.files.root)
            self._unlink_owned_leaf(marker, parent=self.output_dir)

    @staticmethod
    def _open_source(record: FileRecord) -> int:
        """Open an already-registered file without following a path swap."""
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            fd = os.open(record.path, flags)
        except OSError as exc:
            raise BridgeError("Archive source is unavailable", status=409, code="archive_source_changed") from exc
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size != record.size:
                raise BridgeError("Archive source topology changed", status=409, code="archive_source_changed")
            return fd
        except Exception:
            os.close(fd)
            raise

    def _write_record(self, zf: zipfile.ZipFile, record: FileRecord, *, arcname: str) -> None:
        """Stream from a verified descriptor and re-check hash/size while writing."""
        fd = self._open_source(record)
        digest = hashlib.sha256()
        total = 0
        info = zipfile.ZipInfo(filename=arcname)
        info.compress_type = self.limits.compression
        info.external_attr = 0o600 << 16
        try:
            with os.fdopen(fd, "rb", closefd=True) as source, zf.open(info, "w") as destination:
                while True:
                    chunk = source.read(1024 * 1024)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > record.size:
                        raise BridgeError("Archive source size changed", status=409, code="archive_source_changed")
                    digest.update(chunk)
                    destination.write(chunk)
        except BridgeError:
            raise
        except OSError as exc:
            raise BridgeError("Archive source read failed", status=409, code="archive_source_changed") from exc
        if total != record.size or not secrets.compare_digest(digest.hexdigest(), record.sha256):
            raise BridgeError("Archive source integrity changed", status=409, code="archive_source_changed")

    def _build_locked(self, file_refs: Iterable[str], *, archive_name: str) -> FileRecord:
        refs = list(dict.fromkeys(file_refs))
        if not refs:
            raise BridgeError("No files selected", code="empty_archive")
        if len(refs) > self.limits.max_members:
            raise BridgeError("Archive member limit exceeded", status=413, code="zip_member_limit")
        records: list[FileRecord] = []
        total = 0
        for ref in refs:
            record = self.files.get(ref)
            if record is None:
                raise BridgeError("Archive source file not found", status=404, code="file_not_found")
            total += record.size
            if total > self.limits.max_total_bytes:
                raise BridgeError("Archive size limit exceeded", status=413, code="zip_size_limit")
            records.append(record)

        token = secrets.token_hex(20)
        target = self.output_dir / f"archive_{token}.zip.part"
        final = self.files.root / f".archive_{token}.zip"
        marker = self._create_pending_marker(token)
        registered = False
        try:
            for candidate in (target, final):
                try:
                    os.lstat(candidate)
                except FileNotFoundError:
                    continue
                except OSError as exc:
                    raise BridgeError("Archive destination state is unavailable", status=500, code="archive_recovery_unsafe") from exc
                raise BridgeError("Archive destination collision", status=500, code="archive_destination_collision")

            with zipfile.ZipFile(target, "w", compression=self.limits.compression, allowZip64=False) as zf:
                used: set[str] = set()
                for record in records:
                    arcname = unique_name(record.name, used)
                    self._write_record(zf, record, arcname=arcname)
            with zipfile.ZipFile(target, "r") as zf:
                if len(zf.infolist()) != len(records):
                    raise BridgeError("Archive validation failed", status=500, code="zip_validation_failed")
                bad = zf.testzip()
                if bad is not None:
                    raise BridgeError("Archive CRC validation failed", status=500, code="zip_crc_failed")
                member_keys: set[str] = set()
                for info in zf.infolist():
                    name = info.filename
                    if name.startswith("/") or name.startswith("\\") or ".." in Path(name).parts:
                        raise BridgeError("Unsafe archive member", status=500, code="unsafe_zip_member")
                    key = _collision_key(name)
                    if key in member_keys:
                        raise BridgeError("Archive member collision", status=500, code="zip_member_collision")
                    member_keys.add(key)
            target.replace(final)
            try:
                os.chmod(final, 0o600)
            except OSError:
                pass
            record = self.files.add(final, name=safe_archive_name(archive_name), mime_type="application/zip")
            registered = True
            try:
                self._unlink_owned_leaf(marker, parent=self.output_dir)
            except BridgeError:
                # The archive is already durably registered. A leftover marker
                # is safe: the next locked reconciliation sees the DB row and
                # removes only the marker while preserving the registered file.
                pass
            return record
        finally:
            try:
                self._unlink_owned_leaf(target, parent=self.output_dir)
            except BridgeError:
                pass
            if not registered:
                try:
                    self._unlink_owned_leaf(final, parent=self.files.root)
                except BridgeError:
                    pass
            try:
                self._unlink_owned_leaf(marker, parent=self.output_dir)
            except BridgeError:
                pass

    def build(self, file_refs: Iterable[str], *, archive_name: str = "telegram-files.zip") -> FileRecord:
        with self._archive_lock():
            self._reconcile_pending()
            return self._build_locked(file_refs, archive_name=archive_name)
