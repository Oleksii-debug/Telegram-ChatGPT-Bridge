"""Traversal-safe ZIP creation for files already in private storage.

Archive construction is synchronous because it operates on owner-controlled local
regular files. The builder still enforces a bounded cooperative deadline and an
optional cancellation signal at every chunk/member boundary. Cancellation is
honored only before private-file registry commit begins; once registration starts,
the operation is allowed to finish rather than report a cancelled result after a
durable effect.
"""

from __future__ import annotations

import hashlib
import os
import secrets
import stat
import time
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable

from .errors import BridgeError
from .filenames import filename_collision_key, safe_filename
from .storage import FileRecord, FileRecordStore


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
    max_build_seconds: float = 120.0
    compression: int = zipfile.ZIP_DEFLATED

    def __post_init__(self) -> None:
        if (
            isinstance(self.max_members, bool)
            or isinstance(self.max_total_bytes, bool)
            or isinstance(self.max_build_seconds, bool)
            or not 1 <= self.max_members <= 500
            or self.max_total_bytes <= 0
            or not isinstance(self.max_build_seconds, (int, float))
            or not 0.1 <= float(self.max_build_seconds) <= 600.0
            or self.compression not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED, zipfile.ZIP_BZIP2, zipfile.ZIP_LZMA}
        ):
            raise ValueError("invalid archive limits")


class ArchiveBuilder:
    _CHUNK_BYTES = 1024 * 1024

    def __init__(
        self,
        *,
        files: FileRecordStore,
        output_dir: Path,
        limits: ArchiveLimits | None = None,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self.files = files
        self.output_dir = output_dir.resolve()
        self.limits = limits or ArchiveLimits()
        if not callable(monotonic):
            raise ValueError("monotonic clock is required")
        self.monotonic = monotonic
        self.output_dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.output_dir, 0o700)
        except OSError:
            pass

    def _check_liveness(self, *, deadline: float, cancelled: Callable[[], bool] | None) -> None:
        if cancelled is not None:
            try:
                stop = cancelled()
            except Exception as exc:
                raise BridgeError(
                    "Archive cancellation state is unavailable",
                    status=503,
                    code="archive_cancellation_check_failed",
                    details={"retryable": True},
                ) from exc
            if not isinstance(stop, bool):
                raise BridgeError(
                    "Archive cancellation state is invalid",
                    status=503,
                    code="archive_cancellation_check_failed",
                    details={"retryable": True},
                )
            if stop:
                raise BridgeError(
                    "Archive build cancelled",
                    status=409,
                    code="archive_cancelled",
                    details={"retryable": True},
                )
        if self.monotonic() >= deadline:
            raise BridgeError(
                "Archive build timed out",
                status=504,
                code="archive_timeout",
                details={"retryable": True},
            )

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

    def _write_record(
        self,
        zf: zipfile.ZipFile,
        record: FileRecord,
        *,
        arcname: str,
        deadline: float,
        cancelled: Callable[[], bool] | None,
    ) -> None:
        """Stream from a verified descriptor and re-check hash/size while writing."""
        self._check_liveness(deadline=deadline, cancelled=cancelled)
        fd = self._open_source(record)
        digest = hashlib.sha256()
        total = 0
        info = zipfile.ZipInfo(filename=arcname)
        info.compress_type = self.limits.compression
        info.external_attr = 0o600 << 16
        try:
            with os.fdopen(fd, "rb", closefd=True) as source, zf.open(info, "w") as destination:
                while True:
                    self._check_liveness(deadline=deadline, cancelled=cancelled)
                    chunk = source.read(self._CHUNK_BYTES)
                    self._check_liveness(deadline=deadline, cancelled=cancelled)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > record.size:
                        raise BridgeError("Archive source size changed", status=409, code="archive_source_changed")
                    digest.update(chunk)
                    destination.write(chunk)
                    self._check_liveness(deadline=deadline, cancelled=cancelled)
        except BridgeError:
            raise
        except OSError as exc:
            raise BridgeError("Archive source read failed", status=409, code="archive_source_changed") from exc
        if total != record.size or not secrets.compare_digest(digest.hexdigest(), record.sha256):
            raise BridgeError("Archive source integrity changed", status=409, code="archive_source_changed")

    def _validate_member(
        self,
        zf: zipfile.ZipFile,
        info: zipfile.ZipInfo,
        *,
        deadline: float,
        cancelled: Callable[[], bool] | None,
    ) -> None:
        """Read one member to EOF so ZipExtFile verifies CRC cooperatively."""
        try:
            with zf.open(info, "r") as member:
                while True:
                    self._check_liveness(deadline=deadline, cancelled=cancelled)
                    chunk = member.read(self._CHUNK_BYTES)
                    self._check_liveness(deadline=deadline, cancelled=cancelled)
                    if not chunk:
                        return
        except BridgeError:
            raise
        except (OSError, EOFError, RuntimeError, zipfile.BadZipFile) as exc:
            raise BridgeError("Archive CRC validation failed", status=500, code="zip_crc_failed") from exc

    def build(
        self,
        file_refs: Iterable[str],
        *,
        archive_name: str = "telegram-files.zip",
        cancelled: Callable[[], bool] | None = None,
    ) -> FileRecord:
        if cancelled is not None and not callable(cancelled):
            raise BridgeError(
                "Archive cancellation state is invalid",
                status=503,
                code="archive_cancellation_check_failed",
                details={"retryable": True},
            )
        deadline = self.monotonic() + float(self.limits.max_build_seconds)
        self._check_liveness(deadline=deadline, cancelled=cancelled)
        refs = list(dict.fromkeys(file_refs))
        if not refs:
            raise BridgeError("No files selected", code="empty_archive")
        if len(refs) > self.limits.max_members:
            raise BridgeError("Archive member limit exceeded", status=413, code="zip_member_limit")
        records: list[FileRecord] = []
        total = 0
        for ref in refs:
            self._check_liveness(deadline=deadline, cancelled=cancelled)
            record = self.files.get(ref)
            self._check_liveness(deadline=deadline, cancelled=cancelled)
            if record is None:
                raise BridgeError("Archive source file not found", status=404, code="file_not_found")
            total += record.size
            if total > self.limits.max_total_bytes:
                raise BridgeError("Archive size limit exceeded", status=413, code="zip_size_limit")
            records.append(record)
        target = self.output_dir / f"archive_{secrets.token_hex(20)}.zip.part"
        final = self.files.root / f"{secrets.token_hex(20)}.zip"
        used: set[str] = set()
        registered = False
        try:
            self._check_liveness(deadline=deadline, cancelled=cancelled)
            with zipfile.ZipFile(target, "w", compression=self.limits.compression, allowZip64=False) as zf:
                for record in records:
                    self._check_liveness(deadline=deadline, cancelled=cancelled)
                    arcname = unique_name(record.name, used)
                    self._write_record(
                        zf,
                        record,
                        arcname=arcname,
                        deadline=deadline,
                        cancelled=cancelled,
                    )
            self._check_liveness(deadline=deadline, cancelled=cancelled)
            with zipfile.ZipFile(target, "r") as zf:
                infos = zf.infolist()
                if len(infos) != len(records):
                    raise BridgeError("Archive validation failed", status=500, code="zip_validation_failed")
                member_keys: set[str] = set()
                for info in infos:
                    self._check_liveness(deadline=deadline, cancelled=cancelled)
                    name = info.filename
                    if name.startswith("/") or name.startswith("\\") or ".." in Path(name).parts:
                        raise BridgeError("Unsafe archive member", status=500, code="unsafe_zip_member")
                    key = _collision_key(name)
                    if key in member_keys:
                        raise BridgeError("Archive member collision", status=500, code="zip_member_collision")
                    member_keys.add(key)
                    self._validate_member(zf, info, deadline=deadline, cancelled=cancelled)
            self._check_liveness(deadline=deadline, cancelled=cancelled)
            target.replace(final)
            try:
                os.chmod(final, 0o600)
            except OSError:
                pass
            self._check_liveness(deadline=deadline, cancelled=cancelled)
            # This is the local durable-effect boundary. FileRecordStore.add()
            # validates/hashes and commits registry state. Do not report a
            # cancellation after this call starts: the caller must receive the
            # durable success rather than retry a completed local effect.
            record = self.files.add(final, name=safe_archive_name(archive_name), mime_type="application/zip")
            registered = True
            return record
        finally:
            try:
                if target.exists():
                    target.unlink()
            except OSError:
                pass
            if not registered:
                try:
                    if final.exists() and final.is_file():
                        final.unlink()
                except OSError:
                    pass
