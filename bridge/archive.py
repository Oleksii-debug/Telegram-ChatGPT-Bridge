"""Traversal-safe ZIP creation for files already in private storage."""

from __future__ import annotations

import hashlib
import os
import secrets
import stat
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

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
    def __init__(self, *, files: FileRecordStore, output_dir: Path, limits: ArchiveLimits | None = None) -> None:
        self.files = files
        self.output_dir = output_dir.resolve()
        self.limits = limits or ArchiveLimits()
        self.output_dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.output_dir, 0o700)
        except OSError:
            pass

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

    def build(self, file_refs: Iterable[str], *, archive_name: str = "telegram-files.zip") -> FileRecord:
        refs = list(file_refs)
        # The public Action schema declares file_refs uniqueItems=true. Runtime
        # must reject a duplicate instead of silently normalizing it away.
        if len(refs) != len(dict.fromkeys(refs)):
            raise BridgeError("Duplicate archive file reference", code="invalid_list")
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
        target = self.output_dir / f"archive_{secrets.token_hex(20)}.zip.part"
        final = self.files.root / f"{secrets.token_hex(20)}.zip"
        used: set[str] = set()
        registered = False
        try:
            with zipfile.ZipFile(target, "w", compression=self.limits.compression, allowZip64=False) as zf:
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
