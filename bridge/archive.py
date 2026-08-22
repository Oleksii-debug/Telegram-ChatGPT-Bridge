"""Traversal-safe ZIP creation for files already in private storage."""

from __future__ import annotations

import os
import re
import secrets
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from .errors import BridgeError
from .storage import FileRecord, FileRecordStore


def safe_archive_name(name: str) -> str:
    candidate = name.replace("\\", "/").split("/")[-1]
    candidate = re.sub(r"[\x00-\x1f<>:\"|?*]+", "_", candidate)
    candidate = candidate.strip(" .") or "file"
    if candidate in {".", ".."}:
        candidate = "file"
    return candidate[:180]


def unique_name(name: str, used: set[str]) -> str:
    base = safe_archive_name(name)
    stem = Path(base).stem or "file"
    suffix = Path(base).suffix
    candidate = base
    index = 2
    while candidate.casefold() in used:
        candidate = f"{stem} ({index}){suffix}"
        index += 1
    used.add(candidate.casefold())
    return candidate


@dataclass(frozen=True)
class ArchiveLimits:
    max_members: int = 200
    max_total_bytes: int = 750 * 1024 * 1024
    compression: int = zipfile.ZIP_DEFLATED


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

    def build(self, file_refs: Iterable[str], *, archive_name: str = "telegram-files.zip") -> FileRecord:
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
        target = self.output_dir / f"archive_{secrets.token_hex(20)}.zip.part"
        final = self.files.root / f"{secrets.token_hex(20)}.zip"
        used: set[str] = set()
        try:
            with zipfile.ZipFile(target, "w", compression=self.limits.compression, allowZip64=False) as zf:
                for record in records:
                    arcname = unique_name(record.name, used)
                    zf.write(record.path, arcname=arcname)
            with zipfile.ZipFile(target, "r") as zf:
                if len(zf.infolist()) != len(records):
                    raise BridgeError("Archive validation failed", status=500, code="zip_validation_failed")
                bad = zf.testzip()
                if bad is not None:
                    raise BridgeError("Archive CRC validation failed", status=500, code="zip_crc_failed")
                for info in zf.infolist():
                    name = info.filename
                    if name.startswith("/") or name.startswith("\\") or ".." in Path(name).parts:
                        raise BridgeError("Unsafe archive member", status=500, code="unsafe_zip_member")
            target.replace(final)
            try:
                os.chmod(final, 0o600)
            except OSError:
                pass
            return self.files.add(final, name=safe_archive_name(archive_name), mime_type="application/zip")
        finally:
            try:
                if target.exists():
                    target.unlink()
            except OSError:
                pass
