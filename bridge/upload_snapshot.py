"""Immutable descriptor-backed snapshots for Telegram SEND_FILES.

Production composition uses this module to bind a commit-approved opaque file
identity to exact bytes before any mutating Telegram RPC.  It builds on the
canonical descriptor-bound ``open_verified_file`` primitive and never exposes a
filesystem path or writable file descriptor to the writer.
"""
from __future__ import annotations

import hashlib
import io
import os
import re
import secrets
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO, Iterator, Sequence

from .file_access import VerifiedPrivateFile, open_verified_file
from .filenames import safe_filename
from .storage import FileRecordStore

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_DEFAULT_SEND_FILE_BYTES = 100 * 1024 * 1024
_DEFAULT_SEND_TOTAL_BYTES = 250 * 1024 * 1024


@dataclass(frozen=True)
class UploadFileIdentity:
    file_ref: str
    sha256: str
    size: int

    def __post_init__(self) -> None:
        if not isinstance(self.file_ref, str) or not self.file_ref:
            raise ValueError("file_ref is required")
        if not isinstance(self.sha256, str) or not _SHA256_RE.fullmatch(self.sha256):
            raise ValueError("sha256 must be lowercase hex")
        if isinstance(self.size, bool) or not isinstance(self.size, int) or self.size <= 0:
            raise ValueError("size must be a positive integer")


class VerifiedUploadFile(io.BufferedIOBase):
    """Read-only pathless snapshot whose bytes have been re-hashed pre-effect."""

    def __init__(
        self,
        handle: BinaryIO,
        *,
        file_ref: str,
        sha256: str,
        size: int,
        mime_type: str,
        name: str,
    ) -> None:
        super().__init__()
        self._handle = handle
        self.file_ref = file_ref
        self.sha256 = sha256
        self.size = size
        self.mime_type = mime_type
        self.name = safe_filename(name)

    @classmethod
    def from_verified(cls, verified: VerifiedPrivateFile, *, snapshot_dir: Path) -> "VerifiedUploadFile | None":
        record = verified.record
        snapshot: BinaryIO | None = None
        digest = hashlib.sha256()
        total = 0
        try:
            snapshot = tempfile.TemporaryFile(mode="w+b", dir=str(snapshot_dir))
            try:
                os.fchmod(snapshot.fileno(), 0o600)
            except OSError:
                pass
            verified.handle.seek(0)
            while True:
                chunk = verified.handle.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > record.size:
                    return None
                snapshot.write(chunk)
                digest.update(chunk)
            if total != record.size or not secrets.compare_digest(digest.hexdigest(), record.sha256):
                return None
            snapshot.flush()
            snapshot.seek(0)
            result = cls(
                snapshot,
                file_ref=record.file_ref,
                sha256=record.sha256,
                size=record.size,
                mime_type=record.mime_type,
                name=record.name,
            )
            snapshot = None
            return result
        except (OSError, ValueError):
            return None
        finally:
            verified.close()
            if snapshot is not None:
                try:
                    snapshot.close()
                except Exception:
                    pass

    def read(self, size: int = -1) -> bytes:
        self._checkClosed()
        return self._handle.read(size)

    def readinto(self, buffer: Any) -> int:
        self._checkClosed()
        return self._handle.readinto(buffer)

    def seek(self, offset: int, whence: int = os.SEEK_SET) -> int:
        self._checkClosed()
        return self._handle.seek(offset, whence)

    def tell(self) -> int:
        self._checkClosed()
        return self._handle.tell()

    def fileno(self) -> int:
        self._checkClosed()
        raise io.UnsupportedOperation("verified upload snapshot descriptor is private")

    def readable(self) -> bool:
        return not self.closed and self._handle.readable()

    def seekable(self) -> bool:
        return not self.closed and self._handle.seekable()

    def writable(self) -> bool:
        return False

    def close(self) -> None:
        if self.closed:
            return
        try:
            if not self._handle.closed:
                self._handle.close()
        finally:
            super().close()


class VerifiedUploadBatch:
    def __init__(self, files: Sequence[VerifiedUploadFile]) -> None:
        self._files = tuple(files)
        self._closed = False

    @property
    def files(self) -> tuple[VerifiedUploadFile, ...]:
        return self._files

    @property
    def closed(self) -> bool:
        return self._closed

    def __len__(self) -> int:
        return len(self._files)

    def __iter__(self) -> Iterator[VerifiedUploadFile]:
        return iter(self._files)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        for upload in self._files:
            try:
                upload.close()
            except Exception:
                pass


def open_verified_upload_batch(
    store: FileRecordStore,
    identities: Sequence[UploadFileIdentity],
    *,
    max_files: int = 10,
    max_file_bytes: int = _DEFAULT_SEND_FILE_BYTES,
    max_total_bytes: int = _DEFAULT_SEND_TOTAL_BYTES,
) -> VerifiedUploadBatch | None:
    if isinstance(identities, (str, bytes)) or not isinstance(identities, Sequence):
        raise ValueError("identities must be a sequence")
    if isinstance(max_files, bool) or not isinstance(max_files, int) or max_files <= 0:
        raise ValueError("max_files must be positive")
    if (
        isinstance(max_file_bytes, bool)
        or not isinstance(max_file_bytes, int)
        or max_file_bytes <= 0
        or isinstance(max_total_bytes, bool)
        or not isinstance(max_total_bytes, int)
        or max_total_bytes <= 0
    ):
        raise ValueError("bounded upload byte policy required")
    if not identities or len(identities) > max_files:
        raise ValueError("invalid upload file count")
    if any(not isinstance(item, UploadFileIdentity) for item in identities):
        raise ValueError("invalid upload identity")
    if any(item.size > max_file_bytes for item in identities):
        raise ValueError("upload file too large")
    if sum(item.size for item in identities) > max_total_bytes:
        raise ValueError("upload batch too large")
    refs = [item.file_ref for item in identities]
    if len(set(refs)) != len(refs):
        raise ValueError("duplicate upload file_ref")

    opened: list[VerifiedUploadFile] = []
    try:
        for identity in identities:
            verified = open_verified_file(store, identity.file_ref)
            if verified is None:
                return None
            upload = VerifiedUploadFile.from_verified(verified, snapshot_dir=store.root)
            if upload is None:
                return None
            if (
                upload.file_ref != identity.file_ref
                or upload.size != identity.size
                or not secrets.compare_digest(upload.sha256, identity.sha256)
            ):
                upload.close()
                return None
            opened.append(upload)
        return VerifiedUploadBatch(opened)
    finally:
        if len(opened) != len(identities):
            for upload in opened:
                try:
                    upload.close()
                except Exception:
                    pass


__all__ = [
    "UploadFileIdentity",
    "VerifiedUploadBatch",
    "VerifiedUploadFile",
    "open_verified_upload_batch",
]
