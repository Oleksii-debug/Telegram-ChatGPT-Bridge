"""Descriptor-bound access to registered private files.

The file registry intentionally exposes opaque references, not filesystem paths.
This module closes path time-of-check/time-of-use gaps for callers that must
stream or upload registered files after their registry metadata has been checked.
"""

from __future__ import annotations

import hashlib
import io
import os
import re
import secrets
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO, Iterator, Sequence

from .filenames import safe_filename
from .storage import FileRecord, FileRecordStore

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_DEFAULT_SEND_FILE_BYTES = 100 * 1024 * 1024
_DEFAULT_SEND_TOTAL_BYTES = 250 * 1024 * 1024


@dataclass
class VerifiedPrivateFile:
    """A registry record pinned to one already-verified open file descriptor."""

    record: FileRecord
    handle: BinaryIO

    def close(self) -> None:
        if not self.handle.closed:
            self.handle.close()


@dataclass(frozen=True)
class UploadFileIdentity:
    """Expected public identity for one file selected for an external upload."""

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
    """Read-only verified snapshot suitable for a Telegram file-like upload.

    The source registry inode is copied before any external effect into an
    unnamed owner-private temporary stream while size/SHA-256 are revalidated.
    The resulting standard ``io.IOBase`` object is independent from later
    pathname replacement *and* in-place mutation of the registered source.

    Only safe upload metadata is copied onto the wrapper. There is no filesystem
    path property; ``name`` is a sanitized display filename.
    """

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
    def from_verified(
        cls,
        verified: VerifiedPrivateFile,
        *,
        snapshot_dir: Path,
    ) -> "VerifiedUploadFile | None":
        """Copy one verified source into a pathless snapshot and verify the copy."""

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

            if total != record.size:
                return None
            if not secrets.compare_digest(digest.hexdigest(), record.sha256):
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
        return self._handle.fileno()

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
    """Own a complete set of immutable upload snapshots as one lifetime boundary."""

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

    def __getitem__(self, index: int) -> VerifiedUploadFile:
        return self._files[index]

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        for upload in self._files:
            try:
                upload.close()
            except Exception:
                pass

    def __enter__(self) -> "VerifiedUploadBatch":
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.close()


def _directory_flags() -> int:
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    return flags


def _file_flags() -> int:
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    return flags


def _private_directory(info: os.stat_result) -> bool:
    if not stat.S_ISDIR(info.st_mode):
        return False
    if hasattr(os, "getuid") and info.st_uid != os.getuid():
        return False
    return stat.S_IMODE(info.st_mode) & 0o077 == 0


def _open_beneath_private_root(root: Path, relative: Path) -> int:
    """Open ``relative`` beneath ``root`` without following symlink components."""

    parts = relative.parts
    if not parts or any(part in {"", ".", ".."} for part in parts):
        raise OSError("unsafe relative private file path")

    current_fd = os.open(root, _directory_flags())
    try:
        if not _private_directory(os.fstat(current_fd)):
            raise OSError("private file root is not owner-private")
        for component in parts[:-1]:
            next_fd = os.open(component, _directory_flags(), dir_fd=current_fd)
            try:
                if not _private_directory(os.fstat(next_fd)):
                    raise OSError("private file directory is not owner-private")
            except Exception:
                os.close(next_fd)
                raise
            os.close(current_fd)
            current_fd = next_fd
        return os.open(parts[-1], _file_flags(), dir_fd=current_fd)
    finally:
        os.close(current_fd)


def _hash_handle(handle: BinaryIO, *, expected_size: int) -> str | None:
    digest = hashlib.sha256()
    total = 0
    handle.seek(0)
    while True:
        chunk = handle.read(1024 * 1024)
        if not chunk:
            break
        total += len(chunk)
        if total > expected_size:
            return None
        digest.update(chunk)
    if total != expected_size:
        return None
    handle.seek(0)
    return digest.hexdigest()


def open_verified_file(store: FileRecordStore, file_ref: str) -> VerifiedPrivateFile | None:
    """Return an open descriptor that remains bound to the verified file inode.

    ``FileRecordStore.get`` revalidates registry topology/hash first. We then
    open the recorded path through owner-private directory descriptors with
    ``O_NOFOLLOW`` where available and independently revalidate topology,
    size and SHA-256 on that exact descriptor. Callers must stream from the
    returned handle rather than reopen ``record.path``.
    """

    record = store.get(file_ref)
    if record is None:
        return None
    try:
        relative = Path(record.path).relative_to(store.root)
    except ValueError:
        return None

    fd: int | None = None
    handle: BinaryIO | None = None
    try:
        fd = _open_beneath_private_root(store.root, relative)
        info_before = os.fstat(fd)
        if not stat.S_ISREG(info_before.st_mode) or info_before.st_nlink != 1:
            return None
        if hasattr(os, "getuid") and info_before.st_uid != os.getuid():
            return None
        if info_before.st_size != record.size:
            return None

        handle = os.fdopen(fd, "rb", closefd=True)
        fd = None
        digest = _hash_handle(handle, expected_size=record.size)
        if digest is None or not secrets.compare_digest(digest, record.sha256):
            handle.close()
            return None

        info_after = os.fstat(handle.fileno())
        if (
            info_after.st_dev != info_before.st_dev
            or info_after.st_ino != info_before.st_ino
            or info_after.st_nlink != 1
            or info_after.st_size != record.size
        ):
            handle.close()
            return None
        return VerifiedPrivateFile(record=record, handle=handle)
    except (OSError, ValueError):
        if handle is not None and not handle.closed:
            handle.close()
        return None
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass


def open_verified_upload_batch(
    store: FileRecordStore,
    identities: Sequence[UploadFileIdentity],
    *,
    max_files: int = 10,
    max_file_bytes: int = _DEFAULT_SEND_FILE_BYTES,
    max_total_bytes: int = _DEFAULT_SEND_TOTAL_BYTES,
) -> VerifiedUploadBatch | None:
    """Create an immutable verified SEND_FILES-style snapshot batch pre-effect.

    Shape/size limits mirror the canonical private send-files policy by default.
    Each registered source is descriptor-verified and then copied into a private
    unnamed snapshot with another exact size/SHA-256 check. If any member fails,
    all snapshots created so far are closed before returning ``None``.
    """

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
            upload = VerifiedUploadFile.from_verified(
                verified,
                snapshot_dir=store.root,
            )
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
        # Ownership transfers only after the complete batch has been assembled.
        if len(opened) != len(identities):
            for upload in opened:
                try:
                    upload.close()
                except Exception:
                    pass
