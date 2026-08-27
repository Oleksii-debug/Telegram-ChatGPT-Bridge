"""Descriptor-bound access to registered private files.

The file registry intentionally exposes opaque references, not filesystem paths.
This module closes path time-of-check/time-of-use gaps for callers that must
stream a registered file after its registry metadata has been checked.
"""

from __future__ import annotations

import hashlib
import os
import secrets
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from .storage import FileRecord, FileRecordStore


@dataclass
class VerifiedPrivateFile:
    """A registry record pinned to one immutable-by-path verified byte snapshot."""

    record: FileRecord
    handle: BinaryIO

    def close(self) -> None:
        if not self.handle.closed:
            self.handle.close()


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


def _snapshot_verified_handle(
    source: BinaryIO,
    *,
    expected_size: int,
    expected_sha256: str,
    snapshot_dir: Path,
) -> BinaryIO | None:
    """Copy and verify source bytes into an unlinked private snapshot."""

    digest = hashlib.sha256()
    total = 0
    snapshot: BinaryIO | None = None
    try:
        snapshot = tempfile.TemporaryFile(mode="w+b", dir=snapshot_dir)
        source.seek(0)
        while True:
            chunk = source.read(1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > expected_size:
                snapshot.close()
                return None
            digest.update(chunk)
            snapshot.write(chunk)
        if total != expected_size or not secrets.compare_digest(digest.hexdigest(), expected_sha256):
            snapshot.close()
            return None
        snapshot.flush()
        os.fsync(snapshot.fileno())
        snapshot.seek(0)
        return snapshot
    except (OSError, ValueError):
        if snapshot is not None and not snapshot.closed:
            snapshot.close()
        return None


def open_verified_file(store: FileRecordStore, file_ref: str) -> VerifiedPrivateFile | None:
    """Return a verified private byte snapshot for streaming.

    ``FileRecordStore.get`` revalidates registry topology/hash first. We then
    open the recorded path through owner-private directory descriptors with
    ``O_NOFOLLOW`` where available and independently validate topology and
    identity on that exact descriptor. Bytes are copied while hashing into an
    unlinked private temporary file, so later writes to the registered inode
    cannot alter the returned stream.
    """

    record = store.get(file_ref)
    if record is None:
        return None
    try:
        relative = Path(record.path).relative_to(store.root)
    except ValueError:
        return None

    fd: int | None = None
    source: BinaryIO | None = None
    snapshot: BinaryIO | None = None
    try:
        fd = _open_beneath_private_root(store.root, relative)
        info_before = os.fstat(fd)
        if not stat.S_ISREG(info_before.st_mode) or info_before.st_nlink != 1:
            return None
        if hasattr(os, "getuid") and info_before.st_uid != os.getuid():
            return None
        if info_before.st_size != record.size:
            return None

        source = os.fdopen(fd, "rb", closefd=True)
        fd = None
        snapshot = _snapshot_verified_handle(
            source,
            expected_size=record.size,
            expected_sha256=record.sha256,
            snapshot_dir=store.root,
        )
        if snapshot is None:
            return None

        info_after = os.fstat(source.fileno())
        if (
            info_after.st_dev != info_before.st_dev
            or info_after.st_ino != info_before.st_ino
            or info_after.st_nlink != 1
            or info_after.st_size != record.size
        ):
            snapshot.close()
            return None
        source.close()
        source = None
        return VerifiedPrivateFile(record=record, handle=snapshot)
    except (OSError, ValueError):
        if snapshot is not None and not snapshot.closed:
            snapshot.close()
        return None
    finally:
        if source is not None and not source.closed:
            source.close()
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
