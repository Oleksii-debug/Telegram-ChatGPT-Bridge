# -*- coding: utf-8 -*-
"""TOCTOU-resistant owner-private HOSTiQ control/evidence primitives.

Reads, writes and executable opens are descriptor-relative with O_NOFOLLOW and
identity checks. Private evidence writes are no-clobber: a final path is created
by hard-linking an already-fsynced private temporary inode, so an existing
symlink/file can never be silently replaced. Callers may retain an immutable
file-identity snapshot to bind later state transitions to the exact inode read.
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path

from ops.release_guard import SafetyError

_REQUIRED_FLAGS = ("O_NOFOLLOW", "O_DIRECTORY")
MAX_PRIVATE_TEXT_BYTES = 4096
MAX_PRIVATE_JSON_BYTES = 64 * 1024


@dataclass(frozen=True)
class PrivateFileIdentity:
    dev: int
    ino: int
    size: int
    uid: int
    mode: int
    nlink: int
    mtime_ns: int
    ctime_ns: int


def _require_posix_primitives() -> None:
    if os.name != "posix" or any(not hasattr(os, name) for name in _REQUIRED_FLAGS):
        raise SafetyError("required POSIX private-control primitives unavailable")


def _private_dir_stat_ok(st: os.stat_result, *, writable: bool = False) -> bool:
    mode = stat.S_IMODE(st.st_mode)
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.getuid() or mode & 0o077:
        return False
    if writable and not (mode & stat.S_IWUSR and mode & stat.S_IXUSR):
        return False
    return True


def _private_file_stat_ok(st: os.stat_result, *, require_executable: bool, allow_empty: bool) -> bool:
    mode = stat.S_IMODE(st.st_mode)
    if not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid() or st.st_nlink != 1 or mode & 0o077:
        return False
    if require_executable and not (mode & stat.S_IXUSR):
        return False
    if not allow_empty and st.st_size == 0:
        return False
    return True


def _same_identity(before: os.stat_result, after: os.stat_result) -> bool:
    return before.st_dev == after.st_dev and before.st_ino == after.st_ino


def _identity(st: os.stat_result) -> PrivateFileIdentity:
    return PrivateFileIdentity(
        dev=int(st.st_dev),
        ino=int(st.st_ino),
        size=int(st.st_size),
        uid=int(st.st_uid),
        mode=int(stat.S_IMODE(st.st_mode)),
        nlink=int(st.st_nlink),
        mtime_ns=int(st.st_mtime_ns),
        ctime_ns=int(st.st_ctime_ns),
    )


def private_identity_sha256(identity: PrivateFileIdentity) -> str:
    if not isinstance(identity, PrivateFileIdentity):
        raise SafetyError("private file identity invalid")
    raw = (
        f"{identity.dev}:{identity.ino}:{identity.size}:{identity.uid}:"
        f"{identity.mode}:{identity.nlink}:{identity.mtime_ns}:{identity.ctime_ns}"
    ).encode("ascii")
    return hashlib.sha256(raw).hexdigest()


def _identity_matches_stat(identity: PrivateFileIdentity, st: os.stat_result) -> bool:
    observed = _identity(st)
    return observed == identity


def _canonical_relative(root: Path, path: Path) -> tuple[Path, tuple[str, ...]]:
    root = Path(os.path.abspath(os.fspath(root.expanduser())))
    path = Path(os.path.abspath(os.fspath(path.expanduser())))
    try:
        rel = path.relative_to(root)
    except ValueError as exc:
        raise SafetyError("private control path escapes root") from exc
    parts = rel.parts
    if not parts or any(part in {"", ".", ".."} for part in parts):
        raise SafetyError("private control relative path invalid")
    return root, parts


def open_private_directory_fd(path: Path, *, create: bool = False, writable: bool = False) -> tuple[int, os.stat_result]:
    """Open one owner-private directory and bind its pathname to an fd identity."""
    _require_posix_primitives()
    path = Path(os.path.abspath(os.fspath(path.expanduser())))
    if create:
        try:
            os.mkdir(path, 0o700)
        except FileExistsError:
            pass
        except OSError as exc:
            raise SafetyError("private directory creation failed") from exc
    try:
        before = os.lstat(path)
    except OSError as exc:
        raise SafetyError("private directory unavailable") from exc
    if stat.S_ISLNK(before.st_mode) or not _private_dir_stat_ok(before, writable=writable):
        raise SafetyError("private directory unsafe")
    flags = os.O_RDONLY | int(getattr(os, "O_DIRECTORY")) | int(getattr(os, "O_NOFOLLOW")) | int(getattr(os, "O_CLOEXEC", 0))
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise SafetyError("private directory open failed") from exc
    after = os.fstat(fd)
    if not _private_dir_stat_ok(after, writable=writable) or not _same_identity(before, after):
        os.close(fd)
        raise SafetyError("private directory changed during open")
    return fd, after


def open_private_fd(
    root: Path,
    path: Path,
    *,
    require_executable: bool = False,
    allow_empty: bool = False,
) -> int:
    """Open one private regular file and return a validated read-only fd."""
    _require_posix_primitives()
    root, parts = _canonical_relative(root, path)
    nofollow = int(getattr(os, "O_NOFOLLOW"))
    directory = int(getattr(os, "O_DIRECTORY"))
    cloexec = int(getattr(os, "O_CLOEXEC", 0))

    root_before = os.lstat(root)
    if not _private_dir_stat_ok(root_before) or stat.S_ISLNK(root_before.st_mode):
        raise SafetyError("private control root unsafe")
    root_fd = os.open(root, os.O_RDONLY | directory | nofollow | cloexec)
    opened_dirs = [root_fd]
    try:
        root_after = os.fstat(root_fd)
        if not _private_dir_stat_ok(root_after) or not _same_identity(root_before, root_after):
            raise SafetyError("private control root changed during open")
        current_fd = root_fd
        for part in parts[:-1]:
            before = os.stat(part, dir_fd=current_fd, follow_symlinks=False)
            if stat.S_ISLNK(before.st_mode) or not _private_dir_stat_ok(before):
                raise SafetyError("private control directory component unsafe")
            next_fd = os.open(part, os.O_RDONLY | directory | nofollow | cloexec, dir_fd=current_fd)
            after = os.fstat(next_fd)
            if not _private_dir_stat_ok(after) or not _same_identity(before, after):
                os.close(next_fd)
                raise SafetyError("private control directory changed during open")
            opened_dirs.append(next_fd)
            current_fd = next_fd

        leaf = parts[-1]
        before = os.stat(leaf, dir_fd=current_fd, follow_symlinks=False)
        if stat.S_ISLNK(before.st_mode) or not _private_file_stat_ok(before, require_executable=require_executable, allow_empty=allow_empty):
            raise SafetyError("private control file unsafe")
        fd = os.open(leaf, os.O_RDONLY | nofollow | cloexec, dir_fd=current_fd)
        after = os.fstat(fd)
        if not _private_file_stat_ok(after, require_executable=require_executable, allow_empty=allow_empty) or not _same_identity(before, after):
            os.close(fd)
            raise SafetyError("private control file changed during open")
        return fd
    finally:
        for directory_fd in reversed(opened_dirs):
            try:
                os.close(directory_fd)
            except OSError:
                pass


def validate_private_file(
    root: Path,
    path: Path,
    *,
    require_executable: bool = False,
    allow_empty: bool = False,
) -> Path:
    fd = open_private_fd(root, path, require_executable=require_executable, allow_empty=allow_empty)
    os.close(fd)
    return Path(os.path.abspath(os.fspath(path.expanduser())))


def _read_fd_text(fd: int, *, max_bytes: int) -> str:
    chunks: list[bytes] = []
    total = 0
    while True:
        block = os.read(fd, min(1024, max_bytes + 1 - total))
        if not block:
            break
        chunks.append(block)
        total += len(block)
        if total > max_bytes:
            raise SafetyError("private control text too large")
    try:
        return b"".join(chunks).decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        raise SafetyError("private control text encoding invalid") from exc


def read_private_text_with_identity(
    root: Path,
    path: Path,
    *,
    max_bytes: int = MAX_PRIVATE_TEXT_BYTES,
) -> tuple[str, PrivateFileIdentity]:
    if not isinstance(max_bytes, int) or isinstance(max_bytes, bool) or not 1 <= max_bytes <= MAX_PRIVATE_JSON_BYTES:
        raise SafetyError("private text byte bound invalid")
    fd = open_private_fd(root, path)
    try:
        before = os.fstat(fd)
        text = _read_fd_text(fd, max_bytes=max_bytes)
        after = os.fstat(fd)
        # In-place mutation of the accepted inode is also a state change.
        if _identity(before) != _identity(after):
            raise SafetyError("private control file changed during read")
        return text, _identity(after)
    finally:
        os.close(fd)


def read_private_text(root: Path, path: Path, *, max_bytes: int = MAX_PRIVATE_TEXT_BYTES) -> str:
    text, _ = read_private_text_with_identity(root, path, max_bytes=max_bytes)
    return text


def verify_private_file_identity(root: Path, path: Path, expected: PrivateFileIdentity) -> None:
    """Fail unless the current pathname still names the exact accepted inode/state."""
    fd = open_private_fd(root, path)
    try:
        observed = os.fstat(fd)
        if not _identity_matches_stat(expected, observed):
            raise SafetyError("private control file identity changed")
    finally:
        os.close(fd)


def _write_all(fd: int, raw: bytes) -> None:
    offset = 0
    while offset < len(raw):
        written = os.write(fd, raw[offset:])
        if written <= 0:
            raise SafetyError("private evidence write failed")
        offset += written


def write_private_bytes_no_clobber(root: Path, path: Path, raw: bytes, *, max_bytes: int = MAX_PRIVATE_JSON_BYTES) -> PrivateFileIdentity:
    """Create one private direct-child file without following or replacing names."""
    if not isinstance(raw, bytes) or not raw or len(raw) > max_bytes:
        raise SafetyError("private evidence payload size invalid")
    root, parts = _canonical_relative(root, path)
    if len(parts) != 1:
        raise SafetyError("private evidence write must target a direct child")
    leaf = parts[0]
    root_fd, root_identity = open_private_directory_fd(root, create=True, writable=True)
    nofollow = int(getattr(os, "O_NOFOLLOW"))
    cloexec = int(getattr(os, "O_CLOEXEC", 0))
    temp = f".{leaf}.{secrets.token_hex(12)}.tmp"
    temp_fd: int | None = None
    linked = False
    temp_stat: os.stat_result | None = None
    try:
        try:
            os.stat(leaf, dir_fd=root_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise SafetyError("private evidence final path already exists")

        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | nofollow | cloexec
        try:
            temp_fd = os.open(temp, flags, 0o600, dir_fd=root_fd)
        except OSError as exc:
            raise SafetyError("private evidence temporary create failed") from exc
        _write_all(temp_fd, raw)
        os.fsync(temp_fd)
        temp_stat = os.fstat(temp_fd)
        if not _private_file_stat_ok(temp_stat, require_executable=False, allow_empty=False) or temp_stat.st_size != len(raw):
            raise SafetyError("private evidence temporary validation failed")

        # link() is atomic no-clobber for the final name; unlike replace()/rename(),
        # it cannot overwrite a concurrently introduced final symlink/file.
        try:
            os.link(temp, leaf, src_dir_fd=root_fd, dst_dir_fd=root_fd, follow_symlinks=False)
        except FileExistsError as exc:
            raise SafetyError("private evidence final path raced into existence") from exc
        except OSError as exc:
            raise SafetyError("private evidence final link failed") from exc
        linked = True
        os.fsync(root_fd)
        os.unlink(temp, dir_fd=root_fd)
        os.fsync(root_fd)

        final_stat = os.stat(leaf, dir_fd=root_fd, follow_symlinks=False)
        if (
            stat.S_ISLNK(final_stat.st_mode)
            or not _private_file_stat_ok(final_stat, require_executable=False, allow_empty=False)
            or not _same_identity(temp_stat, final_stat)
            or final_stat.st_size != len(raw)
        ):
            raise SafetyError("private evidence final validation failed")

        # The pathname of the evidence root must still identify the opened dir.
        root_now = os.lstat(root)
        if not _private_dir_stat_ok(root_now, writable=True) or not _same_identity(root_identity, root_now):
            raise SafetyError("private evidence root changed during write")
        return _identity(final_stat)
    finally:
        if temp_fd is not None:
            try:
                os.close(temp_fd)
            except OSError:
                pass
        # Best-effort cleanup only of our unique temporary name. A successfully
        # linked final is intentionally retained on later failure so evidence is
        # never silently replaced/rewritten; subsequent use fails closed.
        try:
            os.unlink(temp, dir_fd=root_fd)
        except OSError:
            pass
        try:
            os.close(root_fd)
        except OSError:
            pass


def write_private_json_no_clobber(root: Path, path: Path, payload: dict, *, max_bytes: int = MAX_PRIVATE_JSON_BYTES) -> PrivateFileIdentity:
    if not isinstance(payload, dict):
        raise SafetyError("private evidence JSON root invalid")
    try:
        raw = (json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode("ascii")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise SafetyError("private evidence JSON encoding failed") from exc
    return write_private_bytes_no_clobber(root, path, raw, max_bytes=max_bytes)


def run_private_executable(root: Path, path: Path, *, timeout: float) -> int:
    if not isinstance(timeout, (int, float)) or isinstance(timeout, bool) or not 0.1 <= float(timeout) <= 120.0:
        raise SafetyError("private executable timeout invalid")
    fd = open_private_fd(root, path, require_executable=True)
    try:
        proc_path = f"/proc/self/fd/{fd}"
        if not Path("/proc/self/fd").is_dir():
            raise SafetyError("secure fd execution path unavailable")
        try:
            proc = subprocess.run(
                [proc_path],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=float(timeout),
                check=False,
                pass_fds=(fd,),
            )
        except subprocess.TimeoutExpired:
            return -1
        return int(proc.returncode)
    finally:
        os.close(fd)
