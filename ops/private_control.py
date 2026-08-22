# -*- coding: utf-8 -*-
"""TOCTOU-resistant access to owner-private HOSTiQ control files.

The public repository contains only the mechanism. Real credential/control
values remain server-side. Every component is opened relative to an already
validated directory descriptor with O_NOFOLLOW and identity is checked across
pre-open metadata versus fstat before any read or execution.
"""
from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path

from ops.release_guard import SafetyError

_REQUIRED_FLAGS = ("O_NOFOLLOW", "O_DIRECTORY")
MAX_PRIVATE_TEXT_BYTES = 4096


def _require_posix_primitives() -> None:
    if os.name != "posix" or any(not hasattr(os, name) for name in _REQUIRED_FLAGS):
        raise SafetyError("required POSIX private-control primitives unavailable")


def _private_dir_stat_ok(st: os.stat_result) -> bool:
    return stat.S_ISDIR(st.st_mode) and st.st_uid == os.getuid() and not (stat.S_IMODE(st.st_mode) & 0o077)


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


def open_private_fd(
    root: Path,
    path: Path,
    *,
    require_executable: bool = False,
    allow_empty: bool = False,
) -> int:
    """Open one private regular file and return a validated read-only fd.

    Caller owns the returned fd. The function fails if a path component is
    swapped between lstat/stat-at and open/fstat, if a symlink is introduced,
    or if owner/mode/link/topology invariants are violated.
    """
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


def read_private_text(root: Path, path: Path, *, max_bytes: int = MAX_PRIVATE_TEXT_BYTES) -> str:
    if not isinstance(max_bytes, int) or isinstance(max_bytes, bool) or not 1 <= max_bytes <= MAX_PRIVATE_TEXT_BYTES:
        raise SafetyError("private text byte bound invalid")
    fd = open_private_fd(root, path)
    try:
        chunks = []
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
    finally:
        os.close(fd)


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
