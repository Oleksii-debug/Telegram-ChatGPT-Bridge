# -*- coding: utf-8 -*-
"""Descriptor-bound POSIX primitives for small private mutable state.

This module contains no project secrets. It is intended for owner-private control
roots where a pathname must not be able to redirect an atomic update through a
symlink, special file, hardlink, or replaced parent directory.

Durability claim is deliberately narrow: after a successful call returns, the
new file contents and containing-directory rename/link metadata have been fsynced
on the same POSIX host/filesystem. This is not a cross-host or storage-hardware
power-loss guarantee.
"""
from __future__ import annotations

import errno
import json
import os
import secrets
import stat
from pathlib import Path
from typing import Any


class PrivateStateError(RuntimeError):
    """Stable, content-free private-state filesystem failure."""


def _same_inode(left: os.stat_result, right: os.stat_result) -> bool:
    return left.st_dev == right.st_dev and left.st_ino == right.st_ino


def _absolute(path: str | Path) -> Path:
    return Path(os.path.abspath(os.fspath(Path(path).expanduser())))


def _dir_flags() -> int:
    required = ("O_DIRECTORY", "O_NOFOLLOW")
    if os.name != "posix" or any(not hasattr(os, name) for name in required):
        raise PrivateStateError("private_state_safe_primitives_unavailable")
    return os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)


def _walk_directory(path: Path) -> tuple[int, os.stat_result]:
    """Open an absolute directory without following any pathname symlink."""
    path = _absolute(path)
    parts = path.parts
    if not parts or parts[0] != os.sep:
        raise PrivateStateError("private_state_parent_not_absolute")

    flags = _dir_flags()
    try:
        current_fd = os.open(os.sep, flags)
    except OSError:
        raise PrivateStateError("private_state_root_open_failed") from None
    opened = [current_fd]
    try:
        for component in parts[1:]:
            try:
                before = os.stat(component, dir_fd=current_fd, follow_symlinks=False)
            except OSError:
                raise PrivateStateError("private_state_parent_missing_or_unsafe") from None
            if stat.S_ISLNK(before.st_mode) or not stat.S_ISDIR(before.st_mode):
                raise PrivateStateError("private_state_parent_topology_unsafe")
            try:
                next_fd = os.open(component, flags, dir_fd=current_fd)
            except OSError:
                raise PrivateStateError("private_state_parent_open_failed") from None
            after = os.fstat(next_fd)
            if not stat.S_ISDIR(after.st_mode) or not _same_inode(before, after):
                os.close(next_fd)
                raise PrivateStateError("private_state_parent_changed")
            opened.append(next_fd)
            current_fd = next_fd

        st = os.fstat(current_fd)
        mode = stat.S_IMODE(st.st_mode)
        if (
            not stat.S_ISDIR(st.st_mode)
            or st.st_uid != os.geteuid()
            or mode & 0o077
            or not (mode & stat.S_IWUSR)
            or not (mode & stat.S_IXUSR)
        ):
            raise PrivateStateError("private_state_parent_mode_unsafe")
        retained = os.dup(current_fd)
        return retained, os.fstat(retained)
    finally:
        for fd in reversed(opened):
            try:
                os.close(fd)
            except OSError:
                pass


def _verify_parent_binding(parent: Path, expected: os.stat_result) -> None:
    fd, observed = _walk_directory(parent)
    try:
        if not _same_inode(expected, observed):
            raise PrivateStateError("private_state_parent_changed")
    finally:
        os.close(fd)


def _validate_named_leaf(st: os.stat_result, *, mode: int, label: str) -> None:
    if not stat.S_ISREG(st.st_mode):
        raise PrivateStateError(f"{label}_not_regular")
    if st.st_uid != os.geteuid():
        raise PrivateStateError(f"{label}_wrong_owner")
    if st.st_nlink != 1:
        raise PrivateStateError(f"{label}_hardlinked")
    if stat.S_IMODE(st.st_mode) != mode:
        raise PrivateStateError(f"{label}_wrong_mode")


def _lstat_at(parent_fd: int, name: str) -> os.stat_result | None:
    try:
        return os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    except OSError:
        raise PrivateStateError("private_state_leaf_metadata_failed") from None


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    offset = 0
    while offset < len(view):
        try:
            written = os.write(fd, view[offset:])
        except OSError:
            raise PrivateStateError("private_state_temp_write_failed") from None
        if written <= 0:
            raise PrivateStateError("private_state_temp_write_failed")
        offset += written


def _make_temp(parent_fd: int, final_name: str, data: bytes, mode: int) -> tuple[str, os.stat_result]:
    if not hasattr(os, "O_NOFOLLOW"):
        raise PrivateStateError("private_state_safe_primitives_unavailable")
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | os.O_NOFOLLOW
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    for _ in range(32):
        name = f".{final_name}.{secrets.token_hex(16)}.tmp"
        try:
            fd = os.open(name, flags, mode, dir_fd=parent_fd)
        except FileExistsError:
            continue
        except OSError:
            raise PrivateStateError("private_state_temp_create_failed") from None
        try:
            os.fchmod(fd, mode)
            _write_all(fd, data)
            os.fsync(fd)
            st = os.fstat(fd)
            _validate_named_leaf(st, mode=mode, label="private_state_temp")
            if st.st_size != len(data):
                raise PrivateStateError("private_state_temp_size_mismatch")
            return name, st
        finally:
            os.close(fd)
    raise PrivateStateError("private_state_temp_name_exhausted")


def _cleanup_temp(parent_fd: int, temp_name: str | None) -> None:
    if not temp_name:
        return
    try:
        os.unlink(temp_name, dir_fd=parent_fd)
    except FileNotFoundError:
        return
    except OSError:
        raise PrivateStateError("private_state_temp_cleanup_failed") from None
    try:
        os.fsync(parent_fd)
    except OSError:
        raise PrivateStateError("private_state_parent_fsync_failed") from None


def _encode_json(payload: Any) -> bytes:
    try:
        return (json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")
    except (TypeError, ValueError, UnicodeError):
        raise PrivateStateError("private_state_json_invalid") from None


def atomic_replace_json(path: str | Path, payload: Any, *, mode: int = 0o600) -> None:
    """Atomically replace one owner-private JSON leaf with fsync + race checks."""
    path = _absolute(path)
    if not path.name or path.name in {".", ".."} or os.sep in path.name:
        raise PrivateStateError("private_state_leaf_name_invalid")
    data = _encode_json(payload)
    parent_fd, parent_stat = _walk_directory(path.parent)
    temp_name: str | None = None
    committed = False
    try:
        before = _lstat_at(parent_fd, path.name)
        if before is not None:
            _validate_named_leaf(before, mode=mode, label="private_state_target")

        temp_name, temp_stat = _make_temp(parent_fd, path.name, data, mode)
        _verify_parent_binding(path.parent, parent_stat)

        current = _lstat_at(parent_fd, path.name)
        if before is None:
            if current is not None:
                raise PrivateStateError("private_state_target_raced")
        else:
            if current is None or not _same_inode(before, current):
                raise PrivateStateError("private_state_target_raced")
            _validate_named_leaf(current, mode=mode, label="private_state_target")

        try:
            os.replace(temp_name, path.name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
        except OSError:
            raise PrivateStateError("private_state_replace_failed") from None
        temp_name = None
        committed = True
        try:
            os.fsync(parent_fd)
        except OSError:
            raise PrivateStateError("private_state_parent_fsync_failed") from None

        named = _lstat_at(parent_fd, path.name)
        if named is None or not _same_inode(named, temp_stat):
            raise PrivateStateError("private_state_post_replace_changed")
        _validate_named_leaf(named, mode=mode, label="private_state_target")
        if named.st_size != len(data):
            raise PrivateStateError("private_state_post_replace_size_mismatch")
        _verify_parent_binding(path.parent, parent_stat)
    finally:
        if temp_name is not None:
            _cleanup_temp(parent_fd, temp_name)
        os.close(parent_fd)
        # If the public parent pathname was replaced after the committed rename,
        # the call fails closed above; the function never retries into the new
        # pathname and therefore never redirects private state.
        _ = committed


def atomic_create_json_once(path: str | Path, payload: Any, *, mode: int = 0o600) -> None:
    """Durably create a one-shot JSON marker without ever replacing an existing leaf."""
    path = _absolute(path)
    if not path.name or path.name in {".", ".."} or os.sep in path.name:
        raise PrivateStateError("private_state_leaf_name_invalid")
    data = _encode_json(payload)
    parent_fd, parent_stat = _walk_directory(path.parent)
    temp_name: str | None = None
    linked = False
    try:
        if _lstat_at(parent_fd, path.name) is not None:
            raise PrivateStateError("private_state_already_exists")
        temp_name, temp_stat = _make_temp(parent_fd, path.name, data, mode)
        _verify_parent_binding(path.parent, parent_stat)
        if _lstat_at(parent_fd, path.name) is not None:
            raise PrivateStateError("private_state_already_exists")
        try:
            os.link(
                temp_name,
                path.name,
                src_dir_fd=parent_fd,
                dst_dir_fd=parent_fd,
                follow_symlinks=False,
            )
            linked = True
        except FileExistsError:
            raise PrivateStateError("private_state_already_exists") from None
        except OSError as exc:
            if exc.errno in {errno.ELOOP, errno.EMLINK}:
                raise PrivateStateError("private_state_target_topology_unsafe") from None
            raise PrivateStateError("private_state_link_failed") from None
        try:
            os.fsync(parent_fd)
        except OSError:
            raise PrivateStateError("private_state_parent_fsync_failed") from None

        try:
            os.unlink(temp_name, dir_fd=parent_fd)
        except OSError:
            raise PrivateStateError("private_state_temp_cleanup_failed") from None
        temp_name = None
        try:
            os.fsync(parent_fd)
        except OSError:
            raise PrivateStateError("private_state_parent_fsync_failed") from None

        named = _lstat_at(parent_fd, path.name)
        if named is None or not _same_inode(named, temp_stat):
            raise PrivateStateError("private_state_post_create_changed")
        _validate_named_leaf(named, mode=mode, label="private_state_target")
        if named.st_size != len(data):
            raise PrivateStateError("private_state_post_create_size_mismatch")
        _verify_parent_binding(path.parent, parent_stat)
    finally:
        if temp_name is not None:
            _cleanup_temp(parent_fd, temp_name)
        os.close(parent_fd)
        _ = linked
