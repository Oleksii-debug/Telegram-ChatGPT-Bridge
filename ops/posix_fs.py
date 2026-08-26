# -*- coding: utf-8 -*-
"""Descriptor-bound POSIX primitives for private Telegram Bridge filesystem state.

All path components are opened with ``O_NOFOLLOW`` and all security decisions are
made from ``fstat``/``fstatat`` data tied to the descriptor actually used.
Atomic writes and recursive cleanup operate through directory descriptors.
"""
from __future__ import annotations

import os
import secrets
import stat
from dataclasses import dataclass
from pathlib import Path


class FilesystemSafetyError(RuntimeError):
    """A required filesystem identity/topology invariant could not be proven."""


@dataclass(frozen=True)
class InodeIdentity:
    dev: int
    ino: int

    @classmethod
    def from_stat(cls, info: os.stat_result) -> "InodeIdentity":
        return cls(info.st_dev, info.st_ino)


def same_inode(left: os.stat_result, right: os.stat_result) -> bool:
    return left.st_dev == right.st_dev and left.st_ino == right.st_ino


def lexical_absolute(path: str | Path) -> Path:
    return Path(os.path.abspath(os.path.expanduser(os.fspath(path))))


def _require_posix() -> None:
    if os.name != "posix" or not hasattr(os, "O_DIRECTORY") or not hasattr(os, "O_NOFOLLOW"):
        raise FilesystemSafetyError("safe POSIX filesystem primitives unavailable")
    if os.open not in getattr(os, "supports_dir_fd", set()) or os.stat not in getattr(os, "supports_dir_fd", set()):
        raise FilesystemSafetyError("openat/fstatat dir_fd support unavailable")


def _directory_flags() -> int:
    _require_posix()
    return os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)


def _component(name: str) -> str:
    if not name or name in {".", ".."} or "/" in name or "\x00" in name:
        raise FilesystemSafetyError("unsafe filesystem component")
    return name


def _open_component(parent_fd: int, name: str) -> tuple[int, os.stat_result]:
    name = _component(name)
    try:
        before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except OSError as exc:
        raise FilesystemSafetyError("directory component is unavailable") from exc
    if not stat.S_ISDIR(before.st_mode) or stat.S_ISLNK(before.st_mode):
        raise FilesystemSafetyError("directory component is unsafe")
    try:
        fd = os.open(name, _directory_flags(), dir_fd=parent_fd)
    except OSError as exc:
        raise FilesystemSafetyError("directory component could not be opened safely") from exc
    try:
        after = os.fstat(fd)
        if not same_inode(before, after):
            raise FilesystemSafetyError("directory component changed during open")
        return fd, after
    except Exception:
        os.close(fd)
        raise


def open_directory_fd(
    path: str | Path,
    *,
    create_missing: bool = False,
    create_mode: int = 0o700,
    final_private: bool = False,
    final_exact_mode: int | None = None,
    owner_uid: int | None = None,
) -> tuple[int, os.stat_result]:
    """Descriptor-walk an absolute directory without following symlinks."""
    _require_posix()
    absolute = lexical_absolute(path)
    if not absolute.parts or absolute.parts[0] != os.sep:
        raise FilesystemSafetyError("absolute POSIX directory path required")
    try:
        current_fd = os.open(os.sep, _directory_flags())
    except OSError as exc:
        raise FilesystemSafetyError("filesystem root could not be opened") from exc
    current_info = os.fstat(current_fd)
    try:
        for raw in absolute.parts[1:]:
            name = _component(raw)
            try:
                child_fd, child_info = _open_component(current_fd, name)
            except FilesystemSafetyError as exc:
                if not (create_missing and isinstance(exc.__cause__, FileNotFoundError)):
                    raise
                try:
                    os.mkdir(name, create_mode, dir_fd=current_fd)
                except FileExistsError:
                    pass
                except OSError as mkdir_exc:
                    raise FilesystemSafetyError("directory component could not be created safely") from mkdir_exc
                child_fd, child_info = _open_component(current_fd, name)
            os.close(current_fd)
            current_fd, current_info = child_fd, child_info

        if not stat.S_ISDIR(current_info.st_mode):
            raise FilesystemSafetyError("expected directory is not a directory")
        uid = os.geteuid() if owner_uid is None and hasattr(os, "geteuid") else owner_uid
        if uid is not None and current_info.st_uid != uid:
            raise FilesystemSafetyError("directory owner is unexpected")
        mode = stat.S_IMODE(current_info.st_mode)
        if final_exact_mode is not None and mode != final_exact_mode:
            raise FilesystemSafetyError("directory mode is unexpected")
        if final_private and mode & 0o077:
            raise FilesystemSafetyError("directory permissions are too broad")
        return current_fd, current_info
    except Exception:
        os.close(current_fd)
        raise


def verify_directory_binding(
    path: str | Path,
    expected: os.stat_result | InodeIdentity,
    *,
    final_private: bool = False,
    final_exact_mode: int | None = None,
    owner_uid: int | None = None,
) -> None:
    fd, actual = open_directory_fd(
        path,
        final_private=final_private,
        final_exact_mode=final_exact_mode,
        owner_uid=owner_uid,
    )
    try:
        wanted = expected if isinstance(expected, InodeIdentity) else InodeIdentity.from_stat(expected)
        if InodeIdentity.from_stat(actual) != wanted:
            raise FilesystemSafetyError("directory pathname binding changed")
    finally:
        os.close(fd)


def stat_leaf_nofollow(parent_fd: int, name: str) -> os.stat_result | None:
    try:
        return os.stat(_component(name), dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise FilesystemSafetyError("leaf metadata is unavailable") from exc


def open_regular_at(
    parent_fd: int,
    name: str,
    flags: int,
    *,
    mode: int = 0o600,
    owner_uid: int | None = None,
    exact_mode: int | None = None,
    require_single_link: bool = True,
    require_empty: bool = False,
) -> tuple[int, os.stat_result]:
    """Open one regular leaf relative to a trusted directory descriptor."""
    _require_posix()
    flags |= os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(_component(name), flags, mode, dir_fd=parent_fd)
    except OSError as exc:
        raise FilesystemSafetyError("leaf could not be opened safely") from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise FilesystemSafetyError("leaf is not a regular file")
        uid = os.geteuid() if owner_uid is None and hasattr(os, "geteuid") else owner_uid
        if uid is not None and info.st_uid != uid:
            raise FilesystemSafetyError("leaf owner is unexpected")
        if require_single_link and info.st_nlink != 1:
            raise FilesystemSafetyError("leaf hardlink topology is unsafe")
        if exact_mode is not None and stat.S_IMODE(info.st_mode) != exact_mode:
            raise FilesystemSafetyError("leaf mode is unexpected")
        if require_empty and info.st_size != 0:
            raise FilesystemSafetyError("leaf must be empty")
        return fd, info
    except Exception:
        os.close(fd)
        raise


def verify_leaf_binding(parent_fd: int, name: str, open_fd: int) -> None:
    named = stat_leaf_nofollow(parent_fd, name)
    if named is None or not same_inode(named, os.fstat(open_fd)):
        raise FilesystemSafetyError("leaf pathname binding changed")


def atomic_write_bytes(
    path: str | Path,
    data: bytes,
    *,
    mode: int = 0o600,
    parent_private: bool = False,
    parent_exact_mode: int | None = None,
) -> None:
    """Atomic replace through one bound parent; never open an existing target."""
    absolute = lexical_absolute(path)
    name = _component(absolute.name)
    parent_fd, parent_info = open_directory_fd(
        absolute.parent,
        final_private=parent_private,
        final_exact_mode=parent_exact_mode,
    )
    temp_name = f".{name}.tmp-{os.getpid()}-{secrets.token_hex(12)}"
    temp_fd: int | None = None
    try:
        temp_fd, _ = open_regular_at(
            parent_fd,
            temp_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            mode=mode,
            exact_mode=mode,
        )
        view = memoryview(data)
        while view:
            try:
                written = os.write(temp_fd, view)
            except OSError as exc:
                raise FilesystemSafetyError("atomic private write failed") from exc
            if written <= 0:
                raise FilesystemSafetyError("atomic private write made no progress")
            view = view[written:]
        os.fsync(temp_fd)
        verify_leaf_binding(parent_fd, temp_name, temp_fd)
        os.replace(temp_name, name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
        verify_leaf_binding(parent_fd, name, temp_fd)
        os.fsync(parent_fd)
        verify_directory_binding(
            absolute.parent,
            parent_info,
            final_private=parent_private,
            final_exact_mode=parent_exact_mode,
        )
    finally:
        if temp_fd is not None:
            try:
                os.close(temp_fd)
            except OSError:
                pass
        try:
            os.unlink(temp_name, dir_fd=parent_fd)
        except OSError:
            pass
        os.close(parent_fd)


def _remove_tree_entry(parent_fd: int, name: str) -> None:
    """unlinkat/rmdirat recursion; symlinks and special leaves are never followed."""
    info = stat_leaf_nofollow(parent_fd, name)
    if info is None:
        return
    if stat.S_ISDIR(info.st_mode):
        child_fd, opened = _open_component(parent_fd, name)
        try:
            for entry in list(os.scandir(child_fd)):
                _remove_tree_entry(child_fd, entry.name)
            named = stat_leaf_nofollow(parent_fd, name)
            if named is None or not same_inode(named, opened):
                raise FilesystemSafetyError("cleanup directory binding changed")
        finally:
            os.close(child_fd)
        try:
            os.rmdir(name, dir_fd=parent_fd)
        except OSError as exc:
            raise FilesystemSafetyError("cleanup directory removal failed") from exc
    else:
        try:
            os.unlink(name, dir_fd=parent_fd)
        except OSError as exc:
            raise FilesystemSafetyError("cleanup leaf removal failed") from exc


def safe_remove_tree(path: str | Path) -> None:
    absolute = lexical_absolute(path)
    parent_fd, parent_info = open_directory_fd(absolute.parent)
    try:
        _remove_tree_entry(parent_fd, absolute.name)
        verify_directory_binding(absolute.parent, parent_info)
    finally:
        os.close(parent_fd)
