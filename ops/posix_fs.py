# -*- coding: utf-8 -*-
"""Descriptor-bound POSIX filesystem primitives for private Bridge state.

Threat model:
- reject symlink traversal at every opened path component;
- validate owner/type/mode/link-count on the descriptor actually used;
- detect parent/leaf replacement between validation and use;
- perform atomic writes and cleanup relative to already-open directory fds;
- never follow a symlink during cleanup.

These primitives assume a POSIX host with openat-style ``dir_fd`` support,
``O_DIRECTORY`` and ``O_NOFOLLOW``.  They fail closed when those primitives are
unavailable.  They do not claim to defend against a fully malicious same-UID
process that can replace every ancestor including the stable account home while
an operation is in flight; callers must additionally keep the hosting account
root outside attacker-controlled rename authority.
"""
from __future__ import annotations

import os
import secrets
import stat
from dataclasses import dataclass
from pathlib import Path


class FilesystemSafetyError(RuntimeError):
    """A private filesystem invariant could not be proven."""


@dataclass(frozen=True)
class InodeIdentity:
    dev: int
    ino: int

    @classmethod
    def from_stat(cls, info: os.stat_result) -> "InodeIdentity":
        return cls(info.st_dev, info.st_ino)


def same_inode(left: os.stat_result, right: os.stat_result) -> bool:
    return left.st_dev == right.st_dev and left.st_ino == right.st_ino


def _require_posix_primitives() -> None:
    required = ("O_DIRECTORY", "O_NOFOLLOW")
    if os.name != "posix" or any(not hasattr(os, name) for name in required):
        raise FilesystemSafetyError("safe POSIX filesystem primitives unavailable")
    if os.open not in getattr(os, "supports_dir_fd", set()):
        raise FilesystemSafetyError("openat dir_fd support unavailable")
    if os.stat not in getattr(os, "supports_dir_fd", set()):
        raise FilesystemSafetyError("fstatat dir_fd support unavailable")


def lexical_absolute(path: str | Path) -> Path:
    return Path(os.path.abspath(os.path.expanduser(os.fspath(path))))


def _directory_flags() -> int:
    _require_posix_primitives()
    return os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)


def _validate_component(name: str) -> str:
    if not name or name in {".", ".."} or "/" in name or "\x00" in name:
        raise FilesystemSafetyError("unsafe filesystem component")
    return name


def _validate_directory_stat(
    info: os.stat_result,
    *,
    owner_uid: int | None = None,
    exact_mode: int | None = None,
    private: bool = False,
) -> None:
    if not stat.S_ISDIR(info.st_mode):
        raise FilesystemSafetyError("expected directory is not a directory")
    uid = os.geteuid() if owner_uid is None and hasattr(os, "geteuid") else owner_uid
    if uid is not None and info.st_uid != uid:
        raise FilesystemSafetyError("directory owner is unexpected")
    mode = stat.S_IMODE(info.st_mode)
    if exact_mode is not None and mode != exact_mode:
        raise FilesystemSafetyError("directory mode is unexpected")
    if private and mode & 0o077:
        raise FilesystemSafetyError("directory permissions are too broad")


def _open_component(parent_fd: int, component: str) -> tuple[int, os.stat_result]:
    component = _validate_component(component)
    try:
        before = os.stat(component, dir_fd=parent_fd, follow_symlinks=False)
    except OSError as exc:
        raise FilesystemSafetyError("directory component is unavailable") from exc
    if not stat.S_ISDIR(before.st_mode) or stat.S_ISLNK(before.st_mode):
        raise FilesystemSafetyError("directory component is unsafe")
    try:
        child_fd = os.open(component, _directory_flags(), dir_fd=parent_fd)
    except OSError as exc:
        raise FilesystemSafetyError("directory component could not be opened safely") from exc
    try:
        after = os.fstat(child_fd)
        if not same_inode(before, after):
            raise FilesystemSafetyError("directory component changed during open")
        return child_fd, after
    except Exception:
        os.close(child_fd)
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
    """Open an absolute directory without following any symlink component.

    Missing components may be created descriptor-relatively when
    ``create_missing`` is true. Existing components are never chmod-normalized.
    """
    _require_posix_primitives()
    absolute = lexical_absolute(path)
    parts = absolute.parts
    if not parts or parts[0] != os.sep:
        raise FilesystemSafetyError("absolute POSIX directory path required")
    try:
        current_fd = os.open(os.sep, _directory_flags())
    except OSError as exc:
        raise FilesystemSafetyError("filesystem root could not be opened") from exc
    current_info = os.fstat(current_fd)
    try:
        for raw_component in parts[1:]:
            component = _validate_component(raw_component)
            try:
                child_fd, child_info = _open_component(current_fd, component)
            except FilesystemSafetyError as exc:
                cause = exc.__cause__
                missing = isinstance(cause, FileNotFoundError)
                if not (create_missing and missing):
                    raise
                try:
                    os.mkdir(component, create_mode, dir_fd=current_fd)
                except FileExistsError:
                    pass
                except OSError as mkdir_exc:
                    raise FilesystemSafetyError("directory component could not be created safely") from mkdir_exc
                child_fd, child_info = _open_component(current_fd, component)
            os.close(current_fd)
            current_fd, current_info = child_fd, child_info

        _validate_directory_stat(
            current_info,
            owner_uid=owner_uid,
            exact_mode=final_exact_mode,
            private=final_private,
        )
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
        expected_identity = expected if isinstance(expected, InodeIdentity) else InodeIdentity.from_stat(expected)
        if InodeIdentity.from_stat(actual) != expected_identity:
            raise FilesystemSafetyError("directory pathname binding changed")
    finally:
        os.close(fd)


def stat_leaf_nofollow(parent_fd: int, name: str) -> os.stat_result | None:
    name = _validate_component(name)
    try:
        return os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise FilesystemSafetyError("leaf metadata is unavailable") from exc


def validate_regular_stat(
    info: os.stat_result,
    *,
    owner_uid: int | None = None,
    exact_mode: int | None = None,
    require_single_link: bool = True,
    require_empty: bool = False,
) -> None:
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
    _require_posix_primitives()
    name = _validate_component(name)
    flags |= os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(name, flags, mode, dir_fd=parent_fd)
    except OSError as exc:
        raise FilesystemSafetyError("leaf could not be opened safely") from exc
    try:
        info = os.fstat(fd)
        validate_regular_stat(
            info,
            owner_uid=owner_uid,
            exact_mode=exact_mode,
            require_single_link=require_single_link,
            require_empty=require_empty,
        )
        return fd, info
    except Exception:
        os.close(fd)
        raise


def verify_leaf_binding(parent_fd: int, name: str, open_fd: int) -> None:
    named = stat_leaf_nofollow(parent_fd, name)
    if named is None:
        raise FilesystemSafetyError("bound leaf disappeared")
    opened = os.fstat(open_fd)
    if not same_inode(named, opened):
        raise FilesystemSafetyError("leaf pathname binding changed")


def atomic_write_bytes(
    path: str | Path,
    data: bytes,
    *,
    mode: int = 0o600,
    parent_private: bool = False,
    parent_exact_mode: int | None = None,
) -> None:
    """Atomically replace one leaf through a bound parent descriptor."""
    absolute = lexical_absolute(path)
    name = _validate_component(absolute.name)
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
            require_single_link=True,
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
        except FileNotFoundError:
            pass
        except OSError:
            pass
        os.close(parent_fd)


def read_regular_bytes(
    path: str | Path,
    *,
    max_bytes: int | None = None,
    expected_mode: int | None = None,
    parent_private: bool = False,
    parent_exact_mode: int | None = None,
) -> bytes:
    """Read one regular file from the exact descriptor that was validated."""
    absolute = lexical_absolute(path)
    parent_fd, parent_info = open_directory_fd(
        absolute.parent,
        final_private=parent_private,
        final_exact_mode=parent_exact_mode,
    )
    fd: int | None = None
    try:
        fd, before = open_regular_at(parent_fd, absolute.name, os.O_RDONLY, exact_mode=expected_mode)
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if max_bytes is not None and total > max_bytes:
                raise FilesystemSafetyError("private file exceeds read bound")
            chunks.append(chunk)
        after = os.fstat(fd)
        if (
            not same_inode(before, after)
            or before.st_size != after.st_size
            or getattr(before, "st_mtime_ns", None) != getattr(after, "st_mtime_ns", None)
            or getattr(before, "st_ctime_ns", None) != getattr(after, "st_ctime_ns", None)
            or before.st_nlink != after.st_nlink
        ):
            raise FilesystemSafetyError("file changed while being read")
        verify_leaf_binding(parent_fd, absolute.name, fd)
        verify_directory_binding(
            absolute.parent,
            parent_info,
            final_private=parent_private,
            final_exact_mode=parent_exact_mode,
        )
        return b"".join(chunks)
    finally:
        if fd is not None:
            os.close(fd)
        os.close(parent_fd)


def _remove_tree_entry(parent_fd: int, name: str) -> None:
    """Remove one entry without ever following a symlink."""
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
        return
    try:
        os.unlink(name, dir_fd=parent_fd)
    except OSError as exc:
        raise FilesystemSafetyError("cleanup leaf removal failed") from exc


def safe_remove_tree(path: str | Path) -> None:
    """Descriptor-relative recursive cleanup; symlinks are unlinked, never followed."""
    absolute = lexical_absolute(path)
    parent_fd, parent_info = open_directory_fd(absolute.parent)
    try:
        _remove_tree_entry(parent_fd, absolute.name)
        verify_directory_binding(absolute.parent, parent_info)
    finally:
        os.close(parent_fd)
