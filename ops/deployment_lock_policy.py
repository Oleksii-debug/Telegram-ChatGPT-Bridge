# -*- coding: utf-8 -*-
"""Fail-closed policy and descriptor-bound acquisition for deployment locks.

The deployment transaction lock is non-secret, but it serializes mutations of a
security-sensitive private control plane. The lock therefore binds both the
control-root pathname and lock leaf to opened POSIX descriptors instead of
trusting a pathname validation followed by a later full-path open.
"""
from __future__ import annotations

import contextlib
import os
import stat
from pathlib import Path

try:
    import fcntl
except ImportError:  # pragma: no cover - supported deployment runtime is POSIX
    fcntl = None


class LockPolicyError(RuntimeError):
    """Unsafe or ambiguous deployment-lock topology."""


def _expected_uid() -> int:
    if hasattr(os, "geteuid"):
        return int(os.geteuid())
    if hasattr(os, "getuid"):
        return int(os.getuid())
    raise LockPolicyError("deployment lock owner identity unavailable")


def _same_inode(left: os.stat_result, right: os.stat_result) -> bool:
    return left.st_dev == right.st_dev and left.st_ino == right.st_ino


def _require_safe_primitives() -> None:
    if (
        os.name != "posix"
        or fcntl is None
        or not hasattr(os, "O_DIRECTORY")
        or not hasattr(os, "O_NOFOLLOW")
    ):
        raise LockPolicyError("deployment lock safe POSIX primitives unavailable")


def _directory_flags() -> int:
    _require_safe_primitives()
    return (
        os.O_RDONLY
        | int(getattr(os, "O_DIRECTORY"))
        | int(getattr(os, "O_NOFOLLOW"))
        | int(getattr(os, "O_CLOEXEC", 0))
    )


def _absolute(path: Path) -> Path:
    value = Path(os.path.abspath(os.fspath(Path(path).expanduser())))
    if not value.is_absolute() or value == Path(os.sep):
        raise LockPolicyError("deployment control root path invalid")
    return value


def _validate_control_root_stat(st: os.stat_result) -> None:
    mode = stat.S_IMODE(st.st_mode)
    if not stat.S_ISDIR(st.st_mode):
        raise LockPolicyError("deployment control root is not a directory")
    if st.st_uid != _expected_uid():
        raise LockPolicyError("deployment control root owner is unexpected")
    if mode & 0o077:
        raise LockPolicyError("deployment control root is not owner-private")
    if not (mode & stat.S_IWUSR) or not (mode & stat.S_IXUSR):
        raise LockPolicyError("deployment control root is not owner-writable/searchable")


def _validate_lock_stat(st: os.stat_result, *, owner_uid: int | None = None) -> None:
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
        raise LockPolicyError("deployment lock must be a regular file")
    expected_uid = _expected_uid() if owner_uid is None else int(owner_uid)
    if st.st_uid != expected_uid:
        raise LockPolicyError("deployment lock owner mismatch")
    if stat.S_IMODE(st.st_mode) != 0o600:
        raise LockPolicyError("deployment lock mode must already be 0600")
    if st.st_nlink != 1:
        raise LockPolicyError("deployment lock hardlink topology rejected")
    if st.st_size != 0:
        raise LockPolicyError("deployment lock must be empty")


def validate_preexisting_lock(path: Path, *, owner_uid: int | None = None) -> dict[str, int]:
    """Reject unsafe existing lock topology/content without normalizing it."""
    try:
        st = path.lstat()
    except OSError as exc:
        raise LockPolicyError("deployment lock metadata unavailable") from exc
    _validate_lock_stat(st, owner_uid=owner_uid)
    return {"mode": 0o600, "size": 0, "nlink": 1}


def _open_control_root_fd(path: Path) -> tuple[int, os.stat_result, Path]:
    """Walk an absolute root from / without following any pathname symlink."""
    root = _absolute(path)
    parts = root.parts
    if not parts or parts[0] != os.sep:
        raise LockPolicyError("deployment control root must be absolute")

    flags = _directory_flags()
    try:
        current_fd = os.open(os.sep, flags)
    except OSError as exc:
        raise LockPolicyError("deployment control root ancestor open failed") from exc

    try:
        for component in parts[1:]:
            try:
                before = os.stat(component, dir_fd=current_fd, follow_symlinks=False)
            except OSError as exc:
                raise LockPolicyError("deployment control root ancestor metadata unavailable") from exc
            if stat.S_ISLNK(before.st_mode) or not stat.S_ISDIR(before.st_mode):
                raise LockPolicyError("deployment control root ancestor topology unsafe")
            try:
                next_fd = os.open(component, flags, dir_fd=current_fd)
            except OSError as exc:
                raise LockPolicyError("deployment control root ancestor open failed") from exc
            try:
                after = os.fstat(next_fd)
                if not stat.S_ISDIR(after.st_mode) or not _same_inode(before, after):
                    raise LockPolicyError("deployment control root ancestor changed during open")
            except Exception:
                os.close(next_fd)
                raise
            os.close(current_fd)
            current_fd = next_fd

        root_stat = os.fstat(current_fd)
        _validate_control_root_stat(root_stat)
        return current_fd, root_stat, root
    except Exception:
        try:
            os.close(current_fd)
        except OSError:
            pass
        raise


def _verify_control_root_binding(root: Path, expected: os.stat_result) -> None:
    verify_fd, observed, _ = _open_control_root_fd(root)
    try:
        if not _same_inode(expected, observed):
            raise LockPolicyError("deployment control root changed during lock acquisition")
    finally:
        os.close(verify_fd)


def _relative_leaf_stat(root_fd: int, leaf: str) -> os.stat_result | None:
    try:
        return os.stat(leaf, dir_fd=root_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise LockPolicyError("deployment lock leaf metadata unavailable") from exc


@contextlib.contextmanager
def hold_deployment_lock(control_root: Path, lock_name: str):
    """Acquire a descriptor-bound nonblocking deployment lock.

    Both newly-created and pre-existing leaves are opened relative to the exact
    directory descriptor obtained by a no-symlink ancestor walk. The public
    control-root pathname and leaf pathname are rebound to their descriptors
    after flock, so parent/leaf replacement during validation/open fails closed.
    """
    _require_safe_primitives()
    if (
        not isinstance(lock_name, str)
        or not lock_name
        or lock_name in {".", ".."}
        or Path(lock_name).name != lock_name
        or os.sep in lock_name
    ):
        raise LockPolicyError("deployment lock leaf name invalid")

    root_fd, root_stat, root = _open_control_root_fd(control_root)
    lock_fd: int | None = None
    flocked = False
    try:
        before = _relative_leaf_stat(root_fd, lock_name)
        if before is not None:
            _validate_lock_stat(before)

        flags = os.O_RDWR | int(getattr(os, "O_NOFOLLOW")) | int(getattr(os, "O_CLOEXEC", 0))
        flags |= int(getattr(os, "O_NONBLOCK", 0))
        if before is None:
            flags |= os.O_CREAT | os.O_EXCL
        try:
            lock_fd = os.open(lock_name, flags, 0o600, dir_fd=root_fd)
        except OSError as exc:
            raise LockPolicyError("deployment lock could not be opened descriptor-relatively") from exc

        opened = os.fstat(lock_fd)
        _validate_lock_stat(opened)
        if before is not None and not _same_inode(before, opened):
            raise LockPolicyError("deployment lock leaf changed during open")

        _verify_control_root_binding(root, root_stat)

        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            flocked = True
        except BlockingIOError as exc:
            raise LockPolicyError("another deployment transaction owns the lock") from exc
        except OSError as exc:
            raise LockPolicyError("deployment lock flock failed") from exc

        # Rebind both public names after flock. This closes races where the root
        # or leaf is swapped after fstat but before serialization is established.
        _verify_control_root_binding(root, root_stat)
        named = _relative_leaf_stat(root_fd, lock_name)
        if named is None:
            raise LockPolicyError("deployment lock leaf disappeared after flock")
        _validate_lock_stat(named)
        current = os.fstat(lock_fd)
        _validate_lock_stat(current)
        if not _same_inode(named, current):
            raise LockPolicyError("deployment lock leaf changed before critical section")

        yield root / lock_name
    finally:
        if lock_fd is not None:
            if flocked:
                try:
                    fcntl.flock(lock_fd, fcntl.LOCK_UN)
                except OSError:
                    pass
            try:
                os.close(lock_fd)
            except OSError:
                pass
        try:
            os.close(root_fd)
        except OSError:
            pass
