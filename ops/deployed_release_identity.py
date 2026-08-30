# -*- coding: utf-8 -*-
"""Fail-closed identity derivation and descriptor binding for deployed releases."""
from __future__ import annotations

import json
import os
import re
import stat
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from ops.release_guard import SafetyError

SHA40_RE = re.compile(r"^[0-9a-f]{40}$")
PREPARED_RELEASE_NAME = "PREPARED_RELEASE.json"
MAX_PREPARED_RELEASE_BYTES = 16 * 1024


def _close_quietly(fd: int | None) -> None:
    if fd is None:
        return
    try:
        os.close(fd)
    except OSError:
        pass


def _open_bound_release_root(root: Path, expected: os.stat_result) -> int:
    nofollow = getattr(os, "O_NOFOLLOW", None)
    directory = getattr(os, "O_DIRECTORY", None)
    if nofollow is None or directory is None:
        raise SafetyError("descriptor-safe deployed release validation unavailable")
    flags = os.O_RDONLY | int(directory) | int(nofollow) | int(getattr(os, "O_CLOEXEC", 0))
    try:
        fd = os.open(root, flags)
    except OSError as exc:
        raise SafetyError("deployed release root open failed") from exc
    try:
        opened = os.fstat(fd)
        if (
            not stat.S_ISDIR(opened.st_mode)
            or opened.st_dev != expected.st_dev
            or opened.st_ino != expected.st_ino
        ):
            raise SafetyError("deployed release root changed during validation")
        return fd
    except Exception:
        _close_quietly(fd)
        raise


def _read_bound_prepared_release(root_fd: int) -> bytes:
    try:
        before = os.stat(PREPARED_RELEASE_NAME, dir_fd=root_fd, follow_symlinks=False)
    except (OSError, TypeError, NotImplementedError) as exc:
        raise SafetyError("prepared release metadata unavailable") from exc
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise SafetyError("prepared release metadata topology unsafe")
    if before.st_size <= 0 or before.st_size > MAX_PREPARED_RELEASE_BYTES:
        raise SafetyError("prepared release metadata size unsafe")

    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        raise SafetyError("descriptor-safe prepared release validation unavailable")
    flags = os.O_RDONLY | int(nofollow) | int(getattr(os, "O_CLOEXEC", 0))
    fd: int | None = None
    try:
        try:
            fd = os.open(PREPARED_RELEASE_NAME, flags, dir_fd=root_fd)
        except (OSError, TypeError, NotImplementedError) as exc:
            raise SafetyError("prepared release metadata open failed") from exc
        opened = os.fstat(fd)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or opened.st_dev != before.st_dev
            or opened.st_ino != before.st_ino
            or opened.st_size != before.st_size
        ):
            raise SafetyError("prepared release metadata changed during validation")
        raw = bytearray()
        while len(raw) <= MAX_PREPARED_RELEASE_BYTES:
            chunk = os.read(fd, min(4096, MAX_PREPARED_RELEASE_BYTES + 1 - len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
        if len(raw) > MAX_PREPARED_RELEASE_BYTES:
            raise SafetyError("prepared release metadata too large")
        after = os.fstat(fd)
        if (
            after.st_dev != opened.st_dev
            or after.st_ino != opened.st_ino
            or after.st_size != opened.st_size
            or not stat.S_ISREG(after.st_mode)
            or after.st_nlink != 1
        ):
            raise SafetyError("prepared release metadata changed during read")
        return bytes(raw)
    finally:
        _close_quietly(fd)


def _validate_bound_release(root: Path, root_fd: int, expected: os.stat_result) -> str:
    candidate_sha = root.name
    if not SHA40_RE.fullmatch(candidate_sha):
        raise SafetyError("deployed release root is not exact-SHA versioned")
    raw = _read_bound_prepared_release(root_fd)
    opened = os.fstat(root_fd)
    if (
        not stat.S_ISDIR(opened.st_mode)
        or opened.st_dev != expected.st_dev
        or opened.st_ino != expected.st_ino
    ):
        raise SafetyError("deployed release root changed during validation")
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SafetyError("prepared release metadata invalid") from exc
    if not isinstance(payload, dict):
        raise SafetyError("prepared release metadata schema invalid")
    metadata_sha = payload.get("sha")
    if not isinstance(metadata_sha, str) or not SHA40_RE.fullmatch(metadata_sha):
        raise SafetyError("prepared release metadata SHA invalid")
    if metadata_sha != candidate_sha:
        raise SafetyError("deployed release identity mismatch")
    return candidate_sha


def _initial_root_identity(app_root: Path) -> tuple[Path, os.stat_result]:
    root = Path(app_root).expanduser()
    try:
        root_lstat = root.lstat()
    except OSError as exc:
        raise SafetyError("deployed release root unavailable") from exc
    if stat.S_ISLNK(root_lstat.st_mode) or not stat.S_ISDIR(root_lstat.st_mode):
        raise SafetyError("deployed release root topology unsafe")
    return root, root_lstat


def derive_deployed_release_sha(app_root: Path) -> str:
    root, root_lstat = _initial_root_identity(app_root)
    root_fd: int | None = None
    try:
        root_fd = _open_bound_release_root(root, root_lstat)
        candidate_sha = _validate_bound_release(root, root_fd, root_lstat)
    finally:
        _close_quietly(root_fd)

    try:
        root_after = root.lstat()
    except OSError as exc:
        raise SafetyError("deployed release root changed during validation") from exc
    if (
        stat.S_ISLNK(root_after.st_mode)
        or not stat.S_ISDIR(root_after.st_mode)
        or root_after.st_dev != root_lstat.st_dev
        or root_after.st_ino != root_lstat.st_ino
    ):
        raise SafetyError("deployed release root changed during validation")
    return candidate_sha


def require_armed_candidate_matches_deployed(app_root: Path, armed_candidate_sha: str) -> str:
    if not isinstance(armed_candidate_sha, str) or not SHA40_RE.fullmatch(armed_candidate_sha):
        raise SafetyError("armed Passenger candidate SHA invalid")
    deployed_sha = derive_deployed_release_sha(app_root)
    if deployed_sha != armed_candidate_sha:
        raise SafetyError("armed Passenger candidate does not match deployed release")
    return deployed_sha


@contextmanager
def bound_deployed_release_root(app_root: Path, armed_candidate_sha: str) -> Iterator[tuple[Path, str]]:
    """Keep the validated release inode open through Passenger evidence collection.

    The yielded path is the Linux descriptor path for the already-open release
    root. This prevents a same-name pathname replacement after identity
    verification from redirecting the subsequent WSGI/runtime evidence reads.
    """
    if not isinstance(armed_candidate_sha, str) or not SHA40_RE.fullmatch(armed_candidate_sha):
        raise SafetyError("armed Passenger candidate SHA invalid")
    if os.name != "posix" or not Path("/proc/self/fd").is_dir():
        raise SafetyError("bound deployed release path unavailable")

    root, root_lstat = _initial_root_identity(app_root)
    root_fd: int | None = None
    try:
        root_fd = _open_bound_release_root(root, root_lstat)
        deployed_sha = _validate_bound_release(root, root_fd, root_lstat)
        if deployed_sha != armed_candidate_sha:
            raise SafetyError("armed Passenger candidate does not match deployed release")
        bound_path = Path(f"/proc/self/fd/{root_fd}")
        if not bound_path.is_dir():
            raise SafetyError("bound deployed release path unavailable")
        yield bound_path, deployed_sha
    finally:
        _close_quietly(root_fd)
