# -*- coding: utf-8 -*-
"""Fail-closed identity derivation and descriptor binding for deployed releases."""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from contextlib import contextmanager
from dataclasses import dataclass
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


def _read_regular_leaf(root_fd: int, name: str, *, max_bytes: int) -> bytes:
    try:
        before = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
    except (OSError, TypeError, NotImplementedError) as exc:
        raise SafetyError("deployed release file unavailable") from exc
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise SafetyError("deployed release file topology unsafe")
    if before.st_size < 0 or before.st_size > max_bytes:
        raise SafetyError("deployed release file size unsafe")

    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        raise SafetyError("descriptor-safe deployed release file validation unavailable")
    flags = os.O_RDONLY | int(nofollow) | int(getattr(os, "O_CLOEXEC", 0))
    fd: int | None = None
    try:
        try:
            fd = os.open(name, flags, dir_fd=root_fd)
        except (OSError, TypeError, NotImplementedError) as exc:
            raise SafetyError("deployed release file open failed") from exc
        opened = os.fstat(fd)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or opened.st_dev != before.st_dev
            or opened.st_ino != before.st_ino
            or opened.st_size != before.st_size
        ):
            raise SafetyError("deployed release file changed during validation")
        raw = bytearray()
        while len(raw) <= max_bytes:
            chunk = os.read(fd, min(65536, max_bytes + 1 - len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
        if len(raw) > max_bytes:
            raise SafetyError("deployed release file too large")
        after = os.fstat(fd)
        if (
            after.st_dev != opened.st_dev
            or after.st_ino != opened.st_ino
            or after.st_size != opened.st_size
            or not stat.S_ISREG(after.st_mode)
            or after.st_nlink != 1
        ):
            raise SafetyError("deployed release file changed during read")
        return bytes(raw)
    finally:
        _close_quietly(fd)


def _read_bound_prepared_release(root_fd: int) -> bytes:
    raw = _read_regular_leaf(root_fd, PREPARED_RELEASE_NAME, max_bytes=MAX_PREPARED_RELEASE_BYTES)
    if not raw:
        raise SafetyError("prepared release metadata size unsafe")
    return raw


def _validate_bound_release(root_name: str, root_fd: int, expected: os.stat_result) -> str:
    if not SHA40_RE.fullmatch(root_name):
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
    if metadata_sha != root_name:
        raise SafetyError("deployed release identity mismatch")
    return root_name


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
        candidate_sha = _validate_bound_release(root.name, root_fd, root_lstat)
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


@dataclass(frozen=True)
class BoundDeployedRelease:
    root_fd: int
    root_name: str
    expected_dev: int
    expected_ino: int
    deployed_sha: str

    @property
    def proc_path(self) -> Path:
        return Path(f"/proc/self/fd/{self.root_fd}")

    def revalidate(self) -> str:
        expected = os.fstat(self.root_fd)
        if expected.st_dev != self.expected_dev or expected.st_ino != self.expected_ino:
            raise SafetyError("bound deployed release root identity changed")
        return _validate_bound_release(self.root_name, self.root_fd, expected)

    def regular_leaf_sha256(self, name: str, *, max_bytes: int = 8 * 1024 * 1024) -> str:
        raw = _read_regular_leaf(self.root_fd, name, max_bytes=max_bytes)
        return hashlib.sha256(raw).hexdigest()


@contextmanager
def bound_deployed_release_root(app_root: Path, armed_candidate_sha: str) -> Iterator[BoundDeployedRelease]:
    """Keep the validated release inode authoritative through finalization."""
    if not isinstance(armed_candidate_sha, str) or not SHA40_RE.fullmatch(armed_candidate_sha):
        raise SafetyError("armed Passenger candidate SHA invalid")
    if os.name != "posix" or not Path("/proc/self/fd").is_dir():
        raise SafetyError("bound deployed release path unavailable")

    root, root_lstat = _initial_root_identity(app_root)
    root_fd: int | None = None
    try:
        root_fd = _open_bound_release_root(root, root_lstat)
        deployed_sha = _validate_bound_release(root.name, root_fd, root_lstat)
        if deployed_sha != armed_candidate_sha:
            raise SafetyError("armed Passenger candidate does not match deployed release")
        bound = BoundDeployedRelease(
            root_fd=root_fd,
            root_name=root.name,
            expected_dev=int(root_lstat.st_dev),
            expected_ino=int(root_lstat.st_ino),
            deployed_sha=deployed_sha,
        )
        if not bound.proc_path.is_dir():
            raise SafetyError("bound deployed release path unavailable")
        yield bound
    finally:
        _close_quietly(root_fd)
