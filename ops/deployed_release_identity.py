# -*- coding: utf-8 -*-
"""Fail-closed identity derivation for an actually deployed versioned release."""
from __future__ import annotations

import json
import os
import re
import stat
from pathlib import Path

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


def derive_deployed_release_sha(app_root: Path) -> str:
    """Derive release identity from a descriptor-bound exact-SHA release root.

    The root pathname is used only to obtain the initial expected identity and to
    verify that the same path identity still exists after validation. Metadata is
    opened relative to the already-bound directory descriptor, preventing a
    same-name root replacement from redirecting PREPARED_RELEASE.json lookup.
    """
    root = Path(app_root).expanduser()
    try:
        root_lstat = root.lstat()
    except OSError as exc:
        raise SafetyError("deployed release root unavailable") from exc
    if stat.S_ISLNK(root_lstat.st_mode) or not stat.S_ISDIR(root_lstat.st_mode):
        raise SafetyError("deployed release root topology unsafe")

    candidate_sha = root.name
    if not SHA40_RE.fullmatch(candidate_sha):
        raise SafetyError("deployed release root is not exact-SHA versioned")

    root_fd: int | None = None
    try:
        root_fd = _open_bound_release_root(root, root_lstat)
        raw = _read_bound_prepared_release(root_fd)
        bound_after = os.fstat(root_fd)
        if (
            not stat.S_ISDIR(bound_after.st_mode)
            or bound_after.st_dev != root_lstat.st_dev
            or bound_after.st_ino != root_lstat.st_ino
        ):
            raise SafetyError("deployed release root changed during validation")
    finally:
        _close_quietly(root_fd)

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
