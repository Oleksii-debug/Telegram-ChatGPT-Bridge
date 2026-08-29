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


def derive_deployed_release_sha(app_root: Path) -> str:
    """Derive release identity from the serving app root, never from a caller label.

    A deployable release is expected to live in a directory named by its exact
    40-character commit SHA and to contain a regular, non-symlink
    PREPARED_RELEASE.json whose ``sha`` field agrees with that directory name.
    The metadata file is opened with O_NOFOLLOW where the platform supports it.
    """
    root = Path(app_root).expanduser()
    try:
        root_lstat = root.lstat()
    except OSError as exc:
        raise SafetyError("deployed release root unavailable") from exc
    if root.is_symlink() or not stat.S_ISDIR(root_lstat.st_mode):
        raise SafetyError("deployed release root topology unsafe")

    candidate_sha = root.name
    if not SHA40_RE.fullmatch(candidate_sha):
        raise SafetyError("deployed release root is not exact-SHA versioned")

    metadata = root / PREPARED_RELEASE_NAME
    try:
        meta_lstat = metadata.lstat()
    except OSError as exc:
        raise SafetyError("prepared release metadata unavailable") from exc
    if metadata.is_symlink() or not stat.S_ISREG(meta_lstat.st_mode) or meta_lstat.st_nlink != 1:
        raise SafetyError("prepared release metadata topology unsafe")
    if meta_lstat.st_size <= 0 or meta_lstat.st_size > MAX_PREPARED_RELEASE_BYTES:
        raise SafetyError("prepared release metadata size unsafe")

    flags = os.O_RDONLY | int(getattr(os, "O_CLOEXEC", 0))
    if hasattr(os, "O_NOFOLLOW"):
        flags |= int(getattr(os, "O_NOFOLLOW"))
    try:
        fd = os.open(metadata, flags)
    except OSError as exc:
        raise SafetyError("prepared release metadata open failed") from exc
    try:
        opened = os.fstat(fd)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or opened.st_dev != meta_lstat.st_dev
            or opened.st_ino != meta_lstat.st_ino
            or opened.st_size != meta_lstat.st_size
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
    finally:
        os.close(fd)

    try:
        payload = json.loads(bytes(raw).decode("utf-8"))
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
        root.is_symlink()
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
