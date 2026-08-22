# -*- coding: utf-8 -*-
"""Fail-closed policy for pre-existing deployment lock artifacts.

This helper is deliberately side-effect free. It validates the inode that an
integration caller intends to use as the private deployment lock. The current
`ops.deploy_release` entrypoint must wire this policy before L4 can be claimed
fully closed.
"""
from __future__ import annotations

import os
import stat
from pathlib import Path


class LockPolicyError(RuntimeError):
    pass


def validate_preexisting_lock(path: Path, *, owner_uid: int | None = None) -> dict[str, int]:
    """Reject unsafe existing lock topology/content without normalizing it."""
    try:
        st = path.lstat()
    except OSError as exc:
        raise LockPolicyError("deployment lock metadata unavailable") from exc
    if stat.S_ISLNK(st.st_mode):
        raise LockPolicyError("deployment lock symlink rejected")
    if not stat.S_ISREG(st.st_mode):
        raise LockPolicyError("deployment lock must be a regular file")
    expected_uid = os.getuid() if owner_uid is None and hasattr(os, "getuid") else owner_uid
    if expected_uid is not None and st.st_uid != expected_uid:
        raise LockPolicyError("deployment lock owner mismatch")
    if stat.S_IMODE(st.st_mode) != 0o600:
        raise LockPolicyError("deployment lock mode must already be 0600")
    if st.st_nlink != 1:
        raise LockPolicyError("deployment lock hardlink topology rejected")
    if st.st_size != 0:
        raise LockPolicyError("deployment lock must be empty")
    return {"mode": 0o600, "size": 0, "nlink": 1}