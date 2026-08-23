# -*- coding: utf-8 -*-
"""BURST01-07 adapter from commit-bound SEND_FILES payloads to DEV04 snapshots.

The write lane intentionally stores the opaque Bridge reference under ``file_id``
inside the private preview envelope.  The media lane intentionally calls the same
opaque reference ``file_ref``.  This module is the only translation boundary: it
never resolves, returns, logs, stringifies, or reopens a filesystem pathname.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from bridge.file_access import (
    UploadFileIdentity,
    VerifiedUploadBatch,
    open_verified_upload_batch,
)
from bridge.storage import FileRecordStore

_EXPECTED_IDENTITY_KEYS = frozenset({"file_id", "sha256", "size"})


def open_commit_bound_upload_batch(
    store: FileRecordStore,
    identities: Sequence[Mapping[str, Any]],
) -> VerifiedUploadBatch | None:
    """Create DEV04 immutable snapshots from DEV05's exact commit-bound identity.

    ``identities`` must be the already-normalized payload loaded from the preview
    store by commit.  Order is preserved.  Any shape/identity/content failure is
    raised or returned before the Telegram adapter is entered, so callers may
    classify it as a proven pre-effect failure.
    """

    if not isinstance(store, FileRecordStore):
        raise ValueError("private file store required")
    if isinstance(identities, (str, bytes)) or not isinstance(identities, Sequence):
        raise ValueError("commit-bound identities must be a sequence")
    if not identities:
        raise ValueError("commit-bound identities are required")

    converted: list[UploadFileIdentity] = []
    for raw in identities:
        if not isinstance(raw, Mapping) or set(raw) != _EXPECTED_IDENTITY_KEYS:
            raise ValueError("invalid commit-bound upload identity")
        converted.append(
            UploadFileIdentity(
                file_ref=raw["file_id"],
                sha256=raw["sha256"],
                size=raw["size"],
            )
        )

    return open_verified_upload_batch(store, tuple(converted))


__all__ = ["open_commit_bound_upload_batch"]
