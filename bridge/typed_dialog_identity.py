"""Preserve Telegram peer type across the dialogs -> history/search boundary.

Telethon entities expose a raw positive ``entity.id`` for users, legacy chats and
channels. Returning that raw value from the public dialogs API loses the peer
type, so a later numeric ``history(chat=...)``/``search(chat=...)`` lookup can
resolve the wrong peer or fail for groups/channels. Telethon v1 represents peer
identity with marked integers: users stay positive, chats are negative, and
channels use the ``-100...`` namespace.

This installer is dependency-free and network-free. It only changes the
``DialogRecord.id`` emitted by ``TelethonReadBackend``; the existing resolver
already accepts signed decimal references and passes the marked integer to the
Telegram client.
"""
from __future__ import annotations

from dataclasses import replace
from typing import Any

from .backend import TelethonReadBackend

_ORIGINAL_DIALOG_RECORD = TelethonReadBackend._dialog_record.__func__
_CHANNEL_MARK = 1_000_000_000_000


def marked_dialog_id(entity: Any, kind: str) -> str:
    """Return a stable Telethon-v1 marked peer id when the raw id is usable."""
    raw = getattr(entity, "id", None)
    if isinstance(raw, bool) or not isinstance(raw, int) or raw == 0:
        return "" if raw is None else str(raw)
    peer_id = abs(raw)
    if kind == "user":
        return str(peer_id)
    if kind == "group":
        return str(-peer_id)
    if kind == "channel":
        return str(-(_CHANNEL_MARK + peer_id))
    return str(raw)


def _typed_dialog_record(cls: type[TelethonReadBackend], dialog: Any):
    record = _ORIGINAL_DIALOG_RECORD(cls, dialog)
    entity = getattr(dialog, "entity", dialog)
    marked = marked_dialog_id(entity, record.kind)
    if not marked:
        return record
    return replace(record, id=marked)


def install_typed_dialog_identity() -> None:
    """Install typed dialog identity exactly once for production read paths."""
    current = TelethonReadBackend.__dict__.get("_dialog_record")
    if getattr(current, "_final10_b3_typed_dialog_identity", False):
        return
    replacement = classmethod(_typed_dialog_record)
    setattr(replacement, "_final10_b3_typed_dialog_identity", True)
    TelethonReadBackend._dialog_record = replacement


__all__ = ["install_typed_dialog_identity", "marked_dialog_id"]
