"""Canonical read-side models and cursor helpers."""

from __future__ import annotations

import base64
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable

from .errors import BridgeError
from .filenames import safe_filename

MAX_CURSOR_BYTES = 512


def _iso_utc(value: datetime | str | None) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        raw = value
        if raw.endswith("Z"):
            raw = raw[:-1] + "+00:00"
        try:
            value = datetime.fromisoformat(raw)
        except ValueError as exc:
            raise BridgeError("Invalid timestamp", code="invalid_timestamp") from exc
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def canonical_timestamp(value: datetime | str | None) -> str | None:
    """Return the canonical UTC representation used for read ordering/cursors."""

    return _iso_utc(value)


@dataclass(frozen=True)
class EntityRef:
    id: str
    kind: str
    display_name: str | None = None
    username: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class DialogRecord:
    id: str
    kind: str
    title: str
    username: str | None = None
    unread_count: int = 0
    pinned: bool = False
    last_message_at: str | None = None

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["last_message_at"] = _iso_utc(self.last_message_at)
        return payload


@dataclass(frozen=True)
class MediaRecord:
    type: str
    file_ref: str
    name: str | None = None
    mime_type: str | None = None
    size: int | None = None
    duration_seconds: float | None = None
    width: int | None = None
    height: int | None = None

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        # Telegram/file metadata is untrusted display input. Keep the internal
        # record faithful for backend/download matching, but expose one strict
        # UTF-8, path-independent filename through JSON. Message text is not
        # transformed here or anywhere in this filename policy.
        if self.name is not None:
            payload["name"] = safe_filename(self.name, "file", limit=180)
        return payload


@dataclass(frozen=True)
class MessageRecord:
    id: int
    chat_id: str
    timestamp: str
    text: str
    sender: EntityRef | None = None
    outgoing: bool = False
    reply_to_message_id: int | None = None
    media: tuple[MediaRecord, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        # Preserve the established internal MessageRecord UTC offset spelling
        # used by existing integrations while API serialization and cursor
        # comparisons remain canonically normalized through _iso_utc().
        if self.timestamp.endswith("Z"):
            object.__setattr__(self, "timestamp", self.timestamp[:-1] + "+00:00")

    def to_dict(self, *, include_text: bool = True) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "id": self.id,
            "chat_id": self.chat_id,
            "timestamp": _iso_utc(self.timestamp),
            "outgoing": self.outgoing,
            "reply_to_message_id": self.reply_to_message_id,
            "sender": self.sender.to_dict() if self.sender else None,
            "media": [m.to_dict() for m in self.media],
        }
        if include_text:
            payload["text"] = self.text
        return payload


@dataclass(frozen=True)
class Page:
    items: tuple[Any, ...]
    next_cursor: str | None
    scanned: int


def encode_cursor(payload: dict[str, Any]) -> str:
    raw = json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii")
    if len(raw) > MAX_CURSOR_BYTES:
        raise BridgeError("Cursor state is too large", status=500, code="cursor_state_too_large")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def decode_cursor(token: str | None) -> dict[str, Any] | None:
    if token in (None, ""):
        return None
    if not isinstance(token, str) or len(token) > 1024:
        raise BridgeError("Invalid cursor", code="invalid_cursor")
    if any(ch not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" for ch in token):
        raise BridgeError("Invalid cursor", code="invalid_cursor")
    padded = token + "=" * (-len(token) % 4)
    try:
        raw = base64.urlsafe_b64decode(padded.encode("ascii"))
        if len(raw) > MAX_CURSOR_BYTES:
            raise ValueError
        obj = json.loads(raw.decode("ascii"))
    except Exception as exc:
        raise BridgeError("Invalid cursor", code="invalid_cursor") from exc
    if not isinstance(obj, dict):
        raise BridgeError("Invalid cursor", code="invalid_cursor")
    return obj


def message_sort_key(message: MessageRecord) -> tuple[str, int, str]:
    """Stable total ordering key, including chat identity for global search."""

    return (canonical_timestamp(message.timestamp) or "", int(message.id), str(message.chat_id))


def stable_message_sort(messages: Iterable[MessageRecord], *, reverse: bool = True) -> list[MessageRecord]:
    return sorted(messages, key=message_sort_key, reverse=reverse)
