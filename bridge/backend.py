"""Telegram read backend abstraction and Telethon-compatible adapter.

The adapter imports Telethon lazily and performs no network activity at module
import or application construction time. A client factory can be injected for
credential-free deterministic tests. Every adapter operation owns a bounded
client lifecycle when the supplied client exposes connect/auth/disconnect hooks.
"""

from __future__ import annotations

import asyncio
import hashlib
import inspect
import unicodedata
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, AsyncIterator, Awaitable, Callable, Protocol

from .errors import BridgeError
from .models import (
    DialogRecord,
    EntityRef,
    MediaRecord,
    MessageRecord,
    Page,
    canonical_timestamp,
    decode_cursor,
    encode_cursor,
    message_sort_key,
    stable_message_sort,
)
from .validation import DateRange, normalize_search_text


class ReadBackend(Protocol):
    def list_dialogs(self, *, limit: int, cursor: str | None, query: str, unread_only: bool) -> Page: ...
    def history(self, *, chat: str, limit: int, cursor: str | None) -> Page: ...
    def search(
        self,
        *,
        chat: str | None,
        sender: str | None,
        text: str,
        dates: DateRange,
        limit: int,
        cursor: str | None,
        scan_limit: int,
    ) -> Page: ...
    def get_message(self, *, chat: str, message_id: int) -> MessageRecord: ...
    def download_media(self, *, chat: str, message_id: int, file_ref: str, destination: str) -> dict[str, Any]: ...


class UnavailableReadBackend:
    """Safe default used when real Telegram wiring is intentionally absent."""

    def _unavailable(self) -> None:
        raise BridgeError("Telegram read backend is not configured", status=503, code="telegram_backend_unconfigured")

    def list_dialogs(self, **kwargs: Any) -> Page:
        del kwargs
        self._unavailable()

    def history(self, **kwargs: Any) -> Page:
        del kwargs
        self._unavailable()

    def search(self, **kwargs: Any) -> Page:
        del kwargs
        self._unavailable()

    def get_message(self, **kwargs: Any) -> MessageRecord:
        del kwargs
        self._unavailable()

    def download_media(self, **kwargs: Any) -> dict[str, Any]:
        del kwargs
        self._unavailable()


@dataclass(frozen=True)
class TelethonReadConfig:
    request_timeout_seconds: int = 30
    dialog_scan_limit: int = 2_000
    search_scan_limit: int = 5_000
    flood_wait_cap_seconds: int = 30

    def __post_init__(self) -> None:
        for name, value, low, high in (
            ("request_timeout_seconds", self.request_timeout_seconds, 1, 120),
            ("dialog_scan_limit", self.dialog_scan_limit, 1, 20_000),
            ("search_scan_limit", self.search_scan_limit, 1, 50_000),
            ("flood_wait_cap_seconds", self.flood_wait_cap_seconds, 1, 300),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
                raise ValueError(f"{name} is outside the safe range")


@dataclass(frozen=True)
class _GlobalSearchContinuation:
    """Restart-safe, non-secret messages.searchGlobal continuation state."""

    offset_id: int
    peer_kind: str
    peer_id: int
    offset_rate: int


class TelethonReadBackend:
    """Map Telethon-like objects into stable read-side API records."""

    _ENTITY_NOT_FOUND_ERRORS = frozenset(
        {
            "UsernameInvalidError",
            "UsernameNotOccupiedError",
            "PeerIdInvalidError",
            "ChannelInvalidError",
            "ChatIdInvalidError",
        }
    )
    _FLOOD_WAIT_ERRORS = frozenset({"FloodWaitError", "FloodWait"})

    def __init__(
        self,
        *,
        client_factory: Callable[[], Any],
        config: TelethonReadConfig | None = None,
    ) -> None:
        self.client_factory = client_factory
        self.config = config or TelethonReadConfig()

    @staticmethod
    async def _maybe_await(value: Any) -> Any:
        return await value if hasattr(value, "__await__") else value

    async def _make_client(self) -> Any:
        return await self._maybe_await(self.client_factory())

    @asynccontextmanager
    async def _client_session(self) -> AsyncIterator[Any]:
        """Bound connect/auth/disconnect to one operation and always clean up."""
        client = await self._make_client()
        try:
            connect = getattr(client, "connect", None)
            if callable(connect):
                await self._maybe_await(connect())

            checker = getattr(client, "is_user_authorized", None)
            if checker is not None:
                state = checker() if callable(checker) else checker
                authorized = await self._maybe_await(state)
                if authorized is not True:
                    raise BridgeError(
                        "Telegram user session is not authorized",
                        status=503,
                        code="telegram_not_authorized",
                        details={"retryable": False},
                    )
            yield client
        finally:
            disconnect = getattr(client, "disconnect", None)
            if callable(disconnect):
                try:
                    await self._maybe_await(disconnect())
                except Exception:
                    pass

    @staticmethod
    def _entity_kind(entity: Any) -> str:
        name = entity.__class__.__name__.casefold()
        if "channel" in name:
            return "channel"
        if "chat" in name:
            return "group"
        if "user" in name:
            return "user"
        return "unknown"

    @staticmethod
    def _entity_title(entity: Any) -> str:
        title = getattr(entity, "title", None)
        if title:
            return str(title)
        first = str(getattr(entity, "first_name", None) or "")
        last = str(getattr(entity, "last_name", None) or "")
        full = (first + " " + last).strip()
        username = getattr(entity, "username", None)
        return full or (str(username) if username else str(getattr(entity, "id", "unknown")))

    @staticmethod
    def _optional_text(value: Any) -> str | None:
        if value is None or value == "":
            return None
        return str(value)

    @staticmethod
    def _optional_int(value: Any, *, minimum: int = 0) -> int | None:
        if value is None or value == "":
            return None
        try:
            result = int(value)
        except (TypeError, ValueError, OverflowError):
            return None
        return result if result >= minimum else None

    @staticmethod
    def _optional_float(value: Any, *, minimum: float = 0.0) -> float | None:
        if value is None or value == "":
            return None
        try:
            result = float(value)
        except (TypeError, ValueError, OverflowError):
            return None
        return result if result >= minimum else None

    @classmethod
    def _dialog_record(cls, dialog: Any) -> DialogRecord:
        entity = getattr(dialog, "entity", dialog)
        date = getattr(getattr(dialog, "message", None), "date", None)
        return DialogRecord(
            id=str(getattr(entity, "id", "")),
            kind=cls._entity_kind(entity),
            title=cls._entity_title(entity),
            username=cls._optional_text(getattr(entity, "username", None)),
            unread_count=max(0, int(getattr(dialog, "unread_count", 0) or 0)),
            pinned=bool(getattr(dialog, "pinned", False)),
            last_message_at=canonical_timestamp(date) if isinstance(date, datetime) else None,
        )

    @classmethod
    def _media_records(cls, message: Any) -> tuple[MediaRecord, ...]:
        file_obj = getattr(message, "file", None)
        media = getattr(message, "media", None)
        if media is None and file_obj is None:
            return ()
        if getattr(message, "voice", None):
            kind = "voice"
        elif getattr(message, "video_note", None):
            kind = "video_note"
        elif getattr(message, "photo", None):
            kind = "photo"
        elif getattr(message, "video", None):
            kind = "video"
        elif getattr(message, "audio", None):
            kind = "audio"
        elif getattr(message, "sticker", None):
            kind = "sticker"
        elif getattr(message, "document", None):
            kind = "document"
        else:
            kind = "other"

        msg_id = int(getattr(message, "id", 0) or 0)
        media_id = (
            getattr(getattr(message, "document", None), "id", None)
            or getattr(getattr(message, "photo", None), "id", None)
            or getattr(file_obj, "id", None)
            or 0
        )
        chat_hint = (
            getattr(message, "chat_id", None)
            or getattr(getattr(message, "peer_id", None), "channel_id", None)
            or getattr(getattr(message, "peer_id", None), "chat_id", None)
            or getattr(getattr(message, "peer_id", None), "user_id", None)
            or 0
        )
        digest = hashlib.sha256(f"v1:{chat_hint}:{msg_id}:{kind}:{media_id}".encode("ascii", "strict")).hexdigest()[:20]
        file_ref = f"tg_{msg_id}_{digest}"
        return (
            MediaRecord(
                type=kind,
                file_ref=file_ref,
                name=cls._optional_text(getattr(file_obj, "name", None)) if file_obj is not None else None,
                mime_type=cls._optional_text(getattr(file_obj, "mime_type", None)) if file_obj is not None else None,
                size=cls._optional_int(getattr(file_obj, "size", None)) if file_obj is not None else None,
                duration_seconds=cls._optional_float(getattr(file_obj, "duration", None)) if file_obj is not None else None,
                width=cls._optional_int(getattr(file_obj, "width", None), minimum=1) if file_obj is not None else None,
                height=cls._optional_int(getattr(file_obj, "height", None), minimum=1) if file_obj is not None else None,
            ),
        )

    @classmethod
    async def _message_record(
        cls,
        message: Any,
        chat_id: str,
        *,
        require_sender_details: bool = False,
    ) -> MessageRecord:
        sender_id = getattr(message, "sender_id", None)
        sender_obj = None
        getter = getattr(message, "get_sender", None)
        if callable(getter):
            try:
                sender_obj = await cls._maybe_await(getter())
            except Exception:
                # History/message reads can still expose the stable sender ID if
                # optional display metadata is unavailable. A person-name or
                # username search cannot truthfully return an empty result when
                # sender resolution itself failed, so that path is strict.
                if require_sender_details:
                    raise
                sender_obj = None
        sender = None
        if sender_obj is not None:
            sender = EntityRef(
                id=str(getattr(sender_obj, "id", sender_id or "")),
                kind=cls._entity_kind(sender_obj),
                display_name=cls._entity_title(sender_obj),
                username=cls._optional_text(getattr(sender_obj, "username", None)),
            )
        elif sender_id is not None:
            sender = EntityRef(id=str(sender_id), kind="unknown")

        date = getattr(message, "date", None)
        if not isinstance(date, datetime):
            date = datetime.fromtimestamp(0, tz=timezone.utc)
        elif date.tzinfo is None:
            date = date.replace(tzinfo=timezone.utc)
        reply = getattr(getattr(message, "reply_to", None), "reply_to_msg_id", None)
        return MessageRecord(
            id=int(getattr(message, "id", 0) or 0),
            chat_id=str(getattr(message, "chat_id", None) or chat_id),
            timestamp=canonical_timestamp(date) or "1970-01-01T00:00:00Z",
            text=str(getattr(message, "message", None) or ""),
            sender=sender,
            outgoing=bool(getattr(message, "out", False)),
            reply_to_message_id=int(reply) if reply is not None else None,
            media=cls._media_records(message),
        )

    @staticmethod
    def _cursor_signature(scope: str, *parts: str) -> str:
        material = "\x1f".join((scope, *parts)).encode("utf-8", "strict")
        return hashlib.sha256(material).hexdigest()[:24]

    @staticmethod
    def _invalid_cursor(exc: Exception | None = None) -> BridgeError:
        error = BridgeError("Invalid cursor", code="invalid_cursor")
        if exc is not None:
            error.__cause__ = exc
        return error

    @classmethod
    def _message_boundary(
        cls,
        cursor: str | None,
        scope: str,
        signature: str,
    ) -> tuple[str, int, str] | None:
        decoded = decode_cursor(cursor)
        if decoded is None:
            return None
        if set(decoded) != {"v", "scope", "sig", "boundary"}:
            raise cls._invalid_cursor()
        if decoded.get("v") != 2 or decoded.get("scope") != scope or decoded.get("sig") != signature:
            raise cls._invalid_cursor()
        boundary = decoded.get("boundary")
        if not isinstance(boundary, list) or len(boundary) != 3:
            raise cls._invalid_cursor()
        stamp, message_id, chat_id = boundary
        if not isinstance(stamp, str) or not stamp or len(stamp) > 64:
            raise cls._invalid_cursor()
        if isinstance(message_id, bool) or not isinstance(message_id, int) or message_id < 0 or message_id > 2**63 - 1:
            raise cls._invalid_cursor()
        if not isinstance(chat_id, str) or not chat_id or len(chat_id) > 256:
            raise cls._invalid_cursor()
        try:
            normalized = canonical_timestamp(stamp)
        except BridgeError as exc:
            raise cls._invalid_cursor(exc) from exc
        if normalized != stamp:
            raise cls._invalid_cursor()
        return stamp, message_id, chat_id

    @classmethod
    def _dialog_boundary(
        cls,
        cursor: str | None,
        signature: str,
    ) -> tuple[str, str] | None:
        decoded = decode_cursor(cursor)
        if decoded is None:
            return None
        if set(decoded) != {"v", "scope", "sig", "boundary"}:
            raise cls._invalid_cursor()
        if decoded.get("v") != 2 or decoded.get("scope") != "dialogs" or decoded.get("sig") != signature:
            raise cls._invalid_cursor()
        boundary = decoded.get("boundary")
        if not isinstance(boundary, list) or len(boundary) != 2:
            raise cls._invalid_cursor()
        stamp, dialog_id = boundary
        if not isinstance(stamp, str) or len(stamp) > 64:
            raise cls._invalid_cursor()
        if not isinstance(dialog_id, str) or not dialog_id or len(dialog_id) > 256:
            raise cls._invalid_cursor()
        if stamp:
            try:
                normalized = canonical_timestamp(stamp)
            except BridgeError as exc:
                raise cls._invalid_cursor(exc) from exc
            if normalized != stamp:
                raise cls._invalid_cursor()
        return stamp, dialog_id

    @staticmethod
    def _dialog_key(record: DialogRecord) -> tuple[str, str]:
        return canonical_timestamp(record.last_message_at) or "", str(record.id)

    @staticmethod
    def _message_next_cursor(
        scope: str,
        signature: str,
        page: list[MessageRecord],
        *,
        has_more: bool,
    ) -> str | None:
        if not has_more or not page:
            return None
        last = page[-1]
        stamp, message_id, chat_id = message_sort_key(last)
        return encode_cursor(
            {
                "v": 2,
                "scope": scope,
                "sig": signature,
                "boundary": [stamp, message_id, chat_id],
            }
        )

    @classmethod
    def _dialog_next_cursor(
        cls,
        signature: str,
        page: list[DialogRecord],
        *,
        has_more: bool,
    ) -> str | None:
        if not has_more or not page:
            return None
        stamp, dialog_id = cls._dialog_key(page[-1])
        return encode_cursor(
            {
                "v": 2,
                "scope": "dialogs",
                "sig": signature,
                "boundary": [stamp, dialog_id],
            }
        )

    def _run(self, coro: Awaitable[Any]) -> Any:
        try:
            return asyncio.run(asyncio.wait_for(coro, timeout=self.config.request_timeout_seconds))
        except asyncio.TimeoutError as exc:
            raise BridgeError("Telegram read timed out", status=504, code="telegram_timeout", details={"retryable": True}) from exc
        except BridgeError:
            raise
        except Exception as exc:
            name = exc.__class__.__name__
            seconds = getattr(exc, "seconds", None)
            if name in self._FLOOD_WAIT_ERRORS:
                retry = min(
                    max(1, int(seconds) if isinstance(seconds, int) and seconds > 0 else 1),
                    self.config.flood_wait_cap_seconds,
                )
                raise BridgeError(
                    "Telegram rate limit encountered",
                    status=429,
                    code="telegram_flood_wait",
                    retry_after_seconds=retry,
                    details={"retryable": True},
                ) from exc
            raise BridgeError("Telegram read operation failed", status=502, code="telegram_rpc_error", details={"retryable": True}) from exc

    async def _iter_dialogs(self, client: Any, limit: int) -> list[Any]:
        iterator = client.iter_dialogs(limit=limit)
        if hasattr(iterator, "__aiter__"):
            return [item async for item in iterator]
        return list(iterator)

    @staticmethod
    def _supports_named_parameter(callable_obj: Any, parameter: str) -> bool:
        """Return true only for an explicitly declared callable parameter.

        Production Telethon declares ``offset_id`` explicitly. Generic test
        fakes that merely accept ``**kwargs`` are not assumed to implement its
        semantics; they stay on the bounded compatibility path.
        """
        try:
            return parameter in inspect.signature(callable_obj).parameters
        except (TypeError, ValueError):
            return False

    async def _iter_messages(
        self,
        client: Any,
        entity: Any,
        limit: int,
        *,
        search: str = "",
        offset_id: int | None = None,
    ) -> list[Any]:
        method = client.iter_messages
        kwargs: dict[str, Any] = {"limit": limit}
        if search:
            kwargs["search"] = search
        if offset_id is not None and self._supports_named_parameter(method, "offset_id"):
            kwargs["offset_id"] = offset_id
        try:
            iterator = method(entity, **kwargs)
        except TypeError:
            # Simple deterministic fakes may intentionally expose only the
            # minimal iter_messages(entity, limit) contract. Filtering remains
            # deterministic below; real Telethon clients receive supported
            # server-side search/offset hints.
            iterator = method(entity, limit=limit)
        if hasattr(iterator, "__aiter__"):
            return [item async for item in iterator]
        return list(iterator)

    async def _resolve(self, client: Any, ref: str) -> Any:
        try:
            target: Any = int(ref) if ref.lstrip("-").isdigit() else ref.lstrip("@")
            return await self._maybe_await(client.get_entity(target))
        except BridgeError:
            raise
        except Exception as exc:
            if isinstance(exc, ValueError) or exc.__class__.__name__ in self._ENTITY_NOT_FOUND_ERRORS:
                raise BridgeError("Chat not found", status=404, code="chat_not_found") from exc
            raise

    def list_dialogs(self, *, limit: int, cursor: str | None, query: str, unread_only: bool) -> Page:
        async def work() -> Page:
            async with self._client_session() as client:
                dialogs = await self._iter_dialogs(client, self.config.dialog_scan_limit)
                records = [self._dialog_record(d) for d in dialogs]
                needle = normalize_search_text(query.strip())
                if needle:
                    records = [d for d in records if needle in normalize_search_text(f"{d.title} {d.username or ''} {d.id}")]
                if unread_only:
                    records = [d for d in records if d.unread_count > 0]
                records.sort(key=self._dialog_key, reverse=True)
                signature = self._cursor_signature("dialogs", needle, "1" if unread_only else "0")
                boundary = self._dialog_boundary(cursor, signature)
                if boundary is not None:
                    records = [record for record in records if self._dialog_key(record) < boundary]
                page = records[:limit]
                has_more = len(records) > limit
                return Page(
                    tuple(page),
                    self._dialog_next_cursor(signature, page, has_more=has_more),
                    min(len(dialogs), self.config.dialog_scan_limit),
                )

        return self._run(work())

    def history(self, *, chat: str, limit: int, cursor: str | None) -> Page:
        async def work() -> Page:
            signature = self._cursor_signature("history", chat.strip())
            boundary = self._message_boundary(cursor, "history", signature)
            async with self._client_session() as client:
                entity = await self._resolve(client, chat)
                method = client.iter_messages
                supports_offset = self._supports_named_parameter(method, "offset_id")

                # Telethon history is newest->oldest and ``offset_id`` is an
                # exclusive older-than boundary. Fetching only limit+1 keeps
                # every page bounded and lets a cursor traverse histories far
                # beyond the former fixed search_scan_limit ceiling. Minimal
                # legacy fakes without explicit offset semantics retain the old
                # bounded rescan only for non-production compatibility tests.
                if boundary is None:
                    fetch_limit = limit + 1
                    offset_id = None
                elif supports_offset:
                    fetch_limit = limit + 1
                    offset_id = boundary[1]
                else:
                    fetch_limit = self.config.search_scan_limit
                    offset_id = None

                messages = await self._iter_messages(
                    client,
                    entity,
                    fetch_limit,
                    offset_id=offset_id,
                )
                chat_id = str(getattr(entity, "id", chat))
                records = stable_message_sort([await self._message_record(m, chat_id) for m in messages], reverse=True)
                if boundary is not None:
                    records = [record for record in records if message_sort_key(record) < boundary]
                page = records[:limit]
                has_more = len(records) > limit
                return Page(
                    tuple(page),
                    self._message_next_cursor("history", signature, page, has_more=has_more),
                    len(messages),
                )

        return self._run(work())

    @staticmethod
    def _looks_like_username(ref: str) -> bool:
        candidate = ref.lstrip("@")
        return bool(candidate) and len(candidate) <= 32 and all(
            character.isascii() and (character.isalnum() or character == "_")
            for character in candidate
        )

    async def _resolve_search_sender(
        self,
        client: Any,
        ref: str,
        *,
        dialogs: list[Any] | None = None,
    ) -> Any:
        """Resolve a person once so bounded scans cannot silently lose identity."""

        raw = ref.strip()
        needle = normalize_search_text(raw.lstrip("@"))
        if not needle:
            raise BridgeError("Sender is required", code="invalid_sender")

        direct_hint = raw.startswith("@") or raw.lstrip("-").isdigit() or self._looks_like_username(raw)
        if direct_hint:
            target: Any = int(raw) if raw.lstrip("-").isdigit() else raw.lstrip("@")
            getter = getattr(client, "get_entity", None)
            if callable(getter):
                try:
                    entity = await self._maybe_await(getter(target))
                except Exception as exc:
                    if not (isinstance(exc, ValueError) or exc.__class__.__name__ in self._ENTITY_NOT_FOUND_ERRORS):
                        raise
                else:
                    if self._entity_kind(entity) != "user":
                        raise BridgeError("Sender reference is not a person", code="sender_not_person")
                    return entity

        source_dialogs = dialogs
        if source_dialogs is None:
            source_dialogs = await self._iter_dialogs(client, self.config.dialog_scan_limit + 1)
            if len(source_dialogs) > self.config.dialog_scan_limit:
                raise BridgeError(
                    "Sender lookup exceeds the configured dialog bound",
                    status=400,
                    code="sender_lookup_limit_exceeded",
                    details={"retryable": False},
                )

        ranked: dict[str, tuple[int, Any]] = {}
        for dialog in source_dialogs:
            entity = getattr(dialog, "entity", dialog)
            if self._entity_kind(entity) != "user":
                continue
            entity_id = str(getattr(entity, "id", ""))
            username = normalize_search_text(str(getattr(entity, "username", None) or ""))
            display_name = normalize_search_text(self._entity_title(entity))
            exact = needle in {normalize_search_text(entity_id), username, display_name}
            combined = normalize_search_text(
                f"{entity_id} {getattr(entity, 'username', None) or ''} {self._entity_title(entity)}"
            )
            score = 2 if exact else 1 if needle in combined else 0
            if score:
                key = entity_id or f"object:{id(entity)}"
                previous = ranked.get(key)
                if previous is None or score > previous[0]:
                    ranked[key] = (score, entity)

        if ranked:
            best_score = max(score for score, _ in ranked.values())
            best = [entity for score, entity in ranked.values() if score == best_score]
            if len(best) == 1:
                return best[0]
            raise BridgeError(
                "Sender reference is ambiguous",
                code="sender_ambiguous",
                details={"match_count": len(best)},
            )
        raise BridgeError("Sender not found", status=404, code="sender_not_found")

    @classmethod
    def _bind_resolved_sender(cls, record: MessageRecord, sender_entity: Any) -> MessageRecord | None:
        expected_id = str(getattr(sender_entity, "id", ""))
        if not expected_id:
            raise BridgeError(
                "Resolved sender has no stable identifier",
                status=502,
                code="telegram_sender_identity_invalid",
            )
        if record.sender is not None and record.sender.id and record.sender.id != expected_id:
            return None
        return MessageRecord(
            id=record.id,
            chat_id=record.chat_id,
            timestamp=record.timestamp,
            text=record.text,
            sender=EntityRef(
                id=expected_id,
                kind=cls._entity_kind(sender_entity),
                display_name=cls._entity_title(sender_entity),
                username=cls._optional_text(getattr(sender_entity, "username", None)),
            ),
            outgoing=record.outgoing,
            reply_to_message_id=record.reply_to_message_id,
            media=record.media,
        )

    @staticmethod
    def _global_peer_parts(message: Any) -> tuple[str, int]:
        peer = getattr(message, "peer_id", None)
        for kind, attribute in (("user", "user_id"), ("chat", "chat_id"), ("channel", "channel_id")):
            value = getattr(peer, attribute, None)
            if isinstance(value, int) and not isinstance(value, bool) and value > 0:
                return kind, value
        raise BridgeError(
            "Telegram global result lacks a stable peer",
            status=502,
            code="telegram_global_peer_missing",
        )

    @staticmethod
    def _next_global_offset_rate(result: Any, last_message: Any) -> int:
        rate = getattr(result, "next_rate", None)
        if rate is not None:
            if isinstance(rate, bool) or not isinstance(rate, int) or rate < 0:
                raise BridgeError(
                    "Telegram global search returned an invalid continuation rate",
                    status=502,
                    code="telegram_global_rate_invalid",
                )
            return rate

        stamp = getattr(last_message, "date", None)
        if isinstance(stamp, datetime):
            if stamp.tzinfo is None:
                stamp = stamp.replace(tzinfo=timezone.utc)
            value = int(stamp.timestamp())
        elif isinstance(stamp, bool) or not isinstance(stamp, int):
            raise BridgeError(
                "Telegram global search continuation lacks a usable message date",
                status=502,
                code="telegram_global_rate_missing",
            )
        else:
            value = stamp
        if value < 0:
            raise BridgeError(
                "Telegram global search continuation has an invalid message date",
                status=502,
                code="telegram_global_rate_invalid",
            )
        return value

    @classmethod
    def _decode_global_cursor(
        cls,
        token: str | None,
        signature: str,
    ) -> _GlobalSearchContinuation | None:
        decoded = decode_cursor(token)
        if decoded is None:
            return None
        if (
            set(decoded) != {"v", "scope", "sig", "tg"}
            or decoded.get("v") != 3
            or decoded.get("scope") != "search-global"
            or decoded.get("sig") != signature
        ):
            raise cls._invalid_cursor()
        tg = decoded.get("tg")
        if not isinstance(tg, dict) or set(tg) != {"offset_id", "peer_kind", "peer_id", "offset_rate"}:
            raise cls._invalid_cursor()
        offset_id = tg["offset_id"]
        peer_kind = tg["peer_kind"]
        peer_id = tg["peer_id"]
        offset_rate = tg["offset_rate"]
        if isinstance(offset_id, bool) or not isinstance(offset_id, int) or offset_id <= 0:
            raise cls._invalid_cursor()
        if peer_kind not in {"user", "chat", "channel"}:
            raise cls._invalid_cursor()
        if isinstance(peer_id, bool) or not isinstance(peer_id, int) or peer_id <= 0:
            raise cls._invalid_cursor()
        if isinstance(offset_rate, bool) or not isinstance(offset_rate, int) or offset_rate < 0:
            raise cls._invalid_cursor()
        return _GlobalSearchContinuation(offset_id, peer_kind, peer_id, offset_rate)

    @staticmethod
    def _encode_global_cursor(signature: str, state: _GlobalSearchContinuation) -> str:
        return encode_cursor(
            {
                "v": 3,
                "scope": "search-global",
                "sig": signature,
                "tg": {
                    "offset_id": state.offset_id,
                    "peer_kind": state.peer_kind,
                    "peer_id": state.peer_id,
                    "offset_rate": state.offset_rate,
                },
            }
        )

    @staticmethod
    async def _restore_global_input_peer(
        client: Any,
        types: Any,
        state: _GlobalSearchContinuation | None,
    ) -> Any:
        if state is None:
            return types.InputPeerEmpty()
        constructor = {
            "user": types.PeerUser,
            "chat": types.PeerChat,
            "channel": types.PeerChannel,
        }[state.peer_kind]
        resolver = getattr(client, "get_input_entity", None)
        if not callable(resolver):
            raise BridgeError(
                "Telegram client cannot restore the global continuation peer",
                status=503,
                code="telegram_global_peer_restore_unsupported",
            )
        return await TelethonReadBackend._maybe_await(resolver(constructor(state.peer_id)))

    async def _search_global_chunk(
        self,
        client: Any,
        *,
        query: str,
        limit: int,
        state: _GlobalSearchContinuation | None,
        max_date: datetime | None,
    ) -> tuple[list[Any], _GlobalSearchContinuation | None]:
        if not query:
            raise BridgeError(
                "Telegram global text search requires a non-empty query",
                status=400,
                code="telegram_global_query_empty",
            )
        try:
            from telethon import functions, types
        except Exception as exc:
            raise BridgeError(
                "Telethon global search support is unavailable",
                status=503,
                code="telegram_global_search_unsupported",
            ) from exc
        peer = await self._restore_global_input_peer(client, types, state)
        request = functions.messages.SearchGlobalRequest(
            q=query,
            filter=types.InputMessagesFilterEmpty(),
            min_date=None,
            max_date=max_date,
            offset_rate=0 if state is None else state.offset_rate,
            offset_peer=peer,
            offset_id=0 if state is None else state.offset_id,
            limit=limit,
        )
        caller = getattr(client, "__call__", None)
        if not callable(caller):
            raise BridgeError(
                "Telegram client does not support raw global search",
                status=503,
                code="telegram_global_search_unsupported",
            )
        result = await self._maybe_await(client(request))
        messages = list(getattr(result, "messages", ()) or ())
        if not messages:
            return [], None
        last = messages[-1]
        message_id = getattr(last, "id", None)
        if isinstance(message_id, bool) or not isinstance(message_id, int) or message_id <= 0:
            raise BridgeError(
                "Telegram global result lacks a stable message identifier",
                status=502,
                code="telegram_global_message_id_invalid",
            )
        peer_kind, peer_id = self._global_peer_parts(last)
        return messages, _GlobalSearchContinuation(
            message_id,
            peer_kind,
            peer_id,
            self._next_global_offset_rate(result, last),
        )

    async def _global_text_search(
        self,
        client: Any,
        *,
        sender_entity: Any | None,
        sender_cf: str,
        needle: str,
        server_query: str,
        dates: DateRange,
        limit: int,
        cursor: str | None,
        scan_limit: int,
    ) -> Page:
        signature = self._cursor_signature(
            "search-global-v3",
            sender_cf,
            needle,
            canonical_timestamp(dates.start) or "",
            canonical_timestamp(dates.end) or "",
            str(scan_limit),
        )
        state = self._decode_global_cursor(cursor, signature)
        budget = min(scan_limit, self.config.search_scan_limit)
        max_date = dates.end + timedelta(seconds=1) if dates.end is not None else None
        scanned = 0
        output: list[MessageRecord] = []
        exhausted = False
        while len(output) < limit and scanned < budget:
            remaining = min(limit - len(output), budget - scanned, 100)
            raw, next_state = await self._search_global_chunk(
                client,
                query=server_query,
                limit=remaining,
                state=state,
                max_date=max_date,
            )
            scanned += len(raw)
            if not raw:
                exhausted = True
                state = None
                break
            for message in raw:
                record = await self._message_record(
                    message,
                    str(getattr(message, "chat_id", None) or "global"),
                )
                if sender_entity is not None:
                    bound = self._bind_resolved_sender(record, sender_entity)
                    if bound is None:
                        continue
                    record = bound
                stamp = datetime.fromisoformat(record.timestamp.replace("Z", "+00:00"))
                if not dates.contains(stamp):
                    continue
                if needle and needle not in normalize_search_text(record.text):
                    continue
                output.append(record)
            state = next_state
            if state is None:
                exhausted = True
                break
        next_cursor = None if exhausted or state is None else self._encode_global_cursor(signature, state)
        return Page(tuple(output), next_cursor, scanned)

    async def _iter_dialog_search_one(
        self,
        client: Any,
        entity: Any,
        *,
        sender_entity: Any | None,
        offset_id: int | None,
        offset_date: datetime | None,
    ) -> list[Any]:
        method = client.iter_messages
        kwargs: dict[str, Any] = {"limit": 1}
        if sender_entity is not None:
            if not self._supports_named_parameter(method, "from_user"):
                raise BridgeError(
                    "Telegram client does not support person-constrained search",
                    status=503,
                    code="telegram_global_sender_unsupported",
                )
            kwargs["from_user"] = sender_entity
        if offset_id is not None:
            if not self._supports_named_parameter(method, "offset_id"):
                raise BridgeError(
                    "Telegram client does not support search continuation",
                    status=503,
                    code="telegram_search_continuation_unsupported",
                )
            kwargs["offset_id"] = offset_id
        if offset_date is not None:
            if not self._supports_named_parameter(method, "offset_date"):
                raise BridgeError(
                    "Telegram client does not support date-bounded search",
                    status=503,
                    code="telegram_search_date_unsupported",
                )
            kwargs["offset_date"] = offset_date
        iterator = method(entity, **kwargs)
        if hasattr(iterator, "__aiter__"):
            return [message async for message in iterator]
        return list(iterator)

    async def _global_filter_search(
        self,
        client: Any,
        *,
        dialogs: list[Any],
        sender_entity: Any | None,
        sender_cf: str,
        dates: DateRange,
        limit: int,
        cursor: str | None,
        scan_limit: int,
    ) -> Page:
        """Merge one bounded per-dialog stream when searchGlobal cannot accept q=""."""

        signature = self._cursor_signature(
            "search-global-dialogs-v1",
            sender_cf,
            canonical_timestamp(dates.start) or "",
            canonical_timestamp(dates.end) or "",
            str(scan_limit),
        )
        boundary = self._message_boundary(cursor, "search-global-dialogs", signature)
        budget = min(scan_limit, self.config.search_scan_limit)
        entities: list[Any] = []
        seen: set[tuple[str, str]] = set()
        for dialog in dialogs:
            entity = getattr(dialog, "entity", dialog)
            identity = (self._entity_kind(entity), str(getattr(entity, "id", "")))
            if not identity[1] or identity in seen:
                continue
            last_date = getattr(getattr(dialog, "message", None), "date", None)
            if dates.start is not None and isinstance(last_date, datetime):
                normalized = last_date if last_date.tzinfo else last_date.replace(tzinfo=timezone.utc)
                if normalized.astimezone(timezone.utc) < dates.start:
                    continue
            seen.add(identity)
            entities.append(entity)

        if len(entities) > budget:
            raise BridgeError(
                "Global filter search needs a larger scan_limit to cover every dialog truthfully",
                status=400,
                code="global_search_scan_limit_too_small",
                details={"limit": budget, "count": len(entities), "retryable": False},
            )

        upper_dates = [value for value in (dates.end,) if value is not None]
        if boundary is not None:
            upper_dates.append(datetime.fromisoformat(boundary[0].replace("Z", "+00:00")))
        offset_date = min(upper_dates) + timedelta(seconds=1) if upper_dates else None
        scanned = 0
        budget_exhausted = False
        heads: dict[int, tuple[Any, MessageRecord, int]] = {}

        async def advance(index: int, offset_id: int | None) -> tuple[Any, MessageRecord, int] | None:
            nonlocal scanned, budget_exhausted
            entity = entities[index]
            current_offset = offset_id
            while scanned < budget:
                rows = await self._iter_dialog_search_one(
                    client,
                    entity,
                    sender_entity=sender_entity,
                    offset_id=current_offset,
                    offset_date=offset_date,
                )
                if not rows:
                    return None
                message = rows[0]
                message_id = getattr(message, "id", None)
                if isinstance(message_id, bool) or not isinstance(message_id, int) or message_id <= 0:
                    raise BridgeError(
                        "Telegram search result lacks a stable message identifier",
                        status=502,
                        code="telegram_message_id_invalid",
                    )
                current_offset = message_id
                scanned += 1
                record = await self._message_record(
                    message,
                    str(getattr(entity, "id", "global")),
                )
                if sender_entity is not None:
                    bound = self._bind_resolved_sender(record, sender_entity)
                    if bound is None:
                        continue
                    record = bound
                stamp = datetime.fromisoformat(record.timestamp.replace("Z", "+00:00"))
                if dates.start is not None and stamp < dates.start:
                    return None
                if not dates.contains(stamp):
                    continue
                if boundary is not None and message_sort_key(record) >= boundary:
                    continue
                return message, record, current_offset
            budget_exhausted = True
            return None

        for index in range(len(entities)):
            candidate = await advance(index, None)
            if candidate is not None:
                heads[index] = candidate
            if budget_exhausted and index + 1 < len(entities):
                raise BridgeError(
                    "Global filter search exhausted its scan bound before every dialog was covered",
                    status=400,
                    code="global_search_scan_limit_exhausted",
                    details={"retryable": False},
                )

        output: list[MessageRecord] = []
        while heads and len(output) < limit:
            index = max(heads, key=lambda item: message_sort_key(heads[item][1]))
            _, record, current_offset = heads.pop(index)
            output.append(record)
            candidate = await advance(index, current_offset)
            if candidate is not None:
                heads[index] = candidate
            if len(output) >= limit or budget_exhausted:
                break

        if not output and budget_exhausted:
            raise BridgeError(
                "Global filter search exhausted its scan bound before finding a stable page boundary",
                status=400,
                code="global_search_scan_limit_exhausted",
                details={"retryable": False},
            )
        has_more = bool(output) and (bool(heads) or budget_exhausted)
        next_cursor = None
        if has_more:
            next_cursor = encode_cursor(
                {
                    "v": 2,
                    "scope": "search-global-dialogs",
                    "sig": signature,
                    "boundary": list(message_sort_key(output[-1])),
                }
            )
        return Page(tuple(output), next_cursor, scanned)

    def search(
        self,
        *,
        chat: str | None,
        sender: str | None,
        text: str,
        dates: DateRange,
        limit: int,
        cursor: str | None,
        scan_limit: int,
    ) -> Page:
        async def work() -> Page:
            needle = normalize_search_text(text.strip())
            sender_raw = sender.strip() if sender else ""
            sender_cf = normalize_search_text(sender_raw.lstrip("@")) if sender_raw else ""
            # Telegram's messages.searchGlobal rejects an empty query.  Text
            # searches therefore use its native restart-safe continuation;
            # person/date-only searches use a bounded per-dialog merge instead
            # of issuing an invalid request or silently returning a newest-only
            # prefix.
            if chat is None:
                server_query = unicodedata.normalize("NFKC", text.strip()) if text.strip() else ""
                async with self._client_session() as client:
                    dialogs: list[Any] | None = None
                    if not server_query:
                        dialogs = await self._iter_dialogs(client, self.config.dialog_scan_limit + 1)
                        if len(dialogs) > self.config.dialog_scan_limit:
                            raise BridgeError(
                                "Global filter search exceeds the configured dialog bound",
                                status=400,
                                code="global_search_dialog_limit_exceeded",
                                details={"retryable": False},
                            )
                    sender_entity = (
                        await self._resolve_search_sender(client, sender_raw, dialogs=dialogs)
                        if sender_raw
                        else None
                    )
                    if server_query:
                        return await self._global_text_search(
                            client,
                            sender_entity=sender_entity,
                            sender_cf=sender_cf,
                            needle=needle,
                            server_query=server_query,
                            dates=dates,
                            limit=limit,
                            cursor=cursor,
                            scan_limit=scan_limit,
                        )
                    return await self._global_filter_search(
                        client,
                        dialogs=dialogs or [],
                        sender_entity=sender_entity,
                        sender_cf=sender_cf,
                        dates=dates,
                        limit=limit,
                        cursor=cursor,
                        scan_limit=scan_limit,
                    )

            signature = self._cursor_signature(
                "search",
                (chat or "").strip(),
                sender_cf,
                needle,
                canonical_timestamp(dates.start) or "",
                canonical_timestamp(dates.end) or "",
                str(scan_limit),
            )
            boundary = self._message_boundary(cursor, "search", signature)
            async with self._client_session() as client:
                entity = await self._resolve(client, chat)
                # Preserve user-visible Unicode while giving Telegram a stable
                # compatibility-normalized server search hint. Local NFKC +
                # casefold filtering remains authoritative for returned rows.
                server_search = unicodedata.normalize("NFKC", text.strip()) if text.strip() else ""
                messages = await self._iter_messages(
                    client,
                    entity,
                    min(scan_limit, self.config.search_scan_limit),
                    search=server_search,
                )
                chat_id = str(getattr(entity, "id", chat))
                require_sender_details = bool(sender_cf and not sender_cf.lstrip("-").isdigit())
                records = [
                    await self._message_record(
                        m,
                        chat_id,
                        require_sender_details=require_sender_details,
                    )
                    for m in messages
                ]
                filtered: list[MessageRecord] = []
                for record in records:
                    stamp = datetime.fromisoformat(record.timestamp.replace("Z", "+00:00"))
                    if not dates.contains(stamp):
                        continue
                    if needle and needle not in normalize_search_text(record.text):
                        continue
                    if sender_cf:
                        stable = record.sender
                        hay = (
                            ""
                            if stable is None
                            else normalize_search_text(
                                f"{stable.id} {stable.username or ''} {stable.display_name or ''}"
                            )
                        )
                        if sender_cf not in hay:
                            continue
                    filtered.append(record)
                filtered = stable_message_sort(filtered, reverse=True)
                if boundary is not None:
                    filtered = [record for record in filtered if message_sort_key(record) < boundary]
                page = filtered[:limit]
                has_more = len(filtered) > limit
                return Page(
                    tuple(page),
                    self._message_next_cursor("search", signature, page, has_more=has_more),
                    len(messages),
                )

        return self._run(work())

    def get_message(self, *, chat: str, message_id: int) -> MessageRecord:
        async def work() -> MessageRecord:
            async with self._client_session() as client:
                entity = await self._resolve(client, chat)
                msg = await self._maybe_await(client.get_messages(entity, ids=message_id))
                if msg is None:
                    raise BridgeError("Message not found", status=404, code="message_not_found")
                return await self._message_record(msg, str(getattr(entity, "id", chat)))

        return self._run(work())

    def download_media(self, *, chat: str, message_id: int, file_ref: str, destination: str) -> dict[str, Any]:
        async def work() -> dict[str, Any]:
            async with self._client_session() as client:
                entity = await self._resolve(client, chat)
                msg = await self._maybe_await(client.get_messages(entity, ids=message_id))
                if msg is None:
                    raise BridgeError("Message not found", status=404, code="message_not_found")
                media = self._media_records(msg)
                if not media or all(item.file_ref != file_ref for item in media):
                    raise BridgeError("File reference does not match message", status=404, code="file_not_found")
                path = await self._maybe_await(client.download_media(msg, file=destination))
                if not path:
                    raise BridgeError("Telegram media download failed", status=502, code="media_download_failed")
                return {"path": str(path)}

        return self._run(work())
