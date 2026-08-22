"""Telegram read backend abstraction and Telethon-compatible adapter.

The adapter imports Telethon lazily and performs no network activity at module
import or application construction time. A client factory can be injected for
credential-free deterministic tests. Every adapter operation owns a bounded
client lifecycle when the supplied client exposes connect/auth/disconnect hooks.
"""

from __future__ import annotations

import asyncio
import hashlib
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, AsyncIterator, Awaitable, Callable, Protocol

from .errors import BridgeError
from .models import DialogRecord, EntityRef, MediaRecord, MessageRecord, Page, decode_cursor, encode_cursor, stable_message_sort
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


class TelethonReadBackend:
    """Map Telethon-like objects into stable read-side API records.

    ``client_factory`` returns a client or awaitable client. If that client
    exposes ``connect()``, ``is_user_authorized()`` or ``disconnect()``, the
    adapter calls those hooks for every bounded operation. Clients without the
    hooks are treated as externally managed, which keeps deterministic fakes
    and later server-side session factories easy to integrate.
    """

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
        """Bound connect/auth/disconnect to one operation and always clean up.

        Cleanup errors are deliberately not surfaced because they must never
        replace the original read error or expose backend exception text. A
        fresh client is requested for the next operation.
        """
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
            last_message_at=date.isoformat() if isinstance(date, datetime) else None,
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
    async def _message_record(cls, message: Any, chat_id: str) -> MessageRecord:
        sender_obj = None
        getter = getattr(message, "get_sender", None)
        if callable(getter):
            try:
                sender_obj = await cls._maybe_await(getter())
            except Exception:
                sender_obj = None
        sender_id = getattr(message, "sender_id", None)
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
            timestamp=date.isoformat(),
            text=str(getattr(message, "message", None) or ""),
            sender=sender,
            outgoing=bool(getattr(message, "out", False)),
            reply_to_message_id=int(reply) if reply is not None else None,
            media=cls._media_records(message),
        )

    @staticmethod
    def _cursor_offset(cursor: str | None, scope: str) -> int:
        decoded = decode_cursor(cursor)
        if decoded is None:
            return 0
        if set(decoded) != {"v", "scope", "offset"} or decoded.get("v") != 1 or decoded.get("scope") != scope:
            raise BridgeError("Invalid cursor", code="invalid_cursor")
        offset = decoded.get("offset")
        if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0 or offset > 1_000_000:
            raise BridgeError("Invalid cursor", code="invalid_cursor")
        return offset

    @staticmethod
    def _next_cursor(scope: str, offset: int, limit: int, total: int) -> str | None:
        nxt = offset + limit
        return encode_cursor({"v": 1, "scope": scope, "offset": nxt}) if nxt < total else None

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
            if name == "FloodWaitError" or (isinstance(seconds, int) and seconds > 0):
                retry = min(max(1, int(seconds or 1)), self.config.flood_wait_cap_seconds)
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

    async def _iter_messages(self, client: Any, entity: Any, limit: int, *, search: str = "") -> list[Any]:
        kwargs: dict[str, Any] = {"limit": limit}
        if search:
            kwargs["search"] = search
        try:
            iterator = client.iter_messages(entity, **kwargs)
        except TypeError:
            # Simple deterministic fakes may intentionally expose only the
            # minimal iter_messages(entity, limit) contract. Filtering remains
            # deterministic below; real Telethon clients receive server-side
            # search hints when supported.
            iterator = client.iter_messages(entity, limit=limit)
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
            raise BridgeError("Chat not found", status=404, code="chat_not_found") from exc

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
                records.sort(key=lambda d: ((d.last_message_at or ""), d.id), reverse=True)
                offset = self._cursor_offset(cursor, "dialogs")
                page = records[offset : offset + limit]
                return Page(tuple(page), self._next_cursor("dialogs", offset, limit, len(records)), min(len(dialogs), self.config.dialog_scan_limit))

        return self._run(work())

    def history(self, *, chat: str, limit: int, cursor: str | None) -> Page:
        async def work() -> Page:
            async with self._client_session() as client:
                entity = await self._resolve(client, chat)
                offset = self._cursor_offset(cursor, "history")
                messages = await self._iter_messages(client, entity, min(self.config.search_scan_limit, limit + 1 + offset))
                chat_id = str(getattr(entity, "id", chat))
                records = stable_message_sort([await self._message_record(m, chat_id) for m in messages], reverse=True)
                page = records[offset : offset + limit]
                return Page(tuple(page), self._next_cursor("history", offset, limit, len(records)), len(messages))

        return self._run(work())

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
            async with self._client_session() as client:
                entity = await self._resolve(client, chat) if chat else None
                messages = await self._iter_messages(
                    client,
                    entity,
                    min(scan_limit, self.config.search_scan_limit),
                    search=text.strip(),
                )
                chat_id = str(getattr(entity, "id", chat or "global"))
                records = [await self._message_record(m, chat_id) for m in messages]
                needle = normalize_search_text(text.strip())
                sender_cf = normalize_search_text(sender.strip()) if sender else ""
                filtered: list[MessageRecord] = []
                for record in records:
                    stamp = datetime.fromisoformat(record.timestamp.replace("Z", "+00:00"))
                    if not dates.contains(stamp):
                        continue
                    if needle and needle not in normalize_search_text(record.text):
                        continue
                    if sender_cf:
                        stable = record.sender
                        hay = "" if stable is None else normalize_search_text(f"{stable.id} {stable.username or ''}")
                        if sender_cf not in hay:
                            continue
                    filtered.append(record)
                filtered = stable_message_sort(filtered, reverse=True)
                offset = self._cursor_offset(cursor, "search")
                page = filtered[offset : offset + limit]
                return Page(tuple(page), self._next_cursor("search", offset, limit, len(filtered)), len(messages))

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
