# -*- coding: utf-8 -*-
"""Credential-free Telegram user-client adapter contracts for safe write operations.

The module intentionally accepts a client factory. Production integration may provide
Telethon at runtime, while CI uses deterministic fakes and never needs Telegram
credentials or a live account.
"""
from __future__ import annotations

import asyncio
import inspect
import ipaddress
import re
from dataclasses import dataclass
from enum import Enum
from typing import Any, Awaitable, Callable, ContextManager, Protocol, Sequence
from urllib.parse import urlparse

from ops.telegram_session_lock import SessionLockError


class TelegramContractError(RuntimeError):
    def __init__(self, code: str, *, status: int = 400, retry_after: int | None = None):
        super().__init__(code)
        self.code = code
        self.status = status
        self.retry_after = retry_after

    def as_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {"error": self.code, "status": self.status}
        if self.retry_after is not None:
            data["retry_after_seconds"] = self.retry_after
        return data


class TelegramAuthorizationState(str, Enum):
    NOT_CONFIGURED = "NOT_CONFIGURED"
    SESSION_UNAUTHORIZED = "SESSION_UNAUTHORIZED"
    AUTHORIZED = "AUTHORIZED"
    TRANSIENT_ERROR = "TRANSIENT_ERROR"


class EntityKind(str, Enum):
    NUMERIC_ID = "NUMERIC_ID"
    USERNAME = "USERNAME"
    SAVED_MESSAGES = "SAVED_MESSAGES"


@dataclass(frozen=True)
class EntityRef:
    kind: EntityKind
    value: int | str


@dataclass(frozen=True)
class TelegramRuntimeConfig:
    application_id_ref: int | None
    application_hash_ref: str | None
    session_reference: str | None
    request_timeout_seconds: float = 20.0
    max_flood_wait_seconds: int = 60
    max_send_chars: int = 4096
    max_forward_messages: int = 100
    max_send_files: int = 10
    synthetic_test_mode: bool = False

    def configured(self) -> bool:
        return bool(self.application_id_ref and self.application_hash_ref and self.session_reference)


@dataclass(frozen=True)
class MessageReceipt:
    message_id: int
    chat_id: int | None


@dataclass(frozen=True)
class WriteReceipt:
    operation: str
    message_ids: tuple[int, ...]
    chat_id: int | None
    count: int


class TelegramClientProtocol(Protocol):
    async def connect(self) -> Any: ...
    async def disconnect(self) -> Any: ...
    async def is_user_authorized(self) -> bool: ...
    async def get_me(self) -> Any: ...
    async def get_entity(self, ref: Any) -> Any: ...
    async def get_messages(self, entity: Any, ids: Any) -> Any: ...
    async def send_message(self, entity: Any, text: str, *, reply_to: int | None = None) -> Any: ...
    async def send_file(self, entity: Any, files: Sequence[str], **kwargs: Any) -> Any: ...
    async def forward_messages(self, entity: Any, ids: Sequence[int], *, from_peer: Any) -> Any: ...


_USERNAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]{3,31}$")
_TME_RE = re.compile(r"^https://t\.me/([A-Za-z][A-Za-z0-9_]{3,31})/?$", re.I)
_NUMERIC_RE = re.compile(r"^-?[1-9][0-9]{0,18}$")


def normalize_entity_ref(value: Any) -> EntityRef:
    if isinstance(value, bool) or value is None:
        raise TelegramContractError("invalid_target")
    if isinstance(value, int):
        if value == 0:
            raise TelegramContractError("invalid_target")
        return EntityRef(EntityKind.NUMERIC_ID, value)
    raw = str(value).strip()
    if not raw or len(raw) > 256 or any(ord(ch) < 32 for ch in raw):
        raise TelegramContractError("invalid_target")
    if raw.casefold() in {"me", "saved", "saved messages"}:
        return EntityRef(EntityKind.SAVED_MESSAGES, "me")
    if _NUMERIC_RE.fullmatch(raw):
        return EntityRef(EntityKind.NUMERIC_ID, int(raw))
    match = _TME_RE.fullmatch(raw)
    if match:
        return EntityRef(EntityKind.USERNAME, match.group(1))
    if raw.startswith("@"):
        raw = raw[1:]
    if _USERNAME_RE.fullmatch(raw):
        return EntityRef(EntityKind.USERNAME, raw)
    # Reject all other URL schemes/hosts and human-title fallbacks in write paths.
    parsed = urlparse(str(value).strip())
    if parsed.scheme or parsed.netloc or "/" in raw or "\\" in raw:
        raise TelegramContractError("invalid_target")
    raise TelegramContractError("invalid_target")


def _class_name(exc: BaseException) -> str:
    return type(exc).__name__.casefold()


def map_telegram_exception(exc: BaseException, *, max_flood_wait_seconds: int) -> TelegramContractError:
    """Map by type/class metadata only; never include raw Telegram exception text."""
    name = _class_name(exc)
    if "floodwait" in name or "flood_wait" in name:
        seconds = getattr(exc, "seconds", None)
        try:
            seconds_i = int(seconds)
        except (TypeError, ValueError):
            seconds_i = max_flood_wait_seconds
        seconds_i = max(1, min(max_flood_wait_seconds, seconds_i))
        return TelegramContractError("telegram_flood_wait", status=429, retry_after=seconds_i)
    if "sessionpasswordneeded" in name or "passwordhashinvalid" in name:
        return TelegramContractError("telegram_2fa_required", status=503)
    if "authkey" in name or "sessionrevoked" in name or "unauthorized" in name:
        return TelegramContractError("telegram_session_unauthorized", status=503)
    if "usernameinvalid" in name or "username_not_occupied" in name or "usernameoccupied" in name:
        return TelegramContractError("telegram_target_invalid", status=404)
    if "peeridinvalid" in name or "channelinvalid" in name or "chatidinvalid" in name:
        return TelegramContractError("telegram_target_invalid", status=404)
    if "messageidinvalid" in name or "message_id_invalid" in name:
        return TelegramContractError("telegram_message_invalid", status=404)
    if "file" in name and ("invalid" in name or "part" in name):
        return TelegramContractError("telegram_file_rejected", status=400)
    if "rpc" in name:
        return TelegramContractError("telegram_rpc_error", status=502)
    return TelegramContractError("telegram_operation_failed", status=502)


def _entity_id(entity: Any) -> int | None:
    raw = getattr(entity, "id", None)
    try:
        return int(raw) if raw is not None else None
    except (TypeError, ValueError):
        return None


def _message_id(message: Any) -> int:
    raw = getattr(message, "id", None)
    if isinstance(raw, bool):
        raise TelegramContractError("telegram_invalid_receipt", status=502)
    try:
        value = int(raw)
    except (TypeError, ValueError) as exc:
        raise TelegramContractError("telegram_invalid_receipt", status=502) from exc
    if value <= 0:
        raise TelegramContractError("telegram_invalid_receipt", status=502)
    return value


def _message_chat_id(message: Any) -> int | None:
    raw = getattr(message, "chat_id", None)
    try:
        return int(raw) if raw is not None else None
    except (TypeError, ValueError):
        return None


class TelegramWriteAdapter:
    """Safe lifecycle wrapper around an injected Telethon-compatible user client."""

    def __init__(
        self,
        config: TelegramRuntimeConfig,
        client_factory: Callable[[], TelegramClientProtocol],
        *,
        session_lock_factory: Callable[[], ContextManager[Any]] | None = None,
    ):
        if config.request_timeout_seconds <= 0 or config.request_timeout_seconds > 120:
            raise ValueError("bounded request timeout required")
        if config.max_flood_wait_seconds <= 0 or config.max_flood_wait_seconds > 600:
            raise ValueError("bounded FloodWait policy required")
        if config.configured() and not config.synthetic_test_mode and session_lock_factory is None:
            raise ValueError("configured Telegram runtime requires a private session process lock")
        self.config = config
        self.client_factory = client_factory
        self.session_lock_factory = session_lock_factory

    def _acquire_session_lock(self) -> ContextManager[Any] | None:
        if self.session_lock_factory is None:
            return None
        return self.session_lock_factory()

    async def authorization_state_async(self) -> TelegramAuthorizationState:
        if not self.config.configured():
            return TelegramAuthorizationState.NOT_CONFIGURED
        client = self.client_factory()
        connected = False
        lock = self._acquire_session_lock()
        try:
            if lock is not None:
                lock.__enter__()
            await asyncio.wait_for(client.connect(), timeout=self.config.request_timeout_seconds)
            connected = True
            authorized = await asyncio.wait_for(client.is_user_authorized(), timeout=self.config.request_timeout_seconds)
            return TelegramAuthorizationState.AUTHORIZED if authorized else TelegramAuthorizationState.SESSION_UNAUTHORIZED
        except asyncio.CancelledError:
            raise
        except (asyncio.TimeoutError, SessionLockError):
            return TelegramAuthorizationState.TRANSIENT_ERROR
        except Exception:
            return TelegramAuthorizationState.TRANSIENT_ERROR
        finally:
            if connected:
                try:
                    await client.disconnect()
                except Exception:
                    pass
            if lock is not None:
                try:
                    lock.__exit__(None, None, None)
                except Exception:
                    pass

    def authorization_state(self) -> TelegramAuthorizationState:
        return asyncio.run(self.authorization_state_async())

    async def _resolve(self, client: TelegramClientProtocol, target: Any) -> Any:
        ref = normalize_entity_ref(target)
        if ref.kind is EntityKind.SAVED_MESSAGES:
            return await client.get_me()
        return await client.get_entity(ref.value)

    async def _validate_reply(self, client: TelegramClientProtocol, entity: Any, reply_to_message_id: Any) -> int:
        if isinstance(reply_to_message_id, bool):
            raise TelegramContractError("invalid_reply_target")
        try:
            reply_id = int(reply_to_message_id)
        except (TypeError, ValueError) as exc:
            raise TelegramContractError("invalid_reply_target") from exc
        if reply_id <= 0:
            raise TelegramContractError("invalid_reply_target")
        msg = await client.get_messages(entity, ids=reply_id)
        if not msg:
            raise TelegramContractError("reply_target_not_found", status=404)
        ent_id = _entity_id(entity)
        msg_chat = _message_chat_id(msg)
        if ent_id is not None and msg_chat is not None and abs(ent_id) != abs(msg_chat):
            raise TelegramContractError("reply_target_chat_mismatch", status=409)
        if _message_id(msg) != reply_id:
            raise TelegramContractError("reply_target_mismatch", status=409)
        return reply_id

    async def _with_client(self, operation: Callable[[TelegramClientProtocol], Awaitable[WriteReceipt]]) -> WriteReceipt:
        if not self.config.configured():
            raise TelegramContractError("telegram_not_configured", status=503)
        client = self.client_factory()
        connected = False
        lock = self._acquire_session_lock()
        try:
            if lock is not None:
                lock.__enter__()
            await asyncio.wait_for(client.connect(), timeout=self.config.request_timeout_seconds)
            connected = True
            authorized = await asyncio.wait_for(client.is_user_authorized(), timeout=self.config.request_timeout_seconds)
            if not authorized:
                raise TelegramContractError("telegram_session_unauthorized", status=503)
            return await asyncio.wait_for(operation(client), timeout=self.config.request_timeout_seconds)
        except asyncio.CancelledError:
            raise
        except asyncio.TimeoutError as exc:
            raise TelegramContractError("telegram_timeout", status=504) from exc
        except SessionLockError as exc:
            if exc.code == "session_lock_timeout":
                raise TelegramContractError("telegram_session_busy", status=409) from None
            raise TelegramContractError("telegram_session_lock_unsafe", status=503) from None
        except TelegramContractError:
            raise
        except Exception as exc:
            raise map_telegram_exception(exc, max_flood_wait_seconds=self.config.max_flood_wait_seconds) from None
        finally:
            if connected:
                try:
                    await client.disconnect()
                except Exception:
                    pass
            if lock is not None:
                try:
                    lock.__exit__(None, None, None)
                except Exception:
                    pass

    async def send_async(self, target: Any, text: Any) -> WriteReceipt:
        if not isinstance(text, str) or not text.strip():
            raise TelegramContractError("text_required")
        if len(text) > self.config.max_send_chars:
            raise TelegramContractError("text_too_long", status=413)

        async def operation(client: TelegramClientProtocol) -> WriteReceipt:
            entity = await self._resolve(client, target)
            msg = await client.send_message(entity, text, reply_to=None)
            return WriteReceipt("SEND", (_message_id(msg),), _entity_id(entity), 1)

        return await self._with_client(operation)

    async def reply_async(self, target: Any, reply_to_message_id: Any, text: Any) -> WriteReceipt:
        if not isinstance(text, str) or not text.strip():
            raise TelegramContractError("text_required")
        if len(text) > self.config.max_send_chars:
            raise TelegramContractError("text_too_long", status=413)

        async def operation(client: TelegramClientProtocol) -> WriteReceipt:
            entity = await self._resolve(client, target)
            reply_id = await self._validate_reply(client, entity, reply_to_message_id)
            msg = await client.send_message(entity, text, reply_to=reply_id)
            return WriteReceipt("REPLY", (_message_id(msg),), _entity_id(entity), 1)

        return await self._with_client(operation)

    async def forward_async(self, source: Any, destination: Any, message_ids: Sequence[Any]) -> WriteReceipt:
        if not isinstance(message_ids, Sequence) or isinstance(message_ids, (str, bytes)):
            raise TelegramContractError("invalid_message_ids")
        ids: list[int] = []
        for raw in message_ids:
            if isinstance(raw, bool):
                raise TelegramContractError("invalid_message_ids")
            try:
                value = int(raw)
            except (TypeError, ValueError) as exc:
                raise TelegramContractError("invalid_message_ids") from exc
            if value <= 0:
                raise TelegramContractError("invalid_message_ids")
            ids.append(value)
        if not ids or len(ids) > self.config.max_forward_messages or len(set(ids)) != len(ids):
            raise TelegramContractError("invalid_message_ids")

        async def operation(client: TelegramClientProtocol) -> WriteReceipt:
            src = await self._resolve(client, source)
            dst = await self._resolve(client, destination)
            # Preflight every source message. Telethon get_messages(entity, ids=...) scopes lookup to source.
            found = await client.get_messages(src, ids=ids)
            rows = found if isinstance(found, list) else [found]
            if len(rows) != len(ids) or any(row is None for row in rows):
                raise TelegramContractError("forward_source_missing", status=404)
            found_ids = [_message_id(row) for row in rows]
            if found_ids != ids:
                raise TelegramContractError("forward_source_mismatch", status=409)
            sent = await client.forward_messages(dst, ids, from_peer=src)
            out = sent if isinstance(sent, list) else [sent]
            return WriteReceipt("FORWARD", tuple(_message_id(row) for row in out), _entity_id(dst), len(out))

        return await self._with_client(operation)

    async def send_files_async(
        self,
        target: Any,
        file_paths: Sequence[str],
        *,
        caption: str = "",
        reply_to_message_id: Any | None = None,
        voice_note: bool = False,
    ) -> WriteReceipt:
        if not isinstance(file_paths, Sequence) or isinstance(file_paths, (str, bytes)):
            raise TelegramContractError("files_required")
        paths = [str(path) for path in file_paths]
        if not paths or len(paths) > self.config.max_send_files:
            raise TelegramContractError("invalid_file_count")
        if any(not path or "\x00" in path for path in paths):
            raise TelegramContractError("invalid_file_reference")
        if not isinstance(caption, str) or len(caption) > self.config.max_send_chars:
            raise TelegramContractError("caption_too_long", status=413)
        if voice_note and len(paths) != 1:
            raise TelegramContractError("voice_note_requires_single_file")

        async def operation(client: TelegramClientProtocol) -> WriteReceipt:
            entity = await self._resolve(client, target)
            reply_id = None
            if reply_to_message_id is not None:
                reply_id = await self._validate_reply(client, entity, reply_to_message_id)
            sent = await client.send_file(
                entity,
                paths,
                caption=caption or None,
                reply_to=reply_id,
                voice_note=bool(voice_note),
            )
            out = sent if isinstance(sent, list) else [sent]
            return WriteReceipt("SEND_FILES", tuple(_message_id(row) for row in out), _entity_id(entity), len(out))

        return await self._with_client(operation)

    def send(self, target: Any, text: Any) -> WriteReceipt:
        return asyncio.run(self.send_async(target, text))

    def reply(self, target: Any, reply_to_message_id: Any, text: Any) -> WriteReceipt:
        return asyncio.run(self.reply_async(target, reply_to_message_id, text))

    def forward(self, source: Any, destination: Any, message_ids: Sequence[Any]) -> WriteReceipt:
        return asyncio.run(self.forward_async(source, destination, message_ids))

    def send_files(self, target: Any, file_paths: Sequence[str], **kwargs: Any) -> WriteReceipt:
        return asyncio.run(self.send_files_async(target, file_paths, **kwargs))


class FakeEntity:
    def __init__(self, entity_id: int, username: str | None = None):
        self.id = entity_id
        self.username = username


class FakeMessage:
    def __init__(self, message_id: int, chat_id: int):
        self.id = message_id
        self.chat_id = chat_id


class DeterministicFakeTelegramClient:
    """In-memory fake used to prove lifecycle/write behavior without network access."""

    def __init__(
        self,
        *,
        authorized: bool = True,
        entities: dict[Any, FakeEntity] | None = None,
        messages: dict[tuple[int, int], FakeMessage] | None = None,
        connect_error: BaseException | None = None,
        operation_error: BaseException | None = None,
        operation_delay: float = 0.0,
    ):
        self.authorized = authorized
        self.entities = entities or {
            100: FakeEntity(100, "target_user"),
            200: FakeEntity(200, "source_user"),
            "target_user": FakeEntity(100, "target_user"),
            "source_user": FakeEntity(200, "source_user"),
        }
        self.messages = messages or {
            (100, 10): FakeMessage(10, 100),
            (200, 20): FakeMessage(20, 200),
            (200, 21): FakeMessage(21, 200),
        }
        self.connect_error = connect_error
        self.operation_error = operation_error
        self.operation_delay = operation_delay
        self.connected = False
        self.connect_count = 0
        self.disconnect_count = 0
        self.external_writes: list[dict[str, Any]] = []
        self._next_message_id = 1000

    async def _delay_or_error(self) -> None:
        if self.operation_delay:
            await asyncio.sleep(self.operation_delay)
        if self.operation_error is not None:
            raise self.operation_error

    async def connect(self) -> None:
        self.connect_count += 1
        if self.connect_error is not None:
            raise self.connect_error
        self.connected = True

    async def disconnect(self) -> None:
        self.disconnect_count += 1
        self.connected = False

    async def is_user_authorized(self) -> bool:
        return self.authorized

    async def get_me(self) -> FakeEntity:
        return self.entities.get(100, FakeEntity(100, "target_user"))

    async def get_entity(self, ref: Any) -> FakeEntity:
        await self._delay_or_error()
        if ref in self.entities:
            return self.entities[ref]
        raise LookupError("not found")

    async def get_messages(self, entity: FakeEntity, ids: Any) -> Any:
        await self._delay_or_error()
        if isinstance(ids, list):
            return [self.messages.get((entity.id, int(value))) for value in ids]
        return self.messages.get((entity.id, int(ids)))

    def _make_message(self, chat_id: int) -> FakeMessage:
        self._next_message_id += 1
        return FakeMessage(self._next_message_id, chat_id)

    async def send_message(self, entity: FakeEntity, text: str, *, reply_to: int | None = None) -> FakeMessage:
        await self._delay_or_error()
        self.external_writes.append({"kind": "send", "chat_id": entity.id, "reply_to": reply_to, "size": len(text)})
        return self._make_message(entity.id)

    async def send_file(self, entity: FakeEntity, files: Sequence[str], **kwargs: Any) -> Any:
        await self._delay_or_error()
        self.external_writes.append({"kind": "files", "chat_id": entity.id, "count": len(files), "voice_note": bool(kwargs.get("voice_note"))})
        return [self._make_message(entity.id) for _ in files]

    async def forward_messages(self, entity: FakeEntity, ids: Sequence[int], *, from_peer: FakeEntity) -> Any:
        await self._delay_or_error()
        self.external_writes.append({"kind": "forward", "source_id": from_peer.id, "chat_id": entity.id, "count": len(ids)})
        return [self._make_message(entity.id) for _ in ids]
