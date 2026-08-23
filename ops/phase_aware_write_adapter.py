# -*- coding: utf-8 -*-
"""Phase-aware Telegram write adapter for duplicate-safe commit handling.

The canonical write store already distinguishes a proven no-side-effect failure
from an unknown external outcome.  The base Telegram adapter intentionally maps
Telegram exceptions but does not expose *when* the mutating RPC boundary was
crossed.  This specialist adapter adds that proof without relying on exception
class names to decide safety.

A failure is converted to ``SafeNoSideEffectFailure`` only while execution is
still strictly before the first call to ``send_message``, ``send_file`` or
``forward_messages``.  Once one of those mutating methods has been invoked, any
exception/timeout remains a normal ``TelegramContractError`` so the persistent
store records AMBIGUOUS and never performs a blind resend.

No Telegram connection is created at import time and no credentials are stored
or logged by this module.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Sequence

from ops.telegram_session_lock import SessionLockError
from ops.telegram_write_adapter import (
    TelegramClientProtocol,
    TelegramContractError,
    TelegramWriteAdapter,
    WriteReceipt,
    _entity_id,
    _message_id,
    map_telegram_exception,
)
from ops.write_safety import SafeNoSideEffectFailure


@dataclass
class _EffectBoundary:
    """Monotonic marker for the first potentially mutating Telegram RPC call."""

    started: bool = False

    def cross(self) -> None:
        self.started = True


def _safe_code(exc: TelegramContractError) -> SafeNoSideEffectFailure:
    """Return the store-recognized failure only after phase proof says pre-effect."""

    return SafeNoSideEffectFailure(exc.code)


class PhaseAwareTelegramWriteAdapter(TelegramWriteAdapter):
    """Telegram write adapter with an explicit pre-effect/post-effect boundary."""

    async def _with_client_phase(
        self,
        operation: Callable[
            [TelegramClientProtocol, Callable[[], None]], Awaitable[WriteReceipt]
        ],
    ) -> WriteReceipt:
        if not self.config.configured():
            raise SafeNoSideEffectFailure("telegram_not_configured")

        client = self.client_factory()
        connected = False
        lock = self._acquire_session_lock()
        boundary = _EffectBoundary()

        try:
            if lock is not None:
                lock.__enter__()
            await asyncio.wait_for(
                client.connect(), timeout=self.config.request_timeout_seconds
            )
            connected = True
            authorized = await asyncio.wait_for(
                client.is_user_authorized(),
                timeout=self.config.request_timeout_seconds,
            )
            if not authorized:
                raise SafeNoSideEffectFailure("telegram_session_unauthorized")
            return await asyncio.wait_for(
                operation(client, boundary.cross),
                timeout=self.config.request_timeout_seconds,
            )
        except asyncio.CancelledError:
            # Cancellation is deliberately not reclassified as safe.  If it
            # reaches the store after CALLING, recovery will conservatively mark
            # the transaction AMBIGUOUS rather than risk a duplicate send.
            raise
        except SafeNoSideEffectFailure:
            raise
        except asyncio.TimeoutError as exc:
            if not boundary.started:
                raise SafeNoSideEffectFailure("telegram_timeout") from None
            raise TelegramContractError("telegram_timeout", status=504) from exc
        except SessionLockError as exc:
            if exc.code == "session_lock_timeout":
                mapped = TelegramContractError("telegram_session_busy", status=409)
            else:
                mapped = TelegramContractError(
                    "telegram_session_lock_unsafe", status=503
                )
            if not boundary.started:
                raise _safe_code(mapped) from None
            raise mapped from None
        except TelegramContractError as exc:
            if not boundary.started:
                raise _safe_code(exc) from None
            raise
        except Exception as exc:
            mapped = map_telegram_exception(
                exc,
                max_flood_wait_seconds=self.config.max_flood_wait_seconds,
            )
            if not boundary.started:
                raise _safe_code(mapped) from None
            raise mapped from None
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

    @staticmethod
    def _preflight_failure(code: str) -> SafeNoSideEffectFailure:
        return SafeNoSideEffectFailure(code)

    async def send_async(self, target: Any, text: Any) -> WriteReceipt:
        if not isinstance(text, str) or not text.strip():
            raise self._preflight_failure("text_required")
        if len(text) > self.config.max_send_chars:
            raise self._preflight_failure("text_too_long")

        async def operation(
            client: TelegramClientProtocol, cross_effect: Callable[[], None]
        ) -> WriteReceipt:
            entity = await self._resolve(client, target)
            cross_effect()
            msg = await client.send_message(entity, text, reply_to=None)
            return WriteReceipt("SEND", (_message_id(msg),), _entity_id(entity), 1)

        return await self._with_client_phase(operation)

    async def reply_async(
        self, target: Any, reply_to_message_id: Any, text: Any
    ) -> WriteReceipt:
        if not isinstance(text, str) or not text.strip():
            raise self._preflight_failure("text_required")
        if len(text) > self.config.max_send_chars:
            raise self._preflight_failure("text_too_long")

        async def operation(
            client: TelegramClientProtocol, cross_effect: Callable[[], None]
        ) -> WriteReceipt:
            entity = await self._resolve(client, target)
            reply_id = await self._validate_reply(
                client, entity, reply_to_message_id
            )
            cross_effect()
            msg = await client.send_message(entity, text, reply_to=reply_id)
            return WriteReceipt("REPLY", (_message_id(msg),), _entity_id(entity), 1)

        return await self._with_client_phase(operation)

    async def forward_async(
        self, source: Any, destination: Any, message_ids: Sequence[Any]
    ) -> WriteReceipt:
        if not isinstance(message_ids, Sequence) or isinstance(
            message_ids, (str, bytes)
        ):
            raise self._preflight_failure("invalid_message_ids")

        ids: list[int] = []
        for raw in message_ids:
            if isinstance(raw, bool):
                raise self._preflight_failure("invalid_message_ids")
            try:
                value = int(raw)
            except (TypeError, ValueError):
                raise self._preflight_failure("invalid_message_ids") from None
            if value <= 0:
                raise self._preflight_failure("invalid_message_ids")
            ids.append(value)
        if (
            not ids
            or len(ids) > self.config.max_forward_messages
            or len(set(ids)) != len(ids)
        ):
            raise self._preflight_failure("invalid_message_ids")

        async def operation(
            client: TelegramClientProtocol, cross_effect: Callable[[], None]
        ) -> WriteReceipt:
            src = await self._resolve(client, source)
            dst = await self._resolve(client, destination)
            found = await client.get_messages(src, ids=ids)
            rows = found if isinstance(found, list) else [found]
            if len(rows) != len(ids) or any(row is None for row in rows):
                raise TelegramContractError("forward_source_missing", status=404)
            found_ids = [_message_id(row) for row in rows]
            if found_ids != ids:
                raise TelegramContractError("forward_source_mismatch", status=409)
            cross_effect()
            sent = await client.forward_messages(dst, ids, from_peer=src)
            out = sent if isinstance(sent, list) else [sent]
            return WriteReceipt(
                "FORWARD",
                tuple(_message_id(row) for row in out),
                _entity_id(dst),
                len(out),
            )

        return await self._with_client_phase(operation)

    async def send_files_async(
        self,
        target: Any,
        file_paths: Sequence[str],
        *,
        caption: str = "",
        reply_to_message_id: Any | None = None,
        voice_note: bool = False,
    ) -> WriteReceipt:
        if not isinstance(file_paths, Sequence) or isinstance(
            file_paths, (str, bytes)
        ):
            raise self._preflight_failure("files_required")
        paths = [str(path) for path in file_paths]
        if not paths or len(paths) > self.config.max_send_files:
            raise self._preflight_failure("invalid_file_count")
        if any(not path or "\x00" in path for path in paths):
            raise self._preflight_failure("invalid_file_reference")
        if not isinstance(caption, str) or len(caption) > self.config.max_send_chars:
            raise self._preflight_failure("caption_too_long")
        if voice_note and len(paths) != 1:
            raise self._preflight_failure("voice_note_requires_single_file")

        async def operation(
            client: TelegramClientProtocol, cross_effect: Callable[[], None]
        ) -> WriteReceipt:
            entity = await self._resolve(client, target)
            reply_id = None
            if reply_to_message_id is not None:
                reply_id = await self._validate_reply(
                    client, entity, reply_to_message_id
                )
            cross_effect()
            sent = await client.send_file(
                entity,
                paths,
                caption=caption or None,
                reply_to=reply_id,
                voice_note=bool(voice_note),
            )
            out = sent if isinstance(sent, list) else [sent]
            return WriteReceipt(
                "SEND_FILES",
                tuple(_message_id(row) for row in out),
                _entity_id(entity),
                len(out),
            )

        return await self._with_client_phase(operation)


__all__ = ["PhaseAwareTelegramWriteAdapter"]
