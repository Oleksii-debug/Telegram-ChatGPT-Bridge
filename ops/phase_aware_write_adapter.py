# -*- coding: utf-8 -*-
"""Phase-aware Telegram write adapter for duplicate-safe commit handling.

The canonical write store already distinguishes a proven no-side-effect failure
from an unknown external outcome. The base Telegram adapter maps Telegram
exceptions but does not expose *when* the mutating RPC boundary was crossed.
This specialist adapter adds that proof without relying on exception class names
to decide safety.

A failure is converted to a structured no-side-effect failure only while
execution is still strictly before the first call to ``send_message``,
``send_file`` or ``forward_messages``. Once one of those mutating methods has
been invoked, any exception/timeout remains a normal ``TelegramContractError``
so the persistent store records AMBIGUOUS and never performs a blind resend.
Even ``SafeNoSideEffectFailure`` is subordinate to this explicit phase marker:
if such an exception escapes after the boundary, it is downgraded to an ordinary
post-effect failure rather than being allowed to create a retryable FAILED_SAFE
transaction.

SEND_FILES additionally supports the DEV04 snapshot-safe upload contract without
reconstructing a filesystem path. A verified upload object is accepted only as a
read-only, seekable ``io.BufferedIOBase`` carrying bounded opaque identity
metadata; its exact object identity is passed to the Telegram client. Mixed
legacy-path/snapshot batches fail before the effect boundary. The media owner is
still responsible for constructing and closing the verified snapshots; this
adapter only preserves that already-verified lifetime/identity through the
mutating RPC call.

For multi-item FORWARD and SEND_FILES, a returned receipt count must equal the
requested effect cardinality. A partial/malformed post-RPC result is not success:
it stays post-effect uncertainty and therefore becomes AMBIGUOUS at the durable
store rather than enabling a blind resend.

No Telegram connection is created at import time and no credentials are stored
or logged by this module.
"""
from __future__ import annotations

import asyncio
import io
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Sequence

from ops.structured_safe_write import SafeWriteMetadataFailure
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


_MAX_UPLOAD_FILE_BYTES = 100 * 1024 * 1024
_MAX_UPLOAD_TOTAL_BYTES = 250 * 1024 * 1024


@dataclass
class _EffectBoundary:
    """Monotonic marker for the first potentially mutating Telegram RPC call."""

    started: bool = False

    def cross(self) -> None:
        self.started = True


@dataclass(frozen=True)
class _SnapshotProof:
    stream: io.BufferedIOBase
    file_ref: str
    sha256: str
    size: int
    name: str


def _safe_code(exc: TelegramContractError) -> SafeWriteMetadataFailure:
    """Preserve only bounded structured metadata after pre-effect proof."""

    return SafeWriteMetadataFailure(
        exc.code,
        status=exc.status,
        retry_after_seconds=exc.retry_after,
    )


def _valid_public_file_ref(value: Any) -> bool:
    return (
        isinstance(value, str)
        and 1 <= len(value) <= 128
        and all(ord(ch) >= 32 for ch in value)
    )


def _valid_snapshot_name(value: Any) -> bool:
    return (
        isinstance(value, str)
        and 1 <= len(value) <= 180
        and "/" not in value
        and "\\" not in value
        and all(ord(ch) >= 32 for ch in value)
    )


def _snapshot_proof(value: Any) -> _SnapshotProof | None:
    """Validate the cross-lane DEV04 upload-handle surface without path access."""

    if not isinstance(value, io.BufferedIOBase) or value.closed:
        return None
    try:
        if not value.readable() or not value.seekable() or value.writable():
            return None
        if value.tell() != 0:
            return None
    except (OSError, ValueError, io.UnsupportedOperation):
        return None

    file_ref = getattr(value, "file_ref", None)
    digest = getattr(value, "sha256", None)
    size = getattr(value, "size", None)
    name = getattr(value, "name", None)
    if not _valid_public_file_ref(file_ref):
        return None
    if (
        not isinstance(digest, str)
        or len(digest) != 64
        or any(ch not in "0123456789abcdef" for ch in digest)
    ):
        return None
    if isinstance(size, bool) or not isinstance(size, int) or not 1 <= size <= _MAX_UPLOAD_FILE_BYTES:
        return None
    if not _valid_snapshot_name(name):
        return None
    return _SnapshotProof(value, file_ref, digest, size, name)


def _snapshot_still_matches(proof: _SnapshotProof) -> bool:
    """Revalidate the same snapshot object immediately before crossing effect."""

    current = _snapshot_proof(proof.stream)
    return current == proof


class PhaseAwareTelegramWriteAdapter(TelegramWriteAdapter):
    """Telegram write adapter with an explicit pre-effect/post-effect boundary."""

    async def _with_client_phase(
        self,
        operation: Callable[
            [TelegramClientProtocol, Callable[[], None]], Awaitable[WriteReceipt]
        ],
    ) -> WriteReceipt:
        if not self.config.configured():
            raise SafeWriteMetadataFailure(
                "telegram_not_configured", status=503
            )

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
                raise SafeWriteMetadataFailure(
                    "telegram_session_unauthorized", status=503
                )
            return await asyncio.wait_for(
                operation(client, boundary.cross),
                timeout=self.config.request_timeout_seconds,
            )
        except asyncio.CancelledError:
            # Cancellation is deliberately not reclassified as safe. If it
            # reaches the store after CALLING, recovery remains conservative.
            raise
        except SafeNoSideEffectFailure:
            if not boundary.started:
                raise
            # Exception *type* is not proof that no Telegram side effect happened.
            # After the explicit boundary, convert it to an ordinary stable
            # transport failure so the durable store records AMBIGUOUS.
            raise TelegramContractError(
                "telegram_operation_failed", status=502
            ) from None
        except asyncio.TimeoutError as exc:
            if not boundary.started:
                raise SafeWriteMetadataFailure(
                    "telegram_timeout", status=504
                ) from None
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
    def _preflight_failure(
        code: str,
        *,
        status: int = 400,
        retry_after_seconds: int | None = None,
    ) -> SafeWriteMetadataFailure:
        return SafeWriteMetadataFailure(
            code,
            status=status,
            retry_after_seconds=retry_after_seconds,
        )

    async def send_async(self, target: Any, text: Any) -> WriteReceipt:
        if not isinstance(text, str) or not text.strip():
            raise self._preflight_failure("text_required")
        if len(text) > self.config.max_send_chars:
            raise self._preflight_failure("text_too_long", status=413)

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
            raise self._preflight_failure("text_too_long", status=413)

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
            if len(out) != len(ids) or any(row is None for row in out):
                raise TelegramContractError("telegram_invalid_receipt", status=502)
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
        file_paths: Sequence[Any],
        *,
        caption: str = "",
        reply_to_message_id: Any | None = None,
        voice_note: bool = False,
    ) -> WriteReceipt:
        if not isinstance(file_paths, Sequence) or isinstance(
            file_paths, (str, bytes)
        ):
            raise self._preflight_failure("files_required")

        items = list(file_paths)
        if not items or len(items) > self.config.max_send_files:
            raise self._preflight_failure("invalid_file_count")

        snapshot_proofs: tuple[_SnapshotProof, ...] = ()
        if all(isinstance(item, str) for item in items):
            if any(not item or "\x00" in item for item in items):
                raise self._preflight_failure("invalid_file_reference")
            upload_items: list[Any] = items
        elif all(isinstance(item, io.BufferedIOBase) for item in items):
            proofs: list[_SnapshotProof] = []
            for item in items:
                proof = _snapshot_proof(item)
                if proof is None:
                    raise self._preflight_failure("invalid_file_reference")
                proofs.append(proof)
            if sum(proof.size for proof in proofs) > _MAX_UPLOAD_TOTAL_BYTES:
                raise self._preflight_failure("invalid_file_reference", status=413)
            snapshot_proofs = tuple(proofs)
            # Preserve exact object identity. Never call str(), reopen a path or
            # materialize a new stream after the media owner has snapshotted it.
            upload_items = [proof.stream for proof in proofs]
        else:
            # Mixed path/descriptor batches can silently downgrade a verified
            # snapshot flow back to pathname TOCTOU, so fail closed.
            raise self._preflight_failure("invalid_file_reference")

        if not isinstance(caption, str) or len(caption) > self.config.max_send_chars:
            raise self._preflight_failure("caption_too_long", status=413)
        if voice_note and len(upload_items) != 1:
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
            if snapshot_proofs and not all(
                _snapshot_still_matches(proof) for proof in snapshot_proofs
            ):
                raise TelegramContractError("invalid_file_reference", status=409)
            cross_effect()
            sent = await client.send_file(
                entity,
                upload_items,
                caption=caption or None,
                reply_to=reply_id,
                voice_note=bool(voice_note),
            )
            out = sent if isinstance(sent, list) else [sent]
            if len(out) != len(upload_items) or any(row is None for row in out):
                raise TelegramContractError("telegram_invalid_receipt", status=502)
            return WriteReceipt(
                "SEND_FILES",
                tuple(_message_id(row) for row in out),
                _entity_id(entity),
                len(out),
            )

        return await self._with_client_phase(operation)


__all__ = ["PhaseAwareTelegramWriteAdapter"]
