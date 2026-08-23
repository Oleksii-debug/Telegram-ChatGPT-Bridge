# -*- coding: utf-8 -*-
"""DEV05 integration seam for phase-aware Telegram write execution.

This subclass keeps canonical request routing untouched and changes only the
SEND_FILES external-effect seam plus the serialization of DEV05 proven-safe
write failures. Private file-reference resolution and hash/size revalidation
happen before any Telegram mutating RPC; failures in that preflight are therefore
explicitly represented as proven no-side-effect failures. Once the Telegram
adapter is invoked, the phase-aware adapter owns classification and any uncertain
outcome remains AMBIGUOUS in the persistent write store.

The optional ``upload_batch_factory`` is the cross-lane composition point for
DEV04's descriptor-verified immutable upload snapshots. The factory receives the
private file store and the exact commit-bound opaque identities. It must return a
batch with ``files`` and ``close()``. When configured, DEV05 never reconstructs a
filesystem path: the returned file-like objects stay alive through the mutating
``send_file`` call and are closed in ``finally``. Factory/identity failures are
pre-effect; adapter or receipt failures after the mutating boundary are never
reclassified as safe.

Without an injected snapshot factory the legacy pathname path remains available
only for compatibility with the current canonical runtime. That fallback is NOT
a claim that the DEV04/DEV05 SEND_FILES TOCTOU is closed; canonical closure
requires DEV01 to integrate the media-owned snapshot factory together with this
write-side lifetime/effect-boundary seam.

For a proven-safe structured failure, bounded status / Retry-After metadata is
preserved all the way to the HTTP response. Raw Telegram exception text, targets,
tokens, private file paths and message content are never copied into the public
error payload.

The module performs no Telegram I/O at import time and is not a production
activation by itself. DEV01 remains the canonical integration owner.
"""
from __future__ import annotations

from collections.abc import Mapping as MappingABC, Sequence
from typing import Any, Callable, Mapping

from bridge.errors import BridgeError
from bridge.integrated_app import UnifiedBridgeApplication
from ops.structured_safe_write import (
    SafeWriteMetadataFailure,
    WriteSafetyMetadataError,
    structured_safe_write_error,
)
from ops.write_safety import SafeNoSideEffectFailure


UploadBatchFactory = Callable[[Any, tuple[Mapping[str, Any], ...]], Any]


class PhaseAwareUnifiedBridgeApplication(UnifiedBridgeApplication):
    """Unified application with proven pre-effect and public-error boundaries."""

    def __init__(
        self,
        *,
        upload_batch_factory: UploadBatchFactory | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(**kwargs)
        self._upload_batch_factory = upload_batch_factory

    @staticmethod
    def _close_pre_effect_batch(batch: Any) -> None:
        """Best-effort cleanup when Telegram has provably not been invoked."""

        close = getattr(batch, "close", None)
        if callable(close):
            try:
                close()
            except Exception:
                # Cleanup failure is not a Telegram effect. Keep the public
                # failure stable/private and let process teardown reclaim FDs.
                pass

    def _open_snapshot_batch(
        self,
        payload: Mapping[str, Any],
    ) -> tuple[Any, tuple[Any, ...]]:
        """Build/validate a media-owned upload batch entirely before Telegram."""

        factory = getattr(self, "_upload_batch_factory", None)
        if factory is None:
            raise RuntimeError("snapshot factory is not configured")

        raw_files = payload.get("files")
        if not isinstance(raw_files, list) or not raw_files:
            raise SafeWriteMetadataFailure("invalid_file_reference", status=400)

        identities: list[Mapping[str, Any]] = []
        for raw in raw_files:
            if not isinstance(raw, MappingABC):
                raise SafeWriteMetadataFailure("invalid_file_reference", status=400)
            item = dict(raw)
            if set(item) != {"file_id", "sha256", "size"}:
                raise SafeWriteMetadataFailure("invalid_file_reference", status=400)
            identities.append(item)

        try:
            batch = factory(self.read_app.files, tuple(identities))
        except SafeNoSideEffectFailure:
            raise
        except Exception:
            raise SafeWriteMetadataFailure(
                "private_file_preflight_failed", status=503
            ) from None

        if batch is None:
            raise SafeWriteMetadataFailure(
                "registered_private_file_identity_mismatch", status=409
            )

        try:
            files = getattr(batch, "files")
            if (
                isinstance(files, (str, bytes))
                or not isinstance(files, Sequence)
                or len(files) != len(identities)
                or not files
            ):
                raise ValueError("invalid snapshot batch surface")
            snapshot_files = tuple(files)
        except Exception:
            self._close_pre_effect_batch(batch)
            raise SafeWriteMetadataFailure(
                "private_file_preflight_failed", status=503
            ) from None

        return batch, snapshot_files

    def _execute_external_write(
        self, action: str, payload: dict[str, Any]
    ) -> Mapping[str, Any]:
        if action != "SEND_FILES":
            return super()._execute_external_write(action, payload)

        adapter = self.write_adapter
        if adapter is None:
            raise SafeWriteMetadataFailure(
                "telegram_writer_unconfigured", status=503
            )
        if self.read_app.files is None:
            raise SafeWriteMetadataFailure(
                "private_file_store_unavailable", status=503
            )

        factory = getattr(self, "_upload_batch_factory", None)
        if factory is not None:
            batch, snapshot_files = self._open_snapshot_batch(payload)
            try:
                receipt = adapter.send_files(
                    payload["target"],
                    snapshot_files,
                    caption=payload.get("caption", ""),
                    reply_to_message_id=payload.get("reply_to_message_id"),
                    voice_note=bool(payload.get("voice_note", False)),
                )
                # Receipt validation is post-effect. Any exception here remains
                # ordinary so the durable store records AMBIGUOUS.
                return self._receipt_metadata(receipt, action)
            finally:
                # If close itself fails after a possible Telegram effect, allow
                # that failure to propagate. The store will conservatively mark
                # the outcome AMBIGUOUS rather than return a false success.
                close = getattr(batch, "close", None)
                if callable(close):
                    close()

        # Legacy compatibility path. This preserves current canonical behavior
        # until DEV01 imports/configures DEV04's immutable upload snapshot seam.
        # It must not be represented as closing the pathname TOCTOU by itself.
        paths: list[str] = []
        try:
            for item in payload["files"]:
                record = self.read_app.files.get(item["file_id"])
                if record is None:
                    raise SafeWriteMetadataFailure(
                        "registered_private_file_unavailable", status=409
                    )
                if record.sha256 != item["sha256"] or record.size != item["size"]:
                    raise SafeWriteMetadataFailure(
                        "registered_private_file_identity_mismatch", status=409
                    )
                paths.append(record.path)
        except SafeNoSideEffectFailure:
            raise
        except Exception:
            # The lookup/revalidation phase has not invoked Telegram. Do not
            # leak storage exception text, file paths or private metadata.
            raise SafeWriteMetadataFailure(
                "private_file_preflight_failed", status=503
            ) from None

        receipt = adapter.send_files(
            payload["target"],
            paths,
            caption=payload.get("caption", ""),
            reply_to_message_id=payload.get("reply_to_message_id"),
            voice_note=bool(payload.get("voice_note", False)),
        )
        # Receipt validation occurs after the mutating RPC boundary. Any failure
        # here intentionally remains an ordinary exception so the store records
        # AMBIGUOUS rather than claiming no effect.
        return self._receipt_metadata(receipt, action)

    def _write_error(
        self,
        start_response: Callable,
        exc: BaseException,
        request_id: str,
    ) -> list[bytes]:
        """Preserve bounded metadata only for a proven no-side-effect failure.

        Canonical ``structured_write_error`` intentionally handles all
        ``WriteSafetyError`` values generically, which would discard DEV05's
        bounded Retry-After metadata because ``WriteSafetyMetadataError`` is a
        ``WriteSafetyError`` subclass. Override only this exact subtype and
        delegate every other error to the canonical implementation.
        """
        if not isinstance(exc, WriteSafetyMetadataError):
            return super()._write_error(start_response, exc, request_id)

        meta = structured_safe_write_error(exc)
        raw_status = meta.get("status")
        status = raw_status if isinstance(raw_status, int) and 400 <= raw_status <= 599 else 500
        raw_code = meta.get("error")
        code = raw_code if isinstance(raw_code, str) and raw_code else "internal_bridge_error"
        code = code[:80]
        raw_retry = meta.get("retry_after_seconds")
        retry = raw_retry if isinstance(raw_retry, int) and 1 <= raw_retry <= 600 else None

        if status == 503:
            message = "Write service is unavailable"
        elif status == 404:
            message = "Not found"
        elif status == 429:
            message = "Write operation is temporarily rate limited"
        else:
            message = "Write request was rejected"

        return self.read_app._error(
            start_response,
            BridgeError(
                message,
                status=status,
                code=code,
                retry_after_seconds=retry,
            ),
            request_id,
        )


__all__ = ["PhaseAwareUnifiedBridgeApplication", "UploadBatchFactory"]
