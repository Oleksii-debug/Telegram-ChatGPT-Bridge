# -*- coding: utf-8 -*-
"""DEV05 integration seam for phase-aware Telegram write execution.

This subclass keeps canonical request routing untouched and changes only the
SEND_FILES external-effect seam plus the serialization of DEV05 proven-safe
write failures. Private file-reference resolution and hash/size revalidation
happen before any Telegram mutating RPC; failures in that preflight are therefore
explicitly represented as proven no-side-effect failures. Once
``adapter.send_files`` is invoked, the phase-aware adapter owns classification
and any uncertain outcome remains AMBIGUOUS in the persistent write store.

For a proven-safe structured failure, bounded status / Retry-After metadata is
preserved all the way to the HTTP response. Raw Telegram exception text, targets,
tokens, private file paths and message content are never copied into the public
error payload.

The module performs no Telegram I/O at import time and is not a production
activation by itself. DEV01 remains the canonical integration owner.
"""
from __future__ import annotations

from typing import Any, Callable, Mapping

from bridge.errors import BridgeError
from bridge.integrated_app import UnifiedBridgeApplication
from ops.structured_safe_write import (
    SafeWriteMetadataFailure,
    WriteSafetyMetadataError,
    structured_safe_write_error,
)
from ops.write_safety import SafeNoSideEffectFailure


class PhaseAwareUnifiedBridgeApplication(UnifiedBridgeApplication):
    """Unified application with proven pre-effect and public-error boundaries."""

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


__all__ = ["PhaseAwareUnifiedBridgeApplication"]
