# -*- coding: utf-8 -*-
"""DEV05 integration seam for phase-aware Telegram write execution.

This subclass keeps canonical request routing untouched and changes only the
SEND_FILES external-effect seam.  Private file-reference resolution and
hash/size revalidation happen before any Telegram mutating RPC; failures in that
preflight are therefore explicitly represented as proven no-side-effect
failures.  Once ``adapter.send_files`` is invoked, the phase-aware adapter owns
classification and any uncertain outcome remains AMBIGUOUS in the persistent
write store.

The module performs no Telegram I/O at import time and is not a production
activation by itself.  DEV01 remains the canonical integration owner.
"""
from __future__ import annotations

from typing import Any, Mapping

from bridge.integrated_app import UnifiedBridgeApplication
from ops.write_safety import SafeNoSideEffectFailure


class PhaseAwareUnifiedBridgeApplication(UnifiedBridgeApplication):
    """Unified application with a proven pre-effect file-reference boundary."""

    def _execute_external_write(
        self, action: str, payload: dict[str, Any]
    ) -> Mapping[str, Any]:
        if action != "SEND_FILES":
            return super()._execute_external_write(action, payload)

        adapter = self.write_adapter
        if adapter is None:
            raise SafeNoSideEffectFailure("telegram_writer_unconfigured")
        if self.read_app.files is None:
            raise SafeNoSideEffectFailure("private_file_store_unavailable")

        paths: list[str] = []
        try:
            for item in payload["files"]:
                record = self.read_app.files.get(item["file_id"])
                if record is None:
                    raise SafeNoSideEffectFailure(
                        "registered_private_file_unavailable"
                    )
                if record.sha256 != item["sha256"] or record.size != item["size"]:
                    raise SafeNoSideEffectFailure(
                        "registered_private_file_identity_mismatch"
                    )
                paths.append(record.path)
        except SafeNoSideEffectFailure:
            raise
        except Exception:
            # The lookup/revalidation phase has not invoked Telegram.  Do not
            # leak storage exception text, file paths or private metadata.
            raise SafeNoSideEffectFailure("private_file_preflight_failed") from None

        receipt = adapter.send_files(
            payload["target"],
            paths,
            caption=payload.get("caption", ""),
            reply_to_message_id=payload.get("reply_to_message_id"),
            voice_note=bool(payload.get("voice_note", False)),
        )
        # Receipt validation occurs after the mutating RPC boundary.  Any failure
        # here intentionally remains an ordinary exception so the store records
        # AMBIGUOUS rather than claiming no effect.
        return self._receipt_metadata(receipt, action)


__all__ = ["PhaseAwareUnifiedBridgeApplication"]
