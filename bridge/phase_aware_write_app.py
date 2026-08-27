# -*- coding: utf-8 -*-
"""Production write integration with secure/reliable state and snapshot uploads."""
from __future__ import annotations

import io
from collections.abc import Mapping as MappingABC, Sequence
from typing import Any, Callable, Mapping

from bridge.app import BridgeApplication
from bridge.errors import BridgeError
from bridge.integrated_app import UnifiedBridgeApplication, _RejectingWriteLimiter
from ops.structured_safe_write import (
    SafeWriteMetadataFailure,
    StructuredSafePersistentWriteStore,
    WriteSafetyMetadataError,
    structured_safe_write_error,
)
from ops.write_endpoint_policy import WriteCoordinator, WriteEndpointPolicy
from ops.write_safety import SafeNoSideEffectFailure

UploadBatchFactory = Callable[[Any, tuple[Mapping[str, Any], ...]], Any]


class PhaseAwareUnifiedBridgeApplication(UnifiedBridgeApplication):
    """Unified app whose production path never falls back to pathname uploads."""

    def __init__(
        self,
        *,
        read_app: BridgeApplication | None = None,
        write_adapter: Any | None = None,
        write_limiter: Any | None = None,
        preview_ttl_seconds: int = 300,
        write_store: Any | None = None,
        upload_batch_factory: UploadBatchFactory | None = None,
    ) -> None:
        # Reproduce the small canonical constructor here so an injected secure
        # store is installed before *any* plain PersistentWriteStore is opened.
        self.read_app = read_app or BridgeApplication()
        self.write_adapter = write_adapter
        self._write_limiter = write_limiter if write_limiter is not None else _RejectingWriteLimiter()
        self._upload_batch_factory = upload_batch_factory
        self.write_store: Any | None = None
        self.write_coordinator: WriteCoordinator | None = None
        private_root = self.read_app.config.private_root

        if write_store is not None and private_root is None:
            raise RuntimeError("write_store_requires_private_root")
        if private_root is not None:
            self.write_store = write_store or StructuredSafePersistentWriteStore(
                private_root.resolve() / "state" / "writes.sqlite3",
                preview_ttl_seconds=preview_ttl_seconds,
            )
            self.write_coordinator = WriteCoordinator(
                self.write_store,
                WriteEndpointPolicy(self._write_limiter),
            )

    @staticmethod
    def _preview_payload(spec: Any, body: dict[str, Any]) -> dict[str, Any]:
        payload = UnifiedBridgeApplication._preview_payload(spec, body)
        if getattr(spec, "action", None) != "SEND_FILES":
            return payload
        raw_files = body.get("files")
        if not isinstance(raw_files, list):
            return payload
        seen: dict[str, tuple[Any, Any]] = {}
        for raw in raw_files:
            if not isinstance(raw, MappingABC):
                continue
            file_ref = raw.get("file_ref")
            if not isinstance(file_ref, str):
                continue
            identity = (raw.get("sha256"), raw.get("size"))
            previous = seen.get(file_ref)
            if previous is not None and previous != identity:
                raise BridgeError("Invalid file reference", status=400, code="invalid_file_reference")
            seen[file_ref] = identity
        return payload

    @staticmethod
    def _close_pre_effect_batch(batch: Any) -> None:
        close = getattr(batch, "close", None)
        if callable(close):
            try:
                close()
            except Exception:
                pass

    @staticmethod
    def _close_preserving_primary(batch: Any) -> None:
        close = getattr(batch, "close", None)
        if callable(close):
            try:
                close()
            except BaseException:
                pass

    @staticmethod
    def _close_after_success(batch: Any) -> None:
        close = getattr(batch, "close", None)
        if not callable(close):
            return
        try:
            close()
        except Exception:
            # Telegram effect may already exist; never classify cleanup as safe.
            raise RuntimeError("post_effect_upload_cleanup_failed") from None

    def _open_snapshot_batch(self, payload: Mapping[str, Any]) -> tuple[Any, tuple[io.BufferedIOBase, ...]]:
        factory = self._upload_batch_factory
        if factory is None:
            raise SafeWriteMetadataFailure("private_file_preflight_failed", status=503)
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
            raise SafeWriteMetadataFailure("private_file_preflight_failed", status=503) from None
        if batch is None:
            raise SafeWriteMetadataFailure("registered_private_file_identity_mismatch", status=409)
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
            if not all(isinstance(item, io.BufferedIOBase) for item in snapshot_files):
                raise ValueError("snapshot factory returned non-stream input")
        except Exception:
            self._close_pre_effect_batch(batch)
            raise SafeWriteMetadataFailure("private_file_preflight_failed", status=503) from None
        return batch, snapshot_files

    def _execute_external_write(self, action: str, payload: dict[str, Any]) -> Mapping[str, Any]:
        if action != "SEND_FILES":
            return super()._execute_external_write(action, payload)
        adapter = self.write_adapter
        if adapter is None:
            raise SafeWriteMetadataFailure("telegram_writer_unconfigured", status=503)
        if self.read_app.files is None:
            raise SafeWriteMetadataFailure("private_file_store_unavailable", status=503)

        # Deliberately no legacy pathname branch in production composition.
        batch, snapshot_files = self._open_snapshot_batch(payload)
        try:
            receipt = adapter.send_files(
                payload["target"],
                snapshot_files,
                caption=payload.get("caption", ""),
                reply_to_message_id=payload.get("reply_to_message_id"),
                voice_note=bool(payload.get("voice_note", False)),
            )
            result = self._receipt_metadata(receipt, action)
        except BaseException:
            self._close_preserving_primary(batch)
            raise
        self._close_after_success(batch)
        return result

    def _write_error(self, start_response: Callable, exc: BaseException, request_id: str) -> list[bytes]:
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
            BridgeError(message, status=status, code=code, retry_after_seconds=retry),
            request_id,
        )


__all__ = ["PhaseAwareUnifiedBridgeApplication", "UploadBatchFactory"]
