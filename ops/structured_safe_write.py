# -*- coding: utf-8 -*-
"""Structured metadata for proven no-side-effect Telegram write failures."""
from __future__ import annotations

import json
import time
from typing import Any, Callable, Mapping

from ops.secure_write_store import SecurePersistentWriteStore
from ops.write_safety import (
    CommitResult,
    ReconciliationRequired,
    SafeNoSideEffectFailure,
    WriteAction,
    WriteSafetyError,
)

_GENERIC_SAFE_CODE = "external_write_rejected"
_PUBLIC_SAFE_CODES = frozenset(
    {
        _GENERIC_SAFE_CODE,
        "text_required", "text_too_long", "invalid_target", "invalid_reply_target",
        "invalid_message_ids", "files_required", "invalid_file_count", "invalid_file_reference",
        "caption_too_long", "voice_note_requires_single_file", "reply_target_not_found",
        "reply_target_chat_mismatch", "reply_target_mismatch", "forward_source_missing",
        "forward_source_mismatch", "telegram_not_configured", "telegram_session_unauthorized",
        "telegram_session_busy", "telegram_session_lock_unsafe", "telegram_timeout",
        "telegram_flood_wait", "telegram_2fa_required", "telegram_target_invalid",
        "telegram_message_invalid", "telegram_file_rejected", "telegram_rpc_error",
        "telegram_operation_failed", "telegram_invalid_receipt", "telegram_writer_unconfigured",
        "private_file_store_unavailable", "registered_private_file_unavailable",
        "registered_private_file_identity_mismatch", "private_file_preflight_failed",
    }
)


def _bounded_code(value: Any, default: str = _GENERIC_SAFE_CODE) -> str:
    return value if isinstance(value, str) and value in _PUBLIC_SAFE_CODES else default


def _bounded_status(value: Any, default: int = 502) -> int:
    if isinstance(value, bool):
        return default
    try:
        status = int(value)
    except (TypeError, ValueError):
        return default
    return status if 400 <= status <= 599 else default


def _bounded_retry(value: Any) -> int | None:
    if isinstance(value, bool) or value is None:
        return None
    try:
        retry = int(value)
    except (TypeError, ValueError):
        return None
    return min(retry, 600) if retry > 0 else None


class SafeWriteMetadataFailure(SafeNoSideEffectFailure):
    def __init__(self, code: str = _GENERIC_SAFE_CODE, *, status: int = 502, retry_after_seconds: int | None = None) -> None:
        super().__init__(_bounded_code(code))
        self.status = _bounded_status(status)
        self.retry_after_seconds = _bounded_retry(retry_after_seconds)


class WriteSafetyMetadataError(WriteSafetyError):
    def __init__(self, code: str, *, status: int, retry_after_seconds: int | None = None) -> None:
        super().__init__(_bounded_code(code), status=_bounded_status(status))
        self.retry_after_seconds = _bounded_retry(retry_after_seconds)


class StructuredSafePersistentWriteStore(SecurePersistentWriteStore):
    """Secure store that preserves bounded metadata only for proven-safe failures."""

    def _record_ambiguous_best_effort(self, idempotency_key: str, fingerprint: str, *, now: int) -> None:
        try:
            self._record_ambiguous(idempotency_key, fingerprint, now=now)
        except Exception:
            pass

    def commit(
        self,
        preview_token: str,
        *,
        expected_action: WriteAction | str,
        idempotency_key: str,
        external_write: Callable[[dict[str, Any]], Mapping[str, Any]],
        now: int | None = None,
    ) -> CommitResult:
        try:
            action_e = expected_action if isinstance(expected_action, WriteAction) else WriteAction(str(expected_action))
        except ValueError as exc:
            raise WriteSafetyError("unsupported_write_action", status=400) from exc
        ts = int(time.time() if now is None else now)
        mode, preview, cached = self._begin_commit(
            preview_token,
            expected_action=action_e,
            idempotency_key=idempotency_key,
            now=ts,
        )
        fingerprint = preview["request_fingerprint"]
        if mode == "REPLAY":
            return CommitResult("COMMITTED", True, fingerprint, cached)
        payload = json.loads(preview["payload_json"])
        raced_commit = self._transition_to_calling(idempotency_key, fingerprint, now=ts)
        if raced_commit is not None:
            return CommitResult("COMMITTED", True, fingerprint, raced_commit)
        try:
            result = dict(external_write(payload))
        except SafeNoSideEffectFailure as exc:
            try:
                self._record_safe_failure(idempotency_key, fingerprint, now=ts)
            except Exception:
                self._record_ambiguous_best_effort(idempotency_key, fingerprint, now=ts)
                raise ReconciliationRequired() from None
            raise WriteSafetyMetadataError(
                _bounded_code(getattr(exc, "code", _GENERIC_SAFE_CODE)),
                status=_bounded_status(getattr(exc, "status", 502)),
                retry_after_seconds=_bounded_retry(getattr(exc, "retry_after_seconds", None)),
            ) from None
        except Exception:
            self._record_ambiguous_best_effort(idempotency_key, fingerprint, now=ts)
            raise ReconciliationRequired() from None
        except BaseException:
            self._record_ambiguous_best_effort(idempotency_key, fingerprint, now=ts)
            raise
        try:
            self._commit_result(idempotency_key, fingerprint, result, now=ts)
        except Exception:
            durable_result = self._durable_committed_result(idempotency_key, fingerprint)
            if durable_result is not None:
                return CommitResult("COMMITTED", False, fingerprint, durable_result)
            self._record_ambiguous_best_effort(idempotency_key, fingerprint, now=ts)
            raise ReconciliationRequired() from None
        return CommitResult("COMMITTED", False, fingerprint, result)


def structured_safe_write_error(exc: BaseException) -> dict[str, Any]:
    if isinstance(exc, WriteSafetyMetadataError):
        out: dict[str, Any] = {"error": _bounded_code(exc.code), "status": exc.status}
        if exc.retry_after_seconds is not None:
            out["retry_after_seconds"] = exc.retry_after_seconds
        return out
    from ops.write_endpoint_policy import structured_write_error
    return structured_write_error(exc)


__all__ = [
    "SafeWriteMetadataFailure", "StructuredSafePersistentWriteStore",
    "WriteSafetyMetadataError", "structured_safe_write_error",
]
