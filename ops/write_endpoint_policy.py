# -*- coding: utf-8 -*-
"""Canonical auth/rate/explicit-command policy for Telegram write endpoints.

Public error metadata is an exact reviewed contract. Exception text and
arbitrary ``code``/``status`` attributes are never treated as a public channel.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Callable, Mapping

from ops.openapi_registry import OperationClass, OperationSpec, registry_by_operation_id
from ops.telegram_write_adapter import TelegramContractError
from ops.write_safety import CommitResult, PersistentWriteStore, PreviewEnvelope, WriteSafetyError


_MAX_PUBLIC_RETRY_AFTER_SECONDS = 600


class EndpointPolicyError(RuntimeError):
    def __init__(self, code: str, *, status: int, retry_after_seconds: int | None = None):
        super().__init__(code)
        self.code = code
        self.status = status
        self.retry_after_seconds = retry_after_seconds

    def as_dict(self) -> dict[str, Any]:
        return _structured_endpoint_error(self)


@dataclass(frozen=True)
class EndpointContext:
    authenticated: bool
    actor_sha256: str
    explicit_user_command: bool = False


def _require_actor_hash(value: str) -> str:
    raw = str(value or "")
    if len(raw) != 64 or any(ch not in "0123456789abcdef" for ch in raw):
        raise EndpointPolicyError("invalid_actor_identity", status=400)
    return raw


class FixedWindowEndpointLimiter:
    """Deterministic fixed-window quota used for private write endpoints."""
    def __init__(self, *, limit: int = 10, window_seconds: int = 60,
                 clock: Callable[[], float] = time.monotonic):
        if not isinstance(limit, int) or isinstance(limit, bool) or limit <= 0 or limit > 1000:
            raise ValueError("bounded positive rate limit required")
        if not isinstance(window_seconds, int) or isinstance(window_seconds, bool) or window_seconds <= 0 or window_seconds > 3600:
            raise ValueError("bounded fixed window required")
        self.limit = limit
        self.window_seconds = window_seconds
        self.clock = clock
        self._buckets: dict[tuple[str, str], tuple[int, int]] = {}

    def consume(self, actor_sha256: str, operation_id: str) -> tuple[int, int]:
        actor = _require_actor_hash(actor_sha256)
        now = max(0, int(self.clock()))
        window_start = (now // self.window_seconds) * self.window_seconds
        key = (actor, str(operation_id))
        stored_start, count = self._buckets.get(key, (window_start, 0))
        if stored_start != window_start:
            stored_start, count = window_start, 0
        if count >= self.limit:
            retry = max(1, stored_start + self.window_seconds - now)
            raise EndpointPolicyError("rate_limited", status=429, retry_after_seconds=retry)
        count += 1
        self._buckets[key] = (stored_start, count)
        return self.limit - count, stored_start + self.window_seconds


class WriteEndpointPolicy:
    def __init__(self, limiter: FixedWindowEndpointLimiter):
        self.limiter = limiter

    def authorize(self, operation_id: str, context: EndpointContext, *, expected_class: OperationClass) -> OperationSpec:
        try:
            spec = registry_by_operation_id(operation_id)
        except Exception:
            raise EndpointPolicyError("unknown_operation", status=404) from None
        if spec.operation_class is not expected_class:
            raise EndpointPolicyError("operation_class_mismatch", status=409)
        if spec.protected and not context.authenticated:
            raise EndpointPolicyError("authentication_required", status=401)
        actor = _require_actor_hash(context.actor_sha256)
        self.limiter.consume(actor, spec.operation_id)
        if expected_class is OperationClass.WRITE_COMMIT:
            if not spec.explicit_user_commit_required:
                raise EndpointPolicyError("unsafe_commit_registry", status=503)
            if context.explicit_user_command is not True:
                raise EndpointPolicyError("explicit_user_commit_required", status=409)
        return spec


def _canonical_store_payload(spec: OperationSpec, payload: Mapping[str, Any]) -> Mapping[str, Any]:
    if spec.action != "SEND_FILES":
        return payload
    out = dict(payload)
    raw_files = payload.get("files")
    if isinstance(raw_files, list):
        converted: list[Any] = []
        for raw in raw_files:
            if isinstance(raw, Mapping):
                item = dict(raw)
                if "file_ref" in item and "file_id" not in item:
                    item["file_id"] = item.pop("file_ref")
                converted.append(item)
            else:
                converted.append(raw)
        out["files"] = converted
    return out


class WriteCoordinator:
    def __init__(self, store: PersistentWriteStore, policy: WriteEndpointPolicy):
        self.store = store
        self.policy = policy

    def preview(self, operation_id: str, context: EndpointContext, payload: Mapping[str, Any], *, now: int | None = None) -> PreviewEnvelope:
        spec = self.policy.authorize(operation_id, context, expected_class=OperationClass.WRITE_PREVIEW)
        if not spec.action:
            raise EndpointPolicyError("write_action_missing", status=503)
        return self.store.create_preview(spec.action, _canonical_store_payload(spec, payload), now=now)

    def commit(self, operation_id: str, context: EndpointContext, *, preview_token: str,
               idempotency_key: str, external_write: Callable[[dict[str, Any]], Mapping[str, Any]],
               now: int | None = None) -> CommitResult:
        spec = self.policy.authorize(operation_id, context, expected_class=OperationClass.WRITE_COMMIT)
        if not spec.action:
            raise EndpointPolicyError("write_action_missing", status=503)
        return self.store.commit(
            preview_token,
            expected_action=spec.action,
            idempotency_key=idempotency_key,
            external_write=external_write,
            now=now,
        )


_SAFE_ENDPOINT_PUBLIC_ERRORS: dict[str, int] = {
    "invalid_actor_identity": 400,
    "unknown_operation": 404,
    "operation_class_mismatch": 409,
    "rate_limited": 429,
    "rate_limiter_unavailable": 503,
    "unsafe_commit_registry": 503,
    "explicit_user_commit_required": 409,
    "write_action_missing": 503,
    "write_rate_limiter_unconfigured": 503,
}

_SAFE_WRITE_SAFETY_PUBLIC_ERRORS: dict[str, int] = {
    "unsupported_write_action": 400,
    "invalid_write_payload": 400,
    "target_required": 400,
    "text_required": 400,
    "text_too_long": 413,
    "reply_target_required": 400,
    "send_cannot_include_reply_target": 400,
    "source_required": 400,
    "invalid_message_ids": 400,
    "caption_too_long": 413,
    "files_required": 400,
    "invalid_file_reference": 400,
    "file_hash_required": 400,
    "invalid_file_size": 400,
    "file_too_large": 413,
    "invalid_file_count": 400,
    "files_total_too_large": 413,
    "voice_note_requires_single_file": 400,
    "invalid_reply_target": 400,
    "invalid_idempotency_key": 400,
    "invalid_preview_ttl": 400,
    "invalid_preview": 404,
    "preview_action_mismatch": 409,
    "idempotency_key_conflict": 409,
    "write_in_progress": 409,
    "write_outcome_unknown_reconciliation_required": 409,
    "previous_safe_failure_requires_new_preview": 409,
    "expired_preview": 409,
    "used_preview": 409,
    "idempotency_state_missing": 409,
    "illegal_write_state_transition": 409,
    "write_result_too_large": 502,
    "external_write_rejected": 502,
}

_SAFE_TELEGRAM_PUBLIC_ERRORS: dict[str, int] = {
    "invalid_target": 400,
    "telegram_flood_wait": 429,
    "telegram_2fa_required": 503,
    "telegram_session_unauthorized": 503,
    "telegram_target_invalid": 404,
    "telegram_message_invalid": 404,
    "telegram_file_rejected": 400,
    "telegram_rpc_error": 502,
    "telegram_operation_failed": 502,
    "telegram_invalid_receipt": 502,
    "invalid_reply_target": 400,
    "reply_target_not_found": 404,
    "reply_target_chat_mismatch": 409,
    "reply_target_mismatch": 409,
    "telegram_not_configured": 503,
    "telegram_timeout": 504,
    "telegram_session_busy": 409,
    "telegram_session_lock_unsafe": 503,
    "text_required": 400,
    "text_too_long": 413,
    "invalid_message_ids": 400,
    "forward_source_missing": 404,
    "forward_source_mismatch": 409,
    "files_required": 400,
    "invalid_file_count": 400,
    "invalid_file_reference": 400,
    "caption_too_long": 413,
    "voice_note_requires_single_file": 400,
}


def _bounded_retry(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        return None
    return min(value, _MAX_PUBLIC_RETRY_AFTER_SECONDS)


def _strict_public_error(code: Any, status: Any, allowed: Mapping[str, int]) -> dict[str, Any] | None:
    if not isinstance(code, str) or isinstance(status, bool) or not isinstance(status, int):
        return None
    expected = allowed.get(code)
    if expected is None or status != expected:
        return None
    return {"error": code, "status": expected}


def _structured_endpoint_error(exc: EndpointPolicyError) -> dict[str, Any]:
    out = _strict_public_error(exc.code, exc.status, _SAFE_ENDPOINT_PUBLIC_ERRORS)
    if out is None:
        return {"error": "internal_bridge_error", "status": 500}
    if exc.code == "rate_limited":
        out["retry_after_seconds"] = _bounded_retry(exc.retry_after_seconds) or 1
    return out


def _structured_write_safety_error(exc: WriteSafetyError) -> dict[str, Any]:
    out = _strict_public_error(exc.code, exc.status, _SAFE_WRITE_SAFETY_PUBLIC_ERRORS)
    return out if out is not None else {"error": "internal_bridge_error", "status": 500}


def _structured_telegram_error(exc: TelegramContractError) -> dict[str, Any]:
    out = _strict_public_error(exc.code, exc.status, _SAFE_TELEGRAM_PUBLIC_ERRORS)
    if out is None:
        return {"error": "internal_bridge_error", "status": 500}
    if exc.code == "telegram_flood_wait":
        out["retry_after_seconds"] = _bounded_retry(exc.retry_after) or 1
    return out


def structured_write_error(exc: BaseException) -> dict[str, Any]:
    """Return stable allowlisted metadata only; never exception text/foreign attrs."""
    if isinstance(exc, EndpointPolicyError):
        return _structured_endpoint_error(exc)
    if isinstance(exc, WriteSafetyError):
        return _structured_write_safety_error(exc)
    if isinstance(exc, TelegramContractError):
        return _structured_telegram_error(exc)
    return {"error": "internal_bridge_error", "status": 500}
