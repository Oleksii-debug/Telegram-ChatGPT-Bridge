# -*- coding: utf-8 -*-
"""Canonical auth/rate/explicit-command policy for Telegram write endpoints."""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Callable, Mapping

from ops.openapi_registry import OperationClass, OperationSpec, registry_by_operation_id
from ops.write_safety import CommitResult, PersistentWriteStore, PreviewEnvelope, WriteSafetyError


class EndpointPolicyError(RuntimeError):
    def __init__(self, code: str, *, status: int, retry_after_seconds: int | None = None):
        super().__init__(code)
        self.code = code
        self.status = status
        self.retry_after_seconds = retry_after_seconds

    def as_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"error": self.code, "status": self.status}
        if self.retry_after_seconds is not None:
            out["retry_after_seconds"] = self.retry_after_seconds
        return out


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
    """Translate DEV3-compatible public file_ref into the store's opaque internal key.

    Only SEND_FILES needs translation. The value is still the same opaque Bridge file
    reference; no server path, filename or private content is introduced.
    """
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
    """Application service enforcing canonical route policy before store effects."""
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


def structured_write_error(exc: BaseException) -> dict[str, Any]:
    """Return stable error metadata only; never copy exception text/server paths."""
    if isinstance(exc, EndpointPolicyError):
        return exc.as_dict()
    if isinstance(exc, WriteSafetyError):
        return {"error": exc.code, "status": exc.status}
    code = getattr(exc, "code", None)
    status = getattr(exc, "status", None)
    retry = getattr(exc, "retry_after", None)
    if isinstance(code, str) and code and isinstance(status, int):
        out: dict[str, Any] = {"error": code, "status": status}
        if isinstance(retry, int) and retry > 0:
            out["retry_after_seconds"] = min(retry, 600)
        return out
    return {"error": "internal_bridge_error", "status": 500}
