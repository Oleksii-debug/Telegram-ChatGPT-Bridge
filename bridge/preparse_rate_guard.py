"""Request-attempt rate limiting before Action JSON parsing.

This middleware repairs the production composition seam where ActionRequestGuard
parses authenticated write bodies before UnifiedBridgeApplication reaches its
own pre-parse request bucket.  It consumes that request-attempt bucket first and
uses a request-local ContextVar to make the downstream canonical consume a
no-op exactly once, while semantic preview/commit quota remains unchanged.
"""
from __future__ import annotations

from contextvars import ContextVar, Token
from typing import Any, Callable, Iterable

from .action_request_guard import ActionRequestGuard
from ops.openapi_registry import OpenAPIContractError, OperationClass, canonical_operation


_PENDING_REQUEST_BUCKET: ContextVar[str | None] = ContextVar(
    "telegram_bridge_preparse_request_bucket", default=None
)


class _DeduplicatingRequestLimiter:
    def __init__(self, delegate: Any):
        self.delegate = delegate

    def consume_for_guard(self, actor_sha256: str, operation_id: str) -> Token:
        bucket = f"request:{operation_id}"
        result = self.delegate.consume(actor_sha256, bucket)
        token = _PENDING_REQUEST_BUCKET.set(bucket)
        # Keep the result reachable for debuggability without exposing it; the
        # caller only needs successful consumption before parsing.
        del result
        return token

    @staticmethod
    def reset(token: Token) -> None:
        _PENDING_REQUEST_BUCKET.reset(token)

    def consume(self, actor_sha256: str, operation_id: str):
        pending = _PENDING_REQUEST_BUCKET.get()
        if pending is not None and operation_id == pending:
            # UnifiedBridgeApplication ignores the return value of its request
            # bucket consume.  Clear first so a second accidental consume cannot
            # also bypass the real limiter.
            _PENDING_REQUEST_BUCKET.set(None)
            return (0, 0)
        return self.delegate.consume(actor_sha256, operation_id)


class PreparseRateLimitedActionGuard:
    """Compose auth -> request-attempt quota -> strict Action parsing."""

    def __init__(self, application: Any):
        self.application = application
        original = getattr(application, "_write_limiter", None)
        if original is None:
            raise RuntimeError("write_limiter_missing")
        self._limiter = _DeduplicatingRequestLimiter(original)
        # WriteCoordinator already owns the original limiter for semantic
        # preview/commit quota.  Only the application's request-attempt consume
        # is replaced so valid writes are not double charged.
        application._write_limiter = self._limiter
        self._action_guard = ActionRequestGuard(application)

    def __call__(self, environ: dict[str, Any], start_response: Callable) -> Iterable[bytes]:
        method = str(environ.get("REQUEST_METHOD") or "GET").upper()
        path = str(environ.get("PATH_INFO") or "/")
        try:
            spec = canonical_operation(path, method)
        except OpenAPIContractError:
            return self._action_guard(environ, start_response)
        if spec.operation_class not in {OperationClass.WRITE_PREVIEW, OperationClass.WRITE_COMMIT}:
            return self._action_guard(environ, start_response)

        # Match the canonical hidden-404 ordering: missing/wrong auth must not
        # consume quota and must not read the body.
        try:
            context = self.application._require_write_auth(environ)
        except Exception:
            return self._action_guard(environ, start_response)

        token: Token | None = None
        try:
            token = self._limiter.consume_for_guard(context.actor_sha256, spec.operation_id)
        except BaseException as exc:
            request_id = self.application.read_app._request_id()
            return self.application._write_error(start_response, exc, request_id)
        try:
            return self._action_guard(environ, start_response)
        finally:
            if token is not None:
                self._limiter.reset(token)


__all__ = ["PreparseRateLimitedActionGuard"]
