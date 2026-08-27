"""Request-attempt rate limiting before Action JSON parsing.

This middleware repairs the production composition seam where ActionRequestGuard
parses authenticated write bodies before UnifiedBridgeApplication reaches its
own pre-parse request bucket. It consumes that request-attempt bucket first and
uses request-local ContextVar state so the downstream canonical consume is a
no-op exactly once, while semantic preview/commit quota remains unchanged.
"""
from __future__ import annotations

from contextvars import ContextVar, Token
from typing import Any, Callable, Iterable

from .action_request_guard import ActionRequestGuard
from .integrated_app import _RejectingWriteLimiter
from ops.openapi_registry import OpenAPIContractError, OperationClass, canonical_operation


_PENDING_REQUEST_BUCKET: ContextVar[str | None] = ContextVar(
    "telegram_bridge_preparse_request_bucket", default=None
)


class _DeduplicatingRequestLimiter:
    def __init__(self, delegate: Any):
        self.delegate = delegate

    def consume_for_guard(self, actor_sha256: str, operation_id: str) -> Token:
        bucket = f"request:{operation_id}"
        self.delegate.consume(actor_sha256, bucket)
        return _PENDING_REQUEST_BUCKET.set(bucket)

    @staticmethod
    def reset(token: Token) -> None:
        _PENDING_REQUEST_BUCKET.reset(token)

    def consume(self, actor_sha256: str, operation_id: str):
        pending = _PENDING_REQUEST_BUCKET.get()
        if pending is not None and operation_id == pending:
            # Clear first so a second accidental consume cannot also bypass the
            # real limiter. UnifiedBridgeApplication ignores this return value.
            _PENDING_REQUEST_BUCKET.set(None)
            return (0, 0)
        return self.delegate.consume(actor_sha256, operation_id)


class PreparseRateLimitedActionGuard(ActionRequestGuard):
    """Compose auth -> request-attempt quota -> strict Action parsing.

    It remains an ActionRequestGuard subtype so the existing production WSGI
    identity contract and tests stay true. Generic/mock applications that do not
    expose the private write limiter retain ordinary ActionRequestGuard behavior.
    """

    def __init__(self, application: Any):
        super().__init__(application)
        original = getattr(application, "_write_limiter", None)
        self._limiter: _DeduplicatingRequestLimiter | None = None
        if original is None:
            return
        self._limiter = _DeduplicatingRequestLimiter(original)
        # Do not mask the canonical fail-closed health classification. A
        # rejecting limiter is consumed by this outer guard and fails before
        # parsing, so the downstream app is never reached and needs no dedup.
        if not isinstance(original, _RejectingWriteLimiter):
            application._write_limiter = self._limiter

    def __call__(self, environ: dict[str, Any], start_response: Callable) -> Iterable[bytes]:
        if self._limiter is None:
            return super().__call__(environ, start_response)

        method = str(environ.get("REQUEST_METHOD") or "GET").upper()
        path = str(environ.get("PATH_INFO") or "/")
        try:
            spec = canonical_operation(path, method)
        except OpenAPIContractError:
            return super().__call__(environ, start_response)
        if spec.operation_class not in {OperationClass.WRITE_PREVIEW, OperationClass.WRITE_COMMIT}:
            return super().__call__(environ, start_response)

        # Preserve canonical hidden-404 ordering: missing/wrong auth neither
        # consumes write quota nor reads the request body.
        try:
            context = self.application._require_write_auth(environ)
        except Exception:
            return super().__call__(environ, start_response)

        token: Token | None = None
        try:
            token = self._limiter.consume_for_guard(context.actor_sha256, spec.operation_id)
        except Exception as exc:
            # Operational limiter failures are mapped through the bounded public
            # write-error contract. Process-control BaseException subclasses must
            # propagate so Passenger/process recovery semantics are not masked.
            request_id = self.application.read_app._request_id()
            return self.application._write_error(start_response, exc, request_id)
        try:
            return super().__call__(environ, start_response)
        finally:
            if token is not None:
                self._limiter.reset(token)


__all__ = ["PreparseRateLimitedActionGuard"]
