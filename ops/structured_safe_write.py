# -*- coding: utf-8 -*-
"""Structured metadata for *proven* no-side-effect Telegram write failures.

This module is a DEV05 integration overlay. It composes the owner-private SQLite
boundary from :mod:`ops.secure_write_store` with the canonical durable write
transaction state machine, while carrying bounded status / Retry-After metadata
only when an adapter has already proved that no mutating Telegram RPC was
started. Unknown or post-effect failures remain AMBIGUOUS exactly as before.

The overlay also closes Python 3.11 cancellation and persistence-failure gaps.
Once durable state has crossed CALLING, cancellation/process-control exceptions
are conservatively classified AMBIGUOUS before the original BaseException is
re-raised. If FAILED_SAFE or AMBIGUOUS persistence itself fails, the request is
never presented as safely retryable: the caller receives reconciliation-required
while durable CALLING/AMBIGUOUS continues to block a blind exact retry.

No raw exception text, Telegram content, target, token or server path is stored
in these error objects.
"""
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
    if retry <= 0:
        return None
    return min(retry, 600)


class SafeWriteMetadataFailure(SafeNoSideEffectFailure):
    """No-side-effect failure with bounded structured transport metadata."""

    def __init__(
        self,
        code: str = "external_write_rejected",
        *,
        status: int = 502,
        retry_after_seconds: int | None = None,
    ) -> None:
        super().__init__(code)
        self.status = _bounded_status(status)
        self.retry_after_seconds = _bounded_retry(retry_after_seconds)


class WriteSafetyMetadataError(WriteSafetyError):
    """Public-safe store error carrying an optional bounded Retry-After value."""

    def __init__(
        self,
        code: str,
        *,
        status: int,
        retry_after_seconds: int | None = None,
    ) -> None:
        super().__init__(code, status=_bounded_status(status))
        self.retry_after_seconds = _bounded_retry(retry_after_seconds)


class StructuredSafePersistentWriteStore(SecurePersistentWriteStore):
    """Secure persistent store plus metadata-preserving FAILED_SAFE results.

    This deliberately derives from ``SecurePersistentWriteStore`` instead of
    creating a parallel plain-SQLite implementation. DEV01 can integrate one
    store object and retain both owner-private topology controls and structured
    failure semantics. The canonical method surface remains unchanged so DEV08
    can wrap this store with its process-shared reliability proxy.
    """

    def _record_ambiguous_best_effort(
        self,
        idempotency_key: str,
        fingerprint: str,
        *,
        now: int,
    ) -> None:
        """Persist AMBIGUOUS when possible; CALLING is also fail-closed."""

        try:
            self._record_ambiguous(idempotency_key, fingerprint, now=now)
        except Exception:
            # A storage/topology failure may leave CALLING durable. Exact retry
            # still cannot execute the external callback, and recovery may later
            # promote that orphan to AMBIGUOUS. Never leak persistence details.
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
            action_e = (
                expected_action
                if isinstance(expected_action, WriteAction)
                else WriteAction(str(expected_action))
            )
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
        raced_commit = self._transition_to_calling(
            idempotency_key, fingerprint, now=ts
        )
        if raced_commit is not None:
            return CommitResult("COMMITTED", True, fingerprint, raced_commit)

        try:
            result = dict(external_write(payload))
        except SafeNoSideEffectFailure as exc:
            try:
                self._record_safe_failure(idempotency_key, fingerprint, now=ts)
            except Exception:
                # The Telegram outcome is known safe, but durable transaction
                # classification is not. Do not return a retryable FAILED_SAFE
                # contract unless that state was actually persisted.
                self._record_ambiguous_best_effort(
                    idempotency_key, fingerprint, now=ts
                )
                raise ReconciliationRequired() from None
            status = _bounded_status(getattr(exc, "status", 502))
            retry = _bounded_retry(
                getattr(exc, "retry_after_seconds", None)
            )
            raise WriteSafetyMetadataError(
                exc.code,
                status=status,
                retry_after_seconds=retry,
            ) from None
        except Exception:
            # After CALLING, arbitrary external errors are outcome-unknown. Even
            # if AMBIGUOUS persistence fails, return the same conservative public
            # contract; a durable CALLING row also prevents blind resend.
            self._record_ambiguous_best_effort(
                idempotency_key, fingerprint, now=ts
            )
            raise ReconciliationRequired() from None
        except BaseException:
            # Python 3.11 asyncio.CancelledError and process-control exceptions do
            # not inherit Exception. The external callback has already been
            # entered, so cancellation cannot be promoted to FAILED_SAFE.
            self._record_ambiguous_best_effort(
                idempotency_key, fingerprint, now=ts
            )
            raise

        try:
            self._commit_result(idempotency_key, fingerprint, result, now=ts)
        except Exception:
            # External success may already have happened. Receipt/result
            # persistence failure is therefore always reconciliation-required.
            self._record_ambiguous_best_effort(
                idempotency_key, fingerprint, now=ts
            )
            raise ReconciliationRequired() from None
        return CommitResult("COMMITTED", False, fingerprint, result)


def structured_safe_write_error(exc: BaseException) -> dict[str, Any]:
    """Serialize only stable bounded metadata; never raw exception text."""

    if isinstance(exc, WriteSafetyMetadataError):
        out: dict[str, Any] = {"error": exc.code, "status": exc.status}
        if exc.retry_after_seconds is not None:
            out["retry_after_seconds"] = exc.retry_after_seconds
        return out

    # Delegate all existing policy/store/Telegram shapes to the canonical
    # serializer so this overlay does not create a parallel error vocabulary.
    from ops.write_endpoint_policy import structured_write_error

    return structured_write_error(exc)


__all__ = [
    "SafeWriteMetadataFailure",
    "StructuredSafePersistentWriteStore",
    "WriteSafetyMetadataError",
    "structured_safe_write_error",
]
