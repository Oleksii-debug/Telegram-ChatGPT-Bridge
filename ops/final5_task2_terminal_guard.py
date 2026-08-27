# -*- coding: utf-8 -*-
"""Isolated Task2 repair candidate for monotonic write terminal states.

This specialist overlay intentionally does not replace the canonical runtime wiring.
Canonical integration should adapt the guarded transition and durable-result recovery
into PersistentWriteStore after review.
"""
from __future__ import annotations

import json
import time
from collections.abc import Callable, Mapping
from typing import Any

from ops.write_safety import (
    CommitResult,
    PersistentWriteStore,
    ReconciliationRequired,
    SafeNoSideEffectFailure,
    TransactionState,
    WriteAction,
    WriteSafetyError,
)


class MonotonicTerminalWriteStore(PersistentWriteStore):
    """PersistentWriteStore variant with monotonic terminal state and truthful recovery."""

    def _record_ambiguous(self, idempotency_key: str, fingerprint: str, *, now: int) -> None:
        key_hash = self._idempotency_hash(idempotency_key)
        with self._connect() as con:
            con.execute("BEGIN IMMEDIATE")
            row = con.execute("SELECT * FROM idempotency WHERE key_hash=?", (key_hash,)).fetchone()
            if row is None or row["request_fingerprint"] != fingerprint:
                con.rollback()
                raise WriteSafetyError("idempotency_state_missing", status=409)

            state = row["state"]
            if state == TransactionState.COMMITTED.value:
                # Durable success is terminal. Never erase the stored receipt.
                con.commit()
                return
            if state != TransactionState.CALLING.value:
                con.rollback()
                raise WriteSafetyError("illegal_write_state_transition", status=409)

            con.execute(
                "UPDATE idempotency SET state=?, updated_at=? WHERE key_hash=?",
                (TransactionState.AMBIGUOUS.value, now, key_hash),
            )
            con.commit()

    def _durable_committed_result(self, idempotency_key: str, fingerprint: str) -> tuple[bool, dict[str, Any] | None]:
        """Return a validated locally durable receipt after a commit-path exception."""
        key_hash = self._idempotency_hash(idempotency_key)
        with self._connect() as con:
            row = con.execute("SELECT * FROM idempotency WHERE key_hash=?", (key_hash,)).fetchone()
            if row is None or row["request_fingerprint"] != fingerprint:
                return False, None
            if row["state"] != TransactionState.COMMITTED.value or not row["result_json"]:
                return False, None
            try:
                result = json.loads(row["result_json"])
            except (TypeError, ValueError, json.JSONDecodeError):
                return False, None
            if not isinstance(result, dict):
                return False, None
            return True, result

    def commit(
        self,
        preview_token: str,
        *,
        expected_action: WriteAction | str,
        idempotency_key: str,
        external_write: Callable[[dict[str, Any]], Mapping[str, Any]],
        now: int | None = None,
    ) -> CommitResult:
        """Canonical commit semantics plus durable-result recovery at the journal boundary."""
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
            self._record_safe_failure(idempotency_key, fingerprint, now=ts)
            raise WriteSafetyError(exc.code, status=502) from None
        except Exception:
            self._record_ambiguous(idempotency_key, fingerprint, now=ts)
            raise ReconciliationRequired() from None
        try:
            self._commit_result(idempotency_key, fingerprint, result, now=ts)
        except Exception:
            durable, durable_result = self._durable_committed_result(idempotency_key, fingerprint)
            if durable:
                return CommitResult("COMMITTED", False, fingerprint, durable_result)
            try:
                self._record_ambiguous(idempotency_key, fingerprint, now=ts)
            finally:
                raise ReconciliationRequired() from None
        return CommitResult("COMMITTED", False, fingerprint, result)
