# -*- coding: utf-8 -*-
"""Isolated Task2 repair candidate for monotonic write terminal states.

This specialist overlay intentionally does not replace the canonical runtime wiring.
Canonical integration should adapt the guarded transition into PersistentWriteStore.
"""
from __future__ import annotations

from ops.write_safety import PersistentWriteStore, TransactionState, WriteSafetyError


class MonotonicTerminalWriteStore(PersistentWriteStore):
    """PersistentWriteStore variant that never downgrades durable COMMITTED state."""

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
                # Durable success is terminal. A later local exception can make the
                # current caller uncertain, but it cannot erase the stored receipt
                # needed for truthful exactly-once replay.
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
