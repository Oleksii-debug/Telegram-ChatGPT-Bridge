# -*- coding: utf-8 -*-
"""DEV08 recovery extensions for clock-rollback-safe crash classification.

The canonical request path must fail closed when wall time moves materially
backward because preview expiry must never be evaluated against rolled-back time.
Startup crash classification has a different requirement: an orphaned guarded
CALLING transaction should still become AMBIGUOUS even while wall time is behind
its persistent high-water mark.

This module composes the existing ``ReliableWriteStoreProxy`` without changing
Telegram/write business semantics.  Recovery uses a timestamp no smaller than the
persistent high-water mark; normal preview/commit calls continue to use the base
proxy's strict ``observe`` behavior.
"""
from __future__ import annotations

from typing import Any

from ops.dev08_reliability import RecoveryReport, ReliableWriteStoreProxy
from ops.write_safety import WriteSafetyError


class RollbackSafeReliableWriteStoreProxy(ReliableWriteStoreProxy):
    """Reliable write proxy whose startup recovery survives wall-clock rollback.

    Only the recovery timestamp policy differs from ``ReliableWriteStoreProxy``.
    Request expiry/idempotency paths remain fail-closed on material backward time.
    """

    def _recovery_timestamp(self, now: int | None = None) -> int:
        if isinstance(now, bool):
            raise WriteSafetyError("invalid_write_clock", status=503)
        try:
            ts = int(self.clock_guard.clock() if now is None else now)
        except (TypeError, ValueError, OverflowError) as exc:
            raise WriteSafetyError("invalid_write_clock", status=503) from exc
        if ts < 0:
            raise WriteSafetyError("invalid_write_clock", status=503)

        with self.store._connect() as con:
            con.execute("BEGIN IMMEDIATE")
            try:
                row = con.execute(
                    "SELECT high_water FROM dev08_write_clock WHERE singleton=1"
                ).fetchone()
                if row is None:
                    con.execute(
                        "INSERT INTO dev08_write_clock(singleton,high_water) VALUES(1,?)",
                        (ts,),
                    )
                    recovery_ts = ts
                else:
                    high_water = int(row["high_water"])
                    recovery_ts = max(ts, high_water)
                    if ts > high_water:
                        con.execute(
                            "UPDATE dev08_write_clock SET high_water=? WHERE singleton=1",
                            (ts,),
                        )
                con.commit()
                return recovery_ts
            except Exception:
                if con.in_transaction:
                    con.rollback()
                raise

    def recover_on_startup(self, *, now: int | None = None) -> RecoveryReport:
        recovery_ts = self._recovery_timestamp(now)
        return self.commit_guard.recover_orphaned_calling(now=recovery_ts)


__all__ = ["RollbackSafeReliableWriteStoreProxy"]
