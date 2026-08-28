# -*- coding: utf-8 -*-
"""Executable red-oracle characterizations for canonical write-state seams.

These tests intentionally prove a defect in the exact canonical anchor rather than
claiming the old implementation is correct. They remain specialist evidence and
should be removed/inverted when the canonical implementation adopts the repair.
"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from ops.write_safety import PersistentWriteStore, ReconciliationRequired, TransactionState


class CanonicalLateFaultStore(PersistentWriteStore):
    """Raise only after the parent has durably committed the successful result."""

    def _commit_result(self, idempotency_key, fingerprint, result, *, now):
        super()._commit_result(idempotency_key, fingerprint, result, now=now)
        raise RuntimeError("synthetic-local-fault-after-durable-commit")


class CanonicalWriteReproducerTests(unittest.TestCase):
    def test_canonical_late_local_fault_downgrades_durable_committed_to_ambiguous(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = CanonicalLateFaultStore(Path(tmp) / "writes.sqlite3")
            preview = store.create_preview(
                "SEND",
                {"target": "target-a", "text": "hello"},
                now=100,
            )
            effects: list[str] = []

            def external(_payload):
                effects.append("effect")
                return {
                    "operation": "SEND",
                    "message_ids": [901],
                    "chat_id": 17,
                    "count": 1,
                }

            with self.assertRaises(ReconciliationRequired):
                store.commit(
                    preview.token,
                    expected_action="SEND",
                    idempotency_key="canonical-late-commit-fault-01",
                    external_write=external,
                    now=101,
                )

            # The external effect happened once and the parent _commit_result already
            # committed success, but canonical commit() catches the later local fault
            # and _record_ambiguous() unconditionally overwrites COMMITTED.
            self.assertEqual(["effect"], effects)
            self.assertEqual(
                TransactionState.AMBIGUOUS.value,
                store.transaction_state("canonical-late-commit-fault-01"),
            )

            # The durable result JSON is now inaccessible through normal replay because
            # AMBIGUOUS is terminal. The safe behavior is still no resend, but truthful
            # cached-success identity has been lost.
            with self.assertRaises(ReconciliationRequired):
                store.commit(
                    preview.token,
                    expected_action="SEND",
                    idempotency_key="canonical-late-commit-fault-01",
                    external_write=lambda _payload: effects.append("unexpected-resend") or {},
                    now=102,
                )
            self.assertEqual(["effect"], effects)


if __name__ == "__main__":
    unittest.main()
