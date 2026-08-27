# -*- coding: utf-8 -*-
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from ops.structured_safe_write import StructuredSafePersistentWriteStore
from ops.write_safety import ReconciliationRequired, WriteAction


class _LateFaultAfterDurableCommitStore(StructuredSafePersistentWriteStore):
    def _commit_result(self, idempotency_key, fingerprint, result, *, now):
        super()._commit_result(idempotency_key, fingerprint, result, now=now)
        raise RuntimeError("synthetic late local fault after durable commit")


class _FaultBeforeDurableCommitStore(StructuredSafePersistentWriteStore):
    def _commit_result(self, idempotency_key, fingerprint, result, *, now):
        raise RuntimeError("synthetic local fault before durable commit")


class StructuredCommitReceiptTests(unittest.TestCase):
    def _preview(self, store):
        return store.create_preview(
            WriteAction.SEND,
            {"target": "peer:123", "text": "safe test only"},
            now=100,
        )

    def test_late_local_fault_returns_matching_durable_committed_receipt(self):
        with tempfile.TemporaryDirectory() as td:
            store = _LateFaultAfterDurableCommitStore(Path(td) / "writes.sqlite3")
            preview = self._preview(store)
            effects = []

            def external_write(payload):
                effects.append(dict(payload))
                return {"message_id": 77, "peer_id": "peer:123"}

            result = store.commit(
                preview.token,
                expected_action=WriteAction.SEND,
                idempotency_key="idem-key-0001",
                external_write=external_write,
                now=101,
            )
            self.assertEqual(result.state, "COMMITTED")
            self.assertFalse(result.idempotent_replay)
            self.assertEqual(result.result, {"message_id": 77, "peer_id": "peer:123"})
            self.assertEqual(len(effects), 1)

            replay = store.commit(
                preview.token,
                expected_action=WriteAction.SEND,
                idempotency_key="idem-key-0001",
                external_write=lambda payload: self.fail("replay must not repeat external effect"),
                now=102,
            )
            self.assertTrue(replay.idempotent_replay)
            self.assertEqual(replay.result, result.result)
            self.assertEqual(len(effects), 1)

    def test_precommit_fault_remains_ambiguous_and_replay_is_blocked(self):
        with tempfile.TemporaryDirectory() as td:
            store = _FaultBeforeDurableCommitStore(Path(td) / "writes.sqlite3")
            preview = self._preview(store)
            effects = []

            def external_write(payload):
                effects.append(dict(payload))
                return {"message_id": 88, "peer_id": "peer:123"}

            with self.assertRaises(ReconciliationRequired):
                store.commit(
                    preview.token,
                    expected_action=WriteAction.SEND,
                    idempotency_key="idem-key-0002",
                    external_write=external_write,
                    now=101,
                )
            self.assertEqual(len(effects), 1)

            with self.assertRaises(ReconciliationRequired):
                store.commit(
                    preview.token,
                    expected_action=WriteAction.SEND,
                    idempotency_key="idem-key-0002",
                    external_write=lambda payload: self.fail("ambiguous replay must not repeat external effect"),
                    now=102,
                )
            self.assertEqual(len(effects), 1)


if __name__ == "__main__":
    unittest.main()
