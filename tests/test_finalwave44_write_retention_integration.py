from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from ops.state_retention import cleanup_write_previews
from ops.write_safety import (
    PersistentWriteStore,
    ReconciliationRequired,
    TransactionState,
    WriteAction,
)


class Finalwave44WriteRetentionIntegrationTests(unittest.TestCase):
    def test_real_write_store_cleanup_preserves_committed_and_ambiguous_replay_guards(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            store = PersistentWriteStore(root / "writes.sqlite3", preview_ttl_seconds=300)

            free = store.create_preview(
                WriteAction.SEND,
                {"target": "synthetic-target", "text": "ephemeral"},
                now=100,
                ttl_seconds=10,
            )
            committed = store.create_preview(
                WriteAction.SEND,
                {"target": "synthetic-target", "text": "committed"},
                now=100,
                ttl_seconds=10,
            )
            ambiguous = store.create_preview(
                WriteAction.SEND,
                {"target": "synthetic-target", "text": "ambiguous"},
                now=100,
                ttl_seconds=10,
            )

            committed_key = "idem-committed-finalwave44"
            ambiguous_key = "idem-ambiguous-finalwave44"
            first = store.commit(
                committed.token,
                expected_action=WriteAction.SEND,
                idempotency_key=committed_key,
                external_write=lambda _payload: {"message_id": 123},
                now=105,
            )
            self.assertFalse(first.idempotent_replay)
            self.assertEqual(first.state, TransactionState.COMMITTED.value)

            def unknown_outcome(_payload: dict[str, object]) -> dict[str, object]:
                raise RuntimeError("synthetic unknown outcome")

            with self.assertRaises(ReconciliationRequired):
                store.commit(
                    ambiguous.token,
                    expected_action=WriteAction.SEND,
                    idempotency_key=ambiguous_key,
                    external_write=unknown_outcome,
                    now=105,
                )

            result = cleanup_write_previews(
                store.db_path,
                now=1000,
                expired_grace_seconds=100,
            )
            self.assertEqual(result.deleted, 1)
            self.assertIsNone(store.get_preview(free.token))
            self.assertIsNotNone(store.get_preview(committed.token))
            self.assertIsNotNone(store.get_preview(ambiguous.token))
            self.assertEqual(store.transaction_state(committed_key), TransactionState.COMMITTED.value)
            self.assertEqual(store.transaction_state(ambiguous_key), TransactionState.AMBIGUOUS.value)

            replay_called = False

            def must_not_write(_payload: dict[str, object]) -> dict[str, object]:
                nonlocal replay_called
                replay_called = True
                return {"message_id": 999}

            replay = store.commit(
                committed.token,
                expected_action=WriteAction.SEND,
                idempotency_key=committed_key,
                external_write=must_not_write,
                now=1001,
            )
            self.assertTrue(replay.idempotent_replay)
            self.assertFalse(replay_called)
            self.assertEqual(replay.result, {"message_id": 123})

            with self.assertRaises(ReconciliationRequired):
                store.commit(
                    ambiguous.token,
                    expected_action=WriteAction.SEND,
                    idempotency_key=ambiguous_key,
                    external_write=must_not_write,
                    now=1001,
                )
            self.assertFalse(replay_called)


if __name__ == "__main__":
    unittest.main()
