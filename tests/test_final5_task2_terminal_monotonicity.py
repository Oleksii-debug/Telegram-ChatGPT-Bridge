import tempfile
import unittest
from pathlib import Path
from unittest import mock

from ops.final5_task2_terminal_guard import MonotonicTerminalWriteStore
from ops.write_safety import ReconciliationRequired, TransactionState, WriteAction, WriteSafetyError


class TerminalStateMonotonicityTests(unittest.TestCase):
    def _store(self):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        return MonotonicTerminalWriteStore(Path(td.name) / "writes.sqlite3")

    def test_late_local_fault_after_durable_commit_does_not_downgrade(self):
        store = self._store()
        preview = store.create_preview(WriteAction.SEND, {"target": "peer", "text": "hello"}, now=100)
        original_commit = store._commit_result

        def commit_then_raise(*args, **kwargs):
            original_commit(*args, **kwargs)
            raise RuntimeError("late-local-fault")

        with mock.patch.object(store, "_commit_result", side_effect=commit_then_raise):
            with self.assertRaises(ReconciliationRequired):
                store.commit(
                    preview.token,
                    expected_action=WriteAction.SEND,
                    idempotency_key="idem-key-123",
                    external_write=lambda payload: {"message_id": 7},
                    now=101,
                )

        self.assertEqual(TransactionState.COMMITTED.value, store.transaction_state("idem-key-123"))
        replay = store.commit(
            preview.token,
            expected_action=WriteAction.SEND,
            idempotency_key="idem-key-123",
            external_write=lambda payload: self.fail("replay must not call external effect"),
            now=102,
        )
        self.assertTrue(replay.idempotent_replay)
        self.assertEqual({"message_id": 7}, replay.result)

    def test_calling_state_can_be_marked_ambiguous(self):
        store = self._store()
        preview = store.create_preview(WriteAction.SEND, {"target": "peer", "text": "hello"}, now=100)
        store.simulate_calling_crash_for_test(
            preview.token,
            expected_action=WriteAction.SEND,
            idempotency_key="idem-key-456",
            now=101,
        )
        envelope = store.get_preview(preview.token)
        store._record_ambiguous("idem-key-456", envelope.request_fingerprint, now=102)
        self.assertEqual(TransactionState.AMBIGUOUS.value, store.transaction_state("idem-key-456"))

    def test_reserved_state_cannot_be_promoted_to_ambiguous(self):
        store = self._store()
        preview = store.create_preview(WriteAction.SEND, {"target": "peer", "text": "hello"}, now=100)
        store.simulate_reserved_crash_for_test(
            preview.token,
            expected_action=WriteAction.SEND,
            idempotency_key="idem-key-789",
            now=101,
        )
        envelope = store.get_preview(preview.token)
        with self.assertRaises(WriteSafetyError) as ctx:
            store._record_ambiguous("idem-key-789", envelope.request_fingerprint, now=102)
        self.assertEqual("illegal_write_state_transition", ctx.exception.code)
        self.assertEqual(TransactionState.RESERVED.value, store.transaction_state("idem-key-789"))


if __name__ == "__main__":
    unittest.main()
