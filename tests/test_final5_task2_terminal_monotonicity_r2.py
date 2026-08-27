import tempfile
import unittest
from pathlib import Path
from unittest import mock

from ops.final5_task2_terminal_guard import MonotonicTerminalWriteStore
from ops.write_safety import ReconciliationRequired, TransactionState, WriteAction, WriteSafetyError


class TerminalStateMonotonicityR2Tests(unittest.TestCase):
    def _store(self):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        return MonotonicTerminalWriteStore(Path(td.name) / "writes.sqlite3")

    def test_late_local_fault_after_durable_commit_returns_receipt_and_replay_is_effect_free(self):
        store = self._store()
        preview = store.create_preview(WriteAction.SEND, {"target": "peer", "text": "hello"}, now=100)
        original_commit = store._commit_result
        external_calls = []

        def commit_then_raise(*args, **kwargs):
            original_commit(*args, **kwargs)
            raise RuntimeError("late-local-fault")

        with mock.patch.object(store, "_commit_result", side_effect=commit_then_raise):
            result = store.commit(
                preview.token,
                expected_action=WriteAction.SEND,
                idempotency_key="idem-key-r2-123",
                external_write=lambda payload: (external_calls.append(payload) or {"message_id": 7}),
                now=101,
            )

        self.assertEqual(TransactionState.COMMITTED.value, store.transaction_state("idem-key-r2-123"))
        self.assertEqual({"message_id": 7}, result.result)
        self.assertEqual(1, len(external_calls))

        replay = store.commit(
            preview.token,
            expected_action=WriteAction.SEND,
            idempotency_key="idem-key-r2-123",
            external_write=lambda payload: self.fail("replay must not perform a second external effect"),
            now=102,
        )
        self.assertTrue(replay.idempotent_replay)
        self.assertEqual({"message_id": 7}, replay.result)
        self.assertEqual(1, len(external_calls))

    def test_commit_fault_before_durable_result_becomes_ambiguous_and_replay_is_blocked(self):
        store = self._store()
        preview = store.create_preview(WriteAction.SEND, {"target": "peer", "text": "hello"}, now=100)
        calls = []
        with mock.patch.object(store, "_commit_result", side_effect=RuntimeError("pre-persist-fault")):
            with self.assertRaises(ReconciliationRequired):
                store.commit(
                    preview.token,
                    expected_action=WriteAction.SEND,
                    idempotency_key="idem-key-r2-124",
                    external_write=lambda payload: (calls.append(payload) or {"message_id": 8}),
                    now=101,
                )
        self.assertEqual(1, len(calls))
        self.assertEqual(TransactionState.AMBIGUOUS.value, store.transaction_state("idem-key-r2-124"))
        with self.assertRaises(ReconciliationRequired):
            store.commit(
                preview.token,
                expected_action=WriteAction.SEND,
                idempotency_key="idem-key-r2-124",
                external_write=lambda payload: self.fail("ambiguous replay must not call external effect"),
                now=102,
            )

    def test_reserved_cannot_transition_to_ambiguous(self):
        store = self._store()
        preview = store.create_preview(WriteAction.SEND, {"target": "peer", "text": "hello"}, now=100)
        store.simulate_reserved_crash_for_test(
            preview.token,
            expected_action=WriteAction.SEND,
            idempotency_key="idem-key-r2-125",
            now=101,
        )
        envelope = store.get_preview(preview.token)
        with self.assertRaises(WriteSafetyError) as ctx:
            store._record_ambiguous("idem-key-r2-125", envelope.request_fingerprint, now=102)
        self.assertEqual("illegal_write_state_transition", ctx.exception.code)
        self.assertEqual(TransactionState.RESERVED.value, store.transaction_state("idem-key-r2-125"))

    def test_committed_cannot_transition_to_safe_failure(self):
        store = self._store()
        preview = store.create_preview(WriteAction.SEND, {"target": "peer", "text": "hello"}, now=100)
        result = store.commit(
            preview.token,
            expected_action=WriteAction.SEND,
            idempotency_key="idem-key-r2-126",
            external_write=lambda payload: {"message_id": 9},
            now=101,
        )
        self.assertEqual("COMMITTED", result.state)
        envelope = store.get_preview(preview.token)
        with self.assertRaises(WriteSafetyError) as ctx:
            store._record_safe_failure("idem-key-r2-126", envelope.request_fingerprint, now=102)
        self.assertEqual("illegal_write_state_transition", ctx.exception.code)
        self.assertEqual(TransactionState.COMMITTED.value, store.transaction_state("idem-key-r2-126"))

    def test_calling_can_transition_to_ambiguous(self):
        store = self._store()
        preview = store.create_preview(WriteAction.SEND, {"target": "peer", "text": "hello"}, now=100)
        store.simulate_calling_crash_for_test(
            preview.token,
            expected_action=WriteAction.SEND,
            idempotency_key="idem-key-r2-127",
            now=101,
        )
        envelope = store.get_preview(preview.token)
        store._record_ambiguous("idem-key-r2-127", envelope.request_fingerprint, now=102)
        self.assertEqual(TransactionState.AMBIGUOUS.value, store.transaction_state("idem-key-r2-127"))


if __name__ == "__main__":
    unittest.main()
