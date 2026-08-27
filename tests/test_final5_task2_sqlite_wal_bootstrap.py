from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from bridge.storage import _configure_sqlite_connection, _sqlite_lock_contention
from ops.structured_safe_write import StructuredSafePersistentWriteStore
from ops.write_safety import PersistentWriteStore, ReconciliationRequired, TransactionState, WriteAction, WriteSafetyError


class _Result:
    def __init__(self, value: str) -> None:
        self.value = value

    def fetchone(self):
        return (self.value,)


class _FakeConnection:
    def __init__(self, actions):
        self.actions = list(actions)
        self.calls: list[str] = []

    def execute(self, sql: str):
        self.calls.append(sql)
        if sql.startswith("PRAGMA busy_timeout="):
            return _Result("ok")
        if sql == "PRAGMA journal_mode=WAL":
            action = self.actions.pop(0)
            if isinstance(action, BaseException):
                raise action
            return _Result(str(action))
        if sql == "PRAGMA synchronous=FULL":
            return _Result("ok")
        raise AssertionError(sql)


def _operational_error(code: int, message: str = "synthetic") -> sqlite3.OperationalError:
    exc = sqlite3.OperationalError(message)
    exc.sqlite_errorcode = code
    return exc


class SQLiteWalBootstrapTests(unittest.TestCase):
    def test_busy_and_locked_codes_are_classified_by_numeric_code(self) -> None:
        self.assertTrue(_sqlite_lock_contention(_operational_error(sqlite3.SQLITE_BUSY)))
        self.assertTrue(_sqlite_lock_contention(_operational_error(sqlite3.SQLITE_LOCKED)))
        self.assertFalse(_sqlite_lock_contention(_operational_error(sqlite3.SQLITE_ERROR, "database is locked")))
        self.assertFalse(_sqlite_lock_contention(sqlite3.OperationalError("database is locked")))

    def test_transient_busy_retries_then_enables_wal(self) -> None:
        connection = _FakeConnection([
            _operational_error(sqlite3.SQLITE_BUSY),
            _operational_error(sqlite3.SQLITE_LOCKED),
            "wal",
        ])
        with mock.patch("bridge.storage.time.sleep") as sleep:
            _configure_sqlite_connection(connection)
        self.assertEqual(connection.calls.count("PRAGMA journal_mode=WAL"), 3)
        self.assertEqual(sleep.call_count, 2)
        self.assertEqual(connection.calls[-1], "PRAGMA synchronous=FULL")

    def test_non_contention_operational_error_fails_without_retry(self) -> None:
        failure = _operational_error(sqlite3.SQLITE_ERROR, "database is locked")
        connection = _FakeConnection([failure])
        with mock.patch("bridge.storage.time.sleep") as sleep:
            with self.assertRaises(sqlite3.OperationalError) as caught:
                _configure_sqlite_connection(connection)
        self.assertIs(caught.exception, failure)
        self.assertEqual(connection.calls.count("PRAGMA journal_mode=WAL"), 1)
        sleep.assert_not_called()

    def test_unexpected_journal_mode_fails_closed(self) -> None:
        connection = _FakeConnection(["delete"])
        with self.assertRaises(sqlite3.OperationalError):
            _configure_sqlite_connection(connection)
        self.assertEqual(connection.calls.count("PRAGMA journal_mode=WAL"), 1)
        self.assertNotIn("PRAGMA synchronous=FULL", connection.calls)

    def test_retry_budget_exhaustion_propagates_lock_error(self) -> None:
        failure = _operational_error(sqlite3.SQLITE_BUSY)
        connection = _FakeConnection([failure])
        with mock.patch("bridge.storage.time.monotonic", side_effect=[10.0, 18.0]):
            with mock.patch("bridge.storage.time.sleep") as sleep:
                with self.assertRaises(sqlite3.OperationalError) as caught:
                    _configure_sqlite_connection(connection)
        self.assertIs(caught.exception, failure)
        self.assertEqual(connection.calls.count("PRAGMA journal_mode=WAL"), 1)
        sleep.assert_not_called()


class WriteTerminalMonotonicityTests(unittest.TestCase):
    def _store(self):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        return PersistentWriteStore(Path(td.name) / "writes.sqlite3")

    def test_late_fault_after_durable_commit_returns_receipt_and_replay_is_effect_free(self) -> None:
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
                idempotency_key="idem-terminal-001",
                external_write=lambda payload: (external_calls.append(payload) or {"message_id": 7}),
                now=101,
            )

        self.assertEqual(TransactionState.COMMITTED.value, store.transaction_state("idem-terminal-001"))
        self.assertEqual({"message_id": 7}, result.result)
        self.assertEqual(1, len(external_calls))

        replay = store.commit(
            preview.token,
            expected_action=WriteAction.SEND,
            idempotency_key="idem-terminal-001",
            external_write=lambda payload: self.fail("replay must not perform a second external effect"),
            now=102,
        )
        self.assertTrue(replay.idempotent_replay)
        self.assertEqual({"message_id": 7}, replay.result)
        self.assertEqual(1, len(external_calls))

    def test_fault_before_durable_result_becomes_ambiguous_and_replay_is_blocked(self) -> None:
        store = self._store()
        preview = store.create_preview(WriteAction.SEND, {"target": "peer", "text": "hello"}, now=100)
        calls = []
        with mock.patch.object(store, "_commit_result", side_effect=RuntimeError("pre-persist-fault")):
            with self.assertRaises(ReconciliationRequired):
                store.commit(
                    preview.token,
                    expected_action=WriteAction.SEND,
                    idempotency_key="idem-terminal-002",
                    external_write=lambda payload: (calls.append(payload) or {"message_id": 8}),
                    now=101,
                )
        self.assertEqual(1, len(calls))
        self.assertEqual(TransactionState.AMBIGUOUS.value, store.transaction_state("idem-terminal-002"))
        with self.assertRaises(ReconciliationRequired):
            store.commit(
                preview.token,
                expected_action=WriteAction.SEND,
                idempotency_key="idem-terminal-002",
                external_write=lambda payload: self.fail("ambiguous replay must not call external effect"),
                now=102,
            )

    def test_reserved_cannot_transition_to_ambiguous(self) -> None:
        store = self._store()
        preview = store.create_preview(WriteAction.SEND, {"target": "peer", "text": "hello"}, now=100)
        store.simulate_reserved_crash_for_test(
            preview.token,
            expected_action=WriteAction.SEND,
            idempotency_key="idem-terminal-003",
            now=101,
        )
        envelope = store.get_preview(preview.token)
        assert envelope is not None
        with self.assertRaises(WriteSafetyError) as ctx:
            store._record_ambiguous("idem-terminal-003", envelope.request_fingerprint, now=102)
        self.assertEqual("illegal_write_state_transition", ctx.exception.code)
        self.assertEqual(TransactionState.RESERVED.value, store.transaction_state("idem-terminal-003"))

    def test_committed_cannot_transition_to_safe_failure(self) -> None:
        store = self._store()
        preview = store.create_preview(WriteAction.SEND, {"target": "peer", "text": "hello"}, now=100)
        result = store.commit(
            preview.token,
            expected_action=WriteAction.SEND,
            idempotency_key="idem-terminal-004",
            external_write=lambda payload: {"message_id": 9},
            now=101,
        )
        self.assertEqual("COMMITTED", result.state)
        envelope = store.get_preview(preview.token)
        assert envelope is not None
        with self.assertRaises(WriteSafetyError) as ctx:
            store._record_safe_failure("idem-terminal-004", envelope.request_fingerprint, now=102)
        self.assertEqual("illegal_write_state_transition", ctx.exception.code)
        self.assertEqual(TransactionState.COMMITTED.value, store.transaction_state("idem-terminal-004"))


class StructuredWriteCommitReceiptTests(unittest.TestCase):
    def _store(self):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        return StructuredSafePersistentWriteStore(Path(td.name) / "writes.sqlite3")

    def test_structured_late_fault_returns_durable_receipt_and_replay_is_effect_free(self) -> None:
        store = self._store()
        preview = store.create_preview(WriteAction.SEND, {"target": "peer:123", "text": "safe test only"}, now=100)
        original_commit = store._commit_result
        effects = []

        def commit_then_raise(*args, **kwargs):
            original_commit(*args, **kwargs)
            raise RuntimeError("synthetic late local fault after durable commit")

        with mock.patch.object(store, "_commit_result", side_effect=commit_then_raise):
            result = store.commit(
                preview.token,
                expected_action=WriteAction.SEND,
                idempotency_key="idem-structured-001",
                external_write=lambda payload: (effects.append(dict(payload)) or {"message_id": 77, "peer_id": "peer:123"}),
                now=101,
            )

        self.assertEqual("COMMITTED", result.state)
        self.assertFalse(result.idempotent_replay)
        self.assertEqual({"message_id": 77, "peer_id": "peer:123"}, result.result)
        self.assertEqual(1, len(effects))
        self.assertEqual(TransactionState.COMMITTED.value, store.transaction_state("idem-structured-001"))

        replay = store.commit(
            preview.token,
            expected_action=WriteAction.SEND,
            idempotency_key="idem-structured-001",
            external_write=lambda payload: self.fail("replay must not repeat external effect"),
            now=102,
        )
        self.assertTrue(replay.idempotent_replay)
        self.assertEqual(result.result, replay.result)
        self.assertEqual(1, len(effects))

    def test_structured_precommit_fault_remains_ambiguous_and_replay_is_blocked(self) -> None:
        store = self._store()
        preview = store.create_preview(WriteAction.SEND, {"target": "peer:123", "text": "safe test only"}, now=100)
        effects = []

        with mock.patch.object(store, "_commit_result", side_effect=RuntimeError("synthetic local fault before durable commit")):
            with self.assertRaises(ReconciliationRequired):
                store.commit(
                    preview.token,
                    expected_action=WriteAction.SEND,
                    idempotency_key="idem-structured-002",
                    external_write=lambda payload: (effects.append(dict(payload)) or {"message_id": 88}),
                    now=101,
                )

        self.assertEqual(1, len(effects))
        self.assertEqual(TransactionState.AMBIGUOUS.value, store.transaction_state("idem-structured-002"))
        with self.assertRaises(ReconciliationRequired):
            store.commit(
                preview.token,
                expected_action=WriteAction.SEND,
                idempotency_key="idem-structured-002",
                external_write=lambda payload: self.fail("ambiguous replay must not repeat external effect"),
                now=102,
            )
        self.assertEqual(1, len(effects))

    def test_structured_missing_matching_receipt_fails_closed_without_terminal_downgrade(self) -> None:
        store = self._store()
        preview = store.create_preview(WriteAction.SEND, {"target": "peer:123", "text": "safe test only"}, now=100)
        original_commit = store._commit_result
        effects = []

        def commit_then_raise(*args, **kwargs):
            original_commit(*args, **kwargs)
            raise RuntimeError("synthetic late local fault after durable commit")

        with mock.patch.object(store, "_commit_result", side_effect=commit_then_raise), mock.patch.object(store, "_durable_committed_result", return_value=None):
            with self.assertRaises(ReconciliationRequired):
                store.commit(
                    preview.token,
                    expected_action=WriteAction.SEND,
                    idempotency_key="idem-structured-003",
                    external_write=lambda payload: (effects.append(dict(payload)) or {"message_id": 99}),
                    now=101,
                )

        self.assertEqual(1, len(effects))
        self.assertEqual(TransactionState.COMMITTED.value, store.transaction_state("idem-structured-003"))
        replay = store.commit(
            preview.token,
            expected_action=WriteAction.SEND,
            idempotency_key="idem-structured-003",
            external_write=lambda payload: self.fail("durable COMMITTED replay must not repeat external effect"),
            now=102,
        )
        self.assertTrue(replay.idempotent_replay)
        self.assertEqual({"message_id": 99}, replay.result)
        self.assertEqual(1, len(effects))


if __name__ == "__main__":
    unittest.main()
