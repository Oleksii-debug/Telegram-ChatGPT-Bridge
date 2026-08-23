from __future__ import annotations

import asyncio
import os
import stat
import tempfile
import unittest
from pathlib import Path

from ops.secure_write_store import SecurePersistentWriteStore
from ops.structured_safe_write import (
    SafeWriteMetadataFailure,
    StructuredSafePersistentWriteStore,
)
from ops.write_safety import (
    ReconciliationRequired,
    TransactionState,
    WriteSafetyError,
)


class FaultingStructuredStore(StructuredSafePersistentWriteStore):
    """Deterministic persistence fault injector; never performs external I/O."""

    def __init__(
        self,
        path: Path,
        *,
        fail_safe_record: bool = False,
        fail_ambiguous_record: bool = False,
        fail_commit_result: bool = False,
    ) -> None:
        self.fail_safe_record = fail_safe_record
        self.fail_ambiguous_record = fail_ambiguous_record
        self.fail_commit_result = fail_commit_result
        super().__init__(path)

    def _record_safe_failure(self, idempotency_key, fingerprint, *, now):
        if self.fail_safe_record:
            raise RuntimeError("synthetic-safe-state-persistence-failure")
        return super()._record_safe_failure(
            idempotency_key, fingerprint, now=now
        )

    def _record_ambiguous(self, idempotency_key, fingerprint, *, now):
        if self.fail_ambiguous_record:
            raise RuntimeError("synthetic-ambiguous-state-persistence-failure")
        return super()._record_ambiguous(
            idempotency_key, fingerprint, now=now
        )

    def _commit_result(self, idempotency_key, fingerprint, result, *, now):
        if self.fail_commit_result:
            raise RuntimeError("synthetic-result-persistence-failure")
        return super()._commit_result(
            idempotency_key, fingerprint, result, now=now
        )


class EffectBoundaryCrashTests(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.root = Path(self.td.name)
        os.chmod(self.root, 0o700)

    def tearDown(self):
        self.td.cleanup()

    @staticmethod
    def _preview(store: StructuredSafePersistentWriteStore):
        return store.create_preview(
            "SEND",
            {"target": "@target_user", "text": "hello"},
            now=100,
        )

    @staticmethod
    def _assert_no_retry_callback(
        testcase: unittest.TestCase,
        store: StructuredSafePersistentWriteStore,
        preview_token: str,
        key: str,
        calls: list[str],
        *,
        now: int,
    ) -> None:
        def forbidden(_payload):
            calls.append("unexpected-retry")
            return {"unexpected": True}

        try:
            store.commit(
                preview_token,
                expected_action="SEND",
                idempotency_key=key,
                external_write=forbidden,
                now=now,
            )
        except (WriteSafetyError, ReconciliationRequired):
            pass
        else:
            testcase.fail("exact retry unexpectedly executed")
        testcase.assertNotIn("unexpected-retry", calls)

    def test_structured_store_includes_secure_filesystem_boundary(self):
        store = StructuredSafePersistentWriteStore(self.root / "writes.sqlite3")
        self.assertIsInstance(store, SecurePersistentWriteStore)
        mode = stat.S_IMODE(os.lstat(store.db_path).st_mode)
        self.assertEqual(0o600, mode)

    def test_failed_safe_persistence_failure_is_not_returned_retryable(self):
        store = FaultingStructuredStore(
            self.root / "safe.sqlite3",
            fail_safe_record=True,
            fail_ambiguous_record=True,
        )
        preview = self._preview(store)
        calls: list[str] = []

        def proven_safe(_payload):
            calls.append("pre-effect-callback")
            raise SafeWriteMetadataFailure(
                "telegram_flood_wait",
                status=429,
                retry_after_seconds=17,
            )

        with self.assertRaises(ReconciliationRequired):
            store.commit(
                preview.token,
                expected_action="SEND",
                idempotency_key="safe-persist-fault-001",
                external_write=proven_safe,
                now=101,
            )

        # The Telegram-side outcome was safe, but FAILED_SAFE could not be
        # persisted. Durable CALLING is conservative and blocks exact retry.
        self.assertEqual(["pre-effect-callback"], calls)
        self.assertEqual(
            TransactionState.CALLING.value,
            store.transaction_state("safe-persist-fault-001"),
        )
        self._assert_no_retry_callback(
            self,
            store,
            preview.token,
            "safe-persist-fault-001",
            calls,
            now=102,
        )

        # Startup recovery may later classify the orphan, still with no resend.
        self.assertEqual(1, store.mark_calling_transaction_ambiguous_on_recovery(now=103))
        self.assertEqual(
            TransactionState.AMBIGUOUS.value,
            store.transaction_state("safe-persist-fault-001"),
        )
        self._assert_no_retry_callback(
            self,
            store,
            preview.token,
            "safe-persist-fault-001",
            calls,
            now=104,
        )

    def test_post_effect_error_with_ambiguous_persistence_failure_never_resends(self):
        store = FaultingStructuredStore(
            self.root / "ambiguous.sqlite3",
            fail_ambiguous_record=True,
        )
        preview = self._preview(store)
        effects: list[str] = []

        def external(_payload):
            effects.append("effect-attempted")
            raise RuntimeError("synthetic-post-effect-timeout")

        with self.assertRaises(ReconciliationRequired):
            store.commit(
                preview.token,
                expected_action="SEND",
                idempotency_key="ambiguous-persist-fault-001",
                external_write=external,
                now=101,
            )
        self.assertEqual(["effect-attempted"], effects)
        self.assertEqual(
            TransactionState.CALLING.value,
            store.transaction_state("ambiguous-persist-fault-001"),
        )
        self._assert_no_retry_callback(
            self,
            store,
            preview.token,
            "ambiguous-persist-fault-001",
            effects,
            now=102,
        )
        self.assertEqual(["effect-attempted"], effects)

    def test_external_success_then_result_persistence_failure_is_ambiguous(self):
        store = FaultingStructuredStore(
            self.root / "result.sqlite3",
            fail_commit_result=True,
        )
        preview = self._preview(store)
        effects: list[str] = []

        def external(_payload):
            effects.append("effect-completed")
            return {"operation": "SEND", "message_ids": [55], "count": 1}

        with self.assertRaises(ReconciliationRequired):
            store.commit(
                preview.token,
                expected_action="SEND",
                idempotency_key="result-persist-fault-001",
                external_write=external,
                now=101,
            )
        self.assertEqual(["effect-completed"], effects)
        self.assertEqual(
            TransactionState.AMBIGUOUS.value,
            store.transaction_state("result-persist-fault-001"),
        )
        self._assert_no_retry_callback(
            self,
            store,
            preview.token,
            "result-persist-fault-001",
            effects,
            now=102,
        )
        self.assertEqual(["effect-completed"], effects)

    def test_cancelled_callback_is_ambiguous_and_exact_retry_never_runs(self):
        store = StructuredSafePersistentWriteStore(self.root / "cancel.sqlite3")
        preview = self._preview(store)
        calls: list[str] = []

        def cancelled(_payload):
            calls.append("callback-entered")
            raise asyncio.CancelledError()

        with self.assertRaises(asyncio.CancelledError):
            store.commit(
                preview.token,
                expected_action="SEND",
                idempotency_key="cancelled-001",
                external_write=cancelled,
                now=101,
            )
        self.assertEqual(["callback-entered"], calls)
        self.assertEqual(
            TransactionState.AMBIGUOUS.value,
            store.transaction_state("cancelled-001"),
        )
        self._assert_no_retry_callback(
            self,
            store,
            preview.token,
            "cancelled-001",
            calls,
            now=102,
        )


if __name__ == "__main__":
    unittest.main()
