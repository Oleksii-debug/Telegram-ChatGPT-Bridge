# -*- coding: utf-8 -*-
from __future__ import annotations

import multiprocessing as mp
import os
import sqlite3
import tempfile
import threading
import time
import unittest
from pathlib import Path

from ops.write_fault_hardening import FaultHardenedPersistentWriteStore
from ops.write_safety import ReconciliationRequired, TransactionState, WriteSafetyError


ACTIONS = {
    "SEND": {"target": "target-a", "text": "hello"},
    "REPLY": {"target": "target-a", "reply_to_message_id": 7, "text": "hello"},
    "FORWARD": {"source": "source-a", "target": "target-a", "message_ids": [7, 8]},
    "SEND_FILES": {
        "target": "target-a",
        "files": [{"file_id": "file-a", "sha256": "a" * 64, "size": 12}],
        "caption": "caption",
        "voice_note": False,
    },
}


def _result(action: str) -> dict[str, object]:
    count = 2 if action == "FORWARD" else 1
    return {"operation": action, "message_ids": list(range(100, 100 + count)), "count": count}


class FaultPointStore(FaultHardenedPersistentWriteStore):
    fault: str | None = None

    def _begin_commit(self, *args, **kwargs):
        if self.fault == "before_reserve":
            raise RuntimeError("fault-before-reserve")
        result = super()._begin_commit(*args, **kwargs)
        if self.fault == "after_reserve":
            raise RuntimeError("fault-after-reserve")
        return result

    def _transition_to_calling(self, *args, **kwargs):
        if self.fault == "before_calling":
            raise RuntimeError("fault-before-calling")
        result = super()._transition_to_calling(*args, **kwargs)
        if self.fault == "after_calling":
            raise RuntimeError("fault-after-calling")
        return result

    def _commit_result(self, *args, **kwargs):
        if self.fault == "before_committed":
            raise RuntimeError("fault-before-committed")
        result = super()._commit_result(*args, **kwargs)
        if self.fault == "after_committed":
            raise RuntimeError("fault-after-committed")
        return result


class ExitAfterCallingStore(FaultHardenedPersistentWriteStore):
    def _transition_to_calling(self, *args, **kwargs):
        result = super()._transition_to_calling(*args, **kwargs)
        os._exit(23)
        return result


def _crash_after_calling_worker(db_path: str, token: str, key: str, action: str) -> None:
    store = ExitAfterCallingStore(db_path)
    store.commit(
        token,
        expected_action=action,
        idempotency_key=key,
        external_write=lambda _payload: {"unexpected": True},
        now=101,
    )


def _same_key_worker(db_path: str, token: str, key: str, counter, output, hold: float) -> None:
    store = FaultHardenedPersistentWriteStore(db_path)

    def external(_payload):
        with counter.get_lock():
            counter.value += 1
        time.sleep(hold)
        return _result("SEND")

    try:
        result = store.commit(
            token,
            expected_action="SEND",
            idempotency_key=key,
            external_write=external,
            now=101,
        )
        output.put(("ok", result.idempotent_replay))
    except WriteSafetyError as exc:
        output.put(("error", exc.code))


def _bootstrap_worker(db_path: str, barrier, output) -> None:
    """Force the canonical schema SELECT seam; hardening must serialize around it."""
    from ops import write_safety

    real_connect = sqlite3.connect

    class CursorProxy:
        def __init__(self, cursor):
            self.cursor = cursor

        def fetchone(self):
            row = self.cursor.fetchone()
            try:
                barrier.wait(timeout=1.0)
            except threading.BrokenBarrierError:
                pass
            return row

        def __getattr__(self, name):
            return getattr(self.cursor, name)

    class ConnectionProxy:
        def __init__(self, inner):
            object.__setattr__(self, "inner", inner)

        def __getattr__(self, name):
            return getattr(self.inner, name)

        def __setattr__(self, name, value):
            if name == "inner":
                object.__setattr__(self, name, value)
            else:
                setattr(self.inner, name, value)

        def execute(self, sql, *args, **kwargs):
            cursor = self.inner.execute(sql, *args, **kwargs)
            normalized = " ".join(str(sql).lower().split())
            if normalized.startswith("select value from meta where key='schema_version'"):
                return CursorProxy(cursor)
            return cursor

        def executescript(self, script):
            return self.inner.executescript(script)

        def close(self):
            return self.inner.close()

    def instrumented_connect(*args, **kwargs):
        return ConnectionProxy(real_connect(*args, **kwargs))

    write_safety.sqlite3.connect = instrumented_connect
    try:
        FaultHardenedPersistentWriteStore(db_path)
        output.put(("ok", ""))
    except BaseException as exc:
        output.put(("error", type(exc).__name__))


class FinalWaveWriteCrashFuzzTests(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.root = Path(self.td.name)
        os.chmod(self.root, 0o700)
        self.db = self.root / "writes.sqlite3"

    def tearDown(self):
        self.td.cleanup()

    def _preview(self, store, action="SEND", now=100):
        return store.create_preview(action, ACTIONS[action], now=now)

    def _restart(self, db=None):
        return FaultHardenedPersistentWriteStore(db or self.db)

    def _assert_retry_does_not_call(self, store, preview, action, key, calls, now=102):
        def forbidden(_payload):
            calls.append("unexpected-retry")
            return _result(action)

        with self.assertRaises(WriteSafetyError):
            store.commit(
                preview.token,
                expected_action=action,
                idempotency_key=key,
                external_write=forbidden,
                now=now,
            )
        self.assertNotIn("unexpected-retry", calls)

    def test_all_actions_commit_once_and_restart_replay_cached(self):
        for offset, action in enumerate(ACTIONS):
            with self.subTest(action=action):
                db = self.root / f"{action.lower()}.sqlite3"
                store = FaultHardenedPersistentWriteStore(db)
                preview = store.create_preview(action, ACTIONS[action], now=100 + offset * 10)
                calls: list[str] = []

                def external(_payload, action=action):
                    calls.append(action)
                    return _result(action)

                first = store.commit(
                    preview.token,
                    expected_action=action,
                    idempotency_key=f"idem-{action.lower()}-0001",
                    external_write=external,
                    now=101 + offset * 10,
                )
                replay = FaultHardenedPersistentWriteStore(db).commit(
                    preview.token,
                    expected_action=action,
                    idempotency_key=f"idem-{action.lower()}-0001",
                    external_write=lambda _payload: self.fail("replay called external effect"),
                    now=102 + offset * 10,
                )
                self.assertFalse(first.idempotent_replay)
                self.assertTrue(replay.idempotent_replay)
                self.assertEqual(first.result, replay.result)
                self.assertEqual([action], calls)

    def test_full_action_fault_matrix_has_no_duplicate_external_effect(self):
        faults = (
            "before_reserve",
            "after_reserve",
            "before_calling",
            "after_calling",
            "before_committed",
            "after_committed",
        )
        for action_index, action in enumerate(ACTIONS):
            for fault_index, fault in enumerate(faults):
                with self.subTest(action=action, fault=fault):
                    db = self.root / f"matrix-{action.lower()}-{fault}.sqlite3"
                    store = FaultPointStore(db)
                    base_now = 1000 + action_index * 100 + fault_index * 10
                    preview = store.create_preview(action, ACTIONS[action], now=base_now)
                    key = f"matrix-{action.lower()}-{fault}-01"
                    store.fault = fault
                    effects: list[str] = []

                    def external(_payload):
                        effects.append("effect")
                        return _result(action)

                    with self.assertRaises((RuntimeError, ReconciliationRequired)):
                        store.commit(
                            preview.token,
                            expected_action=action,
                            idempotency_key=key,
                            external_write=external,
                            now=base_now + 1,
                        )

                    restarted = FaultHardenedPersistentWriteStore(db)
                    state = restarted.transaction_state(key)
                    if fault == "before_reserve":
                        self.assertIsNone(state)
                        restarted.commit(
                            preview.token,
                            expected_action=action,
                            idempotency_key=key,
                            external_write=external,
                            now=base_now + 2,
                        )
                        self.assertEqual(["effect"], effects)
                    elif fault in {"after_reserve", "before_calling"}:
                        self.assertEqual(TransactionState.RESERVED.value, state)
                        restarted.commit(
                            preview.token,
                            expected_action=action,
                            idempotency_key=key,
                            external_write=external,
                            now=base_now + 2,
                        )
                        self.assertEqual(["effect"], effects)
                    elif fault == "after_calling":
                        self.assertEqual(TransactionState.CALLING.value, state)
                        with self.assertRaises(ReconciliationRequired):
                            restarted.commit(
                                preview.token,
                                expected_action=action,
                                idempotency_key=key,
                                external_write=external,
                                now=base_now + 2,
                            )
                        self.assertEqual([], effects)
                        self.assertEqual(TransactionState.AMBIGUOUS.value, restarted.transaction_state(key))
                    elif fault == "before_committed":
                        self.assertEqual(["effect"], effects)
                        self.assertEqual(TransactionState.AMBIGUOUS.value, state)
                        self._assert_retry_does_not_call(
                            restarted, preview, action, key, effects, now=base_now + 2
                        )
                    else:
                        self.assertEqual(["effect"], effects)
                        self.assertEqual(TransactionState.COMMITTED.value, state)
                        replay = restarted.commit(
                            preview.token,
                            expected_action=action,
                            idempotency_key=key,
                            external_write=lambda _payload: self.fail("post-commit replay resent"),
                            now=base_now + 2,
                        )
                        self.assertTrue(replay.idempotent_replay)
                        self.assertEqual(_result(action), replay.result)

    def test_post_effect_before_receipt_is_ambiguous_for_all_actions(self):
        for action in ACTIONS:
            with self.subTest(action=action):
                db = self.root / f"effect-{action}.sqlite3"
                store = FaultHardenedPersistentWriteStore(db)
                preview = store.create_preview(action, ACTIONS[action], now=100)
                effects: list[str] = []

                def external(_payload):
                    effects.append("effect")
                    raise RuntimeError("synthetic-after-effect-before-receipt")

                with self.assertRaises(ReconciliationRequired):
                    store.commit(
                        preview.token,
                        expected_action=action,
                        idempotency_key=f"effect-{action}-01",
                        external_write=external,
                        now=101,
                    )
                self.assertEqual(["effect"], effects)
                self._assert_retry_does_not_call(
                    FaultHardenedPersistentWriteStore(db),
                    preview,
                    action,
                    f"effect-{action}-01",
                    effects,
                )

    def test_process_death_after_calling_before_rpc_recovers_without_effect(self):
        ctx = mp.get_context("fork")
        for index, action in enumerate(ACTIONS):
            with self.subTest(action=action):
                db = self.root / f"dead-{action}.sqlite3"
                store = FaultHardenedPersistentWriteStore(db)
                preview = store.create_preview(action, ACTIONS[action], now=100)
                key = f"dead-after-calling-{action}-01"
                worker = ctx.Process(
                    target=_crash_after_calling_worker,
                    args=(str(db), preview.token, key, action),
                )
                worker.start()
                worker.join(10)
                self.assertFalse(worker.is_alive())
                self.assertEqual(23, worker.exitcode)
                restarted = FaultHardenedPersistentWriteStore(db)
                report = restarted.recover_orphaned_calling(now=90)
                self.assertEqual(1, report["calling_recovered"])
                self.assertEqual(TransactionState.AMBIGUOUS.value, restarted.transaction_state(key))
                calls: list[str] = []
                self._assert_retry_does_not_call(restarted, preview, action, key, calls, now=103)

    def test_rpc_invocation_exception_is_ambiguous_without_retry(self):
        for action in ACTIONS:
            with self.subTest(action=action):
                db = self.root / f"rpc-{action}.sqlite3"
                store = FaultHardenedPersistentWriteStore(db)
                preview = store.create_preview(action, ACTIONS[action], now=100)
                calls: list[str] = []

                def rpc_invocation(_payload):
                    calls.append("rpc-entered")
                    raise RuntimeError("synthetic-rpc-invocation-fault")

                with self.assertRaises(ReconciliationRequired):
                    store.commit(
                        preview.token,
                        expected_action=action,
                        idempotency_key=f"rpc-invoke-{action}-01",
                        external_write=rpc_invocation,
                        now=101,
                    )
                self.assertEqual(["rpc-entered"], calls)
                self._assert_retry_does_not_call(
                    FaultHardenedPersistentWriteStore(db),
                    preview,
                    action,
                    f"rpc-invoke-{action}-01",
                    calls,
                )

    def test_cleanup_cannot_delete_committed_or_ambiguous_tombstone(self):
        store = FaultHardenedPersistentWriteStore(self.db)
        committed = self._preview(store, now=100)
        store.commit(
            committed.token,
            expected_action="SEND",
            idempotency_key="cleanup-commit-01",
            external_write=lambda _: _result("SEND"),
            now=101,
        )
        ambiguous = store.create_preview("SEND", ACTIONS["SEND"], now=102)
        with self.assertRaises(ReconciliationRequired):
            store.commit(
                ambiguous.token,
                expected_action="SEND",
                idempotency_key="cleanup-ambig-01",
                external_write=lambda _: (_ for _ in ()).throw(RuntimeError("fault")),
                now=103,
            )
        report = store.cleanup(now=999999, expired_preview_grace_seconds=0)
        self.assertEqual(0, report["idempotency_tombstones_deleted"])
        self.assertEqual(TransactionState.COMMITTED.value, store.transaction_state("cleanup-commit-01"))
        self.assertEqual(TransactionState.AMBIGUOUS.value, store.transaction_state("cleanup-ambig-01"))

    def test_two_processes_same_key_external_effect_at_most_once(self):
        ctx = mp.get_context("fork")
        store = FaultHardenedPersistentWriteStore(self.db)
        preview = self._preview(store)
        counter = ctx.Value("i", 0)
        output = ctx.Queue()
        args = (str(self.db), preview.token, "two-process-key-01", counter, output, 0.3)
        first = ctx.Process(target=_same_key_worker, args=args)
        second = ctx.Process(target=_same_key_worker, args=args)
        first.start()
        time.sleep(0.05)
        second.start()
        first.join(10)
        second.join(10)
        self.assertFalse(first.is_alive())
        self.assertFalse(second.is_alive())
        self.assertEqual(0, first.exitcode)
        self.assertEqual(0, second.exitcode)
        results = [output.get(timeout=2), output.get(timeout=2)]
        self.assertEqual(1, counter.value)
        self.assertTrue(any(item[0] == "ok" for item in results))
        self.assertTrue(
            all(item[0] == "ok" or item == ("error", "write_in_progress") for item in results)
        )
        replay = self._restart().commit(
            preview.token,
            expected_action="SEND",
            idempotency_key="two-process-key-01",
            external_write=lambda _: self.fail("replay resent"),
            now=102,
        )
        self.assertTrue(replay.idempotent_replay)

    def test_conflicting_same_idempotency_key_never_calls_second_effect(self):
        store = FaultHardenedPersistentWriteStore(self.db)
        first = self._preview(store, now=100)
        store.commit(
            first.token,
            expected_action="SEND",
            idempotency_key="conflicting-key-01",
            external_write=lambda _: _result("SEND"),
            now=101,
        )
        second = store.create_preview(
            "SEND", {"target": "target-a", "text": "different"}, now=102
        )
        calls: list[str] = []
        with self.assertRaisesRegex(WriteSafetyError, "idempotency_key_conflict"):
            store.commit(
                second.token,
                expected_action="SEND",
                idempotency_key="conflicting-key-01",
                external_write=lambda _: calls.append("effect") or _result("SEND"),
                now=103,
            )
        self.assertEqual([], calls)

    def test_persistent_clock_rollback_fails_closed_but_recovery_runs(self):
        store = FaultHardenedPersistentWriteStore(self.db, backward_skew_seconds=2)
        preview = self._preview(store, now=100)
        with self.assertRaisesRegex(WriteSafetyError, "write_clock_moved_backward"):
            FaultHardenedPersistentWriteStore(self.db, backward_skew_seconds=2).commit(
                preview.token,
                expected_action="SEND",
                idempotency_key="clock-rollback-01",
                external_write=lambda _: self.fail("rollback called effect"),
                now=90,
            )
        report = FaultHardenedPersistentWriteStore(
            self.db, backward_skew_seconds=2
        ).recover_orphaned_calling(now=90)
        self.assertEqual(0, report["calling_recovered"])

    def test_schema_bootstrap_serialized_under_forced_two_process_race(self):
        ctx = mp.get_context("fork")
        barrier = ctx.Barrier(2)
        output = ctx.Queue()
        workers = [
            ctx.Process(target=_bootstrap_worker, args=(str(self.db), barrier, output))
            for _ in range(2)
        ]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join(10)
            self.assertFalse(worker.is_alive())
            self.assertEqual(0, worker.exitcode)
        results = [output.get(timeout=2) for _ in workers]
        self.assertEqual(["ok", "ok"], sorted(item[0] for item in results))


if __name__ == "__main__":
    unittest.main()
