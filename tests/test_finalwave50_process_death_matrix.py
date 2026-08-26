# -*- coding: utf-8 -*-
from __future__ import annotations

import multiprocessing as mp
import os
import tempfile
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
        "files": [{"file_id": "file-a", "sha256": "b" * 64, "size": 12}],
        "caption": "caption",
        "voice_note": False,
    },
}


def _receipt(action: str) -> dict[str, object]:
    count = 2 if action == "FORWARD" else 1
    return {"operation": action, "message_ids": list(range(200, 200 + count)), "count": count}


class DeathStore(FaultHardenedPersistentWriteStore):
    death_point: str = ""

    def _begin_commit(self, *args, **kwargs):
        if self.death_point == "before_reserve":
            os._exit(31)
        result = super()._begin_commit(*args, **kwargs)
        if self.death_point == "after_reserve":
            os._exit(32)
        return result

    def _transition_to_calling(self, *args, **kwargs):
        if self.death_point == "before_calling":
            os._exit(33)
        result = super()._transition_to_calling(*args, **kwargs)
        if self.death_point == "after_calling_before_rpc":
            os._exit(34)
        return result

    def _commit_result(self, *args, **kwargs):
        if self.death_point == "after_receipt_before_committed":
            os._exit(37)
        result = super()._commit_result(*args, **kwargs)
        if self.death_point == "after_committed":
            os._exit(38)
        return result


def _death_worker(
    db_path: str,
    preview_token: str,
    key: str,
    action: str,
    death_point: str,
    rpc_attempts,
    fake_effects,
) -> None:
    store = DeathStore(db_path)
    store.death_point = death_point

    def external(_payload):
        # Entry into external_write is already the potentially mutating RPC boundary
        # from the store's perspective. An invocation-time process death therefore
        # must be treated conservatively even when the synthetic effect counter is 0.
        with rpc_attempts.get_lock():
            rpc_attempts.value += 1
        if death_point == "at_rpc_invocation":
            os._exit(35)
        with fake_effects.get_lock():
            fake_effects.value += 1
        if death_point == "after_fake_effect_before_receipt":
            os._exit(36)
        return _receipt(action)

    store.commit(
        preview_token,
        expected_action=action,
        idempotency_key=key,
        external_write=external,
        now=101,
    )


class FinalWaveProcessDeathMatrixTests(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.root = Path(self.td.name)
        os.chmod(self.root, 0o700)
        self.ctx = mp.get_context("fork")

    def tearDown(self):
        self.td.cleanup()

    def _run_death(self, action: str, death_point: str):
        db = self.root / f"death-{action.lower()}-{death_point}.sqlite3"
        store = FaultHardenedPersistentWriteStore(db)
        preview = store.create_preview(action, ACTIONS[action], now=100)
        key = f"death-{action.lower()}-{death_point}-01"
        attempts = self.ctx.Value("i", 0)
        effects = self.ctx.Value("i", 0)
        worker = self.ctx.Process(
            target=_death_worker,
            args=(str(db), preview.token, key, action, death_point, attempts, effects),
        )
        worker.start()
        worker.join(10)
        self.assertFalse(worker.is_alive(), f"worker hung at {death_point}")
        self.assertNotEqual(0, worker.exitcode)
        return db, preview, key, attempts, effects

    def test_process_death_restart_matrix_all_actions(self):
        safe_resume = {"before_reserve", "after_reserve", "before_calling"}
        ambiguous = {
            "after_calling_before_rpc",
            "at_rpc_invocation",
            "after_fake_effect_before_receipt",
            "after_receipt_before_committed",
        }
        committed = {"after_committed"}
        points = tuple(sorted(safe_resume | ambiguous | committed))

        for action in ACTIONS:
            for point in points:
                with self.subTest(action=action, point=point):
                    db, preview, key, attempts, effects = self._run_death(action, point)
                    restarted = FaultHardenedPersistentWriteStore(db)
                    before = restarted.transaction_state(key)

                    if point in safe_resume:
                        self.assertIn(before, {None, TransactionState.RESERVED.value})

                        def resume_external(_payload):
                            with attempts.get_lock():
                                attempts.value += 1
                            with effects.get_lock():
                                effects.value += 1
                            return _receipt(action)

                        result = restarted.commit(
                            preview.token,
                            expected_action=action,
                            idempotency_key=key,
                            external_write=resume_external,
                            now=102,
                        )
                        self.assertEqual("COMMITTED", result.state)
                        self.assertEqual(1, attempts.value)
                        self.assertEqual(1, effects.value)
                        self.assertEqual(TransactionState.COMMITTED.value, restarted.transaction_state(key))
                        continue

                    if point in ambiguous:
                        self.assertEqual(TransactionState.CALLING.value, before)
                        report = restarted.recover_orphaned_calling(now=90)
                        self.assertEqual(1, report["calling_recovered"])
                        self.assertEqual(TransactionState.AMBIGUOUS.value, restarted.transaction_state(key))
                        prior_attempts = attempts.value
                        prior_effects = effects.value
                        with self.assertRaises((ReconciliationRequired, WriteSafetyError)):
                            restarted.commit(
                                preview.token,
                                expected_action=action,
                                idempotency_key=key,
                                external_write=lambda _payload: self.fail("ambiguous write resent"),
                                now=103,
                            )
                        self.assertEqual(prior_attempts, attempts.value)
                        self.assertEqual(prior_effects, effects.value)
                        self.assertLessEqual(effects.value, 1)
                        continue

                    self.assertIn(point, committed)
                    self.assertEqual(TransactionState.COMMITTED.value, before)
                    self.assertEqual(1, attempts.value)
                    self.assertEqual(1, effects.value)
                    replay = restarted.commit(
                        preview.token,
                        expected_action=action,
                        idempotency_key=key,
                        external_write=lambda _payload: self.fail("committed replay resent"),
                        now=102,
                    )
                    self.assertTrue(replay.idempotent_replay)
                    self.assertEqual(_receipt(action), replay.result)
                    self.assertEqual(1, attempts.value)
                    self.assertEqual(1, effects.value)

    def test_cleanup_after_process_death_never_erases_ambiguous_tombstone(self):
        db, preview, key, attempts, effects = self._run_death(
            "SEND", "after_fake_effect_before_receipt"
        )
        restarted = FaultHardenedPersistentWriteStore(db)
        restarted.recover_orphaned_calling(now=102)
        report = restarted.cleanup(now=999999, expired_preview_grace_seconds=0)
        self.assertEqual(0, report["idempotency_tombstones_deleted"])
        self.assertEqual(TransactionState.AMBIGUOUS.value, restarted.transaction_state(key))
        self.assertEqual(1, attempts.value)
        self.assertEqual(1, effects.value)
        with self.assertRaises((ReconciliationRequired, WriteSafetyError)):
            restarted.commit(
                preview.token,
                expected_action="SEND",
                idempotency_key=key,
                external_write=lambda _payload: self.fail("cleanup re-enabled resend"),
                now=103,
            )


if __name__ == "__main__":
    unittest.main()
