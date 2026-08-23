# -*- coding: utf-8 -*-
"""BURST01-02 regressions for A01-11 deployment transaction recovery.

These tests are local/synthetic. They exercise process-loss on the same POSIX
host/filesystem only; they do not claim power-loss durability or production PASS.
"""
from __future__ import annotations

import json
import os
import shutil
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from ops import deploy_release
from ops.release_guard import SafetyError
from test_audit_round8 import RestartSafeDeploymentTransactionTests


class A011DeploymentRecoveryTests(unittest.TestCase):
    def _harness(self) -> RestartSafeDeploymentTransactionTests:
        return RestartSafeDeploymentTransactionTests(
            methodName="test_successful_final_release_is_strict_readonly_except_persistent_binding"
        )

    def _layout(self, root: Path):
        return self._harness().build_layout(root)

    def _kwargs(self, layout):
        return self._harness().kwargs(layout)

    def _journal(self, layout) -> dict:
        return self._harness().journal(layout)

    def _consumed(self, layout) -> list[Path]:
        return self._harness().consumed(layout)

    def _create_backed_up_candidate_active(self, layout) -> None:
        """Crash after atomic active-link switch but before SWITCHED is durable."""
        real_switch = deploy_release.atomic_switch_link

        def switch_then_die(*args, **kwargs):
            real_switch(*args, **kwargs)
            raise SystemExit("synthetic process loss after atomic switch")

        with mock.patch.object(deploy_release, "verify_approved_ref_policy", return_value=layout["new_sha"]), \
             mock.patch.object(deploy_release, "atomic_switch_link", side_effect=switch_then_die):
            with self.assertRaises(SystemExit):
                deploy_release.execute_prepared_release(**self._kwargs(layout))

        self.assertEqual("BACKED_UP", self._journal(layout)["state"])
        self.assertEqual(layout["new_sha"], deploy_release._active_release_sha(layout["active"]))
        self.assertEqual(1, len(self._consumed(layout)))

    def _reconcile_once(self, layout) -> None:
        with mock.patch.object(deploy_release, "verify_approved_ref_policy", return_value=layout["new_sha"]):
            with self.assertRaises(SafetyError):
                deploy_release.execute_prepared_release(**self._kwargs(layout))

    def test_a01_11_backed_up_candidate_active_recovers_through_normal_post_switch_verification(self):
        with tempfile.TemporaryDirectory() as td:
            layout = self._layout(Path(td))
            self._create_backed_up_candidate_active(layout)
            self._reconcile_once(layout)
            journal = self._journal(layout)
            self.assertEqual("DEPLOYED", journal["state"])
            self.assertEqual("resumed_after_switch", journal["recovery_mode"])
            self.assertEqual(layout["new_sha"], deploy_release._active_release_sha(layout["active"]))

    def test_missing_committed_marker_is_ambiguous_and_never_promotes(self):
        with tempfile.TemporaryDirectory() as td:
            layout = self._layout(Path(td))
            self._create_backed_up_candidate_active(layout)
            self._consumed(layout)[0].unlink()
            self._reconcile_once(layout)
            journal = self._journal(layout)
            self.assertEqual("CRITICAL_TRANSACTION_AMBIGUOUS", journal["state"])
            self.assertEqual("committed_marker_missing", journal["reason_code"])
            self.assertEqual(layout["new_sha"], deploy_release._active_release_sha(layout["active"]))

    def test_tampered_committed_marker_is_ambiguous_and_never_promotes(self):
        with tempfile.TemporaryDirectory() as td:
            layout = self._layout(Path(td))
            self._create_backed_up_candidate_active(layout)
            marker = self._consumed(layout)[0]
            payload = json.loads(marker.read_text(encoding="utf-8"))
            payload["approval_id"] = "wrong-approval"
            marker.write_text(json.dumps(payload), encoding="utf-8")
            marker.chmod(0o600)
            self._reconcile_once(layout)
            journal = self._journal(layout)
            self.assertEqual("CRITICAL_TRANSACTION_AMBIGUOUS", journal["state"])
            self.assertEqual("committed_marker_invalid", journal["reason_code"])
            self.assertEqual(layout["new_sha"], deploy_release._active_release_sha(layout["active"]))

    def test_runtime_manifest_change_is_ambiguous_before_candidate_resume(self):
        with tempfile.TemporaryDirectory() as td:
            layout = self._layout(Path(td))
            self._create_backed_up_candidate_active(layout)
            layout["runtime"].write_text(json.dumps({"paths": []}), encoding="utf-8")
            layout["runtime"].chmod(0o600)
            self._reconcile_once(layout)
            journal = self._journal(layout)
            self.assertEqual("CRITICAL_TRANSACTION_AMBIGUOUS", journal["state"])
            self.assertEqual("runtime_manifest_changed", journal["reason_code"])

    def test_missing_previous_release_is_ambiguous_and_never_blindly_redeploys(self):
        with tempfile.TemporaryDirectory() as td:
            layout = self._layout(Path(td))
            self._create_backed_up_candidate_active(layout)
            shutil.rmtree(layout["old"])
            self._reconcile_once(layout)
            journal = self._journal(layout)
            self.assertEqual("CRITICAL_TRANSACTION_AMBIGUOUS", journal["state"])
            self.assertEqual("previous_release_missing", journal["reason_code"])
            self.assertEqual(layout["new_sha"], deploy_release._active_release_sha(layout["active"]))

    def test_candidate_tamper_rolls_back_and_preserves_shared_state_without_state_restore_claim(self):
        with tempfile.TemporaryDirectory() as td:
            layout = self._layout(Path(td))
            self._create_backed_up_candidate_active(layout)
            state_file = layout["state"] / "var/db"
            state_file.write_text("schema-mutated-after-switch", encoding="utf-8")
            candidate = layout["releases"] / layout["new_sha"] / "code.txt"
            os.chmod(candidate, stat.S_IMODE(candidate.stat().st_mode) | stat.S_IWUSR)
            candidate.write_text("tampered", encoding="utf-8")

            self._reconcile_once(layout)
            journal = self._journal(layout)
            self.assertEqual("PRELIVE_RECOVERED", journal["state"])
            self.assertEqual(layout["old"].resolve(), layout["active"].resolve())
            self.assertEqual("schema-mutated-after-switch", state_file.read_text(encoding="utf-8"))
            self.assertFalse((layout["releases"] / layout["new_sha"]).exists())

    def test_recovery_switched_journal_write_failure_rolls_back_to_previous_durably(self):
        with tempfile.TemporaryDirectory() as td:
            layout = self._layout(Path(td))
            self._create_backed_up_candidate_active(layout)
            real_write = deploy_release._write_transaction_journal

            def fail_only_switched(control_root, journal):
                if journal.get("state") == "SWITCHED":
                    raise OSError("synthetic SWITCHED journal persistence failure")
                return real_write(control_root, journal)

            with mock.patch.object(deploy_release, "_write_transaction_journal", side_effect=fail_only_switched):
                self._reconcile_once(layout)

            journal = self._journal(layout)
            self.assertEqual("PRELIVE_RECOVERED", journal["state"])
            self.assertEqual("switched_journal_persist_failed", journal["recovery_mode"])
            self.assertEqual(layout["old"].resolve(), layout["active"].resolve())
            self.assertFalse((layout["releases"] / layout["new_sha"]).exists())

    def test_live_execution_switched_journal_write_failure_records_truthful_terminal_state(self):
        with tempfile.TemporaryDirectory() as td:
            layout = self._layout(Path(td))
            real_write = deploy_release._write_transaction_journal

            def fail_only_switched(control_root, journal):
                if journal.get("state") == "SWITCHED":
                    raise OSError("synthetic live SWITCHED journal persistence failure")
                return real_write(control_root, journal)

            with mock.patch.object(deploy_release, "verify_approved_ref_policy", return_value=layout["new_sha"]), \
                 mock.patch.object(deploy_release, "_write_transaction_journal", side_effect=fail_only_switched):
                rc = deploy_release.execute_prepared_release(**self._kwargs(layout))

            self.assertEqual(20, rc)
            journal = self._journal(layout)
            self.assertEqual("PRELIVE_RECOVERED", journal["state"])
            self.assertEqual("switched_journal_persist_failed", journal["recovery_mode"])
            self.assertEqual(layout["old"].resolve(), layout["active"].resolve())

    def test_deployment_lock_policy_blocks_recovery_before_any_reconciliation_mutation(self):
        with tempfile.TemporaryDirectory() as td:
            layout = self._layout(Path(td))
            self._create_backed_up_candidate_active(layout)
            lock = layout["control"] / deploy_release.TRANSACTION_LOCK
            lock.chmod(0o644)
            before = dict(self._journal(layout))
            with self.assertRaises(SafetyError):
                deploy_release.execute_prepared_release(**self._kwargs(layout))
            self.assertEqual(before, self._journal(layout))
            self.assertEqual(layout["new_sha"], deploy_release._active_release_sha(layout["active"]))
            lock.chmod(0o600)
            self._reconcile_once(layout)
            self.assertEqual("DEPLOYED", self._journal(layout)["state"])

    def test_durable_state_process_loss_matrix_reconciles_without_blind_redeploy(self):
        expected = {
            "MATERIALIZED": "PREAPPROVAL_ABORTED",
            "READY_TO_COMMIT": "PREAPPROVAL_ABORTED",
            "APPROVAL_COMMITTED": "PRELIVE_RECOVERED",
            "QUIESCED": "PRELIVE_RECOVERED",
            "BACKED_UP": "PRELIVE_RECOVERED",
            "SWITCHED": "DEPLOYED",
            "VERIFIED": "DEPLOYED",
        }
        for crash_state, terminal in expected.items():
            with self.subTest(crash_state=crash_state), tempfile.TemporaryDirectory() as td:
                layout = self._layout(Path(td))
                real_transition = deploy_release._transition_transaction

                def transition_then_die(control_root, journal, state, **extra):
                    result = real_transition(control_root, journal, state, **extra)
                    if state == crash_state:
                        raise SystemExit(f"synthetic process loss after {state}")
                    return result

                with mock.patch.object(deploy_release, "verify_approved_ref_policy", return_value=layout["new_sha"]), \
                     mock.patch.object(deploy_release, "_transition_transaction", side_effect=transition_then_die):
                    with self.assertRaises(SystemExit):
                        deploy_release.execute_prepared_release(**self._kwargs(layout))

                self.assertEqual(crash_state, self._journal(layout)["state"])
                self._reconcile_once(layout)
                self.assertEqual(terminal, self._journal(layout)["state"])

    def test_repeated_recovery_is_terminal_and_does_not_switch_again(self):
        with tempfile.TemporaryDirectory() as td:
            layout = self._layout(Path(td))
            self._create_backed_up_candidate_active(layout)
            self._reconcile_once(layout)
            self.assertEqual("DEPLOYED", self._journal(layout)["state"])
            with mock.patch.object(deploy_release, "verify_approved_ref_policy", return_value=layout["new_sha"]), \
                 mock.patch.object(deploy_release, "atomic_switch_link") as switch:
                with self.assertRaises(SafetyError):
                    deploy_release.execute_prepared_release(**self._kwargs(layout))
                switch.assert_not_called()
            self.assertEqual("DEPLOYED", self._journal(layout)["state"])


if __name__ == "__main__":
    unittest.main()
