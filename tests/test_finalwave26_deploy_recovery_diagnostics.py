# -*- coding: utf-8 -*-
"""FINALWAVE-26-01 A01-11 authoritative deployment recovery fault matrix.

Synthetic same-POSIX-host evidence only. These tests exercise the real
``ops.deploy_release`` transaction engine; they do not claim production,
power-loss durability, live Telegram behavior, or persistent-state rollback.
"""
from __future__ import annotations

import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from ops import deploy_release
from ops.release_guard import SafetyError
from test_audit_round8 import RestartSafeDeploymentTransactionTests


class FinalWave26A011RecoveryTests(unittest.TestCase):
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
        real_switch = deploy_release.atomic_switch_link

        def switch_then_die(*args, **kwargs):
            real_switch(*args, **kwargs)
            raise SystemExit("synthetic process loss after atomic switch")

        with mock.patch.object(
            deploy_release, "verify_approved_ref_policy", return_value=layout["new_sha"]
        ), mock.patch.object(deploy_release, "atomic_switch_link", side_effect=switch_then_die):
            with self.assertRaises(SystemExit):
                deploy_release.execute_prepared_release(**self._kwargs(layout))

        self.assertEqual("BACKED_UP", self._journal(layout)["state"])
        self.assertEqual(layout["new_sha"], deploy_release._active_release_sha(layout["active"]))
        self.assertEqual(1, len(self._consumed(layout)))

    def _reconcile_once(self, layout) -> None:
        with mock.patch.object(
            deploy_release, "verify_approved_ref_policy", return_value=layout["new_sha"]
        ):
            with self.assertRaises(SafetyError):
                deploy_release.execute_prepared_release(**self._kwargs(layout))

    def test_invalid_runtime_manifest_durably_terminalizes_before_any_redeploy(self):
        with tempfile.TemporaryDirectory() as td:
            layout = self._layout(Path(td))
            self._create_backed_up_candidate_active(layout)
            layout["runtime"].write_text(json.dumps({"paths": []}), encoding="utf-8")
            layout["runtime"].chmod(0o600)

            with mock.patch.object(deploy_release, "atomic_switch_link") as switch:
                self._reconcile_once(layout)
                switch.assert_not_called()

            journal = self._journal(layout)
            self.assertEqual("CRITICAL_TRANSACTION_AMBIGUOUS", journal["state"])
            self.assertEqual("runtime_manifest_changed", journal["reason_code"])

    def test_critical_terminal_writer_failure_is_not_swallowed_and_retry_never_switches(self):
        with tempfile.TemporaryDirectory() as td:
            layout = self._layout(Path(td))
            self._create_backed_up_candidate_active(layout)
            layout["runtime"].write_text(json.dumps({"paths": []}), encoding="utf-8")
            layout["runtime"].chmod(0o600)
            real_write = deploy_release._write_transaction_journal

            def fail_critical(control_root, journal):
                if journal.get("state") == "CRITICAL_TRANSACTION_AMBIGUOUS":
                    raise OSError("synthetic critical journal write failure")
                return real_write(control_root, journal)

            with mock.patch.object(
                deploy_release, "verify_approved_ref_policy", return_value=layout["new_sha"]
            ), mock.patch.object(
                deploy_release, "_write_transaction_journal", side_effect=fail_critical
            ), mock.patch.object(deploy_release, "atomic_switch_link") as switch:
                with self.assertRaises(SafetyError):
                    deploy_release.execute_prepared_release(**self._kwargs(layout))
                switch.assert_not_called()

            self.assertEqual("BACKED_UP", self._journal(layout)["state"])

            with mock.patch.object(deploy_release, "atomic_switch_link") as switch:
                self._reconcile_once(layout)
                switch.assert_not_called()
            self.assertEqual("CRITICAL_TRANSACTION_AMBIGUOUS", self._journal(layout)["state"])

    def test_switched_missing_committed_marker_terminalizes_before_restart_or_smoke(self):
        with tempfile.TemporaryDirectory() as td:
            layout = self._layout(Path(td))
            self._create_backed_up_candidate_active(layout)
            journal = self._journal(layout)
            deploy_release._transition_transaction(layout["control"], journal, "SWITCHED")
            self._consumed(layout)[0].unlink()

            with mock.patch.object(deploy_release, "run_private_hook") as hook, mock.patch.object(
                deploy_release, "atomic_switch_link"
            ) as switch:
                self._reconcile_once(layout)
                hook.assert_not_called()
                switch.assert_not_called()

            journal = self._journal(layout)
            self.assertEqual("CRITICAL_TRANSACTION_AMBIGUOUS", journal["state"])
            self.assertEqual("committed_marker_missing_or_invalid_after_switch", journal["reason_code"])

    def test_active_target_mismatch_durably_terminalizes_without_physical_switch(self):
        with tempfile.TemporaryDirectory() as td:
            layout = self._layout(Path(td))
            self._create_backed_up_candidate_active(layout)
            unexpected = layout["releases"] / ("9" * 40)
            unexpected.mkdir()
            layout["active"].unlink()
            layout["active"].symlink_to(unexpected)

            with mock.patch.object(deploy_release, "atomic_switch_link") as switch:
                self._reconcile_once(layout)
                switch.assert_not_called()

            journal = self._journal(layout)
            self.assertEqual("CRITICAL_TRANSACTION_AMBIGUOUS", journal["state"])
            self.assertEqual("active_target_mismatch", journal["reason_code"])

    def test_dangling_active_target_durably_terminalizes_without_physical_switch(self):
        with tempfile.TemporaryDirectory() as td:
            layout = self._layout(Path(td))
            self._create_backed_up_candidate_active(layout)
            layout["active"].unlink()
            layout["active"].symlink_to(layout["releases"] / ("4" * 40))

            with mock.patch.object(deploy_release, "atomic_switch_link") as switch:
                self._reconcile_once(layout)
                switch.assert_not_called()

            journal = self._journal(layout)
            self.assertEqual("CRITICAL_TRANSACTION_AMBIGUOUS", journal["state"])
            self.assertEqual("active_target_missing", journal["reason_code"])

    def test_journal_transition_fsyncs_file_and_parent_directory(self):
        with tempfile.TemporaryDirectory() as td:
            layout = self._layout(Path(td))
            self._create_backed_up_candidate_active(layout)
            journal = self._journal(layout)
            real_fsync = os.fsync
            with mock.patch.object(deploy_release.os, "fsync", wraps=real_fsync) as fsync:
                deploy_release._transition_transaction(
                    layout["control"], journal, "CRITICAL_TRANSACTION_AMBIGUOUS",
                    reason_code="synthetic_fsync_evidence",
                )
            self.assertGreaterEqual(fsync.call_count, 2)
            self.assertEqual("CRITICAL_TRANSACTION_AMBIGUOUS", self._journal(layout)["state"])

    @unittest.skipIf(deploy_release.fcntl is None, "POSIX flock required")
    def test_lock_contention_blocks_second_recovery_before_any_switch(self):
        with tempfile.TemporaryDirectory() as td:
            layout = self._layout(Path(td))
            self._create_backed_up_candidate_active(layout)
            before = dict(self._journal(layout))
            with deploy_release._deployment_lock(layout["control"]), mock.patch.object(
                deploy_release, "atomic_switch_link"
            ) as switch:
                with self.assertRaises(SafetyError):
                    deploy_release.execute_prepared_release(**self._kwargs(layout))
                switch.assert_not_called()
            self.assertEqual(before, self._journal(layout))

    def test_cli_execute_invalid_runtime_manifest_terminalizes_active_journal(self):
        with tempfile.TemporaryDirectory() as td:
            layout = self._layout(Path(td))
            self._create_backed_up_candidate_active(layout)
            layout["runtime"].write_text(json.dumps({"paths": []}), encoding="utf-8")
            layout["runtime"].chmod(0o600)
            c = layout["control"]
            argv = [
                "execute",
                "--repo", str(layout["repo"]),
                "--repository-id", self._harness().repository,
                "--approved-ref", "main",
                "--releases-root", str(layout["releases"]),
                "--runtime-manifest", str(layout["runtime"]),
                "--control-root", str(c),
                "--prepared-release", str(layout["prepared"]),
                "--ci-run-id", "40",
                "--audit-id", "audit-40",
                "--active-link", str(layout["active"]),
                "--backup-root", str(layout["root"] / "backups"),
                "--persistent-state-root", str(layout["state"]),
                "--approval-file", str(layout["approval"]),
                "--approval-consumption-root", str(c / "consumed"),
                "--quiesce-hook", str(c / "quiesce"),
                "--resume-hook", str(c / "resume"),
                "--restart-hook", str(c / "restart"),
                "--identity-hook", str(c / "identity"),
                "--unauth-smoke-hook", str(c / "unauth"),
                "--auth-smoke-hook", str(c / "auth"),
                "--status-file", str(c / "status.json"),
            ]
            with mock.patch.object(deploy_release, "atomic_switch_link") as switch, \
                 contextlib.redirect_stdout(io.StringIO()):
                rc = deploy_release.main(argv)
                switch.assert_not_called()
            self.assertEqual(2, rc)
            journal = self._journal(layout)
            self.assertEqual("CRITICAL_TRANSACTION_AMBIGUOUS", journal["state"])
            self.assertEqual("runtime_manifest_changed", journal["reason_code"])


if __name__ == "__main__":
    unittest.main()
