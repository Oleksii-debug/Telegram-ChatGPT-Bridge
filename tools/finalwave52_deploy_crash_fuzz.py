# -*- coding: utf-8 -*-
"""FINALWAVE-52 deployment crash/fault-injection falsification oracle.

This is synthetic same-POSIX-host evidence only. It intentionally exercises the
exact FINALWAVE-26-01 (role01) source snapshot selected by the dedicated CI
workflow. A green result means the named unsafe/recovery behaviors were
reproduced; it is not a production PASS and must not be treated as an
integration regression contract after the defects are repaired.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
TESTS = ROOT / "tests"
if str(TESTS) not in sys.path:
    sys.path.insert(0, str(TESTS))

from ops import deploy_release  # noqa: E402
from ops.release_guard import SafetyError  # noqa: E402
from test_audit_round8 import RestartSafeDeploymentTransactionTests  # noqa: E402


ROLE01_EXACT_SHA = "c4a4f2f050cdab8937db97091844884bd1fb8f3f"


class FinalWave52Role01CrashFalsification(unittest.TestCase):
    """Reproduce residual durable-boundary defects on role01 exact head."""

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

    def _reconcile_expect_safety(self, layout) -> None:
        with mock.patch.object(
            deploy_release, "verify_approved_ref_policy", return_value=layout["new_sha"]
        ):
            with self.assertRaises(SafetyError):
                deploy_release.execute_prepared_release(**self._kwargs(layout))

    def test_role01_primary_invalid_runtime_fix_is_real(self):
        """Positive control: role01 closes the canonical #529 failure itself."""
        with tempfile.TemporaryDirectory() as td:
            layout = self._layout(Path(td))
            self._create_backed_up_candidate_active(layout)
            layout["runtime"].write_text(json.dumps({"paths": []}), encoding="utf-8")
            layout["runtime"].chmod(0o600)
            with mock.patch.object(deploy_release, "atomic_switch_link") as switch:
                self._reconcile_expect_safety(layout)
                switch.assert_not_called()
            journal = self._journal(layout)
            self.assertEqual("CRITICAL_TRANSACTION_AMBIGUOUS", journal["state"])
            self.assertEqual("runtime_manifest_changed", journal["reason_code"])

    def test_role01_valid_but_changed_runtime_manifest_also_terminalizes(self):
        """Positive control: semantic change is closed, not only empty/invalid JSON."""
        with tempfile.TemporaryDirectory() as td:
            layout = self._layout(Path(td))
            self._create_backed_up_candidate_active(layout)
            layout["runtime"].write_text(json.dumps({"paths": ["var/other"]}), encoding="utf-8")
            layout["runtime"].chmod(0o600)
            with mock.patch.object(deploy_release, "atomic_switch_link") as switch:
                self._reconcile_expect_safety(layout)
                switch.assert_not_called()
            journal = self._journal(layout)
            self.assertEqual("CRITICAL_TRANSACTION_AMBIGUOUS", journal["state"])
            self.assertEqual("runtime_manifest_changed", journal["reason_code"])

    def test_falsify_role01_fixed_temp_process_loss_permanently_blocks_retry(self):
        """A dead writer leaves .tmp; O_EXCL then prevents every later terminal write."""
        with tempfile.TemporaryDirectory() as td:
            layout = self._layout(Path(td))
            self._create_backed_up_candidate_active(layout)
            layout["runtime"].write_text(json.dumps({"paths": []}), encoding="utf-8")
            layout["runtime"].chmod(0o600)
            real_replace = deploy_release.os.replace

            def die_before_journal_replace(src, dst):
                src_path, dst_path = Path(src), Path(dst)
                if (
                    src_path.name == deploy_release.TRANSACTION_JOURNAL + ".tmp"
                    and dst_path.name == deploy_release.TRANSACTION_JOURNAL
                ):
                    raise SystemExit("synthetic process loss before journal rename")
                return real_replace(src, dst)

            with mock.patch.object(
                deploy_release, "verify_approved_ref_policy", return_value=layout["new_sha"]
            ), mock.patch.object(deploy_release.os, "replace", side_effect=die_before_journal_replace), \
                 mock.patch.object(deploy_release, "atomic_switch_link") as switch:
                with self.assertRaises(SystemExit):
                    deploy_release.execute_prepared_release(**self._kwargs(layout))
                switch.assert_not_called()

            temp = layout["control"] / (deploy_release.TRANSACTION_JOURNAL + ".tmp")
            self.assertTrue(temp.is_file())
            self.assertEqual("BACKED_UP", self._journal(layout)["state"])

            # Falsification: on role01 exact head the stale O_EXCL temp is not
            # reconciled, so an otherwise safe retry cannot persist ambiguity.
            with mock.patch.object(deploy_release, "atomic_switch_link") as switch:
                self._reconcile_expect_safety(layout)
                switch.assert_not_called()
            self.assertTrue(temp.is_file())
            self.assertEqual("BACKED_UP", self._journal(layout)["state"])

    def test_falsify_role01_candidate_restart_dispatch_is_replayed_after_process_loss(self):
        """Restart completed, process died before evidence, recovery dispatches restart again."""
        with tempfile.TemporaryDirectory() as td:
            layout = self._layout(Path(td))
            real_hook = deploy_release.run_private_hook
            restart_dispatches: list[str] = []

            def restart_then_die(hook, label, timeout=60):
                if label == "restart/reload":
                    restart_dispatches.append(label)
                    real_hook(hook, label, timeout=timeout)
                    raise SystemExit("synthetic process loss after candidate restart dispatch")
                return real_hook(hook, label, timeout=timeout)

            with mock.patch.object(
                deploy_release, "verify_approved_ref_policy", return_value=layout["new_sha"]
            ), mock.patch.object(deploy_release, "run_private_hook", side_effect=restart_then_die):
                with self.assertRaises(SystemExit):
                    deploy_release.execute_prepared_release(**self._kwargs(layout))

            self.assertEqual("SWITCHED", self._journal(layout)["state"])
            self.assertEqual(layout["new_sha"], deploy_release._active_release_sha(layout["active"]))
            self.assertEqual(1, len(restart_dispatches))

            def count_recovery_restart(hook, label, timeout=60):
                if "restart/reload" in label:
                    restart_dispatches.append(label)
                return real_hook(hook, label, timeout=timeout)

            with mock.patch.object(
                deploy_release, "verify_approved_ref_policy", return_value=layout["new_sha"]
            ), mock.patch.object(deploy_release, "run_private_hook", side_effect=count_recovery_restart):
                with self.assertRaises(SafetyError):
                    deploy_release.execute_prepared_release(**self._kwargs(layout))

            # Falsification evidence: one physical restart before death + a
            # second automatic restart on recovery from the same durable state.
            self.assertEqual(2, len(restart_dispatches))
            self.assertEqual("DEPLOYED", self._journal(layout)["state"])

    def test_falsify_role01_rollback_restart_dispatch_is_replayed_after_process_loss(self):
        """Rollback restart completed, process died, recovery restarts previous release again."""
        with tempfile.TemporaryDirectory() as td:
            layout = self._layout(Path(td))
            real_hook = deploy_release.run_private_hook
            real_verify = deploy_release.verify_running_release
            rollback_restarts: list[str] = []

            def fail_candidate_identity(identity_hook, expected_sha):
                if expected_sha == layout["new_sha"]:
                    raise SafetyError("synthetic candidate running identity failure")
                return real_verify(identity_hook, expected_sha)

            def rollback_restart_then_die(hook, label, timeout=60):
                if label == "rollback restart/reload":
                    rollback_restarts.append(label)
                    real_hook(hook, label, timeout=timeout)
                    raise SystemExit("synthetic process loss after rollback restart dispatch")
                return real_hook(hook, label, timeout=timeout)

            with mock.patch.object(
                deploy_release, "verify_approved_ref_policy", return_value=layout["new_sha"]
            ), mock.patch.object(
                deploy_release, "verify_running_release", side_effect=fail_candidate_identity
            ), mock.patch.object(
                deploy_release, "run_private_hook", side_effect=rollback_restart_then_die
            ):
                with self.assertRaises(SystemExit):
                    deploy_release.execute_prepared_release(**self._kwargs(layout))

            self.assertEqual("SWITCHED", self._journal(layout)["state"])
            self.assertEqual(layout["old"].resolve(), layout["active"].resolve())
            self.assertEqual(1, len(rollback_restarts))

            def count_rollback_recovery(hook, label, timeout=60):
                if label == "transaction rollback recovery restart/reload":
                    rollback_restarts.append(label)
                return real_hook(hook, label, timeout=timeout)

            with mock.patch.object(
                deploy_release, "verify_approved_ref_policy", return_value=layout["new_sha"]
            ), mock.patch.object(deploy_release, "run_private_hook", side_effect=count_rollback_recovery):
                with self.assertRaises(SafetyError):
                    deploy_release.execute_prepared_release(**self._kwargs(layout))

            self.assertEqual(2, len(rollback_restarts))
            self.assertEqual("ROLLED_BACK", self._journal(layout)["state"])
            self.assertEqual(layout["old"].resolve(), layout["active"].resolve())


if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(FinalWave52Role01CrashFalsification)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if result.wasSuccessful():
        print(
            "FINALWAVE52_ROLE01_FALSIFIED: primary runtime fix proven; "
            "stale journal temp and candidate/rollback restart replay reproduced"
        )
        raise SystemExit(0)
    raise SystemExit(1)
