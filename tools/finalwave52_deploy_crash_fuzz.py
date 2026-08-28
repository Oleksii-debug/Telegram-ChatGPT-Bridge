# -*- coding: utf-8 -*-
"""FINALWAVE-52 deployment crash/fault-injection falsification oracle.

Synthetic same-POSIX-host evidence only. The dedicated workflow overlays this
oracle onto the exact role01 source snapshot below. A green result means the
remaining restart replay defects were reproduced; it is not production PASS.
"""
from __future__ import annotations

import json
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


ROLE01_EXACT_SHA = "cf2e56a0ed8cd1321a7c989232ad11b559d0062c"


class FinalWave52Role01CrashFalsification(unittest.TestCase):
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

    def test_role01_unique_journal_temp_no_longer_blocks_on_unrelated_stale_temp(self):
        """Positive control for the later role01 repair that superseded FW52-H1."""
        with tempfile.TemporaryDirectory() as td:
            layout = self._layout(Path(td))
            self._create_backed_up_candidate_active(layout)
            stale = layout["control"] / (deploy_release.TRANSACTION_JOURNAL + ".tmp.stale")
            stale.write_text("stale synthetic temp\n", encoding="utf-8")
            stale.chmod(0o600)
            journal = self._journal(layout)
            deploy_release._transition_transaction(
                layout["control"], journal, "CRITICAL_TRANSACTION_AMBIGUOUS",
                reason_code="synthetic_stale_temp_positive_control",
            )
            self.assertTrue(stale.exists())
            self.assertEqual("CRITICAL_TRANSACTION_AMBIGUOUS", self._journal(layout)["state"])

    def test_falsify_role01_candidate_restart_dispatch_is_replayed_after_process_loss(self):
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

            self.assertEqual(2, len(restart_dispatches))
            self.assertEqual("DEPLOYED", self._journal(layout)["state"])

    def test_falsify_role01_rollback_restart_dispatch_is_replayed_after_process_loss(self):
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
            "FINALWAVE52_ROLE01_FALSIFIED: runtime/control-plane/temp repairs proven; "
            "candidate and rollback restart replay remain reproducible"
        )
        raise SystemExit(0)
    raise SystemExit(1)
