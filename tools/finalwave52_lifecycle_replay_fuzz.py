# -*- coding: utf-8 -*-
"""FINALWAVE-52 lifecycle-hook replay falsification for exact role01 source."""
from __future__ import annotations

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


class FinalWave52LifecycleReplayFalsification(unittest.TestCase):
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

    def test_falsify_role01_verified_recovery_replays_completed_restart_and_resume(self):
        """VERIFIED proves lifecycle completion, yet recovery repeats mutating hooks."""
        with tempfile.TemporaryDirectory() as td:
            layout = self._layout(Path(td))
            real_transition = deploy_release._transition_transaction
            real_hook = deploy_release.run_private_hook
            restarts: list[str] = []
            resumes: list[str] = []

            def count_hook(hook, label, timeout=60):
                if "restart/reload" in label:
                    restarts.append(label)
                if "resume/unquiesce" in label:
                    resumes.append(label)
                return real_hook(hook, label, timeout=timeout)

            def transition_then_die(control_root, journal, state, **extra):
                result = real_transition(control_root, journal, state, **extra)
                if state == "VERIFIED":
                    raise SystemExit("synthetic process loss after durable VERIFIED")
                return result

            with mock.patch.object(
                deploy_release, "verify_approved_ref_policy", return_value=layout["new_sha"]
            ), mock.patch.object(
                deploy_release, "run_private_hook", side_effect=count_hook
            ), mock.patch.object(
                deploy_release, "_transition_transaction", side_effect=transition_then_die
            ):
                with self.assertRaises(SystemExit):
                    deploy_release.execute_prepared_release(**self._kwargs(layout))

            self.assertEqual("VERIFIED", self._journal(layout)["state"])
            self.assertEqual(1, len(restarts))
            self.assertEqual(1, len(resumes))

            with mock.patch.object(
                deploy_release, "verify_approved_ref_policy", return_value=layout["new_sha"]
            ), mock.patch.object(deploy_release, "run_private_hook", side_effect=count_hook):
                with self.assertRaises(SafetyError):
                    deploy_release.execute_prepared_release(**self._kwargs(layout))

            # A durable VERIFIED state already proves these two mutating hooks
            # completed. Role01 nevertheless dispatches both a second time.
            self.assertEqual(2, len(restarts))
            self.assertEqual(2, len(resumes))
            self.assertEqual("DEPLOYED", self._journal(layout)["state"])

    def test_falsify_role01_prelive_recovery_restart_is_replayed_after_process_loss(self):
        """Recovery restart completes, process dies, same active state restarts again."""
        with tempfile.TemporaryDirectory() as td:
            layout = self._layout(Path(td))
            real_hook = deploy_release.run_private_hook
            recovery_restarts: list[str] = []

            def fail_backup(*args, **kwargs):
                raise SafetyError("synthetic backup failure after quiesce")

            def prelive_restart_then_die(hook, label, timeout=60):
                if label == "prelive recovery restart/reload":
                    recovery_restarts.append(label)
                    real_hook(hook, label, timeout=timeout)
                    raise SystemExit("synthetic process loss after prelive recovery restart")
                return real_hook(hook, label, timeout=timeout)

            with mock.patch.object(
                deploy_release, "verify_approved_ref_policy", return_value=layout["new_sha"]
            ), mock.patch.object(
                deploy_release, "backup_active", side_effect=fail_backup
            ), mock.patch.object(
                deploy_release, "run_private_hook", side_effect=prelive_restart_then_die
            ):
                with self.assertRaises(SystemExit):
                    deploy_release.execute_prepared_release(**self._kwargs(layout))

            self.assertEqual("QUIESCED", self._journal(layout)["state"])
            self.assertEqual(layout["old"].resolve(), layout["active"].resolve())
            self.assertEqual(1, len(recovery_restarts))

            def count_retry(hook, label, timeout=60):
                if label == "pre-switch transaction recovery restart/reload":
                    recovery_restarts.append(label)
                return real_hook(hook, label, timeout=timeout)

            with mock.patch.object(
                deploy_release, "verify_approved_ref_policy", return_value=layout["new_sha"]
            ), mock.patch.object(deploy_release, "run_private_hook", side_effect=count_retry):
                with self.assertRaises(SafetyError):
                    deploy_release.execute_prepared_release(**self._kwargs(layout))

            self.assertEqual(2, len(recovery_restarts))
            self.assertEqual("PRELIVE_RECOVERED", self._journal(layout)["state"])
            self.assertEqual(layout["old"].resolve(), layout["active"].resolve())


if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(FinalWave52LifecycleReplayFalsification)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if result.wasSuccessful():
        print(
            "FINALWAVE52_LIFECYCLE_REPLAY_FALSIFIED: durable VERIFIED and prelive "
            "recovery paths replay mutating restart/resume hooks"
        )
        raise SystemExit(0)
    raise SystemExit(1)
