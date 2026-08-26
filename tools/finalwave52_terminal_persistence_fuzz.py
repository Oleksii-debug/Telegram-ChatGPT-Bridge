# -*- coding: utf-8 -*-
"""FINALWAVE-52 terminal-persistence falsification for exact role01 source."""
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


class FinalWave52TerminalPersistenceFalsification(unittest.TestCase):
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

    def test_falsify_role01_rc20_can_be_returned_without_durable_rolled_back_state(self):
        """ROLLED_BACK write failure is swallowed, yet execute reports rc20."""
        with tempfile.TemporaryDirectory() as td:
            layout = self._layout(Path(td))
            real_write = deploy_release._write_transaction_journal
            real_hook = deploy_release.run_private_hook

            def fail_auth_smoke(hook, label, timeout=60):
                if label == "authenticated smoke":
                    raise SafetyError("synthetic post-switch auth smoke failure")
                return real_hook(hook, label, timeout=timeout)

            def fail_rolled_back_write(control_root, journal):
                if journal.get("state") == "ROLLED_BACK":
                    raise OSError("synthetic ROLLED_BACK journal persistence failure")
                return real_write(control_root, journal)

            with mock.patch.object(
                deploy_release, "verify_approved_ref_policy", return_value=layout["new_sha"]
            ), mock.patch.object(
                deploy_release, "run_private_hook", side_effect=fail_auth_smoke
            ), mock.patch.object(
                deploy_release, "_write_transaction_journal", side_effect=fail_rolled_back_write
            ):
                rc = deploy_release.execute_prepared_release(**self._kwargs(layout))

            self.assertEqual(20, rc)
            self.assertEqual(layout["old"].resolve(), layout["active"].resolve())
            # Falsification: physical rollback succeeded but durable terminal
            # state did not. The caller nevertheless received the normal rc20.
            self.assertEqual("SWITCHED", self._journal(layout)["state"])

    def test_falsify_role01_rc10_can_be_returned_without_durable_prelive_recovered_state(self):
        """PRELIVE_RECOVERED write failure is swallowed, yet execute reports rc10."""
        with tempfile.TemporaryDirectory() as td:
            layout = self._layout(Path(td))
            real_write = deploy_release._write_transaction_journal

            def fail_backup(*args, **kwargs):
                raise SafetyError("synthetic code backup failure")

            def fail_prelive_terminal_write(control_root, journal):
                if journal.get("state") == "PRELIVE_RECOVERED":
                    raise OSError("synthetic PRELIVE_RECOVERED journal persistence failure")
                return real_write(control_root, journal)

            with mock.patch.object(
                deploy_release, "verify_approved_ref_policy", return_value=layout["new_sha"]
            ), mock.patch.object(
                deploy_release, "backup_active", side_effect=fail_backup
            ), mock.patch.object(
                deploy_release, "_write_transaction_journal", side_effect=fail_prelive_terminal_write
            ):
                rc = deploy_release.execute_prepared_release(**self._kwargs(layout))

            self.assertEqual(10, rc)
            self.assertEqual(layout["old"].resolve(), layout["active"].resolve())
            self.assertEqual("QUIESCED", self._journal(layout)["state"])


if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(FinalWave52TerminalPersistenceFalsification)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if result.wasSuccessful():
        print(
            "FINALWAVE52_TERMINAL_PERSISTENCE_FALSIFIED: role01 returns rc20/rc10 even when "
            "ROLLED_BACK/PRELIVE_RECOVERED are not durably journaled"
        )
        raise SystemExit(0)
    raise SystemExit(1)
