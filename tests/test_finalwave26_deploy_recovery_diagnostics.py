# -*- coding: utf-8 -*-
"""FINALWAVE-26-01 diagnostic reproducer for A01-11 recovery durability.

Synthetic same-POSIX-host evidence only. No production/runtime credentials or
private Telegram data are used here.
"""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from ops import deploy_release
from ops.release_guard import SafetyError
from test_audit_round8 import RestartSafeDeploymentTransactionTests


class FinalWave26A011DiagnosticTests(unittest.TestCase):
    def _harness(self) -> RestartSafeDeploymentTransactionTests:
        return RestartSafeDeploymentTransactionTests(
            methodName="test_successful_final_release_is_strict_readonly_except_persistent_binding"
        )

    def _create_backed_up_candidate_active(self, layout) -> None:
        real_switch = deploy_release.atomic_switch_link

        def switch_then_die(*args, **kwargs):
            real_switch(*args, **kwargs)
            raise SystemExit("synthetic process loss after atomic switch")

        with mock.patch.object(
            deploy_release, "verify_approved_ref_policy", return_value=layout["new_sha"]
        ), mock.patch.object(deploy_release, "atomic_switch_link", side_effect=switch_then_die):
            with self.assertRaises(SystemExit):
                deploy_release.execute_prepared_release(**self._harness().kwargs(layout))

        self.assertEqual("BACKED_UP", self._harness().journal(layout)["state"])
        self.assertEqual(layout["new_sha"], deploy_release._active_release_sha(layout["active"]))

    def test_runtime_manifest_ambiguity_strict_transition_exposes_root_cause(self):
        with tempfile.TemporaryDirectory() as td:
            harness = self._harness()
            layout = harness.build_layout(Path(td))
            self._create_backed_up_candidate_active(layout)
            layout["runtime"].write_text(json.dumps({"paths": []}), encoding="utf-8")
            layout["runtime"].chmod(0o600)

            real_transition = deploy_release._transition_transaction

            def strict_terminalization(control_root, journal, state, **extra):
                return real_transition(control_root, journal, state, **extra)

            with mock.patch.object(
                deploy_release, "verify_approved_ref_policy", return_value=layout["new_sha"]
            ), mock.patch.object(
                deploy_release, "_best_effort_transaction", side_effect=strict_terminalization
            ):
                with self.assertRaises(SafetyError):
                    deploy_release.execute_prepared_release(**harness.kwargs(layout))

            journal = harness.journal(layout)
            self.assertEqual("CRITICAL_TRANSACTION_AMBIGUOUS", journal["state"])
            self.assertEqual("runtime_manifest_changed", journal["reason_code"])


if __name__ == "__main__":
    unittest.main()
