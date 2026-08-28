# -*- coding: utf-8 -*-
"""FINALWAVE-52 previous-release tamper falsification for exact role01 source."""
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


class FinalWave52PreviousReleaseFalsification(unittest.TestCase):
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

    def _create_switched_candidate_active(self, layout) -> None:
        real_switch = deploy_release.atomic_switch_link

        def switch_then_die(*args, **kwargs):
            real_switch(*args, **kwargs)
            raise SystemExit("synthetic process loss after atomic switch")

        with mock.patch.object(
            deploy_release, "verify_approved_ref_policy", return_value=layout["new_sha"]
        ), mock.patch.object(deploy_release, "atomic_switch_link", side_effect=switch_then_die):
            with self.assertRaises(SystemExit):
                deploy_release.execute_prepared_release(**self._kwargs(layout))
        journal = self._journal(layout)
        self.assertEqual("BACKED_UP", journal["state"])
        deploy_release._transition_transaction(layout["control"], journal, "SWITCHED")
        self.assertEqual("SWITCHED", self._journal(layout)["state"])
        self.assertEqual(layout["new_sha"], deploy_release._active_release_sha(layout["active"]))
        self.assertEqual(1, len(self._consumed(layout)))

    def test_falsify_role01_switched_candidate_can_be_deployed_with_previous_release_missing(self):
        """Healthy candidate becomes DEPLOYED although automated rollback target vanished."""
        with tempfile.TemporaryDirectory() as td:
            layout = self._layout(Path(td))
            self._create_switched_candidate_active(layout)
            deploy_release._force_remove_tree(layout["old"])
            self.assertFalse(layout["old"].exists())

            with mock.patch.object(
                deploy_release, "verify_approved_ref_policy", return_value=layout["new_sha"]
            ):
                with self.assertRaises(SafetyError):
                    deploy_release.execute_prepared_release(**self._kwargs(layout))

            self.assertEqual("DEPLOYED", self._journal(layout)["state"])
            self.assertFalse(layout["old"].exists())
            self.assertEqual(layout["new_sha"], deploy_release._active_release_sha(layout["active"]))

    def test_falsify_role01_rollback_accepts_tampered_previous_release_without_provenance_check(self):
        """Rollback restores a same-name previous tree whose code bytes were modified."""
        with tempfile.TemporaryDirectory() as td:
            layout = self._layout(Path(td))
            self._create_switched_candidate_active(layout)
            previous_code = layout["old"] / "code.txt"
            previous_code.chmod(0o600)
            previous_code.write_text("tampered-previous-release", encoding="utf-8")

            with mock.patch.object(
                deploy_release, "verify_approved_ref_policy", return_value=layout["new_sha"]
            ), mock.patch.object(
                deploy_release, "_verify_journal_candidate",
                side_effect=SafetyError("synthetic candidate verification failure")
            ):
                with self.assertRaises(SafetyError):
                    deploy_release.execute_prepared_release(**self._kwargs(layout))

            self.assertEqual("ROLLED_BACK", self._journal(layout)["state"])
            self.assertEqual(layout["old"].resolve(), layout["active"].resolve())
            self.assertEqual("tampered-previous-release", previous_code.read_text(encoding="utf-8"))


if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(FinalWave52PreviousReleaseFalsification)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if result.wasSuccessful():
        print(
            "FINALWAVE52_PREVIOUS_RELEASE_FALSIFIED: role01 can terminalize DEPLOYED without "
            "an available previous release and can roll back to an unverified tampered previous tree"
        )
        raise SystemExit(0)
    raise SystemExit(1)
