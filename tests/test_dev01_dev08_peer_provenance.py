from __future__ import annotations

import json
import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from ops import deploy_release, release_guard
from test_audit_round8 import RestartSafeDeploymentTransactionTests


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "integration" / "provenance_v1.json"
SOURCE_SHA = "2916828628a091a9edd8c4992d9db8834ac1ff68"
MERGE_COMMIT = "5e35599cca1162bad9501044dfb6a79fa358e182"
FIRST_PARENT = "4ebfceb153e94840fa046af88cee1131e0705657"
EXACT_PATHS = {
    "docs/DEV08_DEPLOYMENT_RECOVERY_R3.md",
    "ops/dev08_deploy_recovery.py",
}
EXCLUDED_PATHS = {
    "tests/test_dev08_deploy_recovery.py",
    "tools/verify_dev08_r3_provenance.py",
}

REPOSITORY_GIT_AVAILABLE = (ROOT / ".git").exists()
requires_repository_git = unittest.skipUnless(
    REPOSITORY_GIT_AVAILABLE,
    "repository-level peer provenance requires Git metadata; outer canonical CI verifies it before PREPARE",
)


def _git(*args: str) -> str:
    completed = subprocess.run(
        ["git", *args], cwd=ROOT, check=True,
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        text=True, encoding="utf-8",
    )
    return completed.stdout.strip()


def _blob(ref: str, path: str) -> str:
    value = _git("rev-parse", f"{ref}:{path}")
    if len(value) != 40 or any(ch not in "0123456789abcdef" for ch in value):
        raise AssertionError(f"invalid blob identity: {path}")
    return value


class Dev01Dev08PeerProvenanceTests(unittest.TestCase):
    def test_manifest_records_exact_non_authorizing_oracle_sync(self):
        payload = json.loads(MANIFEST.read_text(encoding="utf-8"))
        sync = payload["swarm_integrations"]["DEV08_DEPLOYMENT_RECOVERY_ORACLE"]
        self.assertEqual(48, sync["pr"])
        self.assertEqual(SOURCE_SHA, sync["source_sha"])
        self.assertEqual(MERGE_COMMIT, sync["merge_commit"])
        self.assertEqual(FIRST_PARENT, sync["first_parent"])
        self.assertEqual(EXACT_PATHS, set(sync["exact_blob_paths"]))
        self.assertEqual(EXCLUDED_PATHS, set(sync["excluded_specialist_paths"]))
        self.assertEqual(32646112339, sync["source_validation_run_id"])
        self.assertEqual(97210515630, sync["source_validation_job_id"])
        self.assertFalse(sync["production_runtime_modified"])
        self.assertFalse(sync["production_mutated"])
        self.assertFalse(sync["deployment_authorized"])

    @requires_repository_git
    def test_semantic_merge_parent_order_and_exact_blobs(self):
        self.assertEqual(
            [FIRST_PARENT, SOURCE_SHA],
            _git("show", "-s", "--format=%P", MERGE_COMMIT).split(),
        )
        subprocess.run(
            ["git", "merge-base", "--is-ancestor", MERGE_COMMIT, "HEAD"],
            cwd=ROOT, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        for path in sorted(EXACT_PATHS):
            with self.subTest(path=path):
                self.assertEqual(_blob("HEAD", path), _blob(SOURCE_SHA, path))

    @requires_repository_git
    def test_specialist_test_and_provenance_tool_are_not_blindly_imported(self):
        for path in sorted(EXCLUDED_PATHS):
            with self.subTest(path=path):
                source = subprocess.run(
                    ["git", "cat-file", "-e", f"{SOURCE_SHA}:{path}"],
                    cwd=ROOT, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                )
                head = subprocess.run(
                    ["git", "cat-file", "-e", f"HEAD:{path}"],
                    cwd=ROOT, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                )
                self.assertEqual(0, source.returncode)
                self.assertNotEqual(0, head.returncode)

    def test_classifier_keeps_recovery_non_authorizing_and_narrow(self):
        from ops.dev08_deploy_recovery import classify_deployment_recovery

        good = classify_deployment_recovery(
            journal_state="BACKED_UP",
            active_role="candidate",
            approval_marker_valid=True,
            runtime_manifest_matches=True,
            candidate_verified=True,
            previous_release_available=True,
        )
        self.assertEqual("RECOVER_AS_SWITCHED", good.action)
        self.assertEqual("SWITCHED", good.journal_transition)
        self.assertEqual(
            "AMBIGUOUS",
            classify_deployment_recovery(
                journal_state="BACKED_UP",
                active_role="candidate",
                approval_marker_valid=False,
                runtime_manifest_matches=True,
                candidate_verified=True,
                previous_release_available=True,
            ).action,
        )


class A011AuthoritativeDeploymentRecoveryTests(unittest.TestCase):
    """A01-11 regressions against ops.deploy_release, not the classifier alone.

    These are same-POSIX-host process-loss tests. They deliberately make no
    full power-loss durability or production deployment claim.
    """

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
        """Crash after atomic symlink replacement and before SWITCHED is durable."""
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
            with self.assertRaises(release_guard.SafetyError):
                deploy_release.execute_prepared_release(**self._kwargs(layout))

    def test_a01_11_observed_switch_resumes_normal_post_switch_verification(self):
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
            layout["old"].rename(layout["releases"] / ("7" * 40))
            self._reconcile_once(layout)
            journal = self._journal(layout)
            self.assertEqual("CRITICAL_TRANSACTION_AMBIGUOUS", journal["state"])
            self.assertEqual("previous_release_missing", journal["reason_code"])
            self.assertEqual(layout["new_sha"], deploy_release._active_release_sha(layout["active"]))

    def test_candidate_tamper_rolls_back_without_claiming_state_schema_restore(self):
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

    def test_recovery_switched_journal_write_failure_rolls_back_durably(self):
        with tempfile.TemporaryDirectory() as td:
            layout = self._layout(Path(td))
            self._create_backed_up_candidate_active(layout)
            real_write = deploy_release._write_transaction_journal

            def fail_only_switched(control_root, journal):
                if journal.get("state") == "SWITCHED":
                    raise OSError("synthetic SWITCHED journal persistence failure")
                return real_write(control_root, journal)

            with mock.patch.object(
                deploy_release, "_write_transaction_journal", side_effect=fail_only_switched
            ):
                self._reconcile_once(layout)

            journal = self._journal(layout)
            self.assertEqual("PRELIVE_RECOVERED", journal["state"])
            self.assertEqual("switched_journal_persist_failed", journal["recovery_mode"])
            self.assertEqual(layout["old"].resolve(), layout["active"].resolve())
            self.assertFalse((layout["releases"] / layout["new_sha"]).exists())

    def test_live_switched_journal_write_failure_preserves_rc20_rollback_semantics(self):
        with tempfile.TemporaryDirectory() as td:
            layout = self._layout(Path(td))
            real_write = deploy_release._write_transaction_journal

            def fail_only_switched(control_root, journal):
                if journal.get("state") == "SWITCHED":
                    raise OSError("synthetic live SWITCHED journal persistence failure")
                return real_write(control_root, journal)

            with mock.patch.object(
                deploy_release, "verify_approved_ref_policy", return_value=layout["new_sha"]
            ), mock.patch.object(
                deploy_release, "_write_transaction_journal", side_effect=fail_only_switched
            ):
                rc = deploy_release.execute_prepared_release(**self._kwargs(layout))

            self.assertEqual(20, rc)
            journal = self._journal(layout)
            self.assertEqual("PRELIVE_RECOVERED", journal["state"])
            self.assertEqual("switched_journal_persist_failed", journal["recovery_mode"])
            self.assertEqual(layout["old"].resolve(), layout["active"].resolve())

    def test_deployment_lock_policy_blocks_recovery_before_reconciliation_mutation(self):
        with tempfile.TemporaryDirectory() as td:
            layout = self._layout(Path(td))
            self._create_backed_up_candidate_active(layout)
            lock = layout["control"] / deploy_release.TRANSACTION_LOCK
            lock.chmod(0o644)
            before = dict(self._journal(layout))
            with self.assertRaises(release_guard.SafetyError):
                deploy_release.execute_prepared_release(**self._kwargs(layout))
            self.assertEqual(before, self._journal(layout))
            self.assertEqual(layout["new_sha"], deploy_release._active_release_sha(layout["active"]))
            lock.chmod(0o600)
            self._reconcile_once(layout)
            self.assertEqual("DEPLOYED", self._journal(layout)["state"])

    def test_durable_process_loss_boundary_matrix_reconciles_without_redeploy(self):
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

                with mock.patch.object(
                    deploy_release, "verify_approved_ref_policy", return_value=layout["new_sha"]
                ), mock.patch.object(
                    deploy_release, "_transition_transaction", side_effect=transition_then_die
                ):
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
            with mock.patch.object(
                deploy_release, "verify_approved_ref_policy", return_value=layout["new_sha"]
            ), mock.patch.object(deploy_release, "atomic_switch_link") as switch:
                with self.assertRaises(release_guard.SafetyError):
                    deploy_release.execute_prepared_release(**self._kwargs(layout))
                switch.assert_not_called()
            self.assertEqual("DEPLOYED", self._journal(layout)["state"])


if __name__ == "__main__":
    unittest.main()
