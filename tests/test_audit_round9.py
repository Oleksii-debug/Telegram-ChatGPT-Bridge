# -*- coding: utf-8 -*-
"""Audit round 9: single deploy entrypoint, pre-materialization journal, lock and provenance."""
from __future__ import annotations

import json
import os
import signal
import stat
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from ops import deploy_release, release_guard


class Round9Layout:
    repository = "synthetic/round9-transaction"

    def __init__(self, root: Path):
        self.root = root
        self.repo = root / "repo"
        self.repo.mkdir()
        (self.repo / ".git").mkdir()
        self.releases = root / "releases"
        self.releases.mkdir()
        (self.releases / ".prepared").mkdir()
        self.old_sha = "7" * 40
        self.new_sha = "8" * 40
        self.old = self.releases / self.old_sha
        self.old.mkdir()
        (self.old / "code.txt").write_text("old", encoding="utf-8")
        self.state = root / "state"
        (self.state / "var").mkdir(parents=True)
        (self.state / "var/db").write_text("state", encoding="utf-8")
        release_guard.attach_persistent_state(self.old, self.state, ["var"])
        self.active = root / "active"
        self.active.symlink_to(self.old)

        self.prepared = self.releases / ".prepared/candidate"
        self.prepared.mkdir()
        (self.prepared / "code.txt").write_text("new", encoding="utf-8")
        payload = deploy_release._payload_manifest_without_meta(self.prepared)
        self.meta = {
            "schema_version": 2,
            "repository": self.repository,
            "approved_ref": "main",
            "sha": self.new_sha,
            "configured_python_version": "3.11.9",
            "python_version": "3.11.9",
            "source_manifest_sha256": "a" * 64,
            "requirements_lock_sha256": None,
            "requirements_test_lock_sha256": None,
            "payload_manifest_sha256": release_guard.sha256_json(payload),
            "runtime_entries": ["var"],
            "persistent_state_mode": "shared_external",
        }
        self.manifest_hash = release_guard.sha256_json(self.meta)
        release_guard.write_json_atomic(
            self.prepared / deploy_release.PREPARED_META,
            self.meta,
            mode=0o644,
        )

        self.control = root / "control"
        self.control.mkdir()
        self.control.chmod(0o700)
        self.runtime = self.control / "runtime.json"
        self.runtime.write_text(json.dumps({"paths": ["var"]}), encoding="utf-8")
        self.runtime.chmod(0o600)
        for name in ("quiesce", "resume", "restart", "identity", "unauth", "auth"):
            hook = self.control / name
            hook.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            hook.chmod(0o700)
        self.approval = self.control / "approval.json"
        self.write_approval("approval-r9-1", "nonce-r9-1")

    def write_approval(self, approval_id: str, nonce: str) -> None:
        now = datetime.now(timezone.utc)
        payload = {
            "approved": True,
            "approved_sha": self.new_sha,
            "repository": self.repository,
            "approved_ref": "main",
            "release_manifest_sha256": self.manifest_hash,
            "ci_run_id": "round9",
            "audit_id": "audit-round9",
            "approval_id": approval_id,
            "nonce": nonce,
            "issued_at": now.isoformat(),
            "expires_at": (now + timedelta(hours=1)).isoformat(),
            "data_schema_change": False,
        }
        self.approval.write_text(json.dumps(payload), encoding="utf-8")
        self.approval.chmod(0o600)

    def kwargs(self):
        c = self.control
        return dict(
            repo=self.repo,
            prepared_release=self.prepared,
            repository_id=self.repository,
            approved_ref="main",
            ci_run_id="round9",
            audit_id="audit-round9",
            active_link=self.active,
            releases_root=self.releases,
            backup_root=self.root / "backups",
            persistent_state_root=self.state,
            runtime_manifest=self.runtime,
            control_root=c,
            approval_file=self.approval,
            approval_consumption_root=c / "consumed",
            quiesce_hook=c / "quiesce",
            resume_hook=c / "resume",
            restart_hook=c / "restart",
            identity_hook=c / "identity",
            unauth_hook=c / "unauth",
            auth_hook=c / "auth",
            status_file=c / "status.json",
        )

    def journal(self) -> dict:
        return json.loads(
            (self.control / deploy_release.TRANSACTION_JOURNAL).read_text(encoding="utf-8")
        )

    def quarantine(self) -> list[Path]:
        root = self.releases / ".quarantine"
        return list(root.iterdir()) if root.exists() else []


class SingleEntrypointTests(unittest.TestCase):
    def test_only_one_deploy_capable_module_exists(self):
        repo_root = Path(__file__).resolve().parents[1]
        self.assertTrue((repo_root / "ops/deploy_release.py").is_file())
        self.assertFalse((repo_root / "ops/deploy_release_legacy.py").exists())
        self.assertFalse((repo_root / "ops/deployment_hardening.py").exists())
        deploy_defs = []
        for path in (repo_root / "ops").glob("*.py"):
            text = path.read_text(encoding="utf-8")
            if "def execute_prepared_release" in text:
                deploy_defs.append(path.name)
        self.assertEqual(["deploy_release.py"], deploy_defs)
        self.assertEqual("ops.deploy_release", deploy_release._supported_deploy_entrypoint())


class PreMaterializationJournalTests(unittest.TestCase):
    def test_journal_is_persisted_before_materialization(self):
        with tempfile.TemporaryDirectory() as td:
            layout = Round9Layout(Path(td))
            order = []
            real_write = deploy_release._write_transaction_journal
            real_materialize = deploy_release._materialize_final_release

            def write_spy(control, journal):
                order.append("journal:" + str(journal["state"]))
                return real_write(control, journal)

            def materialize_spy(*args, **kwargs):
                order.append("materialize")
                return real_materialize(*args, **kwargs)

            with mock.patch.object(
                deploy_release, "verify_approved_ref_policy", return_value=layout.new_sha
            ), mock.patch.object(
                deploy_release, "_write_transaction_journal", side_effect=write_spy
            ), mock.patch.object(
                deploy_release, "_materialize_final_release", side_effect=materialize_spy
            ):
                self.assertEqual(0, deploy_release.execute_prepared_release(**layout.kwargs()))
            self.assertLess(order.index("journal:MATERIALIZING"), order.index("materialize"))

    def test_hard_loss_after_final_rename_is_reconciled_then_fresh_approval_retries(self):
        with tempfile.TemporaryDirectory() as td:
            layout = Round9Layout(Path(td))
            real_materialize = deploy_release._materialize_final_release

            def materialize_then_die(*args, **kwargs):
                result = real_materialize(*args, **kwargs)
                raise SystemExit("synthetic post-rename process loss")

            with mock.patch.object(
                deploy_release, "verify_approved_ref_policy", return_value=layout.new_sha
            ), mock.patch.object(
                deploy_release, "_materialize_final_release", side_effect=materialize_then_die
            ):
                with self.assertRaises(SystemExit):
                    deploy_release.execute_prepared_release(**layout.kwargs())

            self.assertEqual("MATERIALIZING", layout.journal()["state"])
            self.assertTrue((layout.releases / layout.new_sha).is_dir())
            self.assertEqual(layout.old.resolve(), layout.active.resolve())

            with mock.patch.object(
                deploy_release, "verify_approved_ref_policy", return_value=layout.new_sha
            ):
                with self.assertRaises(release_guard.SafetyError):
                    deploy_release.execute_prepared_release(**layout.kwargs())

            self.assertEqual("PREAPPROVAL_ABORTED", layout.journal()["state"])
            self.assertFalse((layout.releases / layout.new_sha).exists())
            self.assertTrue(layout.quarantine())
            self.assertEqual(layout.old.resolve(), layout.active.resolve())

            layout.write_approval("approval-r9-retry", "nonce-r9-retry")
            with mock.patch.object(
                deploy_release, "verify_approved_ref_policy", return_value=layout.new_sha
            ):
                self.assertEqual(0, deploy_release.execute_prepared_release(**layout.kwargs()))
            self.assertEqual(layout.new_sha, deploy_release._active_release_sha(layout.active))

    def test_runtime_manifest_change_blocks_incomplete_recovery(self):
        with tempfile.TemporaryDirectory() as td:
            layout = Round9Layout(Path(td))
            real_materialize = deploy_release._materialize_final_release

            def materialize_then_die(*args, **kwargs):
                result = real_materialize(*args, **kwargs)
                raise SystemExit("synthetic")

            with mock.patch.object(
                deploy_release, "verify_approved_ref_policy", return_value=layout.new_sha
            ), mock.patch.object(
                deploy_release, "_materialize_final_release", side_effect=materialize_then_die
            ):
                with self.assertRaises(SystemExit):
                    deploy_release.execute_prepared_release(**layout.kwargs())

            (layout.state / "logs").mkdir()
            layout.runtime.write_text(json.dumps({"paths": ["var", "logs"]}), encoding="utf-8")
            with self.assertRaises(release_guard.SafetyError):
                deploy_release.execute_prepared_release(**layout.kwargs())
            self.assertEqual("CRITICAL_TRANSACTION_AMBIGUOUS", layout.journal()["state"])
            self.assertEqual(layout.old.resolve(), layout.active.resolve())


class TransitionGraphTests(unittest.TestCase):
    def build_journal(self, root: Path) -> tuple[Path, dict]:
        control = root / "control"
        control.mkdir()
        control.chmod(0o700)
        now = deploy_release.utc_now_iso()
        entries = ["var"]
        runtime_digest = deploy_release._runtime_manifest_digest(entries)
        marker = "a" * 64
        journal = {
            "schema_version": deploy_release.JOURNAL_SCHEMA_VERSION,
            "durability_contract": deploy_release.DURABILITY_CONTRACT,
            "transaction_id": deploy_release._transaction_id(
                "synthetic/graph", "main", "1" * 40, "2" * 40, "b" * 64,
                runtime_digest, marker
            ),
            "repository": "synthetic/graph",
            "approved_ref": "main",
            "sha": "1" * 40,
            "previous_sha": "2" * 40,
            "release_manifest_sha256": "b" * 64,
            "prepared_payload_sha256": "c" * 64,
            "runtime_manifest_sha256": runtime_digest,
            "runtime_entries": entries,
            "approval_id": "approval-graph",
            "approval_marker_sha256": marker,
            "state": "MATERIALIZING",
            "created_at": now,
            "updated_at": now,
        }
        return control, journal

    def test_skipped_backward_and_terminal_reopen_transitions_fail(self):
        with tempfile.TemporaryDirectory() as td:
            control, journal = self.build_journal(Path(td))
            with self.assertRaises(release_guard.SafetyError):
                deploy_release._transition_transaction(control, journal, "READY_TO_COMMIT")
            materialized = deploy_release._transition_transaction(
                control, journal, "MATERIALIZED"
            )
            with self.assertRaises(release_guard.SafetyError):
                deploy_release._transition_transaction(control, materialized, "MATERIALIZING")
            terminal = deploy_release._transition_transaction(
                control, materialized, "PREAPPROVAL_ABORTED"
            )
            with self.assertRaises(release_guard.SafetyError):
                deploy_release._transition_transaction(control, terminal, "MATERIALIZING")


class ApprovalMarkerValidationTests(unittest.TestCase):
    def make_committed_layout(self, root: Path) -> Round9Layout:
        layout = Round9Layout(root)
        approval = release_guard.load_external_approval(
            layout.approval,
            expected_sha=layout.new_sha,
            expected_repository=layout.repository,
            expected_ref="main",
            expected_manifest_sha256=layout.manifest_hash,
            expected_ci_run_id="round9",
            expected_audit_id="audit-round9",
        )
        journal = deploy_release._new_transaction_journal(
            layout.repository,
            "main",
            layout.new_sha,
            layout.old_sha,
            layout.manifest_hash,
            layout.meta,
            ["var"],
            approval,
        )
        deploy_release._write_transaction_journal(layout.control, journal)
        release_guard.consume_external_approval(approval, layout.control / "consumed")
        return layout

    def marker(self, layout: Round9Layout) -> Path:
        return next((layout.control / "consumed").glob("*.consumed.json"))

    def validate(self, layout: Round9Layout):
        journal = layout.journal()
        return deploy_release._validate_consumed_approval_marker(
            control_root=layout.control,
            consumption_root=layout.control / "consumed",
            journal=journal,
            require_exists=True,
        )

    def test_wrong_approval_id_malformed_broad_mode_and_symlink_fail(self):
        cases = ("wrong-id", "malformed", "broad-mode", "symlink")
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as td:
                layout = self.make_committed_layout(Path(td))
                marker = self.marker(layout)
                if case == "wrong-id":
                    payload = json.loads(marker.read_text(encoding="utf-8"))
                    payload["approval_id"] = "different-approval"
                    marker.write_text(json.dumps(payload), encoding="utf-8")
                elif case == "malformed":
                    marker.write_text("{not-json", encoding="utf-8")
                elif case == "broad-mode":
                    marker.chmod(0o644)
                else:
                    target = marker.with_name("marker-target.json")
                    target.write_text(marker.read_text(encoding="utf-8"), encoding="utf-8")
                    target.chmod(0o600)
                    marker.unlink()
                    marker.symlink_to(target)
                with self.assertRaises(release_guard.SafetyError):
                    self.validate(layout)


class PosixTransactionLockTests(unittest.TestCase):
    @unittest.skipUnless(os.name == "posix", "HOSTiQ deployment locking is POSIX-specific")
    def test_real_subprocess_lock_contention_and_crash_release(self):
        with tempfile.TemporaryDirectory() as td:
            control = Path(td) / "control"
            control.mkdir()
            control.chmod(0o700)
            code = textwrap.dedent(
                """
                import sys, time
                from pathlib import Path
                from ops import deploy_release
                control = Path(sys.argv[1])
                with deploy_release._deployment_lock(control):
                    print('LOCKED', flush=True)
                    time.sleep(60)
                """
            )
            process = subprocess.Popen(
                [sys.executable, "-c", code, str(control)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                cwd=Path(__file__).resolve().parents[1],
            )
            try:
                self.assertEqual("LOCKED", process.stdout.readline().strip())
                with self.assertRaises(release_guard.SafetyError):
                    with deploy_release._deployment_lock(control):
                        pass
                process.kill()
                process.wait(timeout=10)
                with deploy_release._deployment_lock(control):
                    pass
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=10)


class RealNonLiveTransactionIntegrationTests(unittest.TestCase):
    @unittest.skipUnless(sys.version_info[:2] == (3, 11), "real integration requires Python 3.11")
    def test_real_git_prepare_then_execute_and_post_switch_rollback(self):
        for fail_auth in (False, True):
            with self.subTest(fail_auth=fail_auth), tempfile.TemporaryDirectory() as td:
                root = Path(td)
                repo = root / "repo"
                repo.mkdir()
                subprocess.run(["git", "init", "-q", "-b", "main"], cwd=repo, check=True)
                subprocess.run(["git", "config", "user.name", "Round9 Integration"], cwd=repo, check=True)
                subprocess.run(["git", "config", "user.email", "round9@example.invalid"], cwd=repo, check=True)
                (repo / "app.py").write_text("VALUE = 9\n", encoding="utf-8")
                tests = repo / "tests"
                tests.mkdir()
                (tests / "test_smoke.py").write_text(
                    "import unittest\nclass T(unittest.TestCase):\n    def test_ok(self): self.assertEqual(1,1)\n",
                    encoding="utf-8",
                )
                subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
                subprocess.run(["git", "commit", "-qm", "round9 integration"], cwd=repo, check=True)
                sha = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip()

                releases = root / "releases"
                prepared, _meta, manifest_hash = deploy_release.prepare_versioned_release(
                    repo=repo,
                    sha=sha,
                    approved_ref="main",
                    repository_id="synthetic/round9-real",
                    releases_root=releases,
                    python_executable=str(Path(sys.executable).resolve(strict=True)),
                    runtime_entries=["var"],
                )

                old_sha = "9" * 40
                old = releases / old_sha
                old.mkdir()
                (old / "old.py").write_text("OLD = 1\n", encoding="utf-8")
                state = root / "state"
                (state / "var").mkdir(parents=True)
                (state / "var/db").write_text("state", encoding="utf-8")
                release_guard.attach_persistent_state(old, state, ["var"])
                active = root / "active"
                active.symlink_to(old)

                control = root / "control"
                control.mkdir()
                control.chmod(0o700)
                runtime = control / "runtime.json"
                runtime.write_text(json.dumps({"paths": ["var"]}), encoding="utf-8")
                runtime.chmod(0o600)
                for name in ("quiesce", "resume", "restart", "identity", "unauth", "auth"):
                    hook = control / name
                    exit_code = 1 if (name == "auth" and fail_auth) else 0
                    hook.write_text(f"#!/bin/sh\nexit {exit_code}\n", encoding="utf-8")
                    hook.chmod(0o700)
                approval = control / "approval.json"
                now = datetime.now(timezone.utc)
                approval.write_text(json.dumps({
                    "approved": True,
                    "approved_sha": sha,
                    "repository": "synthetic/round9-real",
                    "approved_ref": "main",
                    "release_manifest_sha256": manifest_hash,
                    "ci_run_id": "round9-real",
                    "audit_id": "audit-round9-real",
                    "approval_id": "approval-round9-real",
                    "nonce": "nonce-round9-real",
                    "issued_at": now.isoformat(),
                    "expires_at": (now + timedelta(hours=1)).isoformat(),
                    "data_schema_change": False,
                }), encoding="utf-8")
                approval.chmod(0o600)

                kwargs = dict(
                    repo=repo,
                    prepared_release=prepared,
                    repository_id="synthetic/round9-real",
                    approved_ref="main",
                    ci_run_id="round9-real",
                    audit_id="audit-round9-real",
                    active_link=active,
                    releases_root=releases,
                    backup_root=root / "backups",
                    persistent_state_root=state,
                    runtime_manifest=runtime,
                    control_root=control,
                    approval_file=approval,
                    approval_consumption_root=control / "consumed",
                    quiesce_hook=control / "quiesce",
                    resume_hook=control / "resume",
                    restart_hook=control / "restart",
                    identity_hook=control / "identity",
                    unauth_hook=control / "unauth",
                    auth_hook=control / "auth",
                    status_file=control / "status.json",
                )
                with mock.patch.object(deploy_release, "verify_running_release", return_value=None):
                    rc = deploy_release.execute_prepared_release(**kwargs)
                if fail_auth:
                    self.assertEqual(20, rc)
                    self.assertEqual(old.resolve(), active.resolve())
                    self.assertEqual("ROLLED_BACK", json.loads((control / deploy_release.TRANSACTION_JOURNAL).read_text())["state"])
                else:
                    self.assertEqual(0, rc)
                    self.assertEqual(sha, deploy_release._active_release_sha(active))
                    self.assertEqual("DEPLOYED", json.loads((control / deploy_release.TRANSACTION_JOURNAL).read_text())["state"])


if __name__ == "__main__":
    unittest.main()
