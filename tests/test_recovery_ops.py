# -*- coding: utf-8 -*-
import io
import json
import os
import subprocess
import tarfile
import tempfile
import time
import unittest
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from ops import deploy_release, recovery_capture, release_guard


class ReleaseGuardTests(unittest.TestCase):
    def test_builtin_private_artifacts_are_protected(self):
        protected = (
            "var/session.dat", "nested/var/state.bin", ".env", ".env.production",
            "account.session", "state.sqlite3", "private_config.json", "private.log",
            "cookies.txt", "browser_profile/Default/state.bin",
        )
        for path in protected:
            self.assertTrue(release_guard.is_protected_relative(path), path)
        self.assertFalse(release_guard.is_protected_relative("src/main.py"))
        self.assertTrue(release_guard.is_persistent_relative("var"))
        self.assertFalse(release_guard.is_persistent_relative(".venv"))

    def test_copying_mutable_state_into_release_is_forbidden(self):
        with self.assertRaises(release_guard.SafetyError):
            release_guard.copy_protected_state(Path("live"), Path("release"))

    def test_shared_persistent_state_survives_release_rollback(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); state = root / "state"; (state / "var").mkdir(parents=True)
            (state / "var/runtime.db").write_text("v1", encoding="utf-8")
            old = root / ("1" * 40); new = root / ("2" * 40); old.mkdir(); new.mkdir()
            release_guard.attach_persistent_state(old, state, ["var"])
            release_guard.attach_persistent_state(new, state, ["var"])
            release_guard.validate_persistent_bindings(old, state, ["var"])
            release_guard.validate_persistent_bindings(new, state, ["var"])
            active = root / "active"; active.symlink_to(old)
            previous = release_guard.atomic_switch_link(active, new)
            (active / "var/runtime.db").write_text("post-switch", encoding="utf-8")
            release_guard.restore_link(active, previous)
            self.assertEqual("post-switch", (active / "var/runtime.db").read_text(encoding="utf-8"))
            self.assertEqual((old / "var").resolve(), (new / "var").resolve())

    def test_runtime_manifest_rejects_nonpersistent_paths(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "runtime.json"
            path.write_text(json.dumps({"paths": ["src/main.py"]}), encoding="utf-8")
            with self.assertRaises(release_guard.SafetyError):
                release_guard.load_runtime_manifest(path)

    def test_recovery_topology_rejects_both_overlap_directions(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); app = root / "app"; app.mkdir()
            with self.assertRaises(release_guard.SafetyError):
                release_guard.validate_recovery_topology(app, app / "recovery")
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); recovery = root / "recovery"; app = recovery / "app"; app.mkdir(parents=True)
            with self.assertRaises(release_guard.SafetyError):
                release_guard.validate_recovery_topology(app, recovery)

    def test_topology_rejects_symlink_alias(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); app = root / "app"; app.mkdir(); real = root / "real"; real.mkdir(); alias = root / "alias"
            try:
                alias.symlink_to(real, target_is_directory=True)
            except (OSError, NotImplementedError):
                self.skipTest("symlinks unavailable")
            with self.assertRaises(release_guard.SafetyError):
                release_guard.validate_recovery_topology(app, alias)

    def test_deployment_topology_rejects_release_backup_overlap(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); repo = root / "repo"; repo.mkdir()
            with self.assertRaises(release_guard.SafetyError):
                release_guard.validate_deployment_topology(
                    repo=repo, active_link=root / "active", releases_root=root / "releases",
                    backup_root=root / "releases/backups", persistent_state_root=root / "state",
                    control_root=root / "control",
                )

    def approval_payload(self, *, sha="a" * 40, manifest="b" * 64, schema=False):
        now = datetime.now(timezone.utc)
        return {
            "approved": True,
            "approved_sha": sha,
            "repository": "Oleksii-debug/Telegram-ChatGPT-Bridge",
            "approved_ref": "main",
            "release_manifest_sha256": manifest,
            "ci_run_id": "12345",
            "audit_id": "audit-pass-1",
            "approval_id": "approval-1",
            "nonce": "nonce-1",
            "issued_at": now.isoformat(),
            "expires_at": (now + timedelta(hours=1)).isoformat(),
            "data_schema_change": schema,
        }

    def load_approval(self, path, *, manifest="b" * 64):
        return release_guard.load_external_approval(
            path,
            expected_sha="a" * 40,
            expected_repository="Oleksii-debug/Telegram-ChatGPT-Bridge",
            expected_ref="main",
            expected_manifest_sha256=manifest,
            expected_ci_run_id="12345",
            expected_audit_id="audit-pass-1",
        )

    def test_external_approval_binds_provenance_permissions_freshness_and_one_time_use(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); approval = root / "approval.json"
            approval.write_text(json.dumps(self.approval_payload()), encoding="utf-8"); approval.chmod(0o600)
            payload = self.load_approval(approval)
            consumed = root / "consumed"; marker = release_guard.consume_external_approval(payload, consumed)
            self.assertTrue(marker.is_file())
            with self.assertRaises(release_guard.SafetyError):
                release_guard.consume_external_approval(payload, consumed)
            bad = self.approval_payload(); bad["repository"] = "other/repo"
            approval.write_text(json.dumps(bad), encoding="utf-8"); approval.chmod(0o600)
            with self.assertRaises(release_guard.SafetyError): self.load_approval(approval)

    def test_external_approval_rejects_broad_permissions_stale_or_schema_change(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); approval = root / "approval.json"; payload = self.approval_payload()
            approval.write_text(json.dumps(payload), encoding="utf-8"); approval.chmod(0o644)
            with self.assertRaises(release_guard.SafetyError): self.load_approval(approval)
            old = datetime.now(timezone.utc) - timedelta(days=2)
            payload["issued_at"] = old.isoformat(); payload["expires_at"] = (old + timedelta(hours=1)).isoformat()
            approval.write_text(json.dumps(payload), encoding="utf-8"); approval.chmod(0o600)
            with self.assertRaises(release_guard.SafetyError): self.load_approval(approval)
            payload = self.approval_payload(schema=True); approval.write_text(json.dumps(payload), encoding="utf-8"); approval.chmod(0o600)
            with self.assertRaises(release_guard.SafetyError): self.load_approval(approval)

    def test_backup_retention_removes_archive_and_hash_as_pair(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); backups = []
            for index in range(4):
                archive = root / f"b{index}.tar.gz"; archive.write_bytes(b"x"); Path(str(archive) + ".sha256").write_text("hash\n")
                os.utime(archive, (1000 + index, 1000 + index)); backups.append(archive)
            removed = release_guard.apply_backup_retention(root, last_known_good=backups[0], keep_newest=1)
            self.assertTrue(removed); self.assertTrue(backups[0].exists())
            for item in removed:
                self.assertFalse(Path(item).exists()); self.assertFalse(Path(item + ".sha256").exists())

    def test_stale_staging_cleanup_preserves_active_marker_and_fresh_stage(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); old = root / ".stage_old"; active = root / ".stage_active"; fresh = root / ".stage_fresh"
            for path in (old, active, fresh): path.mkdir()
            (active / "ACTIVE_LOCK").write_text("busy")
            os.utime(old, (1000, 1000)); os.utime(active, (1000, 1000)); os.utime(fresh, (9900, 9900))
            removed = release_guard.cleanup_stale_staging(root, older_than_seconds=1000, now_timestamp=10000)
            self.assertIn(str(old), removed); self.assertTrue(active.exists()); self.assertTrue(fresh.exists())


class RecoveryCaptureTests(unittest.TestCase):
    def make_app(self, root):
        app = root / "app"; app.mkdir(); (app / "main.py").write_text("print('ok')\n", encoding="utf-8")
        (app / "var").mkdir(); (app / "var/runtime.db").write_text("private-runtime", encoding="utf-8")
        return app

    def test_clean_capture_is_private_recovery_only(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); app = self.make_app(root); recovery = root / "recovery"
            status = recovery_capture.capture(app, recovery)
            self.assertEqual("CANDIDATE_READY_FOR_PRIVATE_AUDIT", status["state"])
            self.assertFalse(status["transfer_performed"]); self.assertFalse(status["cron_or_deploy_worker_installed"])
            out = next(recovery.iterdir()); self.assertTrue((out / "PRIVATE_FULL_BACKUP.tar.gz").is_file()); self.assertTrue((out / "PRIVATE_FULL_BACKUP.tar.gz.sha256").is_file()); self.assertTrue((out / "SANITIZED_CANDIDATE_PRIVATE.tar.gz").is_file())

    def test_capture_rejects_overlap_before_writing_backup(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); app = self.make_app(root); recovery = app / "recovery"
            with self.assertRaises(release_guard.SafetyError): recovery_capture.capture(app, recovery)
            self.assertFalse(recovery.exists())

    def test_generic_alias_in_source_blocks_candidate(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); app = self.make_app(root); recovery = root / "recovery"
            alias = "api_" + "hash"; value = "synthetic-generic-1234567890"
            (app / "settings.py").write_text(alias + "=" + repr(value) + "\n", encoding="utf-8")
            status = recovery_capture.capture(app, recovery); self.assertEqual("CONTAMINATED_BLOCKED", status["state"])
            findings = (next(recovery.iterdir()) / "SCAN_FINDINGS_REDACTED.txt").read_text(encoding="utf-8")
            self.assertIn(alias.upper(), findings); self.assertNotIn(value, findings)

    def test_root_logs_and_cookies_are_quarantined_not_exported(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); app = self.make_app(root); recovery = root / "recovery"
            (app / "private.log").write_text("private message body", encoding="utf-8")
            (app / "cookies.txt").write_text("private cookie material", encoding="utf-8")
            status = recovery_capture.capture(app, recovery); self.assertEqual("CANDIDATE_READY_FOR_PRIVATE_AUDIT", status["state"])
            out = next(recovery.iterdir()); manifest = json.loads((out / "CANDIDATE_MANIFEST.json").read_text(encoding="utf-8"))
            excluded = {item["path"] for item in manifest["excluded"]}
            self.assertIn("private.log", excluded); self.assertIn("cookies.txt", excluded)
            self.assertFalse((out / "candidate/private.log").exists()); self.assertFalse((out / "candidate/cookies.txt").exists())

    def test_unknown_non_source_artifact_requires_private_review(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); app = self.make_app(root); recovery = root / "recovery"; (app / "photo.bin").write_bytes(b"binary")
            status = recovery_capture.capture(app, recovery); self.assertEqual("CONTAMINATED_BLOCKED", status["state"])
            self.assertFalse((next(recovery.iterdir()) / "SANITIZED_CANDIDATE_PRIVATE.tar.gz").exists())

    def test_disguised_archive_in_allowed_source_extension_blocks_candidate(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); app = self.make_app(root); recovery = root / "recovery"; variable = "BRIDGE_" + "TOKEN"
            buffer = io.BytesIO()
            with zipfile.ZipFile(buffer, "w") as archive: archive.writestr("config.txt", variable + "=synthetic-zip-1234567890\n")
            (app / "notes.txt").write_bytes(buffer.getvalue())
            self.assertEqual("CONTAMINATED_BLOCKED", recovery_capture.capture(app, recovery)["state"])


class DeployReleaseTests(unittest.TestCase):
    repository_id = "Oleksii-debug/Telegram-ChatGPT-Bridge"
    approved_ref = "main"
    ci_run_id = "12345"
    audit_id = "audit-pass-1"

    def setup_layout(self, root, *, new_sha="2" * 40):
        repo = root / "repo"; repo.mkdir(); (repo / ".git").mkdir()
        releases = root / "releases"; releases.mkdir(); old_sha = "1" * 40; old = releases / old_sha; old.mkdir(); (old / ".venv").mkdir(); (old / "code.txt").write_text("old")
        state = root / "state"; (state / "var").mkdir(parents=True); (state / "var/runtime.db").write_text("old-state")
        release_guard.attach_persistent_state(old, state, ["var"])
        active = root / "active"; active.symlink_to(old)
        new = releases / new_sha; new.mkdir(); (new / ".venv").mkdir(); (new / "code.txt").write_text("new"); release_guard.attach_persistent_state(new, state, ["var"])
        backups = root / "backups"; control = root / "control"; control.mkdir()
        runtime_manifest = control / "runtime.json"; runtime_manifest.write_text(json.dumps({"paths": ["var"]}), encoding="utf-8"); runtime_manifest.chmod(0o600)
        for name in ("quiesce", "restart", "identity", "unauth", "auth"):
            hook = control / name; hook.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8"); hook.chmod(0o700)
        return {"repo": repo, "releases": releases, "old": old, "old_sha": old_sha, "new": new, "new_sha": new_sha, "state": state, "active": active, "backups": backups, "control": control, "runtime_manifest": runtime_manifest}

    def write_approval(self, layout, sha, manifest_hash):
        now = datetime.now(timezone.utc); path = layout["control"] / "approval.json"
        payload = {
            "approved": True, "approved_sha": sha, "repository": self.repository_id,
            "approved_ref": self.approved_ref, "release_manifest_sha256": manifest_hash,
            "ci_run_id": self.ci_run_id, "audit_id": self.audit_id, "approval_id": "approval-1",
            "nonce": "nonce-1", "issued_at": now.isoformat(), "expires_at": (now + timedelta(hours=1)).isoformat(),
            "data_schema_change": False,
        }
        path.write_text(json.dumps(payload), encoding="utf-8"); path.chmod(0o600); return path

    def deploy_kwargs(self, layout, approval):
        return dict(
            repo=layout["repo"], sha=layout["new_sha"], repository_id=self.repository_id,
            approved_ref=self.approved_ref, ci_run_id=self.ci_run_id, audit_id=self.audit_id,
            active_link=layout["active"], releases_root=layout["releases"], backup_root=layout["backups"],
            persistent_state_root=layout["state"], runtime_manifest=layout["runtime_manifest"],
            control_root=layout["control"], approval_file=approval, approval_consumption_root=layout["control"] / "consumed",
            quiesce_hook=layout["control"] / "quiesce", restart_hook=layout["control"] / "restart",
            identity_hook=layout["control"] / "identity", unauth_hook=layout["control"] / "unauth",
            auth_hook=layout["control"] / "auth", status_file=layout["control"] / "status.json",
            python_executable="/usr/bin/python3",
        )

    def patched_build(self, layout, manifest_hash):
        provenance = {"python_version": "3.11.9"}
        return mock.patch.object(deploy_release, "build_versioned_release", return_value=(layout["new"], provenance, manifest_hash))

    def common_patches(self, layout):
        code_backup = layout["backups"] / "code/fake.tar.gz"; state_backup = layout["backups"] / "state/fake.tar.gz"
        return (
            mock.patch.object(deploy_release, "backup_active", return_value=code_backup),
            mock.patch.object(deploy_release, "backup_persistent_state", return_value=state_backup),
            mock.patch.object(deploy_release, "apply_retention", return_value=[]),
            mock.patch.object(deploy_release, "apply_backup_retention", return_value=[]),
            mock.patch.object(deploy_release, "cleanup_stale_staging", return_value=[]),
        )

    def test_post_switch_state_write_survives_code_rollback(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); layout = self.setup_layout(root); manifest_hash = "a" * 64; approval = self.write_approval(layout, layout["new_sha"], manifest_hash)
            def hook_effect(_path, name, **_kwargs):
                if name == "unauthenticated smoke":
                    (layout["active"] / "var/runtime.db").write_text("post-switch-state", encoding="utf-8")
                    raise release_guard.SafetyError("smoke failure")
            patches = self.common_patches(layout)
            with self.patched_build(layout, manifest_hash), patches[0], patches[1], patches[2], patches[3], patches[4], mock.patch.object(deploy_release, "run_private_hook", side_effect=hook_effect), mock.patch.object(deploy_release, "verify_running_release", return_value=None):
                rc = deploy_release.deploy(**self.deploy_kwargs(layout, approval))
            self.assertEqual(20, rc); self.assertEqual(layout["old"].resolve(), layout["active"].resolve())
            self.assertEqual("post-switch-state", (layout["active"] / "var/runtime.db").read_text(encoding="utf-8"))

    def test_restart_failure_forces_rollback_and_rollback_restart(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); layout = self.setup_layout(root); manifest_hash = "b" * 64; approval = self.write_approval(layout, layout["new_sha"], manifest_hash); calls = []
            def hook_effect(_path, name, **_kwargs):
                calls.append(name)
                if name == "restart/reload": raise release_guard.SafetyError("restart failed")
            patches = self.common_patches(layout)
            with self.patched_build(layout, manifest_hash), patches[0], patches[1], patches[2], patches[3], patches[4], mock.patch.object(deploy_release, "run_private_hook", side_effect=hook_effect), mock.patch.object(deploy_release, "verify_running_release", return_value=None):
                rc = deploy_release.deploy(**self.deploy_kwargs(layout, approval))
            self.assertEqual(20, rc); self.assertIn("rollback restart/reload", calls); self.assertEqual(layout["old"].resolve(), layout["active"].resolve())

    def test_rollback_restart_failure_is_critical(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); layout = self.setup_layout(root); manifest_hash = "c" * 64; approval = self.write_approval(layout, layout["new_sha"], manifest_hash)
            def hook_effect(_path, name, **_kwargs):
                if name in {"restart/reload", "rollback restart/reload"}: raise release_guard.SafetyError("restart failed")
            patches = self.common_patches(layout)
            with self.patched_build(layout, manifest_hash), patches[0], patches[1], patches[2], patches[3], patches[4], mock.patch.object(deploy_release, "run_private_hook", side_effect=hook_effect), mock.patch.object(deploy_release, "verify_running_release", return_value=None):
                rc = deploy_release.deploy(**self.deploy_kwargs(layout, approval))
            self.assertEqual(70, rc); self.assertEqual("CRITICAL_ROLLBACK_FAILED", json.loads((layout["control"] / "status.json").read_text())["state"])

    def test_success_requires_restart_identity_then_smokes(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); layout = self.setup_layout(root); manifest_hash = "d" * 64; approval = self.write_approval(layout, layout["new_sha"], manifest_hash); events = []
            def hook_effect(_path, name, **_kwargs): events.append(name)
            def identity_effect(_path, sha): events.append("identity:" + sha)
            patches = self.common_patches(layout)
            with self.patched_build(layout, manifest_hash), patches[0], patches[1], patches[2], patches[3], patches[4], mock.patch.object(deploy_release, "run_private_hook", side_effect=hook_effect), mock.patch.object(deploy_release, "verify_running_release", side_effect=identity_effect):
                rc = deploy_release.deploy(**self.deploy_kwargs(layout, approval))
            self.assertEqual(0, rc); self.assertEqual(layout["new"].resolve(), layout["active"].resolve())
            self.assertLess(events.index("restart/reload"), events.index("identity:" + layout["new_sha"]))
            self.assertLess(events.index("identity:" + layout["new_sha"]), events.index("unauthenticated smoke"))

    def test_private_hook_timeout_is_fail_closed(self):
        with tempfile.TemporaryDirectory() as td:
            hook = Path(td) / "hook"; hook.write_text("#!/bin/sh\nexit 0\n"); hook.chmod(0o700)
            with mock.patch("subprocess.run", side_effect=subprocess.TimeoutExpired([str(hook)], 1)):
                with self.assertRaises(release_guard.SafetyError): deploy_release.run_private_hook(hook, "restart/reload", timeout=1)

    def test_wrong_python_interpreter_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            executable = Path(td) / "python"; executable.write_text("x"); executable.chmod(0o700)
            with mock.patch.object(deploy_release, "command_output", return_value="3.12.1"):
                with self.assertRaises(release_guard.SafetyError): deploy_release.validate_python_311(str(executable))

    def test_missing_required_tests_blocks_staged_release(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); repo = root / "repo"; repo.mkdir(); (repo / ".git").mkdir(); releases = root / "releases"; state = root / "state"; state.mkdir()
            def fake_export(_repo, _sha, destination): (destination / "main.py").write_text("print('x')\n")
            def fake_run(command, **_kwargs):
                if "venv" in command: py = Path(command[-1]) / "bin/python"; py.parent.mkdir(parents=True); py.write_text(""); py.chmod(0o700)
            with mock.patch.object(deploy_release, "validate_python_311", return_value="3.11.9"), mock.patch.object(deploy_release, "git_export", side_effect=fake_export), mock.patch.object(deploy_release, "run", side_effect=fake_run), mock.patch.object(deploy_release, "command_output", return_value="3.11.9"):
                with self.assertRaises(release_guard.SafetyError) as ctx:
                    deploy_release.build_versioned_release(repo=repo, sha="d" * 40, releases_root=releases, python_executable="python3", persistent_state_root=state, runtime_entries=[], repository_id=self.repository_id, approved_ref=self.approved_ref)
            self.assertIn("test suite is absent", str(ctx.exception))

    def test_unlocked_dependency_manifest_blocks_release(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); repo = root / "repo"; repo.mkdir(); (repo / ".git").mkdir(); releases = root / "releases"; state = root / "state"; state.mkdir()
            def fake_export(_repo, _sha, destination):
                (destination / "requirements.txt").write_text("example==1\n"); (destination / "tests").mkdir(); (destination / "tests/test_x.py").write_text("def test_x(): assert True\n")
            with mock.patch.object(deploy_release, "validate_python_311", return_value="3.11.9"), mock.patch.object(deploy_release, "git_export", side_effect=fake_export):
                with self.assertRaises(release_guard.SafetyError) as ctx:
                    deploy_release.build_versioned_release(repo=repo, sha="e" * 40, releases_root=releases, python_executable="python3", persistent_state_root=state, runtime_entries=[], repository_id=self.repository_id, approved_ref=self.approved_ref)
            self.assertIn("requirements.lock", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
