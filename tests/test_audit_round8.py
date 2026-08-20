# -*- coding: utf-8 -*-
"""Audit round 8: restart-safe deployment journal, strict immutability and test-lock symmetry."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from ops import deploy_release, release_guard


def _wheel_record_line(path: str, data: bytes) -> str:
    digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).decode("ascii").rstrip("=")
    return f"{path},sha256={digest},{len(data)}"


def _build_local_wheel(wheelhouse: Path, distribution: str, module: str, value: str) -> tuple[Path, str]:
    version = "1.0"
    dist_info = f"{distribution}-{version}.dist-info"
    files = {
        f"{module}.py": f"VALUE = {value!r}\n".encode("utf-8"),
        f"{dist_info}/METADATA": (
            "Metadata-Version: 2.1\n"
            f"Name: {distribution}\n"
            f"Version: {version}\n\n"
        ).encode("utf-8"),
        f"{dist_info}/WHEEL": (
            "Wheel-Version: 1.0\n"
            "Generator: telegram-bridge-round8-ci\n"
            "Root-Is-Purelib: true\n"
            "Tag: py3-none-any\n\n"
        ).encode("utf-8"),
    }
    record_path = f"{dist_info}/RECORD"
    record = "\n".join(_wheel_record_line(path, data) for path, data in files.items())
    record += f"\n{record_path},,\n"
    files[record_path] = record.encode("utf-8")
    wheelhouse.mkdir(parents=True, exist_ok=True)
    wheel = wheelhouse / f"{distribution}-{version}-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path, data in files.items():
            archive.writestr(path, data)
    return wheel, hashlib.sha256(wheel.read_bytes()).hexdigest()


def _init_git_repo(repo: Path) -> None:
    repo.mkdir()
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.name", "Audit Round 8"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.email", "round8@example.invalid"], cwd=repo, check=True)


def _commit_repo(repo: Path, message: str) -> str:
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-qm", message], cwd=repo, check=True)
    return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip()


class TestLockNegativeIntegrationTests(unittest.TestCase):
    def make_repo(self, root: Path, *, omit_test_lock: bool = False, tamper_test_hash: bool = False) -> Path:
        repo = root / "repo"
        _init_git_repo(repo)
        (repo / "app.py").write_text("import appdep\nVALUE = appdep.VALUE\n", encoding="utf-8")
        tests = repo / "tests"
        tests.mkdir()
        (tests / "test_smoke.py").write_text(
            "import unittest, appdep, testdep\n"
            "class Smoke(unittest.TestCase):\n"
            "    def test_locked_deps(self):\n"
            "        self.assertEqual(appdep.VALUE, 'app-ok')\n"
            "        self.assertEqual(testdep.VALUE, 'test-ok')\n",
            encoding="utf-8",
        )
        _app_wheel, app_hash = _build_local_wheel(repo / "wheelhouse", "appdep", "appdep", "app-ok")
        _test_wheel, test_hash = _build_local_wheel(repo / "wheelhouse", "testdep", "testdep", "test-ok")
        (repo / "requirements.txt").write_text("appdep==1.0\n", encoding="utf-8")
        (repo / "requirements-test.txt").write_text("testdep==1.0\n", encoding="utf-8")
        (repo / "requirements.lock").write_text(
            "--no-index\n--find-links wheelhouse\n"
            f"appdep==1.0 --hash=sha256:{app_hash}\n",
            encoding="utf-8",
        )
        if not omit_test_lock:
            locked_hash = "0" * 64 if tamper_test_hash else test_hash
            (repo / "requirements-test.lock").write_text(
                "--no-index\n--find-links wheelhouse\n"
                f"testdep==1.0 --hash=sha256:{locked_hash}\n",
                encoding="utf-8",
            )
        return repo

    def _assert_prepare_fails(self, repo: Path, root: Path, label: str) -> None:
        sha = _commit_repo(repo, label)
        with self.assertRaises(release_guard.SafetyError):
            deploy_release.prepare_versioned_release(
                repo=repo, sha=sha, approved_ref="main", repository_id=f"synthetic/{label}",
                releases_root=root / "releases",
                python_executable=str(Path(sys.executable).resolve(strict=True)),
                runtime_entries=[],
            )

    def test_missing_test_lock_fails_closed(self):
        if sys.version_info[:2] != (3, 11):
            self.skipTest("real PREPARE integration is defined for CI Python 3.11")
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            self._assert_prepare_fails(self.make_repo(root, omit_test_lock=True), root, "missing-test-lock")

    def test_tampered_test_lock_hash_fails_closed(self):
        if sys.version_info[:2] != (3, 11):
            self.skipTest("real PREPARE integration is defined for CI Python 3.11")
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            self._assert_prepare_fails(self.make_repo(root, tamper_test_hash=True), root, "tampered-test-lock")

    def test_real_prepare_output_is_strict_readonly(self):
        if sys.version_info[:2] != (3, 11):
            self.skipTest("real PREPARE integration is defined for CI Python 3.11")
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            repo = root / "repo"
            _init_git_repo(repo)
            (repo / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
            tests = repo / "tests"
            tests.mkdir()
            (tests / "test_smoke.py").write_text(
                "import unittest\nclass Smoke(unittest.TestCase):\n"
                "    def test_ok(self): self.assertEqual(1, 1)\n",
                encoding="utf-8",
            )
            sha = _commit_repo(repo, "strict-readonly-prepare")
            prepared, meta, digest = deploy_release.prepare_versioned_release(
                repo=repo, sha=sha, approved_ref="main",
                repository_id="synthetic/strict-readonly-prepare",
                releases_root=root / "releases",
                python_executable=str(Path(sys.executable).resolve(strict=True)),
                runtime_entries=[],
            )
            self.assertEqual(deploy_release.IMMUTABLE_PERMISSION_POLICY,
                             meta["immutable_permission_policy"])
            self.assertEqual(meta, deploy_release.verify_prepared_release(prepared, digest))
            self.assertEqual(0, stat.S_IMODE(prepared.stat().st_mode) & 0o222)
            self.assertEqual(0, stat.S_IMODE((prepared / "app.py").stat().st_mode) & 0o222)
            self.assertEqual(
                0, stat.S_IMODE((prepared / deploy_release.PREPARED_META).stat().st_mode) & 0o222
            )


class RestartSafeDeploymentTransactionTests(unittest.TestCase):
    repository = "synthetic/round8-transaction"

    def build_layout(self, root: Path):
        repo = root / "repo"
        repo.mkdir()
        (repo / ".git").mkdir()
        releases = root / "releases"
        releases.mkdir()
        (releases / ".prepared").mkdir()
        old_sha = "5" * 40
        new_sha = "6" * 40

        old = releases / old_sha
        old.mkdir()
        (old / "code.txt").write_text("old", encoding="utf-8")
        state = root / "state"
        (state / "var").mkdir(parents=True)
        (state / "var/db").write_text("state", encoding="utf-8")
        release_guard.attach_persistent_state(old, state, ["var"])
        active = root / "active"
        active.symlink_to(old)

        prepared = releases / ".prepared/candidate"
        prepared.mkdir()
        (prepared / "code.txt").write_text("new", encoding="utf-8")
        payload = deploy_release._payload_manifest_without_meta(prepared)
        meta = {
            "schema_version": 2,
            "repository": self.repository,
            "approved_ref": "main",
            "sha": new_sha,
            "configured_python_version": "3.11.9",
            "python_version": "3.11.9",
            "source_manifest_sha256": "a" * 64,
            "requirements_lock_sha256": None,
            "requirements_test_lock_sha256": None,
            "payload_manifest_sha256": release_guard.sha256_json(payload),
            "runtime_entries": ["var"],
            "persistent_state_mode": "shared_external",
        }
        manifest_hash = release_guard.sha256_json(meta)
        release_guard.write_json_atomic(prepared / deploy_release.PREPARED_META, meta, mode=0o644)

        control = root / "control"
        control.mkdir()
        control.chmod(0o700)
        runtime = control / "runtime.json"
        runtime.write_text(json.dumps({"paths": ["var"]}), encoding="utf-8")
        runtime.chmod(0o600)
        for name in ("quiesce", "resume", "restart", "identity", "unauth", "auth"):
            hook = control / name
            hook.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            hook.chmod(0o700)

        approval = control / "approval.json"
        self.write_approval(approval, new_sha, manifest_hash, "approval-1", "nonce-1")
        return locals()

    def write_approval(self, path: Path, sha: str, manifest_hash: str, approval_id: str, nonce: str) -> None:
        now = datetime.now(timezone.utc)
        payload = {
            "approved": True,
            "approved_sha": sha,
            "repository": self.repository,
            "approved_ref": "main",
            "release_manifest_sha256": manifest_hash,
            "ci_run_id": "40",
            "audit_id": "audit-40",
            "approval_id": approval_id,
            "nonce": nonce,
            "issued_at": now.isoformat(),
            "expires_at": (now + timedelta(hours=1)).isoformat(),
            "data_schema_change": False,
        }
        path.write_text(json.dumps(payload), encoding="utf-8")
        path.chmod(0o600)

    def kwargs(self, layout):
        c = layout["control"]
        return dict(
            repo=layout["repo"], prepared_release=layout["prepared"], repository_id=self.repository,
            approved_ref="main", ci_run_id="40", audit_id="audit-40", active_link=layout["active"],
            releases_root=layout["releases"], backup_root=layout["root"] / "backups",
            persistent_state_root=layout["state"], runtime_manifest=layout["runtime"], control_root=c,
            approval_file=layout["approval"], approval_consumption_root=c / "consumed",
            quiesce_hook=c / "quiesce", resume_hook=c / "resume", restart_hook=c / "restart",
            identity_hook=c / "identity", unauth_hook=c / "unauth", auth_hook=c / "auth",
            status_file=c / "status.json",
        )

    def journal(self, layout) -> dict:
        return json.loads((layout["control"] / deploy_release.TRANSACTION_JOURNAL).read_text(encoding="utf-8"))

    def consumed(self, layout) -> list[Path]:
        root = layout["control"] / "consumed"
        return list(root.glob("*.consumed.json")) if root.exists() else []

    def quarantine(self, layout) -> list[Path]:
        root = layout["releases"] / ".quarantine"
        return list(root.iterdir()) if root.exists() else []

    def assert_pre_switch_recovered(self, layout) -> None:
        self.assertEqual(layout["old"].resolve(), layout["active"].resolve())
        self.assertFalse((layout["releases"] / layout["new_sha"]).exists())
        self.assertTrue(layout["prepared"].exists())
        self.assertEqual("PRELIVE_RECOVERED", self.journal(layout)["state"])
        self.assertEqual(1, len(self.consumed(layout)))
        self.assertTrue(self.quarantine(layout))

    def retry_with_fresh_approval(self, layout, suffix: str) -> int:
        self.write_approval(
            layout["approval"], layout["new_sha"], layout["manifest_hash"],
            f"approval-{suffix}", f"nonce-{suffix}",
        )
        with mock.patch.object(deploy_release, "verify_approved_ref_policy", return_value=layout["new_sha"]):
            return deploy_release.execute_prepared_release(**self.kwargs(layout))

    def test_started_status_failure_recovers_and_fresh_approval_retries(self):
        with tempfile.TemporaryDirectory() as td:
            layout = self.build_layout(Path(td))
            real_write = deploy_release.write_json_atomic

            def fail_started(path, payload, mode=0o600):
                if path == layout["control"] / "status.json" and payload.get("state") == "STARTED":
                    raise OSError("synthetic STARTED status loss")
                return real_write(path, payload, mode=mode)

            with mock.patch.object(deploy_release, "verify_approved_ref_policy", return_value=layout["new_sha"]), \
                 mock.patch.object(deploy_release, "write_json_atomic", side_effect=fail_started):
                rc = deploy_release.execute_prepared_release(**self.kwargs(layout))
            self.assertEqual(10, rc)
            self.assert_pre_switch_recovered(layout)
            self.assertEqual(0, self.retry_with_fresh_approval(layout, "retry-started"))
            self.assertEqual(layout["new_sha"], deploy_release._active_release_sha(layout["active"]))

    def test_code_backup_failure_recovers_and_fresh_approval_retries(self):
        with tempfile.TemporaryDirectory() as td:
            layout = self.build_layout(Path(td))
            with mock.patch.object(deploy_release, "verify_approved_ref_policy", return_value=layout["new_sha"]), \
                 mock.patch.object(deploy_release, "backup_active",
                                   side_effect=release_guard.SafetyError("synthetic code backup failure")):
                rc = deploy_release.execute_prepared_release(**self.kwargs(layout))
            self.assertEqual(10, rc)
            self.assert_pre_switch_recovered(layout)
            self.assertEqual(0, self.retry_with_fresh_approval(layout, "retry-code-backup"))

    def test_state_backup_failure_recovers_and_fresh_approval_retries(self):
        with tempfile.TemporaryDirectory() as td:
            layout = self.build_layout(Path(td))
            with mock.patch.object(deploy_release, "verify_approved_ref_policy", return_value=layout["new_sha"]), \
                 mock.patch.object(deploy_release, "backup_persistent_state",
                                   side_effect=release_guard.SafetyError("synthetic state backup failure")):
                rc = deploy_release.execute_prepared_release(**self.kwargs(layout))
            self.assertEqual(10, rc)
            self.assert_pre_switch_recovered(layout)
            self.assertEqual(0, self.retry_with_fresh_approval(layout, "retry-state-backup"))

    def test_hard_post_consume_process_loss_reconciles_on_second_invocation(self):
        with tempfile.TemporaryDirectory() as td:
            layout = self.build_layout(Path(td))
            real_consume = deploy_release.consume_external_approval

            def consume_then_die(*args, **kwargs):
                real_consume(*args, **kwargs)
                raise SystemExit("synthetic hard process loss")

            with mock.patch.object(deploy_release, "verify_approved_ref_policy", return_value=layout["new_sha"]), \
                 mock.patch.object(deploy_release, "consume_external_approval", side_effect=consume_then_die):
                with self.assertRaises(SystemExit):
                    deploy_release.execute_prepared_release(**self.kwargs(layout))

            self.assertEqual("READY_TO_COMMIT", self.journal(layout)["state"])
            self.assertEqual(1, len(self.consumed(layout)))
            self.assertTrue((layout["releases"] / layout["new_sha"]).exists())
            self.assertEqual(layout["old"].resolve(), layout["active"].resolve())

            with mock.patch.object(deploy_release, "verify_approved_ref_policy", return_value=layout["new_sha"]):
                with self.assertRaises(release_guard.SafetyError):
                    deploy_release.execute_prepared_release(**self.kwargs(layout))
            self.assert_pre_switch_recovered(layout)

            self.assertEqual(0, self.retry_with_fresh_approval(layout, "retry-hard-loss"))
            self.assertEqual(layout["new_sha"], deploy_release._active_release_sha(layout["active"]))

    def test_post_approval_pre_switch_mutation_is_detected_and_recovered(self):
        with tempfile.TemporaryDirectory() as td:
            layout = self.build_layout(Path(td))
            real_state_backup = deploy_release.backup_persistent_state

            def backup_then_mutate(*args, **kwargs):
                result = real_state_backup(*args, **kwargs)
                final_code = layout["releases"] / layout["new_sha"] / "code.txt"
                os.chmod(final_code, stat.S_IMODE(final_code.stat().st_mode) | stat.S_IWUSR)
                final_code.write_text("same-uid-mutation", encoding="utf-8")
                return result

            with mock.patch.object(deploy_release, "verify_approved_ref_policy", return_value=layout["new_sha"]), \
                 mock.patch.object(deploy_release, "backup_persistent_state", side_effect=backup_then_mutate):
                rc = deploy_release.execute_prepared_release(**self.kwargs(layout))
            self.assertEqual(10, rc)
            self.assert_pre_switch_recovered(layout)

    def test_successful_final_release_is_strict_readonly_except_persistent_binding(self):
        with tempfile.TemporaryDirectory() as td:
            layout = self.build_layout(Path(td))
            with mock.patch.object(deploy_release, "verify_approved_ref_policy", return_value=layout["new_sha"]):
                rc = deploy_release.execute_prepared_release(**self.kwargs(layout))
            self.assertEqual(0, rc)
            final = layout["releases"] / layout["new_sha"]
            self.assertEqual(0, stat.S_IMODE(final.stat().st_mode) & 0o222)
            self.assertEqual(0, stat.S_IMODE((final / "code.txt").stat().st_mode) & 0o222)
            self.assertEqual(0, stat.S_IMODE((final / deploy_release.PREPARED_META).stat().st_mode) & 0o222)
            self.assertTrue((final / "var").is_symlink())
            self.assertEqual("DEPLOYED", self.journal(layout)["state"])


if __name__ == "__main__":
    unittest.main()
