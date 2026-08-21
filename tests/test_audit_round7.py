# -*- coding: utf-8 -*-
import base64
import hashlib
import json
import os
import shutil
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


def build_local_wheel(wheelhouse: Path, distribution: str, module: str, value: str) -> tuple[Path, str]:
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
            "Generator: telegram-bridge-synthetic-ci\n"
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


def init_git_repo(repo: Path) -> None:
    repo.mkdir()
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.name", "Audit Round 7"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.email", "round7@example.invalid"], cwd=repo, check=True)


def commit_repo(repo: Path, message: str = "synthetic round7 source") -> str:
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-qm", message], cwd=repo, check=True)
    return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip()


class HashLockedPrepareIntegrationTests(unittest.TestCase):
    def make_locked_repo(self, root: Path, *, tamper_app_hash: bool = False, omit_app_lock: bool = False):
        repo = root / "repo"
        init_git_repo(repo)
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
        app_wheel, app_hash = build_local_wheel(repo / "wheelhouse", "appdep", "appdep", "app-ok")
        _test_wheel, test_hash = build_local_wheel(repo / "wheelhouse", "testdep", "testdep", "test-ok")
        (repo / "requirements.txt").write_text("appdep==1.0\n", encoding="utf-8")
        (repo / "requirements-test.txt").write_text("testdep==1.0\n", encoding="utf-8")
        if not omit_app_lock:
            lock_hash = ("0" * 64) if tamper_app_hash else app_hash
            (repo / "requirements.lock").write_text(
                "--no-index\n--find-links wheelhouse\n"
                f"appdep==1.0 --hash=sha256:{lock_hash}\n",
                encoding="utf-8",
            )
        (repo / "requirements-test.lock").write_text(
            "--no-index\n--find-links wheelhouse\n"
            f"testdep==1.0 --hash=sha256:{test_hash}\n",
            encoding="utf-8",
        )
        return repo, app_wheel

    def test_real_prepare_installs_app_and_test_hash_locked_dependencies_offline(self):
        if sys.version_info[:2] != (3, 11):
            self.skipTest("real hash-locked PREPARE integration is defined for CI Python 3.11")
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            repo, _wheel = self.make_locked_repo(root)
            sha = commit_repo(repo)
            prepared, meta, digest = deploy_release.prepare_versioned_release(
                repo=repo,
                sha=sha,
                approved_ref="main",
                repository_id="synthetic/hash-locked",
                releases_root=root / "releases",
                python_executable=str(Path(sys.executable).resolve(strict=True)),
                runtime_entries=[],
            )
            self.assertTrue(meta["requirements_lock_sha256"])
            self.assertTrue(meta["requirements_test_lock_sha256"])
            self.assertIn("approved_python_identity", meta)
            verified = deploy_release.verify_prepared_release(prepared, digest)
            self.assertEqual(meta["approved_python_identity"], verified["approved_python_identity"])
            py = prepared / ".venv/bin/python"
            output = subprocess.check_output(
                [str(py), "-c", "import appdep,testdep; print(appdep.VALUE+'|'+testdep.VALUE)"],
                text=True,
            ).strip()
            self.assertEqual("app-ok|test-ok", output)

    def test_missing_application_lock_fails_closed(self):
        if sys.version_info[:2] != (3, 11):
            self.skipTest("real PREPARE integration is defined for CI Python 3.11")
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            repo, _wheel = self.make_locked_repo(root, omit_app_lock=True)
            sha = commit_repo(repo)
            with self.assertRaises(release_guard.SafetyError):
                deploy_release.prepare_versioned_release(
                    repo=repo, sha=sha, approved_ref="main", repository_id="synthetic/missing-lock",
                    releases_root=root / "releases", python_executable=str(Path(sys.executable).resolve(strict=True)),
                    runtime_entries=[],
                )

    def test_tampered_application_lock_hash_fails_closed(self):
        if sys.version_info[:2] != (3, 11):
            self.skipTest("real PREPARE integration is defined for CI Python 3.11")
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            repo, _wheel = self.make_locked_repo(root, tamper_app_hash=True)
            sha = commit_repo(repo)
            with self.assertRaises(release_guard.SafetyError):
                deploy_release.prepare_versioned_release(
                    repo=repo, sha=sha, approved_ref="main", repository_id="synthetic/tampered-lock",
                    releases_root=root / "releases", python_executable=str(Path(sys.executable).resolve(strict=True)),
                    runtime_entries=[],
                )


class InterpreterIdentityTests(unittest.TestCase):
    def test_external_venv_symlink_requires_exact_approval_bound_identity(self):
        if os.name != "posix":
            self.skipTest("POSIX venv symlink identity regression")
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            bindir = root / ".venv/bin"
            bindir.mkdir(parents=True)
            (bindir / "python").symlink_to(Path(sys.executable).resolve(strict=True))
            identity = deploy_release._python_identity(Path(sys.executable).resolve(strict=True))
            manifest = deploy_release._payload_manifest_without_meta(root, identity)
            self.assertEqual(1, manifest["count"])
            wrong = dict(identity)
            wrong["sha256"] = "0" * 64
            with self.assertRaises(release_guard.SafetyError):
                deploy_release._payload_manifest_without_meta(root, wrong)


class FinalTransactionBoundaryTests(unittest.TestCase):
    repository = "synthetic/round7-transaction"

    def build_layout(self, root: Path):
        repo = root / "repo"
        repo.mkdir()
        (repo / ".git").mkdir()
        releases = root / "releases"
        releases.mkdir()
        (releases / ".prepared").mkdir()
        old_sha = "3" * 40
        new_sha = "4" * 40
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
        now = datetime.now(timezone.utc)
        approval = control / "approval.json"
        approval.write_text(json.dumps({
            "approved": True,
            "approved_sha": new_sha,
            "repository": self.repository,
            "approved_ref": "main",
            "release_manifest_sha256": manifest_hash,
            "ci_run_id": "34",
            "audit_id": "audit-34",
            "approval_id": "approval-34",
            "nonce": "nonce-34",
            "issued_at": now.isoformat(),
            "expires_at": (now + timedelta(hours=1)).isoformat(),
            "data_schema_change": False,
        }), encoding="utf-8")
        approval.chmod(0o600)
        return locals()

    def kwargs(self, layout):
        c = layout["control"]
        return dict(
            repo=layout["repo"], prepared_release=layout["prepared"], repository_id=self.repository,
            approved_ref="main", ci_run_id="34", audit_id="audit-34", active_link=layout["active"],
            releases_root=layout["releases"], backup_root=layout["root"] / "backups",
            persistent_state_root=layout["state"], runtime_manifest=layout["runtime"], control_root=c,
            approval_file=layout["approval"], approval_consumption_root=c / "consumed",
            quiesce_hook=c / "quiesce", resume_hook=c / "resume", restart_hook=c / "restart",
            identity_hook=c / "identity", unauth_hook=c / "unauth", auth_hook=c / "auth",
            status_file=c / "status.json",
        )

    def consumed(self, layout):
        root = layout["control"] / "consumed"
        return list(root.glob("*.consumed.json")) if root.exists() else []

    def test_final_materialization_mutation_fails_before_approval_and_cleans(self):
        with tempfile.TemporaryDirectory() as td:
            layout = self.build_layout(Path(td))
            original = shutil.copytree

            def corrupt_copy(src, dst, *args, **kwargs):
                result = original(src, dst, *args, **kwargs)
                (Path(dst) / "code.txt").write_text("copy-corruption", encoding="utf-8")
                return result

            with mock.patch.object(deploy_release, "verify_approved_ref_policy", return_value=layout["new_sha"]), \
                 mock.patch.object(deploy_release.shutil, "copytree", side_effect=corrupt_copy):
                with self.assertRaises(release_guard.SafetyError):
                    deploy_release.execute_prepared_release(**self.kwargs(layout))
            self.assertEqual([], self.consumed(layout))
            self.assertTrue(layout["prepared"].exists())
            self.assertEqual("new", (layout["prepared"] / "code.txt").read_text(encoding="utf-8"))
            self.assertFalse((layout["releases"] / layout["new_sha"]).exists())

    def test_status_checkpoint_failure_is_preapproval_cleanup_safe(self):
        with tempfile.TemporaryDirectory() as td:
            layout = self.build_layout(Path(td))
            real_write = deploy_release.write_json_atomic

            def fail_ready(path, payload, mode=0o600):
                if path == layout["control"] / "status.json" and payload.get("state") == "READY_TO_COMMIT":
                    raise OSError("synthetic status checkpoint failure")
                return real_write(path, payload, mode=mode)

            with mock.patch.object(deploy_release, "verify_approved_ref_policy", return_value=layout["new_sha"]), \
                 mock.patch.object(deploy_release, "write_json_atomic", side_effect=fail_ready), \
                 mock.patch.object(deploy_release, "run_private_hook") as hook:
                with self.assertRaises(release_guard.SafetyError):
                    deploy_release.execute_prepared_release(**self.kwargs(layout))
            hook.assert_not_called()
            self.assertEqual([], self.consumed(layout))
            self.assertTrue(layout["prepared"].exists())
            self.assertFalse((layout["releases"] / layout["new_sha"]).exists())

    def test_nonlive_commit_boundary_verifies_final_before_consuming_approval(self):
        with tempfile.TemporaryDirectory() as td:
            layout = self.build_layout(Path(td))
            order = []
            real_verify = deploy_release._verify_final_materialized_release

            def verify_spy(*args, **kwargs):
                order.append("final-verified")
                return real_verify(*args, **kwargs)

            def stop_at_consume(*args, **kwargs):
                order.append("approval-consume")
                raise release_guard.SafetyError("synthetic stop at approval boundary")

            with mock.patch.object(deploy_release, "verify_approved_ref_policy", return_value=layout["new_sha"]), \
                 mock.patch.object(deploy_release, "_verify_final_materialized_release", side_effect=verify_spy), \
                 mock.patch.object(deploy_release, "consume_external_approval", side_effect=stop_at_consume), \
                 mock.patch.object(deploy_release, "run_private_hook") as hook:
                with self.assertRaises(release_guard.SafetyError):
                    deploy_release.execute_prepared_release(**self.kwargs(layout))
            self.assertEqual(["final-verified", "final-verified", "approval-consume"], order)
            hook.assert_not_called()
            self.assertTrue(layout["prepared"].exists())
            self.assertFalse((layout["releases"] / layout["new_sha"]).exists())


if __name__ == "__main__":
    unittest.main()
