# -*- coding: utf-8 -*-
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from ops import deploy_release, release_guard
from tools import secret_scan


class RealPrepareIntegrationTests(unittest.TestCase):
    def test_real_python311_prepare_and_verify_without_mocks(self):
        if sys.version_info[:2] != (3, 11):
            self.skipTest("real PREPARE integration is defined for CI Python 3.11")
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            repo = root / "repo"
            repo.mkdir()
            subprocess.run(["git", "init", "-q", "-b", "main"], cwd=repo, check=True)
            subprocess.run(["git", "config", "user.name", "Prepare Integration"], cwd=repo, check=True)
            subprocess.run(["git", "config", "user.email", "prepare@example.invalid"], cwd=repo, check=True)
            (repo / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
            tests = repo / "tests"
            tests.mkdir()
            (tests / "test_smoke.py").write_text(
                "import unittest\nclass Smoke(unittest.TestCase):\n    def test_ok(self): self.assertEqual(1, 1)\n",
                encoding="utf-8",
            )
            subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
            subprocess.run(["git", "commit", "-qm", "synthetic prepare source"], cwd=repo, check=True)
            sha = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip()
            python_real = str(Path(sys.executable).resolve(strict=True))
            prepared, meta, digest = deploy_release.prepare_versioned_release(
                repo=repo, sha=sha, approved_ref="main", repository_id="synthetic/prepare",
                releases_root=root / "releases", python_executable=python_real, runtime_entries=[])
            self.assertEqual(2, meta["schema_version"])
            self.assertEqual(sha, meta["sha"])
            self.assertTrue((prepared / ".venv").is_dir())
            self.assertEqual(sha, deploy_release.verify_prepared_release(prepared, digest)["sha"])
            links = [p for p in (prepared / ".venv").rglob("*") if p.is_symlink()]
            if os.name == "posix":
                self.assertTrue(links, "POSIX venv should exercise legitimate symlink policy")

    def test_arbitrary_release_symlink_is_still_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "target").write_text("safe", encoding="utf-8")
            try:
                (root / "link").symlink_to(root / "target")
            except OSError:
                self.skipTest("symlink creation unavailable")
            with self.assertRaises(release_guard.SafetyError):
                deploy_release._payload_manifest_without_meta(root)


class UnsupportedPrefixedContainerTests(unittest.TestCase):
    def test_prefixed_unsupported_signatures_fail_before_allowlist(self):
        signatures = [secret_scan.SEVEN_Z_SIGNATURE, secret_scan.RAR_SIGNATURES[0], secret_scan.RAR_SIGNATURES[1],
                      secret_scan.GZIP_SIGNATURE, secret_scan.BZIP2_SIGNATURE, secret_scan.XZ_SIGNATURE]
        for index, signature in enumerate(signatures):
            with self.subTest(index=index):
                data = b"SFX-PREFIX-" + bytes([index]) + signature + b"synthetic-body\x00"
                allow = {("reviewed.bin", secret_scan._sha256(data)): "Synthetic reviewed non-secret fixture."}
                findings = "\n".join(secret_scan._scan_bytes(data, "reviewed.bin", "test", allow))
                self.assertIn("unsupported", findings)
                self.assertNotIn("synthetic-body", findings)


class TransactionalExecuteTests(unittest.TestCase):
    repository = "synthetic/transaction"

    def build_layout(self, root):
        repo=root/"repo"; repo.mkdir(); (repo/".git").mkdir()
        releases=root/"releases"; releases.mkdir(); (releases/".prepared").mkdir()
        old_sha="1"*40; new_sha="2"*40
        old=releases/old_sha; old.mkdir(); (old/"code.txt").write_text("old")
        state=root/"state"; (state/"var").mkdir(parents=True); (state/"var/db").write_text("state")
        release_guard.attach_persistent_state(old,state,["var"])
        active=root/"active"; active.symlink_to(old)
        prepared=releases/".prepared/candidate"; prepared.mkdir(); (prepared/"code.txt").write_text("new")
        payload=deploy_release._payload_manifest_without_meta(prepared)
        meta={"schema_version":2,"repository":self.repository,"approved_ref":"main","sha":new_sha,
              "configured_python_version":"3.11.9","python_version":"3.11.9","source_manifest_sha256":"a"*64,
              "requirements_lock_sha256":None,"requirements_test_lock_sha256":None,
              "payload_manifest_sha256":release_guard.sha256_json(payload),"runtime_entries":["var"],
              "persistent_state_mode":"shared_external"}
        manifest_hash=release_guard.sha256_json(meta)
        release_guard.write_json_atomic(prepared/deploy_release.PREPARED_META,meta,mode=0o644)
        control=root/"control"; control.mkdir(); control.chmod(0o700)
        runtime=control/"runtime.json"; runtime.write_text(json.dumps({"paths":["var"]})); runtime.chmod(0o600)
        for name in ("quiesce","resume","restart","identity","unauth","auth"):
            p=control/name; p.write_text("#!/bin/sh\nexit 0\n"); p.chmod(0o700)
        now=datetime.now(timezone.utc); approval=control/"approval.json"
        approval.write_text(json.dumps({"approved":True,"approved_sha":new_sha,"repository":self.repository,
            "approved_ref":"main","release_manifest_sha256":manifest_hash,"ci_run_id":"28","audit_id":"audit-28",
            "approval_id":"approval-28","nonce":"nonce-28","issued_at":now.isoformat(),
            "expires_at":(now+timedelta(hours=1)).isoformat(),"data_schema_change":False})); approval.chmod(0o600)
        return locals()

    def kwargs(self,L):
        c=L["control"]
        return dict(repo=L["repo"],prepared_release=L["prepared"],repository_id=self.repository,approved_ref="main",
            ci_run_id="28",audit_id="audit-28",active_link=L["active"],releases_root=L["releases"],
            backup_root=L["root"]/"backups",persistent_state_root=L["state"],runtime_manifest=L["runtime"],control_root=c,
            approval_file=L["approval"],approval_consumption_root=c/"consumed",quiesce_hook=c/"quiesce",resume_hook=c/"resume",
            restart_hook=c/"restart",identity_hook=c/"identity",unauth_hook=c/"unauth",auth_hook=c/"auth",status_file=c/"status.json")

    def consumed(self,L):
        root=L["control"]/"consumed"; return list(root.glob("*.consumed.json")) if root.exists() else []

    def run_preflight_failure(self,L):
        with mock.patch.object(deploy_release,"verify_approved_ref_policy",return_value=L["new_sha"]):
            with self.assertRaises(release_guard.SafetyError):
                deploy_release.execute_prepared_release(**self.kwargs(L))
        self.assertEqual([],self.consumed(L)); self.assertTrue(L["prepared"].exists())

    def test_invalid_active_link_does_not_consume_approval(self):
        with tempfile.TemporaryDirectory() as td:
            L=self.build_layout(Path(td)); L["active"].unlink(); L["active"].mkdir(); self.run_preflight_failure(L)

    def test_existing_final_target_does_not_consume_approval(self):
        with tempfile.TemporaryDirectory() as td:
            L=self.build_layout(Path(td)); (L["releases"]/L["new_sha"]).mkdir(); self.run_preflight_failure(L)

    def test_missing_persistent_entry_does_not_consume_approval(self):
        with tempfile.TemporaryDirectory() as td:
            L=self.build_layout(Path(td)); shutil.rmtree(L["state"]/"var"); self.run_preflight_failure(L)

    def test_partial_materialization_is_cleaned_and_retryable(self):
        with tempfile.TemporaryDirectory() as td:
            L=self.build_layout(Path(td))
            with mock.patch.object(deploy_release,"verify_approved_ref_policy",return_value=L["new_sha"]), \
                 mock.patch.object(deploy_release,"attach_persistent_state",side_effect=release_guard.SafetyError("synthetic partial attach")):
                with self.assertRaises(release_guard.SafetyError):
                    deploy_release.execute_prepared_release(**self.kwargs(L))
            self.assertEqual([],self.consumed(L)); self.assertTrue(L["prepared"].exists())
            self.assertFalse((L["releases"]/L["new_sha"]).exists())
            self.assertFalse((L["releases"]/(".finalize_"+L["new_sha"])).exists())
            with mock.patch.object(deploy_release,"verify_approved_ref_policy",return_value=L["new_sha"]):
                rc=deploy_release.execute_prepared_release(**self.kwargs(L))
            self.assertEqual(0,rc); self.assertEqual(1,len(self.consumed(L)))


if __name__ == "__main__":
    unittest.main()
