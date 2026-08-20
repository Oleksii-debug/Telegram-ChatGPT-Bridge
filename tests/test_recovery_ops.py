# -*- coding: utf-8 -*-
import json, os, tempfile, unittest, zipfile
from pathlib import Path
from unittest import mock
from ops import deploy_release, recovery_capture, release_guard

class ReleaseGuardTests(unittest.TestCase):
    def test_builtin_protected_paths_are_non_overridable(self):
        for path in ("var/session.dat","nested/var/state.bin",".env",".env.production","account.session","state.sqlite3","private_config.json","logs/private.log"): self.assertTrue(release_guard.is_protected_relative(path),path)
        self.assertFalse(release_guard.is_protected_relative("src/main.py"))
    def test_copy_protected_state_ignores_repository_preserve_lists(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); live=root/"live"; stage=root/"stage"; (live/"var/nested").mkdir(parents=True); (live/"src").mkdir(); (live/"var/nested/state.db").write_text("runtime"); (live/".env.production").write_text("private"); (live/"src/main.py").write_text("code")
            copied=release_guard.copy_protected_state(live,stage); self.assertIn("var/nested/state.db",copied); self.assertIn(".env.production",copied); self.assertFalse((stage/"src/main.py").exists())
    def test_symlink_in_live_tree_fails_closed(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); live=root/"live"; stage=root/"stage"; live.mkdir(); (live/"real").write_text("x")
            try: (live/"var").symlink_to(live/"real")
            except (OSError,NotImplementedError): self.skipTest("symlinks unavailable")
            with self.assertRaises(release_guard.SafetyError): release_guard.copy_protected_state(live,stage)
    def test_external_approval_requires_exact_sha(self):
        with tempfile.TemporaryDirectory() as td:
            approval=Path(td)/"approval.json"; approval.write_text(json.dumps({"approved":True,"approved_sha":"a"*40,"approval_id":"audit-1"})); self.assertEqual("a"*40,release_guard.load_external_approval(approval,"a"*40)["approved_sha"])
            with self.assertRaises(release_guard.SafetyError): release_guard.load_external_approval(approval,"b"*40)
    def test_retention_never_removes_active_or_last_known_good(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); paths=[]
            for i in range(8): p=root/f"r{i}"; p.mkdir(); os.utime(p,(1000+i,1000+i)); paths.append(p)
            removable=release_guard.retention_candidates(paths,active=paths[0],last_known_good=paths[1],keep_newest=3); self.assertNotIn(paths[0],removable); self.assertNotIn(paths[1],removable); self.assertTrue(removable)

class RecoveryCaptureTests(unittest.TestCase):
    def make_app(self,root):
        app=root/"app"; app.mkdir(); (app/"main.py").write_text("print('ok')\n"); (app/"var").mkdir(); (app/"var/runtime.db").write_text("private-runtime"); return app
    def test_clean_capture_is_private_recovery_only(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); app=self.make_app(root); recovery=root/"recovery"; status=recovery_capture.capture(app,recovery); self.assertEqual("CANDIDATE_READY_FOR_PRIVATE_AUDIT",status["state"]); self.assertFalse(status["transfer_performed"]); self.assertFalse(status["cron_or_deploy_worker_installed"]); out=next(recovery.iterdir()); self.assertTrue((out/"PRIVATE_FULL_BACKUP.tar.gz").is_file()); self.assertTrue((out/"SANITIZED_CANDIDATE_PRIVATE.tar.gz").is_file())
    def test_hidden_or_unusual_secret_content_blocks_candidate_export(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); app=self.make_app(root); recovery=root/"recovery"; variable="TG_"+"API_HASH"; value="synthetic-hidden-1234567890"; (app/"innocent_name.txt").write_text(variable+"="+value+"\n"); status=recovery_capture.capture(app,recovery); self.assertEqual("CONTAMINATED_BLOCKED",status["state"]); out=next(recovery.iterdir()); findings=(out/"SCAN_FINDINGS_REDACTED.txt").read_text(); self.assertIn(variable,findings); self.assertNotIn(value,findings); self.assertFalse((out/"SANITIZED_CANDIDATE_PRIVATE.tar.gz").exists())
    def test_nested_archive_secret_blocks_candidate_export(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); app=self.make_app(root); recovery=root/"recovery"; variable="BRIDGE_"+"TOKEN"; archive=app/"assets.zip"
            with zipfile.ZipFile(archive,"w") as zf: zf.writestr("nested/config.json",'{"'+variable+'":"synthetic-zip-1234567890"}\n')
            self.assertEqual("CONTAMINATED_BLOCKED",recovery_capture.capture(app,recovery)["state"])
    def test_large_secret_text_blocks_candidate_export(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); app=self.make_app(root); recovery=root/"recovery"; variable="SETUP_"+"KEY"; (app/"large_source.txt").write_text(("A"*5_100_000)+"\n"+variable+"=synthetic-large-1234567890\n"); self.assertEqual("CONTAMINATED_BLOCKED",recovery_capture.capture(app,recovery)["state"])

class DeployReleaseTests(unittest.TestCase):
    def make_active(self,root):
        previous=root/"release-old"; previous.mkdir(); (previous/".venv").mkdir(); (previous/"code.txt").write_text("old"); active=root/"active"; active.symlink_to(previous); new=root/"release-new"; new.mkdir(); (new/".venv").mkdir(); (new/"code.txt").write_text("new"); return active,previous,new
    def write_approval(self,root,sha):
        p=root/"approval.json"; p.write_text(json.dumps({"approved":True,"approved_sha":sha,"approval_id":"auditor-pass-001"})); return p
    def test_failed_preflight_does_not_switch_live_code_or_environment(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); active,previous,_=self.make_active(root); repo=root/"repo"; repo.mkdir(); private=root/"private"; private.mkdir(); sha="a"*40; approval=self.write_approval(private,sha); status_file=private/"status.json"
            with mock.patch.object(deploy_release,"build_versioned_release",side_effect=release_guard.SafetyError("dependency failure")): rc=deploy_release.deploy(repo=repo,sha=sha,active_link=active,releases_root=root/"releases",backup_root=root/"backups",approval_file=approval,unauth_hook=private/"u",auth_hook=private/"a",status_file=status_file)
            self.assertEqual(10,rc); self.assertEqual(previous.resolve(),active.resolve()); self.assertEqual("PRELIVE_FAILED",json.loads(status_file.read_text())["state"])
    def test_failed_health_rolls_back_code_and_versioned_environment_together(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); active,previous,new=self.make_active(root); repo=root/"repo"; repo.mkdir(); private=root/"private"; private.mkdir(); sha="b"*40; approval=self.write_approval(private,sha); status_file=private/"status.json"
            with mock.patch.object(deploy_release,"build_versioned_release",return_value=new), mock.patch.object(deploy_release,"backup_active",return_value=root/"backup.tar.gz"), mock.patch.object(deploy_release,"run_smoke_hook",side_effect=[release_guard.SafetyError("health failed"),None,None]): rc=deploy_release.deploy(repo=repo,sha=sha,active_link=active,releases_root=root/"releases",backup_root=root/"backups",approval_file=approval,unauth_hook=private/"u",auth_hook=private/"a",status_file=status_file)
            self.assertEqual(20,rc); self.assertEqual(previous.resolve(),active.resolve()); self.assertTrue((active.resolve()/".venv").is_dir()); self.assertEqual("ROLLED_BACK",json.loads(status_file.read_text())["state"])
    def test_failed_rollback_is_unmistakably_critical(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); active,_,new=self.make_active(root); repo=root/"repo"; repo.mkdir(); private=root/"private"; private.mkdir(); sha="c"*40; approval=self.write_approval(private,sha); status_file=private/"status.json"
            with mock.patch.object(deploy_release,"build_versioned_release",return_value=new), mock.patch.object(deploy_release,"backup_active",return_value=root/"backup.tar.gz"), mock.patch.object(deploy_release,"run_smoke_hook",side_effect=[release_guard.SafetyError("health failed"),release_guard.SafetyError("rollback health failed")]): rc=deploy_release.deploy(repo=repo,sha=sha,active_link=active,releases_root=root/"releases",backup_root=root/"backups",approval_file=approval,unauth_hook=private/"u",auth_hook=private/"a",status_file=status_file)
            self.assertEqual(70,rc); self.assertEqual("CRITICAL_ROLLBACK_FAILED",json.loads(status_file.read_text())["state"])
    def test_success_switch_keeps_previous_release_as_last_known_good(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); active,previous,new=self.make_active(root); repo=root/"repo"; repo.mkdir(); private=root/"private"; private.mkdir(); sha="f"*40; approval=self.write_approval(private,sha); status_file=private/"status.json"; backup=root/"backups/predeploy.tar.gz"; backup.parent.mkdir(); backup.write_bytes(b"backup")
            with mock.patch.object(deploy_release,"build_versioned_release",return_value=new), mock.patch.object(deploy_release,"backup_active",return_value=backup), mock.patch.object(deploy_release,"run_smoke_hook",return_value=None): rc=deploy_release.deploy(repo=repo,sha=sha,active_link=active,releases_root=root,backup_root=backup.parent,approval_file=approval,unauth_hook=private/"u",auth_hook=private/"a",status_file=status_file)
            self.assertEqual(0,rc); self.assertEqual(new.resolve(),active.resolve()); self.assertTrue(previous.exists()); self.assertEqual("DEPLOYED",json.loads(status_file.read_text())["state"])
    def test_missing_required_tests_blocks_staged_release(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); repo=root/"repo"; repo.mkdir(); (repo/".git").mkdir(); releases=root/"releases"
            def fake_export(_repo,_sha,destination): (destination/"main.py").write_text("print('x')\n")
            def fake_venv_create(_self,path): py=Path(path)/"bin/python"; py.parent.mkdir(parents=True); py.write_text(""); py.chmod(0o700)
            with mock.patch.object(deploy_release,"git_export",side_effect=fake_export), mock.patch("venv.EnvBuilder.create",new=fake_venv_create), mock.patch.object(deploy_release,"run",return_value=None):
                with self.assertRaises(release_guard.SafetyError) as ctx: deploy_release.build_versioned_release(repo=repo,sha="d"*40,live_app=root/"missing",releases_root=releases,python_executable="python3")
            self.assertIn("test suite is absent",str(ctx.exception))
    def test_unlocked_dependency_manifest_blocks_release(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); repo=root/"repo"; repo.mkdir(); (repo/".git").mkdir(); releases=root/"releases"
            def fake_export(_repo,_sha,destination): (destination/"requirements.txt").write_text("example==1\n"); (destination/"tests").mkdir(); (destination/"tests/test_x.py").write_text("def test_x(): assert True\n")
            def fake_venv_create(_self,path): py=Path(path)/"bin/python"; py.parent.mkdir(parents=True); py.write_text(""); py.chmod(0o700)
            with mock.patch.object(deploy_release,"git_export",side_effect=fake_export), mock.patch("venv.EnvBuilder.create",new=fake_venv_create), mock.patch.object(deploy_release,"run",return_value=None):
                with self.assertRaises(release_guard.SafetyError) as ctx: deploy_release.build_versioned_release(repo=repo,sha="e"*40,live_app=root/"missing",releases_root=releases,python_executable="python3")
            self.assertIn("requirements.lock",str(ctx.exception))
if __name__=="__main__": unittest.main()
