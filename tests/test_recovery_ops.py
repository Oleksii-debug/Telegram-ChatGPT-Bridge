# -*- coding: utf-8 -*-
import io, json, os, subprocess, tempfile, time, unittest, zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock
from ops import deploy_release, recovery_capture, release_guard

class ReleaseGuardTests(unittest.TestCase):
    def test_builtin_private_artifacts_are_protected(self):
        for path in ("var/session.dat","nested/var/state.bin",".env",".env.production","account.session","state.sqlite3","private_config.json","private.log","cookies.txt","browser_profile/Default/state.bin"):
            self.assertTrue(release_guard.is_protected_relative(path),path)
        self.assertFalse(release_guard.is_protected_relative("src/main.py")); self.assertTrue(release_guard.is_persistent_relative("var")); self.assertFalse(release_guard.is_persistent_relative(".venv"))

    def test_shared_persistent_state_survives_release_rollback(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); state=root/'state'; (state/'var').mkdir(parents=True); (state/'var/runtime.db').write_text('v1')
            old=root/('1'*40); new=root/('2'*40); old.mkdir(); new.mkdir(); release_guard.attach_persistent_state(old,state,['var']); release_guard.attach_persistent_state(new,state,['var'])
            active=root/'active'; active.symlink_to(old); previous=release_guard.atomic_switch_link(active,new); (active/'var/runtime.db').write_text('post-switch'); release_guard.restore_link(active,previous)
            self.assertEqual('post-switch',(active/'var/runtime.db').read_text()); self.assertEqual((old/'var').resolve(),(new/'var').resolve())

    def test_runtime_manifest_rejects_nonpersistent_paths(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/'runtime.json'; p.write_text(json.dumps({'paths':['src/main.py']}))
            with self.assertRaises(release_guard.SafetyError): release_guard.load_runtime_manifest(p)

    def test_topology_overlap_and_symlink_alias_fail_closed(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); app=root/'app'; app.mkdir()
            with self.assertRaises(release_guard.SafetyError): release_guard.validate_recovery_topology(app,app/'recovery')
            real=root/'real'; real.mkdir(); alias=root/'alias'
            try: alias.symlink_to(real,target_is_directory=True)
            except OSError: return
            with self.assertRaises(release_guard.SafetyError): release_guard.validate_recovery_topology(app,alias)

    def test_deployment_topology_rejects_overlap(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); repo=root/'repo'; repo.mkdir()
            with self.assertRaises(release_guard.SafetyError): release_guard.validate_deployment_topology(repo=repo,active_link=root/'active',releases_root=root/'releases',backup_root=root/'releases/backups',persistent_state_root=root/'state',control_root=root/'control')

    def approval_payload(self,schema=False):
        now=datetime.now(timezone.utc)
        return {'approved':True,'approved_sha':'a'*40,'repository':'repo/id','approved_ref':'main','release_manifest_sha256':'b'*64,'ci_run_id':'1','audit_id':'audit','approval_id':'id','nonce':'nonce','issued_at':now.isoformat(),'expires_at':(now+timedelta(hours=1)).isoformat(),'data_schema_change':schema}

    def test_external_approval_permissions_freshness_single_use(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); p=root/'approval.json'; p.write_text(json.dumps(self.approval_payload())); p.chmod(0o600)
            payload=release_guard.load_external_approval(p,expected_sha='a'*40,expected_repository='repo/id',expected_ref='main',expected_manifest_sha256='b'*64,expected_ci_run_id='1',expected_audit_id='audit')
            marker=release_guard.consume_external_approval(payload,root/'consumed'); self.assertTrue(marker.exists())
            with self.assertRaises(release_guard.SafetyError): release_guard.consume_external_approval(payload,root/'consumed')
            p.chmod(0o644)
            with self.assertRaises(release_guard.SafetyError): release_guard.load_external_approval(p,expected_sha='a'*40,expected_repository='repo/id',expected_ref='main',expected_manifest_sha256='b'*64,expected_ci_run_id='1',expected_audit_id='audit')

    def test_backup_retention_removes_hash_pair_and_staging_lock_is_preserved(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); backups=[]
            for i in range(4):
                a=root/f'b{i}.tar.gz'; a.write_bytes(b'x'); Path(str(a)+'.sha256').write_text('hash'); os.utime(a,(1000+i,1000+i)); backups.append(a)
            removed=release_guard.apply_backup_retention(root,last_known_good=backups[0],keep_newest=1); self.assertTrue(removed); self.assertTrue(backups[0].exists())
            for item in removed: self.assertFalse(Path(item).exists()); self.assertFalse(Path(item+'.sha256').exists())
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); old=root/'.stage_old'; active=root/'.stage_active'; fresh=root/'.stage_fresh'
            for p in (old,active,fresh): p.mkdir()
            (active/'ACTIVE_LOCK').write_text('busy'); os.utime(old,(1000,1000)); os.utime(active,(1000,1000)); os.utime(fresh,(9900,9900))
            removed=release_guard.cleanup_stale_staging(root,older_than_seconds=1000,now_timestamp=10000); self.assertIn(str(old),removed); self.assertTrue(active.exists()); self.assertTrue(fresh.exists())

    def test_exact_source_payload_never_silently_filters_legitimate_named_dirs(self):
        with tempfile.TemporaryDirectory() as td:
            src=Path(td)/'src'; dst=Path(td)/'dst'; src.mkdir()
            for rel in ('data/schema.py','media/codec.py','cache/key.py','uploads/validator.py'):
                p=src/rel; p.parent.mkdir(parents=True,exist_ok=True); p.write_text('x=1\n')
            release_guard.validate_exact_source_payload(src,['var']); release_guard.copy_source_without_protected(src,dst)
            for rel in ('data/schema.py','media/codec.py','cache/key.py','uploads/validator.py'): self.assertEqual((src/rel).read_bytes(),(dst/rel).read_bytes())

    def test_exact_source_payload_forbidden_state_or_binding_conflict_fails(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); (root/'.env.production').write_text('x')
            with self.assertRaises(release_guard.SafetyError): release_guard.validate_exact_source_payload(root,[])
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); (root/'var').mkdir(); (root/'var/code.py').write_text('x')
            with self.assertRaises(release_guard.SafetyError): release_guard.validate_exact_source_payload(root,['var'])

    def test_control_plane_rejects_broad_mode_and_symlink(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)/'control'; root.mkdir(); root.chmod(0o700); hook=root/'hook'; hook.write_text('#!/bin/sh\nexit 0\n'); hook.chmod(0o755)
            with self.assertRaises(release_guard.SafetyError): release_guard.validate_private_control_file(hook,root,'hook',executable=True)
            hook.chmod(0o700); self.assertEqual(hook,release_guard.validate_private_control_file(hook,root,'hook',executable=True))

class RecoveryCaptureTests(unittest.TestCase):
    def make_app(self,root):
        app=root/'app'; app.mkdir(); (app/'main.py').write_text("print('ok')\n"); (app/'var').mkdir(); (app/'var/runtime.db').write_text('private'); return app
    def test_clean_capture_private_only_with_backup_hash(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); app=self.make_app(root); recovery=root/'recovery'; status=recovery_capture.capture(app,recovery); self.assertEqual('CANDIDATE_READY_FOR_PRIVATE_AUDIT',status['state']); self.assertFalse(status['transfer_performed']); self.assertFalse(status['cron_or_deploy_worker_installed']); out=next(recovery.iterdir()); self.assertTrue((out/'PRIVATE_FULL_BACKUP.tar.gz').exists()); self.assertTrue((out/'PRIVATE_FULL_BACKUP.tar.gz.sha256').exists())
    def test_overlap_blocks_before_backup(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); app=self.make_app(root); rec=app/'recovery'
            with self.assertRaises(release_guard.SafetyError): recovery_capture.capture(app,rec)
            self.assertFalse(rec.exists())
    def test_alias_log_cookie_unknown_and_disguised_source_are_safe(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); app=self.make_app(root); rec=root/'r'; value='synthetic-secret-1234567890'; (app/'settings.py').write_text('api_hash='+repr(value)+'\n'); status=recovery_capture.capture(app,rec); self.assertEqual('CONTAMINATED_BLOCKED',status['state']); findings=(next(rec.iterdir())/'SCAN_FINDINGS_REDACTED.txt').read_text(); self.assertIn('API_HASH',findings); self.assertNotIn(value,findings)
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); app=self.make_app(root); rec=root/'r'; (app/'private.log').write_text('private'); (app/'cookies.txt').write_text('private'); status=recovery_capture.capture(app,rec); self.assertEqual('CANDIDATE_READY_FOR_PRIVATE_AUDIT',status['state']); manifest=json.loads((next(rec.iterdir())/'CANDIDATE_MANIFEST.json').read_text()); excluded={i['path'] for i in manifest['excluded']}; self.assertIn('private.log',excluded); self.assertIn('cookies.txt',excluded)
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); app=self.make_app(root); rec=root/'r'; (app/'photo.bin').write_bytes(b'binary'); self.assertEqual('CONTAMINATED_BLOCKED',recovery_capture.capture(app,rec)['state'])
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); app=self.make_app(root); rec=root/'r'; b=io.BytesIO();
            with zipfile.ZipFile(b,'w') as z: z.writestr('config.txt','BRIDGE_TOKEN=synthetic-zip-1234567890\n')
            (app/'notes.txt').write_bytes(b.getvalue()); self.assertEqual('CONTAMINATED_BLOCKED',recovery_capture.capture(app,rec)['state'])

class PrepareExecuteTests(unittest.TestCase):
    repository='Oleksii-debug/Telegram-ChatGPT-Bridge'
    def fake_prepare(self,root):
        repo=root/'repo'; repo.mkdir(); (repo/'.git').mkdir(); releases=root/'releases'; releases.mkdir()
        def fake_export(_r,_s,d): (d/'main.py').write_text('print(1)\n'); (d/'tests').mkdir(); (d/'tests/test_x.py').write_text('def test_x(): assert True\n')
        def fake_run(cmd,**kw):
            if 'venv' in cmd:
                p=Path(cmd[-1])/'bin/python'; p.parent.mkdir(parents=True); p.write_text('py'); p.chmod(0o700)
        return repo,releases,(mock.patch.object(deploy_release,'verify_approved_ref_policy',return_value='a'*40),mock.patch.object(deploy_release,'validate_python_311',return_value='3.11.9'),mock.patch.object(deploy_release,'git_export',side_effect=fake_export),mock.patch.object(deploy_release,'run',side_effect=fake_run),mock.patch.object(deploy_release,'command_output',return_value='3.11.9'))
    def test_prepare_hash_stable_and_metadata_has_no_runtime_timestamp(self):
        hashes=[]
        for _ in range(2):
            with tempfile.TemporaryDirectory() as td:
                repo,releases,p=self.fake_prepare(Path(td))
                with p[0],p[1],p[2],p[3],p[4]: prepared,meta,digest=deploy_release.prepare_versioned_release(repo=repo,sha='a'*40,approved_ref='main',repository_id=self.repository,releases_root=releases,python_executable='python3',runtime_entries=[])
                self.assertTrue(prepared.exists()); self.assertNotIn('generated_at',meta); hashes.append(digest)
        self.assertEqual(hashes[0],hashes[1])
    def test_wrong_python_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            exe=Path(td)/'python'; exe.write_text('x'); exe.chmod(0o700)
            with mock.patch.object(deploy_release,'command_output',return_value='3.12.1'):
                with self.assertRaises(release_guard.SafetyError): deploy_release.validate_python_311(str(exe))
    def test_exact_ref_head_required(self):
        with tempfile.TemporaryDirectory() as td:
            repo=Path(td); subprocess.run(['git','init','-q','-b','main'],cwd=repo,check=True); subprocess.run(['git','config','user.name','T'],cwd=repo,check=True); subprocess.run(['git','config','user.email','t@example.invalid'],cwd=repo,check=True); (repo/'a').write_text('1'); subprocess.run(['git','add','a'],cwd=repo,check=True); subprocess.run(['git','commit','-qm','one'],cwd=repo,check=True); old=subprocess.check_output(['git','rev-parse','HEAD'],cwd=repo,text=True).strip(); (repo/'a').write_text('2'); subprocess.run(['git','commit','-qam','two'],cwd=repo,check=True); head=subprocess.check_output(['git','rev-parse','HEAD'],cwd=repo,text=True).strip(); self.assertEqual(head,deploy_release.verify_approved_ref_policy(repo,head,'main'));
            with self.assertRaises(release_guard.SafetyError): deploy_release.verify_approved_ref_policy(repo,old,'main')

if __name__=='__main__': unittest.main()
