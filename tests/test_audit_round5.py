# -*- coding: utf-8 -*-
import hashlib
import io
import json
import os
import stat
import subprocess
import tarfile
import tempfile
import unittest
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from tools import secret_scan
from ops import deploy_release, release_guard


class ContainerHardeningTests(unittest.TestCase):
    def zip_bytes(self, member, content):
        b=io.BytesIO()
        with zipfile.ZipFile(b,'w',zipfile.ZIP_DEFLATED) as z: z.writestr(member,content)
        return b.getvalue()

    def test_prefixed_sfx_zip_is_parser_detected_before_allowlist(self):
        variable='BRIDGE_'+'TOKEN'; value='synthetic-prefixed-1234567890'
        data=b'MZ'+b'X'*137+self.zip_bytes('config.txt', variable+'='+value+'\n')
        allow={('reviewed.bin',hashlib.sha256(data).hexdigest()):'reviewed synthetic binary'}
        findings='\n'.join(secret_scan._scan_bytes(data,'reviewed.bin','test',allow))
        self.assertIn(variable,findings); self.assertNotIn(value,findings)

    def test_nested_prefixed_zip_is_scanned(self):
        variable='TG_'+'API_HASH'; value='synthetic-nested-sfx-1234567890'
        inner=b'SFX-STUB'+self.zip_bytes('secret.txt',variable+'='+value+'\n')
        outer=self.zip_bytes('payload.bin',inner)
        findings='\n'.join(secret_scan._scan_bytes(outer,'outer.zip','test',{}))
        self.assertIn(variable,findings); self.assertNotIn(value,findings)

    def test_polyglot_zip_tar_fails_closed(self):
        t=io.BytesIO()
        with tarfile.open(fileobj=t,mode='w') as archive:
            data=b'safe'; info=tarfile.TarInfo('a.txt'); info.size=len(data); archive.addfile(info,io.BytesIO(data))
        poly=t.getvalue()+self.zip_bytes('b.txt','safe')
        kind,error=secret_scan._resolved_archive_kind('poly.bin',poly)
        self.assertIsNone(kind); self.assertIn('ambiguous/polyglot',error)

    def test_zip_symlink_metadata_fails_closed(self):
        b=io.BytesIO(); info=zipfile.ZipInfo('link'); info.create_system=3
        info.external_attr=(stat.S_IFLNK|0o777)<<16
        with zipfile.ZipFile(b,'w') as z: z.writestr(info,'target')
        findings='\n'.join(secret_scan._scan_bytes(b.getvalue(),'special.zip','test',{}))
        self.assertIn('zip special member rejected',findings)


class ExactPayloadAndControlTests(unittest.TestCase):
    def test_legitimate_named_source_directories_are_not_silently_filtered(self):
        with tempfile.TemporaryDirectory() as td:
            src=Path(td)/'src'; dst=Path(td)/'dst'; src.mkdir()
            for rel in ('data/schema.py','media/codec.py','cache/keys.py','uploads/validator.py'):
                p=src/rel; p.parent.mkdir(parents=True,exist_ok=True); p.write_text('x=1\n')
            release_guard.validate_exact_source_payload(src,['var'])
            release_guard.copy_source_without_protected(src,dst)
            for rel in ('data/schema.py','media/codec.py','cache/keys.py','uploads/validator.py'):
                self.assertEqual((src/rel).read_bytes(),(dst/rel).read_bytes())

    def test_tracked_secret_state_and_runtime_binding_conflict_hard_fail(self):
        with tempfile.TemporaryDirectory() as td:
            src=Path(td); (src/'.env.production').write_text('placeholder\n')
            with self.assertRaises(release_guard.SafetyError): release_guard.validate_exact_source_payload(src,[])
        with tempfile.TemporaryDirectory() as td:
            src=Path(td); (src/'var').mkdir(); (src/'var/state.py').write_text('x=1\n')
            with self.assertRaises(release_guard.SafetyError): release_guard.validate_exact_source_payload(src,['var'])

    def test_control_root_and_hook_permissions_fail_closed(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)/'control'; root.mkdir(); root.chmod(0o700)
            hook=root/'hook'; hook.write_text('#!/bin/sh\nexit 0\n'); hook.chmod(0o755)
            with self.assertRaises(release_guard.SafetyError): release_guard.validate_private_control_file(hook,root,'hook',executable=True)
            hook.chmod(0o700); self.assertEqual(hook,release_guard.validate_private_control_file(hook,root,'hook',executable=True))

    def test_approved_ref_requires_exact_head(self):
        with tempfile.TemporaryDirectory() as td:
            repo=Path(td); subprocess.run(['git','init','-q','-b','main'],cwd=repo,check=True)
            subprocess.run(['git','config','user.name','Test'],cwd=repo,check=True); subprocess.run(['git','config','user.email','t@example.invalid'],cwd=repo,check=True)
            (repo/'a').write_text('1'); subprocess.run(['git','add','a'],cwd=repo,check=True); subprocess.run(['git','commit','-qm','one'],cwd=repo,check=True)
            old=subprocess.check_output(['git','rev-parse','HEAD'],cwd=repo,text=True).strip()
            (repo/'a').write_text('2'); subprocess.run(['git','commit','-qam','two'],cwd=repo,check=True)
            head=subprocess.check_output(['git','rev-parse','HEAD'],cwd=repo,text=True).strip()
            self.assertEqual(head,deploy_release.verify_approved_ref_policy(repo,head,'main'))
            with self.assertRaises(release_guard.SafetyError): deploy_release.verify_approved_ref_policy(repo,old,'main')


class PrepareExecuteTests(unittest.TestCase):
    repository='Oleksii-debug/Telegram-ChatGPT-Bridge'

    def fake_prepare(self, root):
        repo=root/'repo'; repo.mkdir(); (repo/'.git').mkdir(); releases=root/'releases'; releases.mkdir()
        def fake_export(_repo,_sha,destination):
            (destination/'main.py').write_text('print(1)\n'); (destination/'tests').mkdir(); (destination/'tests/test_x.py').write_text('def test_x(): assert True\n')
        def fake_run(command,**kwargs):
            if 'venv' in command:
                v=Path(command[-1]); p=v/'bin/python'; p.parent.mkdir(parents=True); p.write_text('synthetic-python\n'); p.chmod(0o700)
        patches=(mock.patch.object(deploy_release,'verify_approved_ref_policy',return_value='a'*40),
                 mock.patch.object(deploy_release,'validate_python_311',return_value='3.11.9'),
                 mock.patch.object(deploy_release,'git_export',side_effect=fake_export),
                 mock.patch.object(deploy_release,'run',side_effect=fake_run),
                 mock.patch.object(deploy_release,'command_output',return_value='3.11.9'))
        return repo,releases,patches

    def test_prepare_manifest_hash_is_stable_and_execute_does_not_rebuild(self):
        hashes=[]
        for _ in range(2):
            with tempfile.TemporaryDirectory() as td:
                root=Path(td); repo,releases,patches=self.fake_prepare(root)
                with patches[0],patches[1],patches[2],patches[3],patches[4]:
                    prepared,meta,digest=deploy_release.prepare_versioned_release(repo=repo,sha='a'*40,approved_ref='main',repository_id=self.repository,releases_root=releases,python_executable='python3',runtime_entries=[])
                self.assertTrue(prepared.is_dir()); self.assertNotIn('generated_at',meta); hashes.append(digest)
        self.assertEqual(hashes[0],hashes[1])

    def build_execution_layout(self, root):
        repo=root/'repo'; repo.mkdir(); (repo/'.git').mkdir(); releases=root/'releases'; releases.mkdir(); prepared_parent=releases/'.prepared'; prepared_parent.mkdir()
        old_sha='1'*40; new_sha='2'*40; old=releases/old_sha; old.mkdir(); (old/'code.txt').write_text('old')
        state=root/'state'; (state/'var').mkdir(parents=True); (state/'var/db').write_text('state')
        release_guard.attach_persistent_state(old,state,['var']); active=root/'active'; active.symlink_to(old)
        prepared=prepared_parent/'candidate'; prepared.mkdir(); (prepared/'code.txt').write_text('new')
        payload=deploy_release._payload_manifest_without_meta(prepared)
        meta={'schema_version':1,'repository':self.repository,'approved_ref':'main','sha':new_sha,'configured_python_version':'3.11.9','python_version':'3.11.9','source_manifest_sha256':'a'*64,'requirements_lock_sha256':None,'payload_manifest_sha256':release_guard.sha256_json(payload),'runtime_entries':['var'],'persistent_state_mode':'shared_external'}
        mh=release_guard.sha256_json(meta); release_guard.write_json_atomic(prepared/deploy_release.PREPARED_META,meta,mode=0o644)
        control=root/'control'; control.mkdir(); control.chmod(0o700)
        runtime=control/'runtime.json'; runtime.write_text(json.dumps({'paths':['var']})); runtime.chmod(0o600)
        for n in ('quiesce','resume','restart','identity','unauth','auth'):
            p=control/n; p.write_text('#!/bin/sh\nexit 0\n'); p.chmod(0o700)
        now=datetime.now(timezone.utc); approval=control/'approval.json'; approval.write_text(json.dumps({'approved':True,'approved_sha':new_sha,'repository':self.repository,'approved_ref':'main','release_manifest_sha256':mh,'ci_run_id':'10','audit_id':'audit-10','approval_id':'a1','nonce':'n1','issued_at':now.isoformat(),'expires_at':(now+timedelta(hours=1)).isoformat(),'data_schema_change':False})); approval.chmod(0o600)
        return locals()

    def kwargs(self,L):
        c=L['control']
        return dict(repo=L['repo'],prepared_release=L['prepared'],repository_id=self.repository,approved_ref='main',ci_run_id='10',audit_id='audit-10',active_link=L['active'],releases_root=L['releases'],backup_root=L['root']/'backups',persistent_state_root=L['state'],runtime_manifest=L['runtime'],control_root=c,approval_file=L['approval'],approval_consumption_root=c/'consumed',quiesce_hook=c/'quiesce',resume_hook=c/'resume',restart_hook=c/'restart',identity_hook=c/'identity',unauth_hook=c/'unauth',auth_hook=c/'auth',status_file=c/'status.json')

    def test_execute_success_requires_resume_before_deployed(self):
        with tempfile.TemporaryDirectory() as td:
            L=self.build_execution_layout(Path(td)); events=[]
            def hook(_p,name,**_kw): events.append(name)
            with mock.patch.object(deploy_release,'verify_approved_ref_policy',return_value=L['new_sha']), mock.patch.object(deploy_release,'run_private_hook',side_effect=hook), mock.patch.object(deploy_release,'verify_running_release',side_effect=lambda _p,sha:events.append('identity:'+sha)), mock.patch.object(deploy_release,'backup_active',return_value=L['root']/'cb.tar.gz'), mock.patch.object(deploy_release,'backup_persistent_state',return_value=L['root']/'sb.tar.gz'), mock.patch.object(deploy_release,'apply_retention',return_value=[]), mock.patch.object(deploy_release,'apply_backup_retention',return_value=[]), mock.patch.object(deploy_release,'cleanup_stale_staging',return_value=[]):
                rc=deploy_release.execute_prepared_release(**self.kwargs(L))
            self.assertEqual(0,rc); self.assertIn('resume/unquiesce',events); self.assertLess(events.index('authenticated smoke'),events.index('resume/unquiesce'))
            self.assertEqual('DEPLOYED',json.loads((L['control']/'status.json').read_text())['state'])

    def test_failure_rolls_back_and_resumes_old_release(self):
        with tempfile.TemporaryDirectory() as td:
            L=self.build_execution_layout(Path(td)); events=[]
            def hook(_p,name,**_kw):
                events.append(name)
                if name=='authenticated smoke': raise release_guard.SafetyError('synthetic')
            with mock.patch.object(deploy_release,'verify_approved_ref_policy',return_value=L['new_sha']), mock.patch.object(deploy_release,'run_private_hook',side_effect=hook), mock.patch.object(deploy_release,'verify_running_release',return_value=None), mock.patch.object(deploy_release,'backup_active',return_value=L['root']/'cb.tar.gz'), mock.patch.object(deploy_release,'backup_persistent_state',return_value=L['root']/'sb.tar.gz'):
                rc=deploy_release.execute_prepared_release(**self.kwargs(L))
            self.assertEqual(20,rc); self.assertIn('rollback resume/unquiesce',events); self.assertEqual(L['old'].resolve(),L['active'].resolve())
            self.assertEqual('ROLLED_BACK',json.loads((L['control']/'status.json').read_text())['state'])

    def test_prepared_payload_change_invalidates_prior_approval(self):
        with tempfile.TemporaryDirectory() as td:
            L=self.build_execution_layout(Path(td)); (L['prepared']/'code.txt').write_text('tampered')
            with self.assertRaises(release_guard.SafetyError): deploy_release.verify_prepared_release(L['prepared'],json.loads(L['approval'].read_text())['release_manifest_sha256'])


if __name__=='__main__': unittest.main()
