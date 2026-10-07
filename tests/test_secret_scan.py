# -*- coding: utf-8 -*-
import hashlib, json, subprocess, tempfile, unittest, zipfile
from pathlib import Path
from tools import secret_scan
class SecretScanTests(unittest.TestCase):
    def make_repo(self):
        tmp=tempfile.TemporaryDirectory(); repo=Path(tmp.name)
        subprocess.run(['git','init','-q'],cwd=repo,check=True); subprocess.run(['git','config','user.name','Synthetic Test'],cwd=repo,check=True); subprocess.run(['git','config','user.email','synthetic@example.invalid'],cwd=repo,check=True)
        (repo/'README.md').write_text('synthetic test repository\n',encoding='utf-8'); subprocess.run(['git','add','README.md'],cwd=repo,check=True); subprocess.run(['git','commit','-qm','initial'],cwd=repo,check=True); return tmp,repo
    def commit_all(self,repo,message):subprocess.run(['git','add','-A','-f'],cwd=repo,check=True); subprocess.run(['git','commit','-qm',message],cwd=repo,check=True)
    def test_current_tree_matrix_rejects_policy_artifacts(self):
        tmp,repo=self.make_repo(); self.addCleanup(tmp.cleanup); env_name='.env.production'; key_name='private.key'; designated='BRIDGE_KEYS_SECRET.txt'; case_name='Credentials.JSON'
        (repo/env_name).write_text('SAFE_SYNTHETIC=1\n'); (repo/key_name).write_text('synthetic-key-file\n'); (repo/designated).write_text('synthetic-designated-file\n'); (repo/case_name).write_text('{}\n')
        variable='TG_API_HASH'; value='synthetic-value-1234567890'; structured_variable='GOOGLE_DRIVE_'+'CLIENT_SECRET'; structured='synthetic-json-1234567890'; (repo/'config.txt').write_text(variable+'='+value+'\n'); (repo/'config.json').write_text('{"'+structured_variable.lower()+'": "'+structured+'"}\n'); self.commit_all(repo,'add synthetic policy violations')
        joined='\n'.join(secret_scan.scan_current_tree(repo));
        for name in (env_name,key_name,designated,case_name,variable,structured_variable): self.assertIn(name,joined)
        self.assertNotIn(value,joined); self.assertNotIn(structured,joined)
    def test_history_detects_removed_canary(self):
        tmp,repo=self.make_repo(); self.addCleanup(tmp.cleanup); variable='BRIDGE_TOKEN'; value='synthetic-history-1234567890'; leak=repo/'temporary-config.txt'; leak.write_text(variable+'='+value+'\n'); self.commit_all(repo,'introduce synthetic canary'); leak.unlink(); self.commit_all(repo,'remove synthetic canary')
        current='\n'.join(secret_scan.scan_current_tree(repo)); history='\n'.join(secret_scan.scan_history(repo)); self.assertNotIn(variable,current); self.assertIn(variable,history); self.assertNotIn(value,history)
    def test_history_detects_commit_message_canary(self):
        tmp,repo=self.make_repo(); self.addCleanup(tmp.cleanup); variable='SETUP_KEY'; value='synthetic-commit-message-1234567890'; subprocess.run(['git','commit','--allow-empty','-qm',variable+'='+value],cwd=repo,check=True)
        history='\n'.join(secret_scan.scan_history(repo)); self.assertIn(variable,history); self.assertIn('<commit-message>',history); self.assertNotIn(value,history)
    def test_archive_and_oversized_fail_closed(self):
        tmp,repo=self.make_repo(); self.addCleanup(tmp.cleanup); archive=repo/'baseline.zip';
        with zipfile.ZipFile(archive,'w') as zf: zf.writestr('config.txt','synthetic-private-content')
        oversized=repo/'large.txt'; oversized.write_bytes(b'A'*(secret_scan.MAX_BLOB_BYTES+1)); subprocess.run(['git','add','-f',archive.name,oversized.name],cwd=repo,check=True); findings='\n'.join(secret_scan.scan_current_tree(repo)); self.assertIn('archive/container object',findings); self.assertIn(archive.name,findings); self.assertIn('oversized object',findings); self.assertIn(oversized.name,findings)
    def test_reviewed_hash_allowlist_allows_nonsecret_binary(self):
        tmp,repo=self.make_repo(); self.addCleanup(tmp.cleanup); artifact=repo/'fixture.bin'; data=b'\x00synthetic-nonsecret-binary\x01'; artifact.write_bytes(data); digest=hashlib.sha256(data).hexdigest(); allow={'entries':[{'path':artifact.name,'sha256':digest,'reason':'Synthetic non-secret regression fixture.'}]}; (repo/secret_scan.ALLOWLIST_FILE).write_text(json.dumps(allow)+'\n'); subprocess.run(['git','add','-f',artifact.name,secret_scan.ALLOWLIST_FILE],cwd=repo,check=True); findings='\n'.join(secret_scan.scan_current_tree(repo)); self.assertNotIn(artifact.name,findings)
    def test_shallow_repository_fails_closed(self):
        source_tmp,source=self.make_repo(); self.addCleanup(source_tmp.cleanup); (source/'second.txt').write_text('second\n'); self.commit_all(source,'second'); clone_tmp=tempfile.TemporaryDirectory(); self.addCleanup(clone_tmp.cleanup); clone=Path(clone_tmp.name)/'clone'; subprocess.run(['git','clone','-q','--depth','1',source.resolve().as_uri(),str(clone)],check=True); self.assertTrue(secret_scan._is_shallow(clone)); self.assertIn('repository checkout is shallow','\n'.join(secret_scan.scan_history(clone)))
    def test_placeholder_value_is_allowed(self):
        self.assertTrue(secret_scan.is_placeholder('<SECRET>')); self.assertTrue(secret_scan.is_placeholder('${{ secrets.EXAMPLE }}')); self.assertFalse(secret_scan.is_placeholder('synthetic-real-looking-value'))
if __name__=='__main__':unittest.main()
