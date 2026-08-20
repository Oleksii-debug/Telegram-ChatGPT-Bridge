# -*- coding: utf-8 -*-
import hashlib, io, json, subprocess, tempfile, unittest, zipfile
from pathlib import Path
from tools import secret_scan

class SecretScanTests(unittest.TestCase):
    def make_repo(self):
        tmp=tempfile.TemporaryDirectory(); repo=Path(tmp.name)
        subprocess.run(["git","init","-q"],cwd=repo,check=True); subprocess.run(["git","config","user.name","Synthetic Test"],cwd=repo,check=True); subprocess.run(["git","config","user.email","synthetic@example.invalid"],cwd=repo,check=True)
        (repo/"README.md").write_text("synthetic test repository\n",encoding="utf-8"); subprocess.run(["git","add","README.md"],cwd=repo,check=True); subprocess.run(["git","commit","-qm","initial"],cwd=repo,check=True); return tmp,repo
    def commit_all(self,repo,message): subprocess.run(["git","add","-A","-f"],cwd=repo,check=True); subprocess.run(["git","commit","-qm",message],cwd=repo,check=True)
    def write_allowlist(self,repo,path,data):
        payload={"entries":[{"path":path,"sha256":hashlib.sha256(data).hexdigest(),"reason":"Synthetic reviewed non-secret fixture."}]}; (repo/secret_scan.ALLOWLIST_FILE).write_text(json.dumps(payload)+"\n",encoding="utf-8")
    def test_current_tree_matrix_rejects_policy_artifacts(self):
        tmp,repo=self.make_repo(); self.addCleanup(tmp.cleanup)
        for name in (".env.production","private.key","BRIDGE_KEYS_SECRET.txt","Credentials.JSON"): (repo/name).write_text("safe fixture\n",encoding="utf-8")
        variable="TG_"+"API_HASH"; value="synthetic-value-1234567890"; structured_variable="GOOGLE_DRIVE_"+"CLIENT_SECRET"; structured="synthetic-json-1234567890"
        (repo/"config.txt").write_text(variable+"="+value+"\n",encoding="utf-8"); (repo/"config.json").write_text('{"'+structured_variable.lower()+'": "'+structured+'"}\n',encoding="utf-8"); self.commit_all(repo,"add synthetic policy violations")
        joined="\n".join(secret_scan.scan_current_tree(repo))
        for token in (".env.production","private.key","BRIDGE_KEYS_SECRET.txt","Credentials.JSON",variable,structured_variable): self.assertIn(token,joined)
        self.assertNotIn(value,joined); self.assertNotIn(structured,joined)
    def test_history_detects_removed_canary(self):
        tmp,repo=self.make_repo(); self.addCleanup(tmp.cleanup); variable="BRIDGE_"+"TOKEN"; value="synthetic-history-1234567890"; leak=repo/"temporary-config.txt"; leak.write_text(variable+"="+value+"\n",encoding="utf-8"); self.commit_all(repo,"introduce synthetic canary"); leak.unlink(); self.commit_all(repo,"remove synthetic canary")
        current="\n".join(secret_scan.scan_current_tree(repo)); history="\n".join(secret_scan.scan_history(repo)); self.assertNotIn(variable,current); self.assertIn(variable,history); self.assertNotIn(value,history)
    def test_history_detects_commit_message_canary(self):
        tmp,repo=self.make_repo(); self.addCleanup(tmp.cleanup); variable="SETUP_"+"KEY"; value="synthetic-commit-message-1234567890"; subprocess.run(["git","commit","--allow-empty","-qm",variable+"="+value],cwd=repo,check=True); history="\n".join(secret_scan.scan_history(repo)); self.assertIn(variable,history); self.assertIn("<commit-message>",history); self.assertNotIn(value,history)
    def test_allowlisted_oversized_text_cannot_bypass_secret_content(self):
        tmp,repo=self.make_repo(); self.addCleanup(tmp.cleanup); variable="BRIDGE_"+"TOKEN"; value="synthetic-oversized-1234567890"; data=(b"A"*5_100_000)+("\n"+variable+"="+value+"\n").encode(); path="large.txt"; (repo/path).write_bytes(data); self.write_allowlist(repo,path,data); subprocess.run(["git","add","-f",path,secret_scan.ALLOWLIST_FILE],cwd=repo,check=True); joined="\n".join(secret_scan.scan_current_tree(repo)); self.assertIn(variable,joined); self.assertNotIn(value,joined)
    def test_allowlisted_binary_cannot_bypass_private_key_marker(self):
        tmp,repo=self.make_repo(); self.addCleanup(tmp.cleanup); marker=("-----BEGIN "+"OPENSSH "+"PRIVATE "+"KEY-----").encode("ascii"); data=b"\x00BIN\x01"+marker+b"\x02END"; path="fixture.bin"; (repo/path).write_bytes(data); self.write_allowlist(repo,path,data); subprocess.run(["git","add","-f",path,secret_scan.ALLOWLIST_FILE],cwd=repo,check=True); joined="\n".join(secret_scan.scan_current_tree(repo)); self.assertIn("private key marker",joined)
    def test_allowlisted_archive_cannot_bypass_prohibited_member(self):
        tmp,repo=self.make_repo(); self.addCleanup(tmp.cleanup); buf=io.BytesIO(); variable="BRIDGE_"+"TOKEN"; value="synthetic-archive-value-1234567890"
        with zipfile.ZipFile(buf,"w") as archive: archive.writestr("nested/.env.production",variable+"="+value+"\n")
        data=buf.getvalue(); path="baseline.zip"; (repo/path).write_bytes(data); self.write_allowlist(repo,path,data); subprocess.run(["git","add","-f",path,secret_scan.ALLOWLIST_FILE],cwd=repo,check=True); joined="\n".join(secret_scan.scan_current_tree(repo)); self.assertIn("forbidden file",joined); self.assertIn(".env.production",joined); self.assertNotIn(value,joined)
    def test_supported_nested_archives_are_recursively_scanned(self):
        tmp,repo=self.make_repo(); self.addCleanup(tmp.cleanup); inner=io.BytesIO(); variable="TG_"+"API_HASH"; value="synthetic-nested-1234567890"
        with zipfile.ZipFile(inner,"w") as archive: archive.writestr("config.txt",variable+"="+value+"\n")
        outer=io.BytesIO();
        with zipfile.ZipFile(outer,"w") as archive: archive.writestr("inner.zip",inner.getvalue())
        (repo/"outer.zip").write_bytes(outer.getvalue()); subprocess.run(["git","add","-f","outer.zip"],cwd=repo,check=True); joined="\n".join(secret_scan.scan_current_tree(repo)); self.assertIn(variable,joined); self.assertNotIn(value,joined)
    def test_archive_path_traversal_fails_closed(self):
        tmp,repo=self.make_repo(); self.addCleanup(tmp.cleanup); buf=io.BytesIO();
        with zipfile.ZipFile(buf,"w") as archive: archive.writestr("../escape.txt","safe")
        (repo/"bad.zip").write_bytes(buf.getvalue()); subprocess.run(["git","add","-f","bad.zip"],cwd=repo,check=True); self.assertIn("unsafe archive member path","\n".join(secret_scan.scan_current_tree(repo)))
    def test_reviewed_hash_allowlist_allows_nonsecret_binary_only(self):
        tmp,repo=self.make_repo(); self.addCleanup(tmp.cleanup); data=b"\x00synthetic-nonsecret-binary\x01"; path="fixture.bin"; (repo/path).write_bytes(data); self.write_allowlist(repo,path,data); subprocess.run(["git","add","-f",path,secret_scan.ALLOWLIST_FILE],cwd=repo,check=True); self.assertNotIn(path,"\n".join(secret_scan.scan_current_tree(repo)))
    def test_placeholder_rules_are_anchored(self):
        positives=("<SECRET>","${{ secrets.EXAMPLE }}","${TG_API_HASH}","$TG_API_HASH","replace-me"); negatives=("prefix-${HOME}-suffix","abc${TG_API_HASH}","${TG_API_HASH}-suffix","synthetic-real-looking-value")
        for value in positives: self.assertTrue(secret_scan.is_placeholder(value),value)
        for value in negatives: self.assertFalse(secret_scan.is_placeholder(value),value)
        variable="TG_"+"API_HASH"; joined="\n".join(secret_scan.scan_text(variable+"=prefix-${HOME}-suffix\n","config.txt","test")); self.assertIn(variable,joined)
    def test_shallow_repository_fails_closed(self):
        source_tmp,source=self.make_repo(); self.addCleanup(source_tmp.cleanup); (source/"second.txt").write_text("second\n",encoding="utf-8"); self.commit_all(source,"second"); clone_tmp=tempfile.TemporaryDirectory(); self.addCleanup(clone_tmp.cleanup); clone=Path(clone_tmp.name)/"clone"; subprocess.run(["git","clone","-q","--depth","1",source.resolve().as_uri(),str(clone)],check=True); self.assertTrue(secret_scan._is_shallow(clone)); self.assertIn("repository checkout is shallow","\n".join(secret_scan.scan_history(clone)))
if __name__=="__main__": unittest.main()
