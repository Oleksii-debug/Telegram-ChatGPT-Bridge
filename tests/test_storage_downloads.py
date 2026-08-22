from __future__ import annotations
import json, os, sqlite3, tempfile, unittest
from pathlib import Path

from bridge.downloads import DownloadLimits, DownloadManager, safe_filename
from bridge.errors import BridgeError
from bridge.storage import CheckpointStore, DownloadItem, FileRecordStore

class FakeBackend:
    def __init__(self, fail_first=False, alt=False): self.calls=0; self.fail_first=fail_first; self.alt=alt
    def download_media(self,**kw):
        self.calls+=1
        if self.fail_first and self.calls==1: raise BridgeError("generic",status=502,code="telegram_rpc_error")
        p=Path(kw['destination']); q=p.with_name(p.name+".alt") if self.alt else p; q.write_bytes(b"abc"); return {"path":str(q)}

class StorageDownloadTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup); root=Path(self.tmp.name)
        self.files=FileRecordStore(root/'state/files.db',root/'files'); self.cps=CheckpointStore(root/'state/jobs.db'); self.backend=FakeBackend(); self.dm=DownloadManager(backend=self.backend,files=self.files,checkpoints=self.cps,staging_dir=root/'tmp')
    def item(self,ident='i1',ref='tg_1_0123456789abcdefabcd',size=3): return DownloadItem(ident,'1',1,ref,'a.txt','text/plain',size,None)
    def test_file_ref_is_opaque_not_path(self):
        p=self.files.root/'x.txt'; p.write_text('abc'); r=self.files.add(p,name='x.txt'); self.assertNotIn('x.txt',r.file_ref); self.assertNotIn('/',r.file_ref)
    def test_file_public_metadata_excludes_path(self):
        p=self.files.root/'x.txt'; p.write_text('abc'); self.assertNotIn('path',self.files.add(p,name='x.txt').public_metadata())
    def test_same_size_content_tamper_fails_lookup(self):
        p=self.files.root/'tamper.txt'; p.write_bytes(b'abc'); r=self.files.add(p,name='tamper.txt'); p.write_bytes(b'xyz'); self.assertIsNone(self.files.get(r.file_ref))
    def test_arbitrary_path_not_file_ref(self): self.assertIsNone(self.files.get('../../etc/passwd'))
    def test_absolute_path_not_file_ref(self): self.assertIsNone(self.files.get('/etc/passwd'))
    def test_symlink_registration_fails(self):
        t=self.files.root/'t'; t.write_text('a'); l=self.files.root/'l'; l.symlink_to(t)
        with self.assertRaises(BridgeError): self.files.add(l,name='l')
    def test_hardlink_registration_fails(self):
        a=self.files.root/'a'; b=self.files.root/'b'; a.write_text('a'); os.link(a,b)
        with self.assertRaises(BridgeError): self.files.add(a,name='a')
    def test_single_download(self): self.assertEqual(self.dm.start_single(self.item())['size'],3)
    def test_expected_size_mismatch(self):
        with self.assertRaises(BridgeError) as cm: self.dm.start_single(self.item(size=4))
        self.assertEqual(cm.exception.code,'file_size_mismatch')
    def test_bulk_deduplicates_same_source(self):
        r=self.dm.start_bulk([self.item('a'),self.item('b')]); self.assertEqual(len(r['files']),1); self.assertEqual(self.backend.calls,1)
    def test_bulk_file_cap(self):
        dm=DownloadManager(backend=self.backend,files=self.files,checkpoints=self.cps,staging_dir=Path(self.tmp.name)/'tmp2',limits=DownloadLimits(max_bulk_files=1))
        with self.assertRaises(BridgeError) as cm: dm.start_bulk([self.item('a','tg_1_0123456789abcdefabcd'),self.item('b','tg_2_0123456789abcdefabcd')])
        self.assertEqual(cm.exception.code,'bulk_file_limit')
    def test_resume_retries_pending_failure(self):
        b=FakeBackend(fail_first=True); dm=DownloadManager(backend=b,files=self.files,checkpoints=self.cps,staging_dir=Path(self.tmp.name)/'tmp3')
        job=self.cps.create([self.item()]); first=dm.resume(job); self.assertEqual(first['status'],'failed'); second=dm.resume(job); self.assertEqual(second['status'],'complete'); self.assertEqual(b.calls,2)
    def test_completed_resume_does_not_redownload(self):
        job=self.cps.create([self.item()]); self.dm.resume(job); calls=self.backend.calls; self.dm.resume(job); self.assertEqual(self.backend.calls,calls)
    def test_checkpoint_corruption_fails_closed(self):
        job=self.cps.create([self.item()])
        with sqlite3.connect(str(self.cps.db_path)) as c: c.execute("UPDATE download_jobs SET payload_json='{}' WHERE job_id=?",(job,)); c.commit()
        with self.assertRaises(BridgeError) as cm: self.cps.load(job)
        self.assertEqual(cm.exception.code,'checkpoint_corrupt')
    def test_checkpoint_hash_corruption_fails_closed(self):
        job=self.cps.create([self.item()])
        with sqlite3.connect(str(self.cps.db_path)) as c: c.execute("UPDATE download_jobs SET payload_sha256='0' WHERE job_id=?",(job,)); c.commit()
        with self.assertRaises(BridgeError): self.cps.load(job)
    def test_alt_backend_staging_path_is_cleaned_after_move(self):
        b=FakeBackend(alt=True); staging=Path(self.tmp.name)/'tmp4'; dm=DownloadManager(backend=b,files=self.files,checkpoints=self.cps,staging_dir=staging); dm.start_single(self.item()); self.assertEqual(list(staging.iterdir()),[])
    def test_safe_filename_traversal(self): self.assertEqual(safe_filename('../../evil.txt'),'evil.txt')
    def test_safe_filename_windows(self): self.assertEqual(safe_filename('..\\evil?.txt'),'evil_.txt')
    def test_private_directory_mode_owner_only(self): self.assertEqual(self.files.root.stat().st_mode & 0o077,0)

if __name__=='__main__': unittest.main()
