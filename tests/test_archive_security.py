from __future__ import annotations
import tempfile, unittest, zipfile
from pathlib import Path
from bridge.archive import ArchiveBuilder, ArchiveLimits, safe_archive_name
from bridge.errors import BridgeError
from bridge.storage import FileRecordStore

class ArchiveTests(unittest.TestCase):
    def setUp(self): self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup); r=Path(self.tmp.name); self.store=FileRecordStore(r/'state/db',r/'files'); self.builder=ArchiveBuilder(files=self.store,output_dir=r/'tmp')
    def add(self,name,data=b'x'):
        p=self.store.root/(str(len(list(self.store.root.iterdir())))+'_'+name.replace('/','_').replace('\\','_')+'.src'); p.write_bytes(data); return self.store.add(p,name=name)
    def test_valid_zip_crc(self):
        a=self.add('one.txt',b'abc'); z=self.builder.build([a.file_ref]); self.assertEqual(z.mime_type,'application/zip'); self.assertEqual(zipfile.ZipFile(z.path).testzip(),None)
    def test_member_traversal_removed(self):
        a=self.add('../../evil.txt'); z=self.builder.build([a.file_ref]); names=zipfile.ZipFile(z.path).namelist(); self.assertEqual(names,['evil.txt']); self.assertNotIn('..',names[0])
    def test_absolute_name_removed(self): self.assertEqual(safe_archive_name('/etc/passwd'),'passwd')
    def test_windows_path_removed(self): self.assertEqual(safe_archive_name('C:\\x\\evil.txt'),'evil.txt')
    def test_duplicate_names_resolved(self):
        a=self.add('same.txt',b'a'); b=self.add('same.txt',b'b'); names=zipfile.ZipFile(self.builder.build([a.file_ref,b.file_ref]).path).namelist(); self.assertEqual(len(set(x.casefold() for x in names)),2)
    def test_unicode_name_preserved(self):
        a=self.add('файл 🦔.txt'); self.assertEqual(zipfile.ZipFile(self.builder.build([a.file_ref]).path).namelist()[0],'файл 🦔.txt')
    def test_missing_ref_fails(self):
        with self.assertRaises(BridgeError) as cm: self.builder.build(['A'*32]); self.assertEqual(cm.exception.code,'file_not_found')
    def test_member_limit(self):
        b=ArchiveBuilder(files=self.store,output_dir=Path(self.tmp.name)/'tmp2',limits=ArchiveLimits(max_members=1)); a=self.add('a'); c=self.add('b')
        with self.assertRaises(BridgeError) as cm: b.build([a.file_ref,c.file_ref]); self.assertEqual(cm.exception.code,'zip_member_limit')
    def test_total_size_limit(self):
        b=ArchiveBuilder(files=self.store,output_dir=Path(self.tmp.name)/'tmp3',limits=ArchiveLimits(max_total_bytes=1)); a=self.add('a',b'ab')
        with self.assertRaises(BridgeError) as cm: b.build([a.file_ref]); self.assertEqual(cm.exception.code,'zip_size_limit')
    def test_archive_file_private_mode(self):
        a=self.add('a'); z=self.builder.build([a.file_ref]); self.assertEqual(Path(z.path).stat().st_mode & 0o077,0)

if __name__=='__main__': unittest.main()
