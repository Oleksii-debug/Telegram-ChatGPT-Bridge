import os
import shutil
import sqlite3
import stat
import tarfile
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from ops import sqlite_state_backup as sb


def private_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    path.chmod(0o700)


def make_wal_db(path: Path, table: str = 'events') -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.parent.chmod(0o700)
    con = sqlite3.connect(path, isolation_level=None, timeout=5)
    con.execute('PRAGMA journal_mode=WAL')
    con.execute('PRAGMA synchronous=FULL')
    con.execute('PRAGMA wal_autocheckpoint=0')
    con.execute(f'CREATE TABLE IF NOT EXISTS {table}(id INTEGER PRIMARY KEY, value TEXT NOT NULL)')
    con.execute('PRAGMA wal_checkpoint(TRUNCATE)')
    path.chmod(0o600)
    return con


class SQLiteStateBackupTests(unittest.TestCase):
    def test_committed_row_resident_in_wal_is_in_self_contained_snapshot(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            state = root/'state'; private_dir(state)
            db = state/'writes.sqlite'
            writer = make_wal_db(db)
            reader = sqlite3.connect(db)
            try:
                writer.execute("INSERT INTO events(value) VALUES('committed-in-wal')")
                wal = Path(str(db)+'-wal')
                self.assertTrue(wal.exists())
                self.assertGreater(wal.stat().st_size, 0)
                wal.chmod(0o600)
                shm = Path(str(db)+'-shm')
                if shm.exists(): shm.chmod(0o600)
                snap = root/'snapshot'
                report = sb.snapshot_persistent_state(state, snap)
                self.assertEqual(('writes.sqlite',), report.sqlite_databases)
                self.assertTrue(any(x.endswith('-wal') for x in report.skipped_sqlite_sidecars))
                self.assertFalse(Path(str(snap/'writes.sqlite')+'-wal').exists())
                self.assertFalse(Path(str(snap/'writes.sqlite')+'-shm').exists())
                restored = sqlite3.connect(snap/'writes.sqlite')
                try:
                    self.assertEqual([('committed-in-wal',)], restored.execute('SELECT value FROM events').fetchall())
                    self.assertEqual('ok', restored.execute('PRAGMA quick_check').fetchone()[0])
                finally:
                    restored.close()
            finally:
                reader.close(); writer.close()

    def test_concurrent_writers_produce_consistent_prefix_snapshot(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); state=root/'state'; private_dir(state)
            db=state/'downloads.sqlite3'; setup=make_wal_db(db); setup.close()
            stop=threading.Event(); errors=[]
            def write_loop():
                con=sqlite3.connect(db, isolation_level=None, timeout=5)
                con.execute('PRAGMA journal_mode=WAL'); con.execute('PRAGMA synchronous=FULL'); con.execute('PRAGMA wal_autocheckpoint=0')
                try:
                    for i in range(1,301):
                        con.execute('INSERT INTO events(value) VALUES(?)',(f'v{i}',))
                        if i % 8 == 0: time.sleep(0.001)
                    stop.set()
                except Exception as e:
                    errors.append(e); stop.set()
                finally: con.close()
            t=threading.Thread(target=write_loop); t.start()
            while True:
                con=sqlite3.connect(db)
                n=con.execute('SELECT count(*) FROM events').fetchone()[0]
                con.close()
                if n >= 8 or stop.is_set(): break
                time.sleep(0.001)
            for suffix in ('-wal','-shm'):
                p=Path(str(db)+suffix)
                if p.exists(): p.chmod(0o600)
            snap=root/'snapshot'
            report=sb.snapshot_persistent_state(state,snap,busy_timeout_ms=10000)
            t.join(10)
            self.assertFalse(t.is_alive()); self.assertFalse(errors)
            src=sqlite3.connect(db); final_count=src.execute('SELECT count(*) FROM events').fetchone()[0]; src.close()
            dst=sqlite3.connect(snap/'downloads.sqlite3')
            snap_count=dst.execute('SELECT count(*) FROM events').fetchone()[0]
            self.assertEqual('ok',dst.execute('PRAGMA quick_check').fetchone()[0]); dst.close()
            self.assertGreaterEqual(snap_count,8); self.assertLessEqual(snap_count,final_count)
            self.assertEqual(('downloads.sqlite3',),report.sqlite_databases)

    def test_inventory_four_runtime_databases_and_restore_roundtrip(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); state=root/'state'; private_dir(state)
            names=('files.sqlite3','downloads.sqlite3','writes.sqlite3','rate_limit.sqlite3')
            keep=[]
            for idx,name in enumerate(names):
                con=make_wal_db(state/name)
                con.execute('INSERT INTO events(value) VALUES(?)',(f'db{idx}',)); keep.append(con)
                for suffix in ('-wal','-shm'):
                    p=Path(str(state/name)+suffix)
                    if p.exists(): p.chmod(0o600)
            (state/'session.marker').write_text('synthetic-private-marker',encoding='utf-8'); (state/'session.marker').chmod(0o600)
            snap=root/'snapshot'; report=sb.snapshot_persistent_state(state,snap)
            self.assertEqual(tuple(sorted(names)),report.sqlite_databases)
            self.assertEqual(('session.marker',),report.ordinary_files)
            archive=root/'state.tar.gz'
            with tarfile.open(archive,'w:gz') as tf: tf.add(snap,arcname='persistent_state')
            restore=root/'restore'; private_dir(restore)
            with tarfile.open(archive,'r:gz') as tf: tf.extractall(restore,filter='data')
            restored_root=restore/'persistent_state'
            self.assertEqual(tuple(sorted(names)),sb.verify_persistent_state_snapshot(restored_root,expected_sqlite=tuple(sorted(names))))
            for idx,name in enumerate(names):
                c=sqlite3.connect(restored_root/name)
                self.assertEqual([(f'db{idx}',)],c.execute('SELECT value FROM events').fetchall()); c.close()
            self.assertEqual('synthetic-private-marker',(restored_root/'session.marker').read_text())
            for con in keep: con.close()

    def test_non_sqlite_mutation_is_fail_closed_and_snapshot_removed(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); state=root/'state'; private_dir(state)
            f=state/'private_config.json'; f.write_bytes(b'x'*(2*1024*1024)); f.chmod(0o600)
            original=sb.os.read; mutated=False
            def read_and_mutate(fd,n):
                nonlocal mutated
                data=original(fd,n)
                if data and not mutated:
                    mutated=True
                    with open(f,'ab') as h: h.write(b'y')
                return data
            snap=root/'snapshot'
            with mock.patch.object(sb.os,'read',side_effect=read_and_mutate):
                with self.assertRaises(sb.SQLiteStateBackupError): sb.snapshot_persistent_state(state,snap)
            self.assertFalse(snap.exists())

    def test_orphan_wal_symlink_hardlink_and_special_file_fail_closed(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); state=root/'state'; private_dir(state)
            orphan=state/'ghost.sqlite-wal'; orphan.write_bytes(b'x'); orphan.chmod(0o600)
            with self.assertRaises(sb.SQLiteStateBackupError): sb.snapshot_persistent_state(state,root/'s1')
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); state=root/'state'; private_dir(state)
            target=state/'a'; target.write_text('x'); target.chmod(0o600); (state/'link').symlink_to(target)
            with self.assertRaises(sb.SQLiteStateBackupError): sb.snapshot_persistent_state(state,root/'s2')
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); state=root/'state'; private_dir(state)
            a=state/'a'; a.write_text('x'); a.chmod(0o600); os.link(a,state/'b')
            with self.assertRaises(sb.SQLiteStateBackupError): sb.snapshot_persistent_state(state,root/'s3')
        if hasattr(os,'mkfifo'):
            with tempfile.TemporaryDirectory() as td:
                root=Path(td); state=root/'state'; private_dir(state); os.mkfifo(state/'fifo',0o600)
                with self.assertRaises(sb.SQLiteStateBackupError): sb.snapshot_persistent_state(state,root/'s4')

    def test_modes_preserved_and_snapshot_root_private(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); state=root/'state'; private_dir(state)
            nested=state/'nested'; nested.mkdir(); nested.chmod(0o700)
            f=nested/'note'; f.write_text('x'); f.chmod(0o400)
            db=nested/'files.sqlite3'; con=make_wal_db(db); con.close(); db.chmod(0o600)
            snap=root/'snapshot'; sb.snapshot_persistent_state(state,snap)
            self.assertEqual(0o700,stat.S_IMODE(snap.stat().st_mode))
            self.assertEqual(0o700,stat.S_IMODE((snap/'nested').stat().st_mode))
            self.assertEqual(0o400,stat.S_IMODE((snap/'nested/note').stat().st_mode))
            self.assertEqual(0o600,stat.S_IMODE((snap/'nested/files.sqlite3').stat().st_mode))

    def test_sqlite_backup_failure_cleans_snapshot_no_raw_fallback(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); state=root/'state'; private_dir(state); db=state/'writes.sqlite'; con=make_wal_db(db); con.close()
            snap=root/'snapshot'
            with mock.patch.object(sb, '_sqlite_backup_verified', side_effect=sb.SQLiteStateBackupError('synthetic crash')):
                with self.assertRaises(sb.SQLiteStateBackupError): sb.snapshot_persistent_state(state,snap)
            self.assertFalse(snap.exists())

    def test_snapshot_overlap_and_broad_mode_fail_closed(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); state=root/'state'; private_dir(state)
            with self.assertRaises(sb.SQLiteStateBackupError): sb.snapshot_persistent_state(state,state/'snapshot')
            state.chmod(0o777)
            with self.assertRaises(sb.SQLiteStateBackupError): sb.snapshot_persistent_state(state,root/'snapshot')

    def test_private_archive_is_0600_hashed_and_restore_verified(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); state=root/'state'; private_dir(state); backups=root/'backups'
            db=state/'writes.sqlite'; con=make_wal_db(db); con.execute("INSERT INTO events(value) VALUES('durable')")
            for suffix in ('-wal','-shm'):
                side=Path(str(db)+suffix)
                if side.exists(): side.chmod(0o600)
            archive,report=sb.create_private_state_archive(state,backups,'state_predeploy_'+'a'*40+'.tar.gz')
            self.assertEqual(0o700,stat.S_IMODE(backups.stat().st_mode))
            self.assertEqual(0o600,stat.S_IMODE(archive.stat().st_mode))
            sidecar=Path(str(archive)+'.sha256')
            self.assertTrue(sidecar.exists()); self.assertEqual(0o600,stat.S_IMODE(sidecar.stat().st_mode))
            self.assertIn(sb.sha256_path(archive),sidecar.read_text())
            self.assertEqual(('writes.sqlite',),sb.verify_private_state_archive(archive,expected_sqlite=report.sqlite_databases))
            self.assertFalse(any(p.name.endswith('.snapshot') for p in backups.iterdir()))
            con.close()

    def test_archive_crash_after_snapshot_removes_partial_material(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); state=root/'state'; private_dir(state); backups=root/'backups'
            db=state/'files.sqlite3'; con=make_wal_db(db); con.close()
            real_open=tarfile.open
            def crash_open(*args,**kwargs):
                if len(args)>1 and args[1]=='w:gz':
                    raise OSError('synthetic tar crash')
                return real_open(*args,**kwargs)
            with mock.patch.object(tarfile,'open',side_effect=crash_open):
                with self.assertRaises(OSError):
                    sb.create_private_state_archive(state,backups,'state_predeploy_'+'b'*40+'.tar.gz')
            self.assertEqual([],list(backups.iterdir()))

    def test_existing_backup_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); state=root/'state'; private_dir(state); backups=root/'backups'
            db=state/'rate_limit.sqlite3'; con=make_wal_db(db); con.close()
            name='state_predeploy_'+'c'*40+'.tar.gz'
            first,_=sb.create_private_state_archive(state,backups,name)
            second,_=sb.create_private_state_archive(state,backups,name)
            self.assertNotEqual(first,second); self.assertTrue(first.exists()); self.assertTrue(second.exists())
            self.assertTrue(Path(str(first)+'.sha256').exists()); self.assertTrue(Path(str(second)+'.sha256').exists())

    def test_hash_pair_tamper_is_detected(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); state=root/'state'; private_dir(state); backups=root/'backups'
            db=state/'writes.sqlite'; con=make_wal_db(db); con.close()
            archive,_=sb.create_private_state_archive(state,backups,'state_predeploy_'+'d'*40+'.tar.gz')
            self.assertEqual(sb.sha256_path(archive),sb.verify_archive_hash_pair(archive))
            archive.chmod(0o600); archive.write_bytes(archive.read_bytes()+b'X')
            with self.assertRaises(sb.SQLiteStateBackupError): sb.verify_archive_hash_pair(archive)

    def test_retry_reaps_unpaired_process_loss_archive_and_stale_snapshot(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); state=root/'state'; private_dir(state); backups=root/'backups'; private_dir(backups)
            db=state/'writes.sqlite'; con=make_wal_db(db); con.close()
            name='state_predeploy_'+'e'*40+'.tar.gz'
            incomplete=backups/name; incomplete.write_bytes(b'partial-after-rename'); incomplete.chmod(0o600)
            stale=backups/f'.{name}.snapshot'; private_dir(stale); (stale/'junk').write_text('x'); (stale/'junk').chmod(0o600)
            archive,_=sb.create_private_state_archive(state,backups,name)
            self.assertEqual(name,archive.name)
            self.assertTrue(Path(str(archive)+'.sha256').exists())
            self.assertFalse(stale.exists())
            sb.verify_archive_hash_pair(archive)

    def test_restore_verifier_rejects_symlink_archive_member(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); private_dir(root/'backups')
            archive=root/'backups'/'crafted.tar.gz'
            info=tarfile.TarInfo('persistent_state/escape'); info.type=tarfile.SYMTYPE; info.linkname='../../outside'; info.mode=0o600
            root_info=tarfile.TarInfo('persistent_state'); root_info.type=tarfile.DIRTYPE; root_info.mode=0o700
            with tarfile.open(archive,'w:gz') as tf:
                tf.addfile(root_info); tf.addfile(info)
            archive.chmod(0o600)
            with self.assertRaises(sb.SQLiteStateBackupError): sb.verify_private_state_archive(archive)

    def test_group_world_writable_persistent_file_fails_closed(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); state=root/'state'; private_dir(state)
            f=state/'unsafe'; f.write_text('x'); f.chmod(0o666)
            with self.assertRaises(sb.SQLiteStateBackupError): sb.snapshot_persistent_state(state,root/'snapshot')

    def test_zero_length_sqlite_name_uses_sqlite_backup_not_raw_copy(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); state=root/'state'; private_dir(state)
            db=state/'new.sqlite3'; db.touch(mode=0o600)
            snap=root/'snapshot'; report=sb.snapshot_persistent_state(state,snap)
            self.assertEqual(('new.sqlite3',),report.sqlite_databases)
            self.assertGreater((snap/'new.sqlite3').stat().st_size,0)
            con=sqlite3.connect(snap/'new.sqlite3')
            try: self.assertEqual('ok',con.execute('PRAGMA quick_check').fetchone()[0])
            finally: con.close()

    def test_nonempty_corrupt_sqlite_named_file_fails_closed(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); state=root/'state'; private_dir(state)
            db=state/'broken.sqlite3'; db.write_bytes(b'not-a-sqlite-database'); db.chmod(0o600)
            with self.assertRaises(sb.SQLiteStateBackupError): sb.snapshot_persistent_state(state,root/'snapshot')


if __name__ == '__main__': unittest.main(verbosity=2)
