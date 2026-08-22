import os
import stat
import tempfile
import unittest
from pathlib import Path

from ops.telegram_session_lock import SessionLockError, TelegramSessionLock

class SessionLockTests(unittest.TestCase):
    def setUp(self):
        self.td=tempfile.TemporaryDirectory(); self.root=Path(self.td.name)/'private'; self.root.mkdir(mode=0o700); self.path=self.root/'telegram-session.lock'
    def tearDown(self): self.td.cleanup()
    def test_acquire_creates_0600_empty_regular_file(self):
        with TelegramSessionLock(self.path,timeout_seconds=0): pass
        st=self.path.stat(); self.assertTrue(stat.S_ISREG(st.st_mode)); self.assertEqual(stat.S_IMODE(st.st_mode),0o600); self.assertEqual(st.st_size,0)
    def test_release_is_idempotent(self):
        lock=TelegramSessionLock(self.path,timeout_seconds=0).acquire(); lock.release(); lock.release()
    def test_double_acquire_rejected(self):
        lock=TelegramSessionLock(self.path,timeout_seconds=0).acquire()
        try:
            with self.assertRaisesRegex(SessionLockError,'already_acquired'): lock.acquire()
        finally: lock.release()
    def test_second_holder_times_out(self):
        first=TelegramSessionLock(self.path,timeout_seconds=0).acquire()
        try:
            with self.assertRaisesRegex(SessionLockError,'session_lock_timeout'): TelegramSessionLock(self.path,timeout_seconds=0).acquire()
        finally: first.release()
    def test_release_allows_next_holder(self):
        first=TelegramSessionLock(self.path,timeout_seconds=0).acquire(); first.release(); second=TelegramSessionLock(self.path,timeout_seconds=0).acquire(); second.release()
    def test_exception_context_releases_lock(self):
        try:
            with TelegramSessionLock(self.path,timeout_seconds=0): raise RuntimeError('boom')
        except RuntimeError: pass
        with TelegramSessionLock(self.path,timeout_seconds=0): pass
    def test_nonempty_existing_lock_rejected(self):
        self.path.write_text('not allowed'); os.chmod(self.path,0o600)
        with self.assertRaisesRegex(SessionLockError,'nonempty'): TelegramSessionLock(self.path,timeout_seconds=0).acquire()
    def test_broad_mode_existing_lock_rejected(self):
        self.path.touch(mode=0o600); os.chmod(self.path,0o644)
        with self.assertRaisesRegex(SessionLockError,'unsafe_session_lock_mode'): TelegramSessionLock(self.path,timeout_seconds=0).acquire()
    def test_hardlink_existing_lock_rejected(self):
        self.path.touch(mode=0o600); other=self.root/'other'; os.link(self.path,other)
        with self.assertRaisesRegex(SessionLockError,'hardlink'): TelegramSessionLock(self.path,timeout_seconds=0).acquire()
    def test_symlink_rejected(self):
        target=self.root/'target'; target.touch(mode=0o600); self.path.symlink_to(target)
        with self.assertRaises(SessionLockError): TelegramSessionLock(self.path,timeout_seconds=0).acquire()
    def test_private_parent_mode_required(self):
        os.chmod(self.root,0o755)
        with self.assertRaisesRegex(SessionLockError,'parent_mode'): TelegramSessionLock(self.path,timeout_seconds=0).acquire()
    def test_parent_auto_created_private(self):
        root=Path(self.td.name)/'new-private'; path=root/'lock';
        with TelegramSessionLock(path,timeout_seconds=0): pass
        self.assertEqual(stat.S_IMODE(root.stat().st_mode),0o700)
    def test_negative_timeout_rejected(self):
        with self.assertRaises(ValueError): TelegramSessionLock(self.path,timeout_seconds=-1)
    def test_excess_timeout_rejected(self):
        with self.assertRaises(ValueError): TelegramSessionLock(self.path,timeout_seconds=61)
    def test_zero_poll_rejected(self):
        with self.assertRaises(ValueError): TelegramSessionLock(self.path,poll_interval_seconds=0)
    def test_excess_poll_rejected(self):
        with self.assertRaises(ValueError): TelegramSessionLock(self.path,poll_interval_seconds=2)
    def test_lock_file_contains_no_session_material(self):
        with TelegramSessionLock(self.path,timeout_seconds=0): self.assertEqual(self.path.read_bytes(),b'')

if __name__=='__main__': unittest.main()
