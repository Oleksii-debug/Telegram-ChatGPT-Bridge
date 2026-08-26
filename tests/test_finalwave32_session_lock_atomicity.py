from __future__ import annotations

import fcntl
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from ops.telegram_session_lock import SessionLockError, TelegramSessionLock


@unittest.skipUnless(os.name == "posix" and hasattr(os, "O_DIRECTORY") and hasattr(os, "O_NOFOLLOW"), "POSIX descriptor security required")
class FinalWave32SessionLockAtomicityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.root = self.base / "private"
        self.root.mkdir(mode=0o700)
        self.path = self.root / "telegram-session.lock"

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_symlink_parent_never_redirects_leaf_creation(self) -> None:
        target = self.base / "target"
        target.mkdir(mode=0o700)
        alias = self.base / "alias"
        alias.symlink_to(target, target_is_directory=True)
        with self.assertRaises(SessionLockError):
            TelegramSessionLock(alias / self.path.name, timeout_seconds=0).acquire()
        self.assertFalse((target / self.path.name).exists())

    def test_parent_replacement_between_directory_open_and_leaf_open_fails_closed(self) -> None:
        real_open = os.open
        displaced = self.base / "private-old"
        raced = False

        def racing_open(path, flags, mode=0o777, *, dir_fd=None):
            nonlocal raced
            if not raced and path == self.path.name and dir_fd is not None:
                raced = True
                self.root.rename(displaced)
                self.root.mkdir(mode=0o700)
            return real_open(path, flags, mode, dir_fd=dir_fd)

        with mock.patch("ops.telegram_session_lock.os.open", side_effect=racing_open):
            with self.assertRaisesRegex(SessionLockError, "parent_changed"):
                TelegramSessionLock(self.path, timeout_seconds=0).acquire()
        self.assertTrue(raced)
        self.assertFalse(self.path.exists())
        self.assertTrue((displaced / self.path.name).exists())

    def test_leaf_replacement_after_flock_is_detected(self) -> None:
        real_flock = fcntl.flock
        displaced = self.root / "old.lock"
        raced = False

        def racing_flock(fd, operation):
            nonlocal raced
            result = real_flock(fd, operation)
            if not raced and operation & fcntl.LOCK_EX:
                raced = True
                self.path.rename(displaced)
                self.path.touch(mode=0o600)
                os.chmod(self.path, 0o600)
            return result

        with mock.patch("ops.telegram_session_lock.fcntl.flock", side_effect=racing_flock):
            with self.assertRaisesRegex(SessionLockError, "leaf_changed"):
                TelegramSessionLock(self.path, timeout_seconds=0).acquire()
        self.assertTrue(raced)

    def test_fifo_symlink_hardlink_and_nonempty_leaf_fail_closed(self) -> None:
        outside = self.base / "outside"
        outside.write_text("x", encoding="utf-8")
        os.chmod(outside, 0o600)

        cases = []
        self.path.symlink_to(outside)
        cases.append("symlink")
        for case in cases:
            with self.subTest(case=case):
                with self.assertRaises(SessionLockError):
                    TelegramSessionLock(self.path, timeout_seconds=0).acquire()
        self.path.unlink()

        os.link(outside, self.path)
        with self.assertRaisesRegex(SessionLockError, "hardlink"):
            TelegramSessionLock(self.path, timeout_seconds=0).acquire()
        self.path.unlink()

        os.mkfifo(self.path, 0o600)
        with self.assertRaises(SessionLockError):
            TelegramSessionLock(self.path, timeout_seconds=0).acquire()
        self.path.unlink()

        self.path.write_text("state", encoding="utf-8")
        os.chmod(self.path, 0o600)
        with self.assertRaisesRegex(SessionLockError, "nonempty"):
            TelegramSessionLock(self.path, timeout_seconds=0).acquire()

    def test_mutual_exclusion_still_works(self) -> None:
        first = TelegramSessionLock(self.path, timeout_seconds=0).acquire()
        try:
            with self.assertRaisesRegex(SessionLockError, "session_lock_timeout"):
                TelegramSessionLock(self.path, timeout_seconds=0).acquire()
        finally:
            first.release()
        with TelegramSessionLock(self.path, timeout_seconds=0):
            pass


if __name__ == "__main__":
    unittest.main()
