from __future__ import annotations

import fcntl
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from ops.telegram_session_lock import SessionLockError, TelegramSessionLock


@unittest.skipUnless(os.name == "posix" and hasattr(os, "O_DIRECTORY") and hasattr(os, "O_NOFOLLOW"), "POSIX descriptor security required")
class Dev07SessionLockSecurityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.root = self.base / "private"
        self.root.mkdir(mode=0o700)
        self.path = self.root / "telegram-session.lock"

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_symlink_parent_is_rejected_without_creating_target_lock(self) -> None:
        target = self.base / "actual-private"
        target.mkdir(mode=0o700)
        alias = self.base / "alias-private"
        alias.symlink_to(target, target_is_directory=True)
        lock_path = alias / "telegram-session.lock"

        with self.assertRaisesRegex(SessionLockError, "parent_topology"):
            TelegramSessionLock(lock_path, timeout_seconds=0).acquire()
        self.assertFalse((target / "telegram-session.lock").exists())

    def test_symlink_ancestor_is_rejected_even_if_final_parent_is_private(self) -> None:
        target = self.base / "actual-tree"
        target.mkdir(mode=0o700)
        private = target / "private"
        private.mkdir(mode=0o700)
        alias = self.base / "tree-alias"
        alias.symlink_to(target, target_is_directory=True)

        with self.assertRaisesRegex(SessionLockError, "parent_topology"):
            TelegramSessionLock(alias / "private" / "telegram-session.lock", timeout_seconds=0).acquire()
        self.assertFalse((private / "telegram-session.lock").exists())

    def test_parent_replacement_between_validation_and_leaf_open_fails_closed(self) -> None:
        real_open = os.open
        displaced = self.base / "private-displaced"
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

    def test_leaf_replacement_before_binding_check_fails_closed(self) -> None:
        real_flock = fcntl.flock
        displaced = self.root / "old-session.lock"
        raced = False

        def racing_flock(fd, operation):
            nonlocal raced
            if not raced and operation & fcntl.LOCK_EX:
                raced = True
                self.path.rename(displaced)
                self.path.touch(mode=0o600)
                os.chmod(self.path, 0o600)
            return real_flock(fd, operation)

        with mock.patch("ops.telegram_session_lock.fcntl.flock", side_effect=racing_flock):
            with self.assertRaisesRegex(SessionLockError, "leaf_changed"):
                TelegramSessionLock(self.path, timeout_seconds=0).acquire()
        self.assertTrue(raced)

    def test_parent_descriptor_binding_preserves_normal_mutual_exclusion(self) -> None:
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
