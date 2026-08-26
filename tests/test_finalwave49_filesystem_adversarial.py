from __future__ import annotations

import os
import unittest
from unittest import mock

from bridge.audit import AuditLog, AuditSecurityError
from ops.posix_fs import FilesystemSafetyError, atomic_write_bytes, safe_remove_tree
from ops.telegram_session_lock import SessionLockError, TelegramSessionLock
from tests.posix_attack_harness import PosixAttackHarness


@unittest.skipUnless(os.name == "posix", "descriptor-bound POSIX tests")
class FinalWave49FilesystemAdversarialTests(unittest.TestCase):
    def setUp(self) -> None:
        self.h = PosixAttackHarness(self)

    def test_atomic_write_replaces_symlink_without_touching_target(self):
        root = self.h.private_dir()
        victim = root / "victim"
        victim.write_bytes(b"sentinel")
        os.chmod(victim, 0o600)
        target = root / "journal.json"
        target.symlink_to(victim)
        atomic_write_bytes(target, b"safe\n", parent_private=True, parent_exact_mode=0o700)
        self.assertFalse(target.is_symlink())
        self.assertEqual(target.read_bytes(), b"safe\n")
        self.assertEqual(victim.read_bytes(), b"sentinel")

    def test_atomic_write_replaces_hardlink_name_without_mutating_peer(self):
        root = self.h.private_dir()
        peer = root / "peer"
        peer.write_bytes(b"peer")
        os.chmod(peer, 0o600)
        target = root / "journal.json"
        os.link(peer, target)
        atomic_write_bytes(target, b"new", parent_private=True, parent_exact_mode=0o700)
        self.assertEqual(peer.read_bytes(), b"peer")
        self.assertEqual(target.read_bytes(), b"new")
        self.assertEqual(peer.stat().st_nlink, 1)

    def test_atomic_write_replaces_fifo_without_opening_it(self):
        if not hasattr(os, "mkfifo"):
            self.skipTest("mkfifo unavailable")
        root = self.h.private_dir()
        target = root / "journal.json"
        os.mkfifo(target, 0o600)
        atomic_write_bytes(target, b"new", parent_private=True, parent_exact_mode=0o700)
        self.assertEqual(target.read_bytes(), b"new")

    def test_atomic_write_replaces_unix_socket_name_without_connecting(self):
        root = self.h.private_dir()
        target = root / "journal.json"
        self.h.unix_socket(target)
        atomic_write_bytes(target, b"new", parent_private=True, parent_exact_mode=0o700)
        self.assertEqual(target.read_bytes(), b"new")

    def test_atomic_write_detects_parent_replacement_during_rename(self):
        root = self.h.private_dir()
        target = root / "journal.json"
        real_replace = os.replace
        moved_holder = []

        def replace_then_swap(src, dst, *args, **kwargs):
            moved_holder.append(self.h.replace_directory(root))
            return real_replace(src, dst, *args, **kwargs)

        with mock.patch("ops.posix_fs.os.replace", side_effect=replace_then_swap):
            with self.assertRaises(FilesystemSafetyError):
                atomic_write_bytes(target, b"private", parent_private=True, parent_exact_mode=0o700)
        self.assertFalse(target.exists())
        self.assertEqual((moved_holder[0] / target.name).read_bytes(), b"private")

    def test_cleanup_unlinks_symlink_without_following_target(self):
        victim = self.h.private_dir("victim")
        sentinel = victim / "sentinel"
        sentinel.write_text("keep", encoding="utf-8")
        tree = self.h.private_dir("tree")
        (tree / "link").symlink_to(victim, target_is_directory=True)
        safe_remove_tree(tree)
        self.assertFalse(tree.exists())
        self.assertEqual(sentinel.read_text(encoding="utf-8"), "keep")

    def test_session_lock_rejects_symlinked_ancestor(self):
        real = self.h.private_dir("real")
        alias = self.h.base / "alias"
        alias.symlink_to(real, target_is_directory=True)
        with self.assertRaises(SessionLockError):
            TelegramSessionLock(alias / "session.lock", timeout_seconds=0).acquire()

    def test_session_lock_detects_parent_replacement_while_held(self):
        root = self.h.private_dir()
        lock = TelegramSessionLock(root / "session.lock", timeout_seconds=0).acquire()
        moved = self.h.replace_directory(root)
        try:
            with self.assertRaisesRegex(SessionLockError, "namespace_changed"):
                lock.assert_intact()
        finally:
            with self.assertRaisesRegex(SessionLockError, "namespace_changed"):
                lock.release()
        self.assertTrue((moved / "session.lock").exists())

    def test_session_lock_detects_leaf_replacement_while_held(self):
        root = self.h.private_dir()
        path = root / "session.lock"
        lock = TelegramSessionLock(path, timeout_seconds=0).acquire()
        old = root / "old.lock"
        path.rename(old)
        path.touch(mode=0o600)
        os.chmod(path, 0o600)
        try:
            with self.assertRaisesRegex(SessionLockError, "namespace_changed"):
                lock.assert_intact()
        finally:
            with self.assertRaisesRegex(SessionLockError, "namespace_changed"):
                lock.release()

    def test_session_lock_rejects_broad_parent_and_wrong_owner_model(self):
        root = self.h.private_dir()
        os.chmod(root, 0o755)
        with self.assertRaisesRegex(SessionLockError, "parent_mode"):
            TelegramSessionLock(root / "session.lock", timeout_seconds=0).acquire()
        os.chmod(root, 0o700)
        with mock.patch("ops.posix_fs.os.geteuid", return_value=os.geteuid() + 10000):
            with self.assertRaises(SessionLockError):
                TelegramSessionLock(root / "session.lock", timeout_seconds=0).acquire()

    def test_audit_rejects_symlinked_ancestor(self):
        real = self.h.private_dir("audit-real")
        alias = self.h.base / "audit-alias"
        alias.symlink_to(real, target_is_directory=True)
        with self.assertRaises(AuditSecurityError):
            AuditLog(alias / "audit.jsonl")

    def test_audit_rejects_leaf_replacement_during_write(self):
        root = self.h.private_dir()
        path = root / "audit.jsonl"
        log = AuditLog(path)
        real_write = os.write
        swapped = False

        def write_then_swap(fd, data):
            nonlocal swapped
            written = real_write(fd, data)
            if not swapped:
                swapped = True
                old = root / "audit-old.jsonl"
                path.rename(old)
                path.write_bytes(b"replacement\n")
                os.chmod(path, 0o600)
            return written

        with mock.patch("bridge.audit.os.write", side_effect=write_then_swap):
            with self.assertRaises(AuditSecurityError):
                log.write("request_error", status=500)

    def test_audit_fifo_rejection_is_nonblocking(self):
        if not hasattr(os, "mkfifo"):
            self.skipTest("mkfifo unavailable")
        root = self.h.private_dir()
        path = root / "audit.jsonl"
        os.mkfifo(path, 0o600)
        with self.assertRaises(AuditSecurityError):
            AuditLog(path).write("request_error", status=500)


if __name__ == "__main__":
    unittest.main()
