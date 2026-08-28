# -*- coding: utf-8 -*-
import os
import signal
import socket
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from ops import deploy_release
from ops import deployment_lock_policy
from ops.release_guard import SafetyError


@unittest.skipUnless(
    os.name == "posix" and hasattr(os, "O_NOFOLLOW") and hasattr(os, "O_DIRECTORY"),
    "descriptor-bound POSIX deployment lock primitives required",
)
class FinalWave31DeploymentLockTests(unittest.TestCase):
    def root(self, td: str) -> Path:
        root = Path(td) / "control"
        root.mkdir(mode=0o700)
        os.chmod(root, 0o700)
        return root

    def lock_path(self, root: Path) -> Path:
        return root / deploy_release.TRANSACTION_LOCK

    def make_lock(self, root: Path, *, mode: int = 0o600, content: bytes = b"") -> Path:
        path = self.lock_path(root)
        path.write_bytes(content)
        os.chmod(path, mode)
        return path

    def test_new_lock_is_exact_private_regular_single_link_empty(self):
        with tempfile.TemporaryDirectory() as td:
            root = self.root(td)
            with deploy_release._deployment_lock(root) as path:
                self.assertEqual(self.lock_path(root), path)
                st = path.lstat()
                self.assertTrue(os.path.isfile(path))
                self.assertEqual(0o600, st.st_mode & 0o777)
                self.assertEqual(1, st.st_nlink)
                self.assertEqual(0, st.st_size)
                self.assertEqual(os.geteuid(), st.st_uid)
            self.assertEqual(b"", self.lock_path(root).read_bytes())

    def test_safe_preexisting_lock_is_accepted_without_normalization(self):
        with tempfile.TemporaryDirectory() as td:
            root = self.root(td)
            lock = self.make_lock(root)
            before = lock.lstat()
            with deploy_release._deployment_lock(root):
                after = lock.lstat()
                self.assertEqual((before.st_dev, before.st_ino), (after.st_dev, after.st_ino))
                self.assertEqual(0o600, after.st_mode & 0o777)

    def test_ancestor_symlink_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            real_parent = base / "real_parent"
            real_parent.mkdir(mode=0o700)
            os.chmod(real_parent, 0o700)
            root = real_parent / "control"
            root.mkdir(mode=0o700)
            os.chmod(root, 0o700)
            alias = base / "alias"
            alias.symlink_to(real_parent, target_is_directory=True)
            with self.assertRaises(SafetyError):
                with deploy_release._deployment_lock(alias / "control"):
                    self.fail("ancestor symlink must never reach critical section")

    def test_ancestor_parent_replacement_between_stat_and_open_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            parent = base / "parent"
            parent.mkdir(mode=0o700)
            os.chmod(parent, 0o700)
            root = parent / "control"
            root.mkdir(mode=0o700)
            os.chmod(root, 0o700)
            moved = base / "moved-parent"
            real_open = deployment_lock_policy.os.open
            triggered = {"done": False}

            def racing_open(target, flags, *args, **kwargs):
                if target == "parent" and kwargs.get("dir_fd") is not None and not triggered["done"]:
                    triggered["done"] = True
                    parent.rename(moved)
                    parent.mkdir(mode=0o700)
                    os.chmod(parent, 0o700)
                    replacement_root = parent / "control"
                    replacement_root.mkdir(mode=0o700)
                    os.chmod(replacement_root, 0o700)
                return real_open(target, flags, *args, **kwargs)

            with mock.patch.object(deployment_lock_policy.os, "open", side_effect=racing_open):
                with self.assertRaises(SafetyError):
                    with deploy_release._deployment_lock(root):
                        self.fail("replaced ancestor parent must never reach critical section")
            self.assertTrue(triggered["done"])

    def test_control_root_replacement_between_binding_and_leaf_open_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            root = self.root(td)
            moved = Path(td) / "moved-control"
            real_open = deployment_lock_policy.os.open
            triggered = {"done": False}

            def racing_open(target, flags, *args, **kwargs):
                if (
                    target == deploy_release.TRANSACTION_LOCK
                    and kwargs.get("dir_fd") is not None
                    and not triggered["done"]
                ):
                    triggered["done"] = True
                    root.rename(moved)
                    root.mkdir(mode=0o700)
                    os.chmod(root, 0o700)
                return real_open(target, flags, *args, **kwargs)

            with mock.patch.object(deployment_lock_policy.os, "open", side_effect=racing_open):
                with self.assertRaises(SafetyError):
                    with deploy_release._deployment_lock(root):
                        self.fail("replaced control root must never reach critical section")
            self.assertTrue(triggered["done"])
            self.assertFalse(self.lock_path(root).exists())
            self.assertTrue((moved / deploy_release.TRANSACTION_LOCK).exists())

    def test_preexisting_leaf_replacement_between_stat_and_open_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            root = self.root(td)
            lock = self.make_lock(root)
            replacement = Path(td) / "replacement"
            replacement.write_bytes(b"")
            os.chmod(replacement, 0o600)
            real_open = deployment_lock_policy.os.open
            triggered = {"done": False}

            def racing_open(target, flags, *args, **kwargs):
                if (
                    target == deploy_release.TRANSACTION_LOCK
                    and kwargs.get("dir_fd") is not None
                    and not triggered["done"]
                ):
                    triggered["done"] = True
                    lock.unlink()
                    replacement.rename(lock)
                return real_open(target, flags, *args, **kwargs)

            with mock.patch.object(deployment_lock_policy.os, "open", side_effect=racing_open):
                with self.assertRaises(SafetyError):
                    with deploy_release._deployment_lock(root):
                        self.fail("replaced leaf must never reach critical section")
            self.assertTrue(triggered["done"])

    def test_absent_leaf_insertion_between_stat_and_open_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            root = self.root(td)
            lock = self.lock_path(root)
            real_open = deployment_lock_policy.os.open
            triggered = {"done": False}

            def racing_open(target, flags, *args, **kwargs):
                if (
                    target == deploy_release.TRANSACTION_LOCK
                    and kwargs.get("dir_fd") is not None
                    and not triggered["done"]
                ):
                    triggered["done"] = True
                    lock.write_bytes(b"")
                    os.chmod(lock, 0o600)
                return real_open(target, flags, *args, **kwargs)

            with mock.patch.object(deployment_lock_policy.os, "open", side_effect=racing_open):
                with self.assertRaises(SafetyError):
                    with deploy_release._deployment_lock(root):
                        self.fail("inserted leaf must never reach critical section")
            self.assertTrue(triggered["done"])

    def test_leaf_replacement_after_flock_is_rejected_by_inode_rebinding(self):
        with tempfile.TemporaryDirectory() as td:
            root = self.root(td)
            lock = self.make_lock(root)
            replacement = Path(td) / "replacement"
            replacement.write_bytes(b"")
            os.chmod(replacement, 0o600)
            real_flock = deployment_lock_policy.fcntl.flock
            triggered = {"done": False}

            def racing_flock(fd, operation):
                result = real_flock(fd, operation)
                if operation & deployment_lock_policy.fcntl.LOCK_EX and not triggered["done"]:
                    triggered["done"] = True
                    lock.unlink()
                    replacement.rename(lock)
                return result

            with mock.patch.object(deployment_lock_policy.fcntl, "flock", side_effect=racing_flock):
                with self.assertRaises(SafetyError):
                    with deploy_release._deployment_lock(root):
                        self.fail("post-flock replaced leaf must never reach critical section")
            self.assertTrue(triggered["done"])

    def test_symlink_hardlink_fifo_socket_broad_nonempty_and_wrong_owner_fail_closed(self):
        cases = ("symlink", "hardlink", "fifo", "socket", "broad", "nonempty")
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as td:
                root = self.root(td)
                lock = self.lock_path(root)
                sock = None
                if case == "symlink":
                    target = Path(td) / "target"
                    target.write_bytes(b"")
                    os.chmod(target, 0o600)
                    lock.symlink_to(target)
                elif case == "hardlink":
                    target = Path(td) / "target"
                    target.write_bytes(b"")
                    os.chmod(target, 0o600)
                    os.link(target, lock)
                elif case == "fifo":
                    os.mkfifo(lock, 0o600)
                elif case == "socket":
                    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                    sock.bind(os.fspath(lock))
                    os.chmod(lock, 0o600)
                elif case == "broad":
                    self.make_lock(root, mode=0o644)
                else:
                    self.make_lock(root, content=b"unexpected")
                try:
                    with self.assertRaises(SafetyError):
                        with deploy_release._deployment_lock(root):
                            self.fail("unsafe lock topology must never reach critical section")
                finally:
                    if sock is not None:
                        sock.close()

        with tempfile.TemporaryDirectory() as td:
            root = self.root(td)
            lock = self.make_lock(root)
            with self.assertRaises(deployment_lock_policy.LockPolicyError):
                deployment_lock_policy.validate_preexisting_lock(lock, owner_uid=os.geteuid() + 1)
            with mock.patch.object(deployment_lock_policy.os, "geteuid", return_value=os.geteuid() + 1):
                with self.assertRaises(SafetyError):
                    with deploy_release._deployment_lock(root):
                        self.fail("wrong-owner control root must never reach critical section")

    def test_broad_control_root_fails_closed(self):
        with tempfile.TemporaryDirectory() as td:
            root = self.root(td)
            os.chmod(root, 0o755)
            with self.assertRaises(SafetyError):
                with deploy_release._deployment_lock(root):
                    self.fail("broad control root must never reach critical section")

    def test_contention_is_mutually_exclusive(self):
        with tempfile.TemporaryDirectory() as td:
            root = self.root(td)
            with deploy_release._deployment_lock(root):
                with self.assertRaises(SafetyError):
                    with deploy_release._deployment_lock(root):
                        self.fail("second contender must not acquire lock")

    @unittest.skipUnless(hasattr(os, "fork") and hasattr(os, "kill"), "fork/kill required")
    def test_process_kill_releases_kernel_flock(self):
        with tempfile.TemporaryDirectory() as td:
            root = self.root(td)
            read_fd, write_fd = os.pipe()
            pid = os.fork()
            if pid == 0:  # pragma: no cover - child process
                os.close(read_fd)
                try:
                    with deploy_release._deployment_lock(root):
                        os.write(write_fd, b"L")
                        time.sleep(30)
                finally:
                    os._exit(0)
            os.close(write_fd)
            try:
                self.assertEqual(b"L", os.read(read_fd, 1))
                with self.assertRaises(SafetyError):
                    with deploy_release._deployment_lock(root):
                        self.fail("parent must not acquire while child owns flock")
                os.kill(pid, signal.SIGKILL)
                os.waitpid(pid, 0)
                pid = None
                with deploy_release._deployment_lock(root):
                    pass
            finally:
                os.close(read_fd)
                if pid:
                    try:
                        os.kill(pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    os.waitpid(pid, 0)

    def test_128_repeated_acquire_release_cycles(self):
        with tempfile.TemporaryDirectory() as td:
            root = self.root(td)
            for _ in range(128):
                with deploy_release._deployment_lock(root):
                    pass
            lock = self.lock_path(root)
            st = lock.lstat()
            self.assertEqual(0o600, st.st_mode & 0o777)
            self.assertEqual(1, st.st_nlink)
            self.assertEqual(0, st.st_size)


if __name__ == "__main__":
    unittest.main()
