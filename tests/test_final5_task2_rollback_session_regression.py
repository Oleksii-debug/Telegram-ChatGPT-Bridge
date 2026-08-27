from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import types
import unittest
from pathlib import Path

from ops.telegram_session_lock import SessionLockError, TelegramSessionLock


PREDECESSOR_EVIDENCE_SHA = "00684e834a523f55ea3b61c1a12cb9dc54cfd947"


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _load_predecessor_session_lock():
    root = _repo_root()
    if not (root / ".git").exists():
        raise unittest.SkipTest("full Git history required for exact predecessor evidence")
    try:
        source = subprocess.check_output(
            ["git", "show", f"{PREDECESSOR_EVIDENCE_SHA}:ops/telegram_session_lock.py"],
            cwd=root,
            text=True,
            stderr=subprocess.DEVNULL,
        )
    except subprocess.CalledProcessError as exc:
        raise unittest.SkipTest("exact predecessor session-lock object unavailable") from exc
    name = "ops._final5_task2_predecessor_session_lock"
    module = types.ModuleType(name)
    module.__package__ = "ops"
    sys.modules[name] = module
    exec(compile(source, "predecessor_telegram_session_lock.py", "exec"), module.__dict__)
    return name, module


@unittest.skipUnless(
    os.name == "posix" and hasattr(os, "O_DIRECTORY") and hasattr(os, "O_NOFOLLOW"),
    "POSIX descriptor security required",
)
class RollbackSessionLockRegressionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.module_name, self.predecessor = _load_predecessor_session_lock()
        self.addCleanup(sys.modules.pop, self.module_name, None)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)

    def test_lock_file_state_is_cross_version_interoperable(self) -> None:
        private = self.base / "private"
        private.mkdir(mode=0o700)
        path = private / "telegram-session.lock"

        current = TelegramSessionLock(path, timeout_seconds=0).acquire()
        current.release()
        with self.predecessor.TelegramSessionLock(path, timeout_seconds=0):
            pass
        with TelegramSessionLock(path, timeout_seconds=0):
            pass

        st = os.lstat(path)
        self.assertEqual(0, st.st_size)
        self.assertEqual(0o600, st.st_mode & 0o777)

    def test_cross_version_holders_share_the_same_kernel_lock(self) -> None:
        private = self.base / "private"
        private.mkdir(mode=0o700)
        path = private / "telegram-session.lock"

        current = TelegramSessionLock(path, timeout_seconds=0).acquire()
        try:
            with self.assertRaisesRegex(
                self.predecessor.SessionLockError, "session_lock_timeout"
            ):
                self.predecessor.TelegramSessionLock(path, timeout_seconds=0).acquire()
        finally:
            current.release()

    def test_exact_predecessor_follows_symlink_parent_but_current_fails_closed(self) -> None:
        target = self.base / "actual-private"
        target.mkdir(mode=0o700)
        alias = self.base / "alias-private"
        alias.symlink_to(target, target_is_directory=True)
        aliased_path = alias / "telegram-session.lock"
        target_path = target / "telegram-session.lock"

        predecessor_lock = self.predecessor.TelegramSessionLock(
            aliased_path, timeout_seconds=0
        ).acquire()
        predecessor_lock.release()
        self.assertTrue(target_path.exists())
        target_path.unlink()

        with self.assertRaises(SessionLockError):
            TelegramSessionLock(aliased_path, timeout_seconds=0).acquire()
        self.assertFalse(target_path.exists())


if __name__ == "__main__":
    unittest.main()
