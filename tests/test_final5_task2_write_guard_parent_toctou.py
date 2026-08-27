# -*- coding: utf-8 -*-
"""Adversarial parent-directory replacement tests for process-shared write locks."""
from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from ops.runtime_write_reliability import ProcessSharedCommitGuard
from ops.write_safety import PersistentWriteStore, WriteSafetyError


@unittest.skipUnless(os.name == "posix", "process-shared flock contract is POSIX")
class Final5Task2WriteGuardParentTOCTOUTests(unittest.TestCase):
    def _guard(self, root: Path) -> ProcessSharedCommitGuard:
        state = root / "state"
        state.mkdir(mode=0o700)
        os.chmod(state, 0o700)
        store = PersistentWriteStore(state / "writes.sqlite3")
        return ProcessSharedCommitGuard(store)

    @staticmethod
    def _key(guard: ProcessSharedCommitGuard, suffix: str) -> str:
        return guard._key_hash(f"synthetic-idempotency-{suffix}")

    def test_symlink_swap_of_validated_lock_root_fails_closed_without_redirected_leaf(self):
        if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
            self.skipTest("descriptor-safe parent opening unavailable")
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            guard = self._guard(root)
            original = guard.lock_root
            displaced = original.with_name("displaced-lock-root")
            redirect = original.with_name("redirect-target")
            original.rename(displaced)
            redirect.mkdir(mode=0o700)
            os.chmod(redirect, 0o700)
            original.symlink_to(redirect, target_is_directory=True)

            with self.assertRaises(WriteSafetyError) as caught:
                guard._open_lock(self._key(guard, "symlink-swap"), fail_busy=True)
            self.assertIn(
                caught.exception.code,
                {"write_guard_lock_root_unavailable", "write_guard_lock_root_unsafe"},
            )
            self.assertEqual([], list(redirect.iterdir()))

    def test_same_owner_same_mode_directory_replacement_fails_identity_check(self):
        if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
            self.skipTest("descriptor-safe parent opening unavailable")
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            guard = self._guard(root)
            original = guard.lock_root
            displaced = original.with_name("displaced-lock-root")
            original.rename(displaced)
            original.mkdir(mode=0o700)
            os.chmod(original, 0o700)

            with self.assertRaises(WriteSafetyError) as caught:
                guard._open_lock(self._key(guard, "directory-swap"), fail_busy=True)
            self.assertEqual("write_guard_lock_root_unsafe", caught.exception.code)
            self.assertEqual([], list(original.iterdir()))

    def test_parent_swap_cannot_split_same_key_lock_while_original_lock_is_held(self):
        if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
            self.skipTest("descriptor-safe parent opening unavailable")
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            guard = self._guard(root)
            key_hash = self._key(guard, "held-parent-swap")
            held = guard._open_lock(key_hash, fail_busy=True)
            self.assertIsInstance(held, int)
            try:
                original = guard.lock_root
                displaced = original.with_name("displaced-lock-root")
                original.rename(displaced)
                original.mkdir(mode=0o700)
                os.chmod(original, 0o700)

                with self.assertRaises(WriteSafetyError) as caught:
                    guard._open_lock(key_hash, fail_busy=True)
                self.assertEqual("write_guard_lock_root_unsafe", caught.exception.code)
                self.assertEqual([], list(original.iterdir()))
                self.assertEqual([f"{key_hash}.lock"], [path.name for path in displaced.iterdir()])
            finally:
                guard._close_lock(held)

    def test_unchanged_parent_preserves_nonblocking_same_key_serialization(self):
        with tempfile.TemporaryDirectory() as td:
            guard = self._guard(Path(td))
            key_hash = self._key(guard, "ordinary-race")
            held = guard._open_lock(key_hash, fail_busy=True)
            self.assertIsInstance(held, int)
            try:
                self.assertIsNone(guard._open_lock(key_hash, fail_busy=False))
            finally:
                guard._close_lock(held)
            reopened = guard._open_lock(key_hash, fail_busy=True)
            self.assertIsInstance(reopened, int)
            guard._close_lock(reopened)


if __name__ == "__main__":
    unittest.main()
