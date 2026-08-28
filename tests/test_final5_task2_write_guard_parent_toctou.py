# -*- coding: utf-8 -*-
"""Adversarial durable lock-root tests for process-shared write effects."""
from __future__ import annotations

import multiprocessing
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from ops import runtime_write_reliability
from ops.runtime_write_reliability import ProcessSharedCommitGuard
from ops.write_safety import PersistentWriteStore, WriteSafetyError


def _bootstrap_guard_worker(db_path: str, barrier, queue) -> None:
    try:
        barrier.wait(timeout=10)
        guard = ProcessSharedCommitGuard(PersistentWriteStore(Path(db_path)))
        queue.put(("ok", guard._lock_root_identity))
    except BaseException as exc:  # pragma: no cover - parent asserts serialized result
        queue.put(("error", getattr(exc, "code", type(exc).__name__)))


@unittest.skipUnless(os.name == "posix", "process-shared flock contract is POSIX")
class Final5Task2WriteGuardParentTOCTOUTests(unittest.TestCase):
    def _store(self, root: Path) -> PersistentWriteStore:
        state = root / "state"
        state.mkdir(mode=0o700, exist_ok=True)
        os.chmod(state, 0o700)
        return PersistentWriteStore(state / "writes.sqlite3")

    def _guard(self, root: Path) -> ProcessSharedCommitGuard:
        return ProcessSharedCommitGuard(self._store(root))

    @staticmethod
    def _key(guard: ProcessSharedCommitGuard, suffix: str) -> str:
        return guard._key_hash(f"synthetic-idempotency-{suffix}")

    def test_clean_bootstrap_persists_exact_versioned_descriptor_identity(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            guard = self._guard(root)
            expected = (guard.lock_root.stat().st_dev, guard.lock_root.stat().st_ino)
            self.assertEqual(expected, guard._lock_root_identity)
            with guard.store._connect() as con:
                rows = con.execute(
                    "SELECT singleton,protocol,root_dev,root_ino FROM runtime_commit_guard_identity"
                ).fetchall()
            self.assertEqual(1, len(rows))
            self.assertEqual(1, rows[0]["singleton"])
            self.assertEqual(1, rows[0]["protocol"])
            self.assertEqual(str(expected[0]), rows[0]["root_dev"])
            self.assertEqual(str(expected[1]), rows[0]["root_ino"])

    def test_restart_accepts_only_the_unchanged_durable_root(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            first = self._guard(root)
            expected = first._lock_root_identity
            restarted = ProcessSharedCommitGuard(PersistentWriteStore(first.store.db_path))
            self.assertEqual(expected, restarted._lock_root_identity)

    def test_concurrent_first_process_bootstrap_converges_on_one_identity(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            store = self._store(root)
            ctx = multiprocessing.get_context("spawn")
            barrier = ctx.Barrier(4)
            queue = ctx.Queue()
            workers = [
                ctx.Process(target=_bootstrap_guard_worker, args=(str(store.db_path), barrier, queue))
                for _ in range(4)
            ]
            for worker in workers:
                worker.start()
            for worker in workers:
                worker.join(20)
            results = [queue.get(timeout=5) for _ in workers]
            self.assertEqual([0, 0, 0, 0], [worker.exitcode for worker in workers])
            self.assertEqual({"ok"}, {result[0] for result in results}, results)
            identities = {tuple(result[1]) for result in results}
            self.assertEqual(1, len(identities), results)
            with store._connect() as con:
                rows = con.execute(
                    "SELECT protocol,root_dev,root_ino FROM runtime_commit_guard_identity"
                ).fetchall()
            self.assertEqual(1, len(rows))
            durable = (int(rows[0]["root_dev"]), int(rows[0]["root_ino"]))
            self.assertEqual(identities, {durable})

    def test_fresh_worker_rejects_replacement_while_old_worker_holds_same_key(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            old_worker = self._guard(root)
            key_hash = self._key(old_worker, "fresh-worker-split")
            held = old_worker._open_lock(key_hash, fail_busy=True)
            self.assertIsInstance(held, int)
            original = old_worker.lock_root
            displaced = original.with_name("displaced-lock-root")
            try:
                original.rename(displaced)
                original.mkdir(mode=0o700)
                os.chmod(original, 0o700)

                with self.assertRaises(WriteSafetyError) as fresh_error:
                    ProcessSharedCommitGuard(PersistentWriteStore(old_worker.store.db_path))
                self.assertEqual("write_guard_lock_root_identity_mismatch", fresh_error.exception.code)
                with self.assertRaises(WriteSafetyError) as old_error:
                    old_worker._open_lock(key_hash, fail_busy=True)
                self.assertEqual("write_guard_lock_root_identity_mismatch", old_error.exception.code)
                self.assertEqual([], list(original.iterdir()))
                self.assertEqual([f"{key_hash}.lock"], [path.name for path in displaced.iterdir()])
            finally:
                self.assertTrue(old_worker._close_lock(held))

    def test_symlink_replacement_fails_closed_without_redirected_leaf(self):
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

    def test_unchanged_root_preserves_nonblocking_same_key_serialization(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            first = self._guard(root)
            second = ProcessSharedCommitGuard(PersistentWriteStore(first.store.db_path))
            key_hash = self._key(first, "ordinary-race")
            held = first._open_lock(key_hash, fail_busy=True)
            self.assertIsInstance(held, int)
            try:
                self.assertIsNone(second._open_lock(key_hash, fail_busy=False))
                with self.assertRaises(WriteSafetyError) as caught:
                    second._open_lock(key_hash, fail_busy=True)
                self.assertEqual("write_in_progress", caught.exception.code)
            finally:
                self.assertTrue(first._close_lock(held))
            reopened = second._open_lock(key_hash, fail_busy=True)
            self.assertIsInstance(reopened, int)
            self.assertTrue(second._close_lock(reopened))

    def test_malformed_durable_identity_fails_closed_without_reseeding(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            guard = self._guard(root)
            with guard.store._connect() as con:
                con.execute("UPDATE runtime_commit_guard_identity SET root_dev='01' WHERE singleton=1")
            with self.assertRaises(WriteSafetyError) as caught:
                ProcessSharedCommitGuard(PersistentWriteStore(guard.store.db_path))
            self.assertEqual("write_guard_lock_root_identity_invalid", caught.exception.code)
            with sqlite3.connect(str(guard.store.db_path)) as con:
                stored = con.execute(
                    "SELECT root_dev FROM runtime_commit_guard_identity WHERE singleton=1"
                ).fetchone()[0]
            self.assertEqual("01", stored)

    def test_leaf_open_failure_and_root_close_failure_preserve_sanitized_primary_error(self):
        with tempfile.TemporaryDirectory() as td:
            guard = self._guard(Path(td))
            root_flags = guard._root_open_flags()
            real_open = os.open
            real_close = os.close
            opened_root: list[int] = []

            def synthetic_open(path, flags, mode=0o777, *, dir_fd=None):
                if dir_fd is not None:
                    raise OSError("synthetic leaf open failure")
                fd = real_open(path, flags, mode)
                opened_root.append(fd)
                return fd

            def synthetic_close(fd):
                if opened_root and fd == opened_root[-1]:
                    real_close(fd)
                    raise OSError("synthetic root close failure")
                return real_close(fd)

            with mock.patch.object(ProcessSharedCommitGuard, "_root_open_flags", return_value=root_flags), \
                 mock.patch.object(runtime_write_reliability.os, "open", side_effect=synthetic_open), \
                 mock.patch.object(runtime_write_reliability.os, "close", side_effect=synthetic_close):
                with self.assertRaises(WriteSafetyError) as caught:
                    guard._open_lock(self._key(guard, "leaf-failure"), fail_busy=True)
            self.assertEqual("write_guard_lock_unavailable", caught.exception.code)

    def test_successful_leaf_is_closed_if_root_cleanup_fails(self):
        with tempfile.TemporaryDirectory() as td:
            guard = self._guard(Path(td))
            root_flags = guard._root_open_flags()
            real_open = os.open
            real_close = os.close
            descriptors: dict[str, int] = {}

            def synthetic_open(path, flags, mode=0o777, *, dir_fd=None):
                fd = real_open(path, flags, mode, dir_fd=dir_fd)
                descriptors["leaf" if dir_fd is not None else "root"] = fd
                return fd

            def synthetic_close(fd):
                if fd == descriptors.get("root"):
                    real_close(fd)
                    raise OSError("synthetic root close failure")
                return real_close(fd)

            with mock.patch.object(ProcessSharedCommitGuard, "_root_open_flags", return_value=root_flags), \
                 mock.patch.object(runtime_write_reliability.os, "open", side_effect=synthetic_open), \
                 mock.patch.object(runtime_write_reliability.os, "close", side_effect=synthetic_close):
                with self.assertRaises(WriteSafetyError) as caught:
                    guard._open_lock(self._key(guard, "root-close"), fail_busy=True)
            self.assertEqual("write_guard_lock_root_cleanup_failed", caught.exception.code)
            with self.assertRaises(OSError):
                os.fstat(descriptors["leaf"])


if __name__ == "__main__":
    unittest.main()
