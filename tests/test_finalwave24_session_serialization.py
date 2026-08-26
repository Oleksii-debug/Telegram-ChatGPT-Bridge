from __future__ import annotations

import asyncio
import fcntl
import multiprocessing as mp
import os
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from bridge.runtime import _ReadSessionLockedClient
from ops.telegram_session_lock import SessionLockError, TelegramSessionLock
from ops.telegram_write_adapter import TelegramContractError, TelegramRuntimeConfig, TelegramWriteAdapter


def _hold_lock_until_killed(path: str, ready) -> None:
    lock = TelegramSessionLock(path, timeout_seconds=0).acquire()
    ready.send("held")
    ready.close()
    try:
        while True:
            time.sleep(1.0)
    finally:
        lock.release()


def _increment_under_lock(path: str, counter_path: str, rounds: int, ready) -> None:
    ready.send("started")
    ready.close()
    for _ in range(rounds):
        with TelegramSessionLock(path, timeout_seconds=5.0, poll_interval_seconds=0.002):
            counter = Path(counter_path)
            value = int(counter.read_text(encoding="ascii"))
            time.sleep(0.001)
            counter.write_text(str(value + 1), encoding="ascii")


@unittest.skipUnless(
    os.name == "posix" and hasattr(os, "O_DIRECTORY") and hasattr(os, "O_NOFOLLOW"),
    "POSIX descriptor security required",
)
class Finalwave24SessionLockSecurityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.root = self.base / "private"
        self.root.mkdir(mode=0o700)
        os.chmod(self.root, 0o700)
        self.path = self.root / "telegram-session.lock"

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_symlink_parent_and_ancestor_fail_closed(self) -> None:
        target = self.base / "actual-tree"
        target.mkdir(mode=0o700)
        private = target / "private"
        private.mkdir(mode=0o700)
        alias = self.base / "tree-alias"
        alias.symlink_to(target, target_is_directory=True)

        with self.assertRaisesRegex(SessionLockError, "parent_topology"):
            TelegramSessionLock(alias / "private" / self.path.name, timeout_seconds=0).acquire()
        self.assertFalse((private / self.path.name).exists())

        direct_target = self.base / "actual-private"
        direct_target.mkdir(mode=0o700)
        direct_alias = self.base / "private-alias"
        direct_alias.symlink_to(direct_target, target_is_directory=True)
        with self.assertRaisesRegex(SessionLockError, "parent_topology"):
            TelegramSessionLock(direct_alias / self.path.name, timeout_seconds=0).acquire()
        self.assertFalse((direct_target / self.path.name).exists())

    def test_existing_hardlink_fifo_broad_mode_and_nonempty_leaf_fail_closed(self) -> None:
        cases = []

        self.path.touch(mode=0o600)
        os.chmod(self.path, 0o600)
        hard = self.root / "hard-copy"
        os.link(self.path, hard)
        cases.append(("hardlink", "hardlink"))
        with self.assertRaisesRegex(SessionLockError, cases[-1][1]):
            TelegramSessionLock(self.path, timeout_seconds=0).acquire()
        hard.unlink()
        self.path.unlink()

        os.mkfifo(self.path, 0o600)
        with self.assertRaisesRegex(SessionLockError, "unsafe_session_lock_file"):
            TelegramSessionLock(self.path, timeout_seconds=0).acquire()
        self.path.unlink()

        self.path.touch(mode=0o600)
        os.chmod(self.path, 0o644)
        with self.assertRaisesRegex(SessionLockError, "unsafe_session_lock_mode"):
            TelegramSessionLock(self.path, timeout_seconds=0).acquire()
        self.path.unlink()

        self.path.write_bytes(b"synthetic-non-secret-marker")
        os.chmod(self.path, 0o600)
        with self.assertRaisesRegex(SessionLockError, "unsafe_session_lock_nonempty"):
            TelegramSessionLock(self.path, timeout_seconds=0).acquire()

    def test_parent_must_remain_exact_owner_private_mode(self) -> None:
        os.chmod(self.root, 0o750)
        with self.assertRaisesRegex(SessionLockError, "parent_mode"):
            TelegramSessionLock(self.path, timeout_seconds=0).acquire()
        self.assertFalse(self.path.exists())

    def test_parent_replacement_during_leaf_open_is_detected_after_flock(self) -> None:
        real_open = os.open
        displaced = self.base / "private-displaced"
        raced = False

        def racing_open(path, flags, mode=0o777, *, dir_fd=None):
            nonlocal raced
            if not raced and path == self.path.name and dir_fd is not None:
                raced = True
                self.root.rename(displaced)
                self.root.mkdir(mode=0o700)
                os.chmod(self.root, 0o700)
            return real_open(path, flags, mode, dir_fd=dir_fd)

        with mock.patch("ops.telegram_session_lock.os.open", side_effect=racing_open):
            with self.assertRaisesRegex(SessionLockError, "parent_changed"):
                TelegramSessionLock(self.path, timeout_seconds=0).acquire()
        self.assertTrue(raced)
        self.assertFalse(self.path.exists())
        self.assertTrue((displaced / self.path.name).exists())

    def test_leaf_replacement_after_flock_before_return_is_detected(self) -> None:
        real_flock = fcntl.flock
        displaced = self.root / "old-session.lock"
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

    def test_retained_parent_and_leaf_identity_detect_lifetime_replacement(self) -> None:
        lock = TelegramSessionLock(self.path, timeout_seconds=0).acquire()
        try:
            displaced_leaf = self.root / "displaced-session.lock"
            self.path.rename(displaced_leaf)
            self.path.touch(mode=0o600)
            os.chmod(self.path, 0o600)
            with self.assertRaisesRegex(SessionLockError, "leaf_changed"):
                lock.assert_held()
        finally:
            lock.release()

        self.path.unlink()
        displaced_root = self.base / "private-displaced"
        lock = TelegramSessionLock(self.path, timeout_seconds=0).acquire()
        try:
            self.root.rename(displaced_root)
            self.root.mkdir(mode=0o700)
            os.chmod(self.root, 0o700)
            with self.assertRaisesRegex(SessionLockError, "parent_changed"):
                lock.assert_held()
        finally:
            lock.release()

    def test_flock_mutual_exclusion_survives_holder_kill(self) -> None:
        context = mp.get_context("fork")
        reader, writer = context.Pipe(duplex=False)
        holder = context.Process(target=_hold_lock_until_killed, args=(str(self.path), writer))
        holder.start()
        try:
            self.assertEqual("held", reader.recv())
            with self.assertRaisesRegex(SessionLockError, "session_lock_timeout"):
                TelegramSessionLock(self.path, timeout_seconds=0).acquire()
        finally:
            holder.terminate()
            holder.join(5.0)
        self.assertFalse(holder.is_alive())
        with TelegramSessionLock(self.path, timeout_seconds=1.0):
            pass
        self.assertEqual(b"", self.path.read_bytes())

    def test_two_processes_complete_128_serialized_cycles_without_lost_update(self) -> None:
        context = mp.get_context("fork")
        counter = self.base / "counter"
        counter.write_text("0", encoding="ascii")
        processes = []
        readers = []
        for _ in range(2):
            reader, writer = context.Pipe(duplex=False)
            process = context.Process(
                target=_increment_under_lock,
                args=(str(self.path), str(counter), 64, writer),
            )
            process.start()
            processes.append(process)
            readers.append(reader)
        try:
            self.assertEqual(["started", "started"], [reader.recv() for reader in readers])
            for process in processes:
                process.join(15.0)
                self.assertEqual(0, process.exitcode)
        finally:
            for process in processes:
                if process.is_alive():
                    process.terminate()
                    process.join(5.0)
        self.assertEqual("128", counter.read_text(encoding="ascii"))
        self.assertEqual(b"", self.path.read_bytes())

    def test_128_single_process_cycles_retain_empty_0600_single_link_leaf(self) -> None:
        for _ in range(128):
            with TelegramSessionLock(self.path, timeout_seconds=0) as lock:
                lock.assert_held()
        metadata = os.lstat(self.path)
        self.assertEqual(0o600, metadata.st_mode & 0o777)
        self.assertEqual(1, metadata.st_nlink)
        self.assertEqual(0, metadata.st_size)
        self.assertEqual(b"", self.path.read_bytes())

    def test_stable_errors_do_not_echo_private_paths_or_payloads(self) -> None:
        self.path.write_bytes(b"synthetic-non-secret-marker")
        os.chmod(self.path, 0o600)
        with self.assertRaises(SessionLockError) as captured:
            TelegramSessionLock(self.path, timeout_seconds=0).acquire()
        self.assertEqual("unsafe_session_lock_nonempty", str(captured.exception))
        self.assertNotIn(str(self.base), str(captured.exception))
        self.assertNotIn("synthetic-non-secret-marker", str(captured.exception))


class _LockAwareClient:
    def __init__(self, lock_path: Path):
        self.lock_path = lock_path
        self.events: list[str] = []
        self.connect_calls = 0

    def _assert_busy(self, event: str) -> None:
        try:
            contender = TelegramSessionLock(self.lock_path, timeout_seconds=0).acquire()
        except SessionLockError as exc:
            if exc.code != "session_lock_timeout":
                raise
            self.events.append(event)
            return
        contender.release()
        raise AssertionError("session lock was not held across Telegram client lifecycle")

    async def connect(self):
        self.connect_calls += 1
        self._assert_busy("connect")

    async def disconnect(self):
        self._assert_busy("disconnect")

    async def is_user_authorized(self):
        self._assert_busy("authorized")
        return True

    async def get_me(self):
        self._assert_busy("get_me")
        return SimpleNamespace(id=123)

    async def get_entity(self, ref):
        self._assert_busy("get_entity")
        return SimpleNamespace(id=123)

    async def send_message(self, entity, text, *, reply_to=None):
        self._assert_busy("send_message")
        return SimpleNamespace(id=456, chat_id=123)


@unittest.skipUnless(os.name == "posix", "POSIX flock semantics required")
class Finalwave24RuntimeSerializationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / "private"
        self.root.mkdir(mode=0o700)
        os.chmod(self.root, 0o700)
        self.lock_path = self.root / "telegram-session.lock"

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _lock_factory(self):
        return TelegramSessionLock(self.lock_path, timeout_seconds=0)

    def _writer(self, client: _LockAwareClient) -> TelegramWriteAdapter:
        return TelegramWriteAdapter(
            TelegramRuntimeConfig(
                application_id_ref=100023,
                application_hash_ref="0" * 32,
                session_reference="synthetic-runtime-reference-material",
                request_timeout_seconds=2.0,
                synthetic_test_mode=True,
            ),
            lambda: client,
            session_lock_factory=self._lock_factory,
        )

    def test_read_wrapper_holds_lock_from_before_connect_through_disconnect(self) -> None:
        client = _LockAwareClient(self.lock_path)
        wrapped = _ReadSessionLockedClient(client, self._lock_factory)

        async def exercise():
            await wrapped.connect()
            with self.assertRaisesRegex(SessionLockError, "session_lock_timeout"):
                TelegramSessionLock(self.lock_path, timeout_seconds=0).acquire()
            await wrapped.disconnect()

        asyncio.run(exercise())
        self.assertEqual(["connect", "disconnect"], client.events)
        with TelegramSessionLock(self.lock_path, timeout_seconds=0):
            pass

    def test_write_adapter_holds_same_lock_for_connect_auth_effect_and_disconnect(self) -> None:
        client = _LockAwareClient(self.lock_path)
        receipt = asyncio.run(self._writer(client).send_async("me", "synthetic text"))
        self.assertEqual((456,), receipt.message_ids)
        self.assertEqual(["connect", "authorized", "get_me", "send_message", "disconnect"], client.events)
        with TelegramSessionLock(self.lock_path, timeout_seconds=0):
            pass

    def test_connected_read_lifecycle_blocks_write_before_writer_connects(self) -> None:
        read_client = _LockAwareClient(self.lock_path)
        read_wrapper = _ReadSessionLockedClient(read_client, self._lock_factory)
        write_client = _LockAwareClient(self.lock_path)
        writer = self._writer(write_client)

        async def exercise():
            await read_wrapper.connect()
            try:
                with self.assertRaises(TelegramContractError) as captured:
                    await writer.send_async("me", "synthetic text")
                self.assertEqual("telegram_session_busy", captured.exception.code)
                self.assertEqual(409, captured.exception.status)
                self.assertEqual(0, write_client.connect_calls)
            finally:
                await read_wrapper.disconnect()
            receipt = await writer.send_async("me", "synthetic text")
            self.assertEqual((456,), receipt.message_ids)

        asyncio.run(exercise())


if __name__ == "__main__":
    unittest.main()
