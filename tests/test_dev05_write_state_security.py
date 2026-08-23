from __future__ import annotations

import os
import stat
import tempfile
import unittest
from pathlib import Path

from ops.secure_write_store import SecurePersistentWriteStore, WriteStateSecurityError


class SecureWriteStateTests(unittest.TestCase):
    def _private_root(self, base: Path) -> Path:
        root = base / "state"
        root.mkdir(mode=0o700)
        os.chmod(root, 0o700)
        return root

    @staticmethod
    def _send_payload(text: str = "synthetic-private-preview") -> dict[str, str]:
        return {"target": "@target_user", "text": text}

    def test_database_is_secure_created_0600_under_022_umask(self):
        with tempfile.TemporaryDirectory() as td:
            state = self._private_root(Path(td))
            old = os.umask(0o022)
            try:
                store = SecurePersistentWriteStore(state / "writes.sqlite3", preview_ttl_seconds=5)
                store.create_preview("SEND", self._send_payload(), now=100)
            finally:
                os.umask(old)
            database = state / "writes.sqlite3"
            self.assertEqual(0o600, stat.S_IMODE(os.lstat(database).st_mode))
            self.assertEqual(1, os.lstat(database).st_nlink)
            for suffix in ("-wal", "-shm"):
                sidecar = Path(str(database) + suffix)
                if sidecar.exists():
                    self.assertEqual(0o600, stat.S_IMODE(os.lstat(sidecar).st_mode))
                    self.assertEqual(1, os.lstat(sidecar).st_nlink)

    def test_broad_existing_database_fails_without_normalizing(self):
        with tempfile.TemporaryDirectory() as td:
            state = self._private_root(Path(td))
            database = state / "writes.sqlite3"
            database.write_bytes(b"")
            os.chmod(database, 0o644)
            with self.assertRaises(WriteStateSecurityError) as ctx:
                SecurePersistentWriteStore(database)
            self.assertEqual("write_state_database_mode_unsafe", ctx.exception.code)
            self.assertEqual(0o644, stat.S_IMODE(os.lstat(database).st_mode))

    def test_symlink_and_hardlink_database_fail_closed(self):
        with tempfile.TemporaryDirectory() as td:
            state = self._private_root(Path(td))
            target = state / "target.sqlite3"
            target.write_bytes(b"")
            os.chmod(target, 0o600)

            symlink = state / "symlink.sqlite3"
            symlink.symlink_to(target)
            with self.assertRaises(WriteStateSecurityError):
                SecurePersistentWriteStore(symlink)

            hard = state / "hard.sqlite3"
            os.link(target, hard)
            with self.assertRaises(WriteStateSecurityError) as ctx:
                SecurePersistentWriteStore(target)
            self.assertEqual("write_state_database_hardlink_unsafe", ctx.exception.code)

    def test_broad_or_symlink_parent_fails_closed(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            broad = base / "broad"
            broad.mkdir(mode=0o755)
            os.chmod(broad, 0o755)
            with self.assertRaises(WriteStateSecurityError) as ctx:
                SecurePersistentWriteStore(broad / "writes.sqlite3")
            self.assertEqual("write_state_parent_mode_unsafe", ctx.exception.code)

            private = base / "private"
            private.mkdir(mode=0o700)
            os.chmod(private, 0o700)
            alias = base / "alias"
            alias.symlink_to(private, target_is_directory=True)
            with self.assertRaises(WriteStateSecurityError):
                SecurePersistentWriteStore(alias / "writes.sqlite3")

    def test_preexisting_broad_sidecar_fails_without_normalizing(self):
        with tempfile.TemporaryDirectory() as td:
            state = self._private_root(Path(td))
            database = state / "writes.sqlite3"
            SecurePersistentWriteStore(database, preview_ttl_seconds=5)
            wal = Path(str(database) + "-wal")
            wal.write_bytes(b"not-a-real-wal")
            os.chmod(wal, 0o644)
            with self.assertRaises(WriteStateSecurityError) as ctx:
                SecurePersistentWriteStore(database, preview_ttl_seconds=5)
            self.assertEqual("write_state_sidecar_mode_unsafe", ctx.exception.code)
            self.assertEqual(0o644, stat.S_IMODE(os.lstat(wal).st_mode))

    def test_preexisting_symlink_and_hardlink_sidecars_fail(self):
        with tempfile.TemporaryDirectory() as td:
            state = self._private_root(Path(td))
            database = state / "writes.sqlite3"
            SecurePersistentWriteStore(database, preview_ttl_seconds=5)
            target = state / "side-target"
            target.write_bytes(b"")
            os.chmod(target, 0o600)

            wal = Path(str(database) + "-wal")
            wal.symlink_to(target)
            with self.assertRaises(WriteStateSecurityError) as ctx:
                SecurePersistentWriteStore(database, preview_ttl_seconds=5)
            self.assertEqual("write_state_sidecar_type_unsafe", ctx.exception.code)
            wal.unlink()

            shm = Path(str(database) + "-shm")
            os.link(target, shm)
            with self.assertRaises(WriteStateSecurityError) as ctx:
                SecurePersistentWriteStore(database, preview_ttl_seconds=5)
            self.assertEqual("write_state_sidecar_hardlink_unsafe", ctx.exception.code)

    def test_restart_preserves_exactly_once_semantics(self):
        with tempfile.TemporaryDirectory() as td:
            state = self._private_root(Path(td))
            database = state / "writes.sqlite3"
            first = SecurePersistentWriteStore(database, preview_ttl_seconds=5)
            preview = first.create_preview("SEND", self._send_payload(), now=100)
            external_calls: list[int] = []
            first.commit(
                preview.token,
                expected_action="SEND",
                idempotency_key="dev05-idempotency-key",
                external_write=lambda payload: (external_calls.append(1) or {"message_ids": [101]}),
                now=101,
            )

            second = SecurePersistentWriteStore(database, preview_ttl_seconds=5)
            replay = second.commit(
                preview.token,
                expected_action="SEND",
                idempotency_key="dev05-idempotency-key",
                external_write=lambda payload: (external_calls.append(2) or {"message_ids": [102]}),
                now=999,
            )
            self.assertTrue(replay.idempotent_replay)
            self.assertEqual([1], external_calls)
            self.assertEqual({"message_ids": [101]}, replay.result)

    def test_ambiguous_state_remains_no_blind_resend_after_restart(self):
        with tempfile.TemporaryDirectory() as td:
            state = self._private_root(Path(td))
            database = state / "writes.sqlite3"
            first = SecurePersistentWriteStore(database, preview_ttl_seconds=5)
            preview = first.create_preview("SEND", self._send_payload(), now=100)
            first.simulate_calling_crash_for_test(
                preview.token,
                expected_action="SEND",
                idempotency_key="dev05-ambiguous-key",
                now=101,
            )
            self.assertEqual(1, first.mark_calling_transaction_ambiguous_on_recovery(now=102))

            second = SecurePersistentWriteStore(database, preview_ttl_seconds=5)
            external_calls: list[int] = []
            with self.assertRaisesRegex(Exception, "reconciliation_required"):
                second.commit(
                    preview.token,
                    expected_action="SEND",
                    idempotency_key="dev05-ambiguous-key",
                    external_write=lambda payload: (external_calls.append(1) or {"message_ids": [103]}),
                    now=103,
                )
            self.assertEqual([], external_calls)


if __name__ == "__main__":
    unittest.main()
