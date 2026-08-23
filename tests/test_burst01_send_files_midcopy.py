from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from bridge.file_access import VerifiedPrivateFile, open_verified_file
from bridge.phase_aware_write_app import PhaseAwareUnifiedBridgeApplication
from bridge.send_files_snapshot_factory import open_commit_bound_upload_batch
from bridge.storage import FileRecordStore
from ops.phase_aware_write_adapter import PhaseAwareTelegramWriteAdapter
from ops.telegram_write_adapter import DeterministicFakeTelegramClient, TelegramRuntimeConfig
from ops.write_safety import SafeNoSideEffectFailure


class MutatingReadHandle:
    """Mutate the still-open source inode after the first snapshot-copy chunk."""

    def __init__(self, inner, path: Path, *, mutate_offset: int):
        self._inner = inner
        self._path = path
        self._mutate_offset = mutate_offset
        self.read_count = 0
        self.mutated = False

    @property
    def closed(self):
        return self._inner.closed

    def seek(self, offset, whence=os.SEEK_SET):
        return self._inner.seek(offset, whence)

    def read(self, size=-1):
        chunk = self._inner.read(size)
        self.read_count += 1
        if self.read_count == 1 and chunk:
            with self._path.open("r+b") as writer:
                writer.seek(self._mutate_offset)
                writer.write(b"M" * 4096)
                writer.flush()
                os.fsync(writer.fileno())
            self.mutated = True
        return chunk

    def close(self):
        self._inner.close()


class MidCopyMutationClient(DeterministicFakeTelegramClient):
    pass


def cfg():
    return TelegramRuntimeConfig(
        application_id_ref=100023,
        application_hash_ref="synthetic-reference",
        session_reference="synthetic-session-reference",
        synthetic_test_mode=True,
        request_timeout_seconds=0.2,
        max_flood_wait_seconds=30,
        max_send_chars=4096,
        max_forward_messages=100,
        max_send_files=10,
    )


class SendFilesMidCopyRaceTests(unittest.TestCase):
    def test_same_inode_mutation_during_snapshot_copy_fails_before_telegram(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            state = base / "state"
            state.mkdir(mode=0o700)
            os.chmod(state, 0o700)
            store = FileRecordStore(state / "files.sqlite3", base / "files")

            # VerifiedUploadFile copies in 1 MiB chunks. Keep the mutation in the
            # second chunk so the first approved chunk has already been copied.
            data = b"A" * (2 * 1024 * 1024 + 8192)
            path = store.root / "large.bin"
            path.write_bytes(data)
            os.chmod(path, 0o600)
            record = store.add(path, name="large.bin")

            verified = open_verified_file(store, record.file_ref)
            self.assertIsNotNone(verified)
            assert verified is not None
            mutating = MutatingReadHandle(
                verified.handle,
                path,
                mutate_offset=1024 * 1024 + 1024,
            )
            wrapped = VerifiedPrivateFile(record=verified.record, handle=mutating)

            client = MidCopyMutationClient()
            app = object.__new__(PhaseAwareUnifiedBridgeApplication)
            app.read_app = SimpleNamespace(files=store)
            app.write_adapter = PhaseAwareTelegramWriteAdapter(cfg(), lambda: client)
            app._upload_batch_factory = open_commit_bound_upload_batch
            payload = {
                "target": "@target_user",
                "files": [{
                    "file_id": record.file_ref,
                    "sha256": record.sha256,
                    "size": record.size,
                }],
                "caption": "",
                "voice_note": False,
            }

            with patch("bridge.file_access.open_verified_file", return_value=wrapped):
                with self.assertRaises(SafeNoSideEffectFailure) as ctx:
                    app._execute_external_write("SEND_FILES", payload)

            self.assertEqual("registered_private_file_identity_mismatch", ctx.exception.code)
            self.assertTrue(mutating.mutated)
            self.assertGreaterEqual(mutating.read_count, 2)
            self.assertTrue(mutating.closed)
            self.assertEqual(0, client.connect_count)
            self.assertEqual([], client.external_writes)


if __name__ == "__main__":
    unittest.main()
