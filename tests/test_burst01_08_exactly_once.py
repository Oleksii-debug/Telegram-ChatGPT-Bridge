from __future__ import annotations

import io
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from bridge.errors import BridgeError
from bridge.phase_aware_write_app import PhaseAwareUnifiedBridgeApplication
from ops.phase_aware_write_adapter import PhaseAwareTelegramWriteAdapter
from ops.structured_safe_write import StructuredSafePersistentWriteStore
from ops.telegram_write_adapter import DeterministicFakeTelegramClient, TelegramRuntimeConfig
from ops.write_safety import (
    ReconciliationRequired,
    SafeNoSideEffectFailure,
    TransactionState,
)


def cfg() -> TelegramRuntimeConfig:
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


class SyntheticSnapshot(io.BufferedIOBase):
    def __init__(self, data: bytes, *, file_ref: str, digest: str):
        super().__init__()
        self._buffer = io.BytesIO(data)
        self.file_ref = file_ref
        self.sha256 = digest
        self.size = len(data)
        self.name = "upload.bin"

    def read(self, size: int = -1) -> bytes:
        self._checkClosed()
        return self._buffer.read(size)

    def readinto(self, buffer) -> int:
        self._checkClosed()
        return self._buffer.readinto(buffer)

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        self._checkClosed()
        return self._buffer.seek(offset, whence)

    def tell(self) -> int:
        self._checkClosed()
        return self._buffer.tell()

    def readable(self) -> bool:
        return not self.closed

    def seekable(self) -> bool:
        return not self.closed

    def writable(self) -> bool:
        return False

    def close(self) -> None:
        if not self.closed:
            self._buffer.close()
        super().close()


class SafeTypedRaisingCloseBatch:
    """Buggy media-owner cleanup that falsely labels a post-effect error safe."""

    def __init__(self, snapshot: SyntheticSnapshot):
        self.files = (snapshot,)
        self.close_calls = 0

    def close(self) -> None:
        self.close_calls += 1
        for item in self.files:
            item.close()
        raise SafeNoSideEffectFailure("private_file_preflight_failed")


class PartialForwardClient(DeterministicFakeTelegramClient):
    async def forward_messages(self, entity, ids, *, from_peer):
        self.external_writes.append(
            {
                "kind": "forward",
                "source_id": from_peer.id,
                "chat_id": entity.id,
                "count": len(ids),
            }
        )
        return [self._make_message(entity.id)]


class PartialFilesClient(DeterministicFakeTelegramClient):
    async def send_file(self, entity, files, **kwargs):
        self.external_writes.append(
            {
                "kind": "files",
                "chat_id": entity.id,
                "count": len(files),
            }
        )
        return [self._make_message(entity.id)]


class Burst0108ExactlyOnceTests(unittest.TestCase):
    def store(self, root: str) -> StructuredSafePersistentWriteStore:
        return StructuredSafePersistentWriteStore(Path(root) / "writes.sqlite3")

    def test_conflicting_duplicate_file_ref_is_rejected_before_preview_persistence(self):
        spec = SimpleNamespace(action="SEND_FILES")
        base = {
            "file_ref": "opaque-file-ref",
            "sha256": "a" * 64,
            "size": 7,
        }
        conflicts = (
            {**base, "sha256": "b" * 64},
            {**base, "size": 8},
        )
        for conflicting in conflicts:
            with self.subTest(conflicting=conflicting):
                body = {
                    "chat": "target_user",
                    "files": [dict(base), conflicting],
                    "caption": "",
                    "voice_note": False,
                }
                with self.assertRaises(BridgeError) as ctx:
                    PhaseAwareUnifiedBridgeApplication._preview_payload(spec, body)
                self.assertEqual("invalid_file_reference", ctx.exception.code)

        exact_duplicate = {
            "chat": "target_user",
            "files": [dict(base), dict(base)],
            "caption": "",
            "voice_note": False,
        }
        payload = PhaseAwareUnifiedBridgeApplication._preview_payload(spec, exact_duplicate)
        self.assertEqual(2, len(payload["files"]))

    def test_post_effect_safe_typed_cleanup_failure_is_ambiguous_and_never_retried(self):
        data = b"approved-snapshot-bytes"
        digest = "a" * 64
        snapshot = SyntheticSnapshot(data, file_ref="opaque-file-ref", digest=digest)
        batch = SafeTypedRaisingCloseBatch(snapshot)
        client = DeterministicFakeTelegramClient()
        adapter = PhaseAwareTelegramWriteAdapter(cfg(), lambda: client)

        app = object.__new__(PhaseAwareUnifiedBridgeApplication)
        app.read_app = SimpleNamespace(files=object())
        app.write_adapter = adapter
        app._upload_batch_factory = lambda store, identities: batch

        payload = {
            "target": "target_user",
            "files": [
                {
                    "file_id": "opaque-file-ref",
                    "sha256": digest,
                    "size": len(data),
                }
            ],
            "caption": "",
            "voice_note": False,
        }

        with tempfile.TemporaryDirectory() as td:
            store = self.store(td)
            preview = store.create_preview("SEND_FILES", payload, now=100)
            with self.assertRaises(ReconciliationRequired):
                store.commit(
                    preview.token,
                    expected_action="SEND_FILES",
                    idempotency_key="burst0108-cleanup-001",
                    external_write=lambda committed: app._execute_external_write(
                        "SEND_FILES", committed
                    ),
                    now=101,
                )

            self.assertEqual(1, len(client.external_writes))
            self.assertEqual(1, batch.close_calls)
            self.assertEqual(
                TransactionState.AMBIGUOUS.value,
                store.transaction_state("burst0108-cleanup-001"),
            )

            restarted = self.store(td)
            retry_calls = []
            with self.assertRaises(ReconciliationRequired):
                restarted.commit(
                    preview.token,
                    expected_action="SEND_FILES",
                    idempotency_key="burst0108-cleanup-001",
                    external_write=lambda committed: retry_calls.append(committed) or {},
                    now=102,
                )
            self.assertEqual([], retry_calls)
            self.assertEqual(1, len(client.external_writes))

    def test_partial_forward_receipt_after_effect_is_ambiguous_and_never_retried(self):
        client = PartialForwardClient()
        adapter = PhaseAwareTelegramWriteAdapter(cfg(), lambda: client)
        payload = {
            "source": "source_user",
            "target": "target_user",
            "message_ids": [20, 21],
        }

        with tempfile.TemporaryDirectory() as td:
            store = self.store(td)
            preview = store.create_preview("FORWARD", payload, now=200)
            with self.assertRaises(ReconciliationRequired):
                store.commit(
                    preview.token,
                    expected_action="FORWARD",
                    idempotency_key="burst0108-forward-001",
                    external_write=lambda committed: adapter.forward(
                        committed["source"],
                        committed["target"],
                        committed["message_ids"],
                    ).__dict__,
                    now=201,
                )

            self.assertEqual(1, len(client.external_writes))
            self.assertEqual(
                TransactionState.AMBIGUOUS.value,
                store.transaction_state("burst0108-forward-001"),
            )
            with self.assertRaises(ReconciliationRequired):
                store.commit(
                    preview.token,
                    expected_action="FORWARD",
                    idempotency_key="burst0108-forward-001",
                    external_write=lambda committed: self.fail("partial forward retried"),
                    now=202,
                )
            self.assertEqual(1, len(client.external_writes))

    def test_partial_send_files_receipt_after_effect_is_ambiguous_and_never_retried(self):
        client = PartialFilesClient()
        adapter = PhaseAwareTelegramWriteAdapter(cfg(), lambda: client)
        payload = {
            "target": "target_user",
            "files": [
                {"file_id": "opaque-a", "sha256": "a" * 64, "size": 1},
                {"file_id": "opaque-b", "sha256": "b" * 64, "size": 1},
            ],
            "caption": "",
            "voice_note": False,
        }

        with tempfile.TemporaryDirectory() as td:
            store = self.store(td)
            preview = store.create_preview("SEND_FILES", payload, now=300)
            with self.assertRaises(ReconciliationRequired):
                store.commit(
                    preview.token,
                    expected_action="SEND_FILES",
                    idempotency_key="burst0108-files-001",
                    external_write=lambda committed: adapter.send_files(
                        committed["target"],
                        ["/synthetic/a", "/synthetic/b"],
                        caption=committed["caption"],
                    ).__dict__,
                    now=301,
                )

            self.assertEqual(1, len(client.external_writes))
            self.assertEqual(
                TransactionState.AMBIGUOUS.value,
                store.transaction_state("burst0108-files-001"),
            )
            with self.assertRaises(ReconciliationRequired):
                store.commit(
                    preview.token,
                    expected_action="SEND_FILES",
                    idempotency_key="burst0108-files-001",
                    external_write=lambda committed: self.fail("partial file send retried"),
                    now=302,
                )
            self.assertEqual(1, len(client.external_writes))


if __name__ == "__main__":
    unittest.main()
