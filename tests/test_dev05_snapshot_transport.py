from __future__ import annotations

import io
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from bridge.phase_aware_write_app import PhaseAwareUnifiedBridgeApplication
from ops.phase_aware_write_adapter import PhaseAwareTelegramWriteAdapter
from ops.structured_safe_write import StructuredSafePersistentWriteStore
from ops.telegram_write_adapter import (
    DeterministicFakeTelegramClient,
    TelegramRuntimeConfig,
)
from ops.write_safety import (
    ReconciliationRequired,
    SafeNoSideEffectFailure,
    TransactionState,
)


def cfg(**overrides):
    values = dict(
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
    values.update(overrides)
    return TelegramRuntimeConfig(**values)


class SyntheticVerifiedSnapshot(io.BufferedIOBase):
    """Credential-free stand-in for DEV04 VerifiedUploadFile."""

    def __init__(self, data: bytes = b"snapshot-bytes", *, ref: str = "opaque-ref"):
        super().__init__()
        self._buffer = io.BytesIO(data)
        self.file_ref = ref
        self.sha256 = "a" * 64
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


class CapturingFileClient(DeterministicFakeTelegramClient):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.received = ()
        self.open_at_send = ()

    async def send_file(self, entity, files, **kwargs):
        self.received = tuple(files)
        self.open_at_send = tuple(not item.closed for item in self.received)
        self.external_writes.append(
            {"kind": "files", "chat_id": entity.id, "count": len(self.received)}
        )
        return [self._make_message(entity.id) for _ in self.received]


class PostEffectSnapshotClient(CapturingFileClient):
    async def send_file(self, entity, files, **kwargs):
        self.received = tuple(files)
        self.open_at_send = tuple(not item.closed for item in self.received)
        self.external_writes.append(
            {"kind": "files", "chat_id": entity.id, "count": len(self.received)}
        )
        raise RuntimeError("synthetic post-effect failure")


class RepositionDuringResolveClient(CapturingFileClient):
    def __init__(self, snapshot):
        super().__init__()
        self.snapshot = snapshot

    async def get_entity(self, ref):
        # This occurs after adapter preflight but before the mutating boundary.
        self.snapshot.seek(1)
        return await super().get_entity(ref)


class SyntheticBatch:
    def __init__(self, files):
        self.files = tuple(files)
        self.closed = False

    def close(self):
        self.closed = True
        for item in self.files:
            item.close()


class SnapshotAdapterBoundaryTests(unittest.TestCase):
    def test_exact_snapshot_object_reaches_client_without_stringification(self):
        snapshot = SyntheticVerifiedSnapshot()
        client = CapturingFileClient()
        adapter = PhaseAwareTelegramWriteAdapter(cfg(), lambda: client)

        receipt = adapter.send_files("@target_user", [snapshot])

        self.assertEqual("SEND_FILES", receipt.operation)
        self.assertEqual(1, receipt.count)
        self.assertEqual(1, len(client.received))
        self.assertIs(snapshot, client.received[0])
        self.assertEqual((True,), client.open_at_send)
        # Adapter preserves media-owner lifetime and never closes/reopens it.
        self.assertFalse(snapshot.closed)
        snapshot.close()

    def test_mixed_path_and_snapshot_batch_fails_before_connect_or_effect(self):
        snapshot = SyntheticVerifiedSnapshot()
        client = CapturingFileClient()
        adapter = PhaseAwareTelegramWriteAdapter(cfg(), lambda: client)

        with self.assertRaises(SafeNoSideEffectFailure) as ctx:
            adapter.send_files("@target_user", [snapshot, "/private/legacy-path"])

        self.assertEqual("invalid_file_reference", ctx.exception.code)
        self.assertEqual(0, client.connect_count)
        self.assertEqual([], client.external_writes)
        self.assertFalse(snapshot.closed)
        snapshot.close()

    def test_snapshot_position_change_during_target_preflight_fails_before_effect(self):
        snapshot = SyntheticVerifiedSnapshot()
        client = RepositionDuringResolveClient(snapshot)
        adapter = PhaseAwareTelegramWriteAdapter(cfg(), lambda: client)

        with self.assertRaises(SafeNoSideEffectFailure) as ctx:
            adapter.send_files("@target_user", [snapshot])

        self.assertEqual("invalid_file_reference", ctx.exception.code)
        self.assertEqual([], client.external_writes)
        snapshot.close()

    def test_post_boundary_snapshot_failure_is_ambiguous_and_never_retried(self):
        snapshot = SyntheticVerifiedSnapshot()
        client = PostEffectSnapshotClient()
        adapter = PhaseAwareTelegramWriteAdapter(cfg(), lambda: client)

        with tempfile.TemporaryDirectory() as td:
            store = StructuredSafePersistentWriteStore(Path(td) / "writes.sqlite3")
            preview = store.create_preview(
                "SEND_FILES",
                {
                    "target": "@target_user",
                    "files": [
                        {"file_id": "opaque-ref", "sha256": "a" * 64, "size": snapshot.size}
                    ],
                    "caption": "",
                    "voice_note": False,
                },
                now=100,
            )

            def external(_payload):
                receipt = adapter.send_files("@target_user", [snapshot])
                return {
                    "operation": receipt.operation,
                    "message_ids": list(receipt.message_ids),
                    "chat_id": receipt.chat_id,
                    "count": receipt.count,
                }

            with self.assertRaises(ReconciliationRequired):
                store.commit(
                    preview.token,
                    expected_action="SEND_FILES",
                    idempotency_key="snapshot-ambiguous-001",
                    external_write=external,
                    now=101,
                )
            self.assertEqual(1, len(client.external_writes))
            self.assertEqual(
                TransactionState.AMBIGUOUS.value,
                store.transaction_state("snapshot-ambiguous-001"),
            )

            retry_calls = []
            with self.assertRaises(ReconciliationRequired):
                store.commit(
                    preview.token,
                    expected_action="SEND_FILES",
                    idempotency_key="snapshot-ambiguous-001",
                    external_write=lambda payload: retry_calls.append(payload) or {},
                    now=102,
                )
            self.assertEqual([], retry_calls)
            self.assertEqual(1, len(client.external_writes))

        snapshot.close()


class SnapshotApplicationLifetimeTests(unittest.TestCase):
    def test_factory_receives_commit_bound_identities_and_batch_lives_through_send(self):
        snapshot = SyntheticVerifiedSnapshot(data=b"stable")
        batch = SyntheticBatch([snapshot])
        client = CapturingFileClient()
        adapter = PhaseAwareTelegramWriteAdapter(cfg(), lambda: client)
        observed = {}

        def factory(store, identities):
            observed["store"] = store
            observed["identities"] = identities
            return batch

        file_store = object()
        app = object.__new__(PhaseAwareUnifiedBridgeApplication)
        app.read_app = SimpleNamespace(files=file_store)
        app.write_adapter = adapter
        app._upload_batch_factory = factory

        payload = {
            "target": "@target_user",
            "files": [
                {"file_id": "opaque-ref", "sha256": "a" * 64, "size": len(b"stable")}
            ],
            "caption": "",
            "voice_note": False,
        }
        result = app._execute_external_write("SEND_FILES", payload)

        self.assertIs(file_store, observed["store"])
        self.assertEqual((payload["files"][0],), observed["identities"])
        self.assertEqual("SEND_FILES", result["operation"])
        self.assertIs(snapshot, client.received[0])
        self.assertEqual((True,), client.open_at_send)
        self.assertTrue(batch.closed)
        self.assertTrue(snapshot.closed)

    def test_snapshot_factory_failure_is_pre_effect_and_never_calls_telegram(self):
        client = CapturingFileClient()
        adapter = PhaseAwareTelegramWriteAdapter(cfg(), lambda: client)
        app = object.__new__(PhaseAwareUnifiedBridgeApplication)
        app.read_app = SimpleNamespace(files=object())
        app.write_adapter = adapter
        app._upload_batch_factory = lambda store, identities: None
        payload = {
            "target": "@target_user",
            "files": [
                {"file_id": "opaque-ref", "sha256": "a" * 64, "size": 7}
            ],
            "caption": "",
            "voice_note": False,
        }

        with self.assertRaises(SafeNoSideEffectFailure) as ctx:
            app._execute_external_write("SEND_FILES", payload)

        self.assertEqual("registered_private_file_identity_mismatch", ctx.exception.code)
        self.assertEqual(0, client.connect_count)
        self.assertEqual([], client.external_writes)


if __name__ == "__main__":
    unittest.main()
