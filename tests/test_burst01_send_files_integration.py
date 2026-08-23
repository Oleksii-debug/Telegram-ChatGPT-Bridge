from __future__ import annotations

import asyncio
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from bridge.file_access import VerifiedUploadBatch
from bridge.phase_aware_write_app import PhaseAwareUnifiedBridgeApplication
from bridge.send_files_snapshot_factory import open_commit_bound_upload_batch
from bridge.storage import FileRecord, FileRecordStore
from ops.phase_aware_write_adapter import PhaseAwareTelegramWriteAdapter
from ops.structured_safe_write import StructuredSafePersistentWriteStore
from ops.telegram_write_adapter import DeterministicFakeTelegramClient, TelegramRuntimeConfig
from ops.write_safety import ReconciliationRequired, request_fingerprint


def cfg(*, timeout: float = 0.15) -> TelegramRuntimeConfig:
    return TelegramRuntimeConfig(
        application_id_ref=100023,
        application_hash_ref="synthetic-reference",
        session_reference="synthetic-session-reference",
        synthetic_test_mode=True,
        request_timeout_seconds=timeout,
        max_flood_wait_seconds=30,
        max_send_chars=4096,
        max_forward_messages=100,
        max_send_files=10,
    )


class CapturingFileClient(DeterministicFakeTelegramClient):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.received = ()
        self.payloads = ()
        self.open_at_send = ()

    async def send_file(self, entity, files, **kwargs):
        self.received = tuple(files)
        self.open_at_send = tuple(not item.closed for item in self.received)
        self.payloads = tuple(item.read() for item in self.received)
        self.external_writes.append(
            {"kind": "files", "chat_id": entity.id, "count": len(self.received)}
        )
        return [self._make_message(entity.id) for _ in self.received]


class TimeoutAfterEffectClient(CapturingFileClient):
    async def send_file(self, entity, files, **kwargs):
        self.received = tuple(files)
        self.open_at_send = tuple(not item.closed for item in self.received)
        self.payloads = tuple(item.read() for item in self.received)
        self.external_writes.append(
            {"kind": "files", "chat_id": entity.id, "count": len(self.received)}
        )
        await asyncio.sleep(0.25)
        return [self._make_message(entity.id) for _ in self.received]


class CancelAfterEffectClient(CapturingFileClient):
    async def send_file(self, entity, files, **kwargs):
        self.received = tuple(files)
        self.open_at_send = tuple(not item.closed for item in self.received)
        self.payloads = tuple(item.read() for item in self.received)
        self.external_writes.append(
            {"kind": "files", "chat_id": entity.id, "count": len(self.received)}
        )
        raise asyncio.CancelledError()


class SendFilesCrossLaneIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.private_root = self.base / "files"
        self.state_root = self.base / "state"
        self.state_root.mkdir(mode=0o700)
        os.chmod(self.state_root, 0o700)
        self.files = FileRecordStore(self.state_root / "files.sqlite3", self.private_root)

    def add_file(self, name: str, data: bytes) -> FileRecord:
        path = self.private_root / name
        path.write_bytes(data)
        os.chmod(path, 0o600)
        return self.files.add(path, name=name)

    @staticmethod
    def identity(record: FileRecord) -> dict[str, object]:
        return {
            "file_id": record.file_ref,
            "sha256": record.sha256,
            "size": record.size,
        }

    def make_app(self, client, *, factory=open_commit_bound_upload_batch, timeout=0.15):
        adapter = PhaseAwareTelegramWriteAdapter(cfg(timeout=timeout), lambda: client)
        app = object.__new__(PhaseAwareUnifiedBridgeApplication)
        app.read_app = SimpleNamespace(files=self.files)
        app.write_adapter = adapter
        app._upload_batch_factory = factory
        return app

    def payload(self, records: list[FileRecord]) -> dict[str, object]:
        return {
            "target": "@target_user",
            "files": [self.identity(record) for record in records],
            "caption": "",
            "voice_note": False,
        }

    def write_store(self) -> StructuredSafePersistentWriteStore:
        return StructuredSafePersistentWriteStore(self.state_root / "writes.sqlite3")

    def test_mapper_is_the_only_file_id_to_file_ref_translation(self):
        record = self.add_file("one.bin", b"approved-one")
        identities = (self.identity(record),)

        batch = open_commit_bound_upload_batch(self.files, identities)
        self.assertIsInstance(batch, VerifiedUploadBatch)
        self.assertEqual(1, len(batch.files))
        self.assertEqual(record.file_ref, batch.files[0].file_ref)
        self.assertEqual(record.sha256, batch.files[0].sha256)
        self.assertEqual(record.size, batch.files[0].size)
        self.assertEqual(b"approved-one", batch.files[0].read())
        batch.close()

        with self.assertRaises(ValueError):
            open_commit_bound_upload_batch(
                self.files,
                ({"file_ref": record.file_ref, "sha256": record.sha256, "size": record.size},),
            )
        with self.assertRaises(ValueError):
            open_commit_bound_upload_batch(
                self.files,
                ({**self.identity(record), "path": record.path},),
            )

    def test_preview_fingerprint_binds_exact_ordered_file_identity(self):
        first = self.add_file("first.bin", b"first")
        second = self.add_file("second.bin", b"second")
        payload = self.payload([first, second])
        fingerprint = request_fingerprint("SEND_FILES", payload)

        reversed_payload = self.payload([second, first])
        changed_hash_payload = self.payload([first, second])
        changed_hash_payload["files"][0]["sha256"] = "0" * 64

        self.assertNotEqual(fingerprint, request_fingerprint("SEND_FILES", reversed_payload))
        self.assertNotEqual(fingerprint, request_fingerprint("SEND_FILES", changed_hash_payload))

    def test_exact_snapshot_objects_and_order_reach_client_then_close(self):
        first = self.add_file("first.bin", b"alpha")
        second = self.add_file("second.bin", b"beta")
        client = CapturingFileClient()
        observed = {}

        def factory(store, identities):
            batch = open_commit_bound_upload_batch(store, identities)
            observed["batch"] = batch
            return batch

        app = self.make_app(client, factory=factory)
        result = app._execute_external_write("SEND_FILES", self.payload([first, second]))

        batch = observed["batch"]
        self.assertEqual("SEND_FILES", result["operation"])
        self.assertEqual((b"alpha", b"beta"), client.payloads)
        self.assertIs(batch.files[0], client.received[0])
        self.assertIs(batch.files[1], client.received[1])
        self.assertEqual((True, True), client.open_at_send)
        self.assertTrue(batch.closed)
        self.assertTrue(all(item.closed for item in batch.files))
        self.assertEqual(1, len(client.external_writes))

    def test_path_replacement_after_snapshot_cannot_redirect_send(self):
        record = self.add_file("swap.bin", b"approved-bytes")
        client = CapturingFileClient()
        observed = {}

        def factory(store, identities):
            batch = open_commit_bound_upload_batch(store, identities)
            observed["batch"] = batch
            path = Path(record.path)
            path.unlink()
            path.write_bytes(b"attacker-bytes")
            os.chmod(path, 0o600)
            return batch

        app = self.make_app(client, factory=factory)
        app._execute_external_write("SEND_FILES", self.payload([record]))

        self.assertEqual((b"approved-bytes",), client.payloads)
        self.assertTrue(observed["batch"].closed)

    def test_same_inode_mutation_after_snapshot_cannot_change_send(self):
        original = b"stable-approved"
        record = self.add_file("inode.bin", original)
        client = CapturingFileClient()

        def factory(store, identities):
            batch = open_commit_bound_upload_batch(store, identities)
            with Path(record.path).open("r+b") as handle:
                handle.seek(0)
                handle.write(b"X" * len(original))
                handle.flush()
                os.fsync(handle.fileno())
            return batch

        app = self.make_app(client, factory=factory)
        app._execute_external_write("SEND_FILES", self.payload([record]))
        self.assertEqual((original,), client.payloads)

    def test_partial_snapshot_failure_is_pre_effect_and_zero_telegram_connect(self):
        first = self.add_file("good.bin", b"good")
        second = self.add_file("bad.bin", b"bad")
        client = CapturingFileClient()
        app = self.make_app(client)
        payload = self.payload([first, second])
        payload["files"][1]["sha256"] = "0" * 64

        with self.assertRaises(Exception) as ctx:
            app._execute_external_write("SEND_FILES", payload)

        self.assertEqual("registered_private_file_identity_mismatch", getattr(ctx.exception, "code", None))
        self.assertEqual(0, client.connect_count)
        self.assertEqual([], client.external_writes)

    def test_post_boundary_timeout_closes_batch_and_restart_never_resends(self):
        record = self.add_file("timeout.bin", b"timeout-approved")
        client = TimeoutAfterEffectClient()
        observed = []

        def factory(store, identities):
            batch = open_commit_bound_upload_batch(store, identities)
            observed.append(batch)
            return batch

        app = self.make_app(client, factory=factory, timeout=0.03)
        store = self.write_store()
        preview = store.create_preview("SEND_FILES", self.payload([record]), now=100)

        with self.assertRaises(ReconciliationRequired):
            store.commit(
                preview.token,
                expected_action="SEND_FILES",
                idempotency_key="burst-timeout-001",
                external_write=lambda payload: app._execute_external_write("SEND_FILES", payload),
                now=101,
            )

        self.assertEqual(1, len(client.external_writes))
        self.assertEqual((b"timeout-approved",), client.payloads)
        self.assertTrue(observed[0].closed)

        restarted = self.write_store()
        second_calls = []
        with self.assertRaises(ReconciliationRequired):
            restarted.commit(
                preview.token,
                expected_action="SEND_FILES",
                idempotency_key="burst-timeout-001",
                external_write=lambda payload: second_calls.append(payload) or {},
                now=102,
            )
        self.assertEqual([], second_calls)
        self.assertEqual(1, len(client.external_writes))

    def test_post_boundary_cancellation_closes_batch_and_restart_never_resends(self):
        record = self.add_file("cancel.bin", b"cancel-approved")
        client = CancelAfterEffectClient()
        observed = []

        def factory(store, identities):
            batch = open_commit_bound_upload_batch(store, identities)
            observed.append(batch)
            return batch

        app = self.make_app(client, factory=factory)
        store = self.write_store()
        preview = store.create_preview("SEND_FILES", self.payload([record]), now=200)

        with self.assertRaises(asyncio.CancelledError):
            store.commit(
                preview.token,
                expected_action="SEND_FILES",
                idempotency_key="burst-cancel-001",
                external_write=lambda payload: app._execute_external_write("SEND_FILES", payload),
                now=201,
            )

        self.assertEqual(1, len(client.external_writes))
        self.assertEqual((b"cancel-approved",), client.payloads)
        self.assertTrue(observed[0].closed)

        restarted = self.write_store()
        with self.assertRaises(ReconciliationRequired):
            restarted.commit(
                preview.token,
                expected_action="SEND_FILES",
                idempotency_key="burst-cancel-001",
                external_write=lambda payload: self.fail("ambiguous retry executed external effect"),
                now=202,
            )
        self.assertEqual(1, len(client.external_writes))

    def test_successful_commit_replays_after_restart_without_second_send(self):
        first = self.add_file("one.bin", b"one")
        second = self.add_file("two.bin", b"two")
        client = CapturingFileClient()
        app = self.make_app(client)
        store = self.write_store()
        preview = store.create_preview("SEND_FILES", self.payload([first, second]), now=300)

        committed = store.commit(
            preview.token,
            expected_action="SEND_FILES",
            idempotency_key="burst-success-001",
            external_write=lambda payload: app._execute_external_write("SEND_FILES", payload),
            now=301,
        )
        self.assertEqual("COMMITTED", committed.state)
        self.assertFalse(committed.idempotent_replay)
        self.assertEqual((b"one", b"two"), client.payloads)
        self.assertEqual(1, len(client.external_writes))

        restarted = self.write_store()
        replay = restarted.commit(
            preview.token,
            expected_action="SEND_FILES",
            idempotency_key="burst-success-001",
            external_write=lambda payload: self.fail("committed replay executed external effect"),
            now=302,
        )
        self.assertEqual("COMMITTED", replay.state)
        self.assertTrue(replay.idempotent_replay)
        self.assertEqual(committed.request_fingerprint, replay.request_fingerprint)
        self.assertEqual(1, len(client.external_writes))

    def test_conflicting_duplicate_reference_fails_pre_effect(self):
        record = self.add_file("dup.bin", b"dup")
        client = CapturingFileClient()
        app = self.make_app(client)
        payload = self.payload([record])
        payload["files"].append(
            {"file_id": record.file_ref, "sha256": "0" * 64, "size": record.size}
        )

        with self.assertRaises(Exception):
            app._execute_external_write("SEND_FILES", payload)
        self.assertEqual(0, client.connect_count)
        self.assertEqual([], client.external_writes)


if __name__ == "__main__":
    unittest.main()
