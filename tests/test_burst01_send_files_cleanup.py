from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from bridge.phase_aware_write_app import PhaseAwareUnifiedBridgeApplication
from bridge.send_files_snapshot_factory import open_commit_bound_upload_batch
from bridge.storage import FileRecordStore
from ops.phase_aware_write_adapter import PhaseAwareTelegramWriteAdapter
from ops.structured_safe_write import StructuredSafePersistentWriteStore
from ops.telegram_write_adapter import DeterministicFakeTelegramClient, TelegramRuntimeConfig
from ops.write_safety import ReconciliationRequired, SafeNoSideEffectFailure


def cfg() -> TelegramRuntimeConfig:
    return TelegramRuntimeConfig(
        application_id_ref=100023,
        application_hash_ref="synthetic-reference",
        session_reference="synthetic-session-reference",
        synthetic_test_mode=True,
        request_timeout_seconds=0.15,
        max_flood_wait_seconds=30,
        max_send_chars=4096,
        max_forward_messages=100,
        max_send_files=10,
    )


class CapturingClient(DeterministicFakeTelegramClient):
    def __init__(self):
        super().__init__()
        self.payloads = ()

    async def send_file(self, entity, files, **kwargs):
        items = tuple(files)
        self.payloads = tuple(item.read() for item in items)
        self.external_writes.append({"kind": "files", "chat_id": entity.id, "count": len(items)})
        return [self._make_message(entity.id) for _ in items]


class RaisingCloseBatch:
    def __init__(self, inner):
        self.inner = inner
        self.files = inner.files
        self.close_calls = 0

    def close(self):
        self.close_calls += 1
        self.inner.close()
        raise RuntimeError("synthetic cleanup failure")


class BadShapeRaisingCloseBatch:
    files = ("/legacy/path",)

    def __init__(self):
        self.close_calls = 0

    def close(self):
        self.close_calls += 1
        raise RuntimeError("synthetic pre-effect cleanup failure")


class SendFilesCleanupBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        base = Path(self.tmp.name)
        self.state = base / "state"
        self.state.mkdir(mode=0o700)
        os.chmod(self.state, 0o700)
        self.files = FileRecordStore(self.state / "files.sqlite3", base / "files")
        path = self.files.root / "approved.bin"
        path.write_bytes(b"approved-cleanup-bytes")
        os.chmod(path, 0o600)
        self.record = self.files.add(path, name="approved.bin")

    def payload(self):
        return {
            "target": "@target_user",
            "files": [{
                "file_id": self.record.file_ref,
                "sha256": self.record.sha256,
                "size": self.record.size,
            }],
            "caption": "",
            "voice_note": False,
        }

    def app(self, client, factory):
        app = object.__new__(PhaseAwareUnifiedBridgeApplication)
        app.read_app = SimpleNamespace(files=self.files)
        app.write_adapter = PhaseAwareTelegramWriteAdapter(cfg(), lambda: client)
        app._upload_batch_factory = factory
        return app

    def store(self):
        return StructuredSafePersistentWriteStore(self.state / "writes.sqlite3")

    def test_cleanup_failure_after_effect_is_ambiguous_and_never_replayed(self):
        client = CapturingClient()
        observed = {}

        def factory(store, identities):
            inner = open_commit_bound_upload_batch(store, identities)
            wrapper = RaisingCloseBatch(inner)
            observed["inner"] = inner
            observed["wrapper"] = wrapper
            return wrapper

        app = self.app(client, factory)
        store = self.store()
        preview = store.create_preview("SEND_FILES", self.payload(), now=100)

        with self.assertRaises(ReconciliationRequired):
            store.commit(
                preview.token,
                expected_action="SEND_FILES",
                idempotency_key="burst-cleanup-post-001",
                external_write=lambda payload: app._execute_external_write("SEND_FILES", payload),
                now=101,
            )

        self.assertEqual((b"approved-cleanup-bytes",), client.payloads)
        self.assertEqual(1, len(client.external_writes))
        self.assertEqual(1, observed["wrapper"].close_calls)
        self.assertTrue(observed["inner"].closed)
        self.assertTrue(all(item.closed for item in observed["inner"].files))

        restarted = self.store()
        with self.assertRaises(ReconciliationRequired):
            restarted.commit(
                preview.token,
                expected_action="SEND_FILES",
                idempotency_key="burst-cleanup-post-001",
                external_write=lambda payload: self.fail("cleanup ambiguity retried Telegram"),
                now=102,
            )
        self.assertEqual(1, len(client.external_writes))

    def test_invalid_factory_surface_cleanup_failure_remains_proven_pre_effect(self):
        client = CapturingClient()
        bad = BadShapeRaisingCloseBatch()
        app = self.app(client, lambda store, identities: bad)

        with self.assertRaises(SafeNoSideEffectFailure) as ctx:
            app._execute_external_write("SEND_FILES", self.payload())

        self.assertEqual("private_file_preflight_failed", ctx.exception.code)
        self.assertEqual(1, bad.close_calls)
        self.assertEqual(0, client.connect_count)
        self.assertEqual([], client.external_writes)


if __name__ == "__main__":
    unittest.main()
