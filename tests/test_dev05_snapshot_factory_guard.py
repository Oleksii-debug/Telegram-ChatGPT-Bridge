from __future__ import annotations

import unittest
from types import SimpleNamespace

from bridge.phase_aware_write_app import PhaseAwareUnifiedBridgeApplication
from ops.phase_aware_write_adapter import PhaseAwareTelegramWriteAdapter
from ops.telegram_write_adapter import DeterministicFakeTelegramClient, TelegramRuntimeConfig
from ops.write_safety import SafeNoSideEffectFailure


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


class PathBatch:
    """Buggy media-factory output that must never downgrade snapshot mode."""

    def __init__(self):
        self.files = ("/private/reopened-path",)
        self.closed = False

    def close(self):
        self.closed = True


class SnapshotFactoryGuardTests(unittest.TestCase):
    def test_configured_snapshot_factory_cannot_return_legacy_paths(self):
        client = DeterministicFakeTelegramClient()
        adapter = PhaseAwareTelegramWriteAdapter(cfg(), lambda: client)
        batch = PathBatch()
        app = object.__new__(PhaseAwareUnifiedBridgeApplication)
        app.read_app = SimpleNamespace(files=object())
        app.write_adapter = adapter
        app._upload_batch_factory = lambda store, identities: batch
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

        self.assertEqual("private_file_preflight_failed", ctx.exception.code)
        self.assertTrue(batch.closed)
        self.assertEqual(0, client.connect_count)
        self.assertEqual([], client.external_writes)


if __name__ == "__main__":
    unittest.main()
