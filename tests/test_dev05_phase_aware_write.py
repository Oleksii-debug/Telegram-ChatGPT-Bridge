from __future__ import annotations

import asyncio
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from bridge.phase_aware_write_app import PhaseAwareUnifiedBridgeApplication
from ops.phase_aware_write_adapter import PhaseAwareTelegramWriteAdapter
from ops.telegram_write_adapter import (
    DeterministicFakeTelegramClient,
    FakeEntity,
    TelegramContractError,
    TelegramRuntimeConfig,
)
from ops.write_safety import (
    PersistentWriteStore,
    ReconciliationRequired,
    SafeNoSideEffectFailure,
    TransactionState,
    WriteSafetyError,
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


def receipt_dict(receipt):
    return {
        "operation": receipt.operation,
        "message_ids": list(receipt.message_ids),
        "chat_id": receipt.chat_id,
        "count": receipt.count,
    }


class FloodWaitError(Exception):
    seconds = 99


class ResolveFloodClient(DeterministicFakeTelegramClient):
    async def get_entity(self, ref):
        raise FloodWaitError("private-preflight-detail")


class PostEffectSendClient(DeterministicFakeTelegramClient):
    async def send_message(self, entity, text, *, reply_to=None):
        self.external_writes.append(
            {
                "kind": "send",
                "chat_id": entity.id,
                "reply_to": reply_to,
                "size": len(text),
            }
        )
        raise FloodWaitError("private-post-effect-detail")


class SlowResolveClient(DeterministicFakeTelegramClient):
    async def get_entity(self, ref):
        await asyncio.sleep(0.05)
        return await super().get_entity(ref)


class PostEffectFileClient(DeterministicFakeTelegramClient):
    async def send_file(self, entity, files, **kwargs):
        self.external_writes.append(
            {
                "kind": "files",
                "chat_id": entity.id,
                "count": len(files),
            }
        )
        raise RuntimeError("private-post-effect-file-detail")


class PhaseBoundaryAdapterTests(unittest.TestCase):
    def test_same_floodwait_class_is_safe_before_boundary(self):
        client = ResolveFloodClient()
        adapter = PhaseAwareTelegramWriteAdapter(cfg(), lambda: client)
        with self.assertRaises(SafeNoSideEffectFailure) as ctx:
            adapter.send("@target_user", "hello")
        self.assertEqual("telegram_flood_wait", ctx.exception.code)
        self.assertEqual([], client.external_writes)
        self.assertNotIn("private-preflight-detail", str(ctx.exception))

    def test_same_floodwait_class_is_ambiguous_after_boundary(self):
        client = PostEffectSendClient()
        adapter = PhaseAwareTelegramWriteAdapter(cfg(), lambda: client)
        with self.assertRaises(TelegramContractError) as ctx:
            adapter.send("@target_user", "hello")
        self.assertEqual("telegram_flood_wait", ctx.exception.code)
        self.assertEqual(429, ctx.exception.status)
        self.assertEqual(30, ctx.exception.retry_after)
        self.assertEqual(1, len(client.external_writes))
        self.assertNotIn("private-post-effect-detail", str(ctx.exception))

    def test_target_resolution_failure_is_proven_pre_effect(self):
        client = DeterministicFakeTelegramClient(
            entities={999: FakeEntity(999, "other_user")}
        )
        adapter = PhaseAwareTelegramWriteAdapter(cfg(), lambda: client)
        with self.assertRaises(SafeNoSideEffectFailure):
            adapter.send("@missing_user", "hello")
        self.assertEqual([], client.external_writes)

    def test_reply_preflight_failure_is_proven_pre_effect(self):
        client = DeterministicFakeTelegramClient(messages={(100, 99): None})
        adapter = PhaseAwareTelegramWriteAdapter(cfg(), lambda: client)
        with self.assertRaises(SafeNoSideEffectFailure) as ctx:
            adapter.reply("@target_user", 99, "hello")
        self.assertEqual("reply_target_not_found", ctx.exception.code)
        self.assertEqual([], client.external_writes)

    def test_timeout_before_mutating_method_is_safe(self):
        client = SlowResolveClient()
        adapter = PhaseAwareTelegramWriteAdapter(
            cfg(request_timeout_seconds=0.01), lambda: client
        )
        with self.assertRaises(SafeNoSideEffectFailure) as ctx:
            adapter.send("@target_user", "hello")
        self.assertEqual("telegram_timeout", ctx.exception.code)
        self.assertEqual([], client.external_writes)

    def test_unauthorized_session_is_safe_pre_effect(self):
        client = DeterministicFakeTelegramClient(authorized=False)
        adapter = PhaseAwareTelegramWriteAdapter(cfg(), lambda: client)
        with self.assertRaises(SafeNoSideEffectFailure) as ctx:
            adapter.send("@target_user", "hello")
        self.assertEqual("telegram_session_unauthorized", ctx.exception.code)
        self.assertEqual([], client.external_writes)


class PersistentOutcomeTests(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.store = PersistentWriteStore(Path(self.td.name) / "writes.sqlite3")

    def tearDown(self):
        self.td.cleanup()

    def test_pre_effect_failure_becomes_failed_safe_not_ambiguous(self):
        client = ResolveFloodClient()
        adapter = PhaseAwareTelegramWriteAdapter(cfg(), lambda: client)
        preview = self.store.create_preview(
            "SEND", {"target": "@target_user", "text": "hello"}, now=100
        )

        def external(payload):
            return receipt_dict(adapter.send(payload["target"], payload["text"]))

        with self.assertRaises(WriteSafetyError) as ctx:
            self.store.commit(
                preview.token,
                expected_action="SEND",
                idempotency_key="dev05-phase-safe-001",
                external_write=external,
                now=101,
            )
        self.assertEqual("telegram_flood_wait", ctx.exception.code)
        self.assertEqual(
            TransactionState.FAILED_SAFE.value,
            self.store.transaction_state("dev05-phase-safe-001"),
        )
        self.assertEqual([], client.external_writes)

    def test_post_effect_failure_is_ambiguous_and_never_blind_resends(self):
        client = PostEffectSendClient()
        adapter = PhaseAwareTelegramWriteAdapter(cfg(), lambda: client)
        preview = self.store.create_preview(
            "SEND", {"target": "@target_user", "text": "hello"}, now=100
        )

        def external(payload):
            return receipt_dict(adapter.send(payload["target"], payload["text"]))

        with self.assertRaises(ReconciliationRequired):
            self.store.commit(
                preview.token,
                expected_action="SEND",
                idempotency_key="dev05-phase-ambiguous-001",
                external_write=external,
                now=101,
            )
        self.assertEqual(1, len(client.external_writes))
        self.assertEqual(
            TransactionState.AMBIGUOUS.value,
            self.store.transaction_state("dev05-phase-ambiguous-001"),
        )

        calls = []
        with self.assertRaises(ReconciliationRequired):
            self.store.commit(
                preview.token,
                expected_action="SEND",
                idempotency_key="dev05-phase-ambiguous-001",
                external_write=lambda payload: calls.append(payload) or {"id": 2},
                now=102,
            )
        self.assertEqual([], calls)
        self.assertEqual(1, len(client.external_writes))


class FilePreflightBoundaryTests(unittest.TestCase):
    @staticmethod
    def app_with(file_store, adapter):
        app = object.__new__(PhaseAwareUnifiedBridgeApplication)
        app.read_app = SimpleNamespace(files=file_store)
        app.write_adapter = adapter
        return app

    def test_missing_registered_file_is_safe_before_adapter_call(self):
        client = DeterministicFakeTelegramClient()
        adapter = PhaseAwareTelegramWriteAdapter(cfg(), lambda: client)
        app = self.app_with(SimpleNamespace(get=lambda _file_id: None), adapter)
        payload = {
            "target": "@target_user",
            "files": [{"file_id": "opaque", "sha256": "a" * 64, "size": 1}],
            "caption": "",
            "voice_note": False,
        }
        with self.assertRaises(SafeNoSideEffectFailure) as ctx:
            app._execute_external_write("SEND_FILES", payload)
        self.assertEqual("registered_private_file_unavailable", ctx.exception.code)
        self.assertEqual([], client.external_writes)

    def test_file_identity_mismatch_is_safe_before_adapter_call(self):
        client = DeterministicFakeTelegramClient()
        adapter = PhaseAwareTelegramWriteAdapter(cfg(), lambda: client)
        record = SimpleNamespace(sha256="b" * 64, size=1, path="/private/item")
        app = self.app_with(SimpleNamespace(get=lambda _file_id: record), adapter)
        payload = {
            "target": "@target_user",
            "files": [{"file_id": "opaque", "sha256": "a" * 64, "size": 1}],
            "caption": "",
            "voice_note": False,
        }
        with self.assertRaises(SafeNoSideEffectFailure) as ctx:
            app._execute_external_write("SEND_FILES", payload)
        self.assertEqual(
            "registered_private_file_identity_mismatch", ctx.exception.code
        )
        self.assertEqual([], client.external_writes)

    def test_file_rpc_failure_after_boundary_is_not_claimed_safe(self):
        client = PostEffectFileClient()
        adapter = PhaseAwareTelegramWriteAdapter(cfg(), lambda: client)
        record = SimpleNamespace(sha256="a" * 64, size=1, path="/private/item")
        app = self.app_with(SimpleNamespace(get=lambda _file_id: record), adapter)
        payload = {
            "target": "@target_user",
            "files": [{"file_id": "opaque", "sha256": "a" * 64, "size": 1}],
            "caption": "",
            "voice_note": False,
        }
        with self.assertRaises(TelegramContractError):
            app._execute_external_write("SEND_FILES", payload)
        self.assertEqual(1, len(client.external_writes))


if __name__ == "__main__":
    unittest.main()
