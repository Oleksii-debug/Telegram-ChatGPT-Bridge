from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from ops.phase_aware_write_adapter import PhaseAwareTelegramWriteAdapter
from ops.structured_safe_write import (
    SafeWriteMetadataFailure,
    StructuredSafePersistentWriteStore,
    WriteSafetyMetadataError,
    structured_safe_write_error,
)
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


class FloodWaitError(Exception):
    seconds = 99


class ResolveFloodClient(DeterministicFakeTelegramClient):
    async def get_entity(self, ref):
        raise FloodWaitError("private-preflight-detail")


class PostEffectFloodClient(DeterministicFakeTelegramClient):
    async def send_message(self, entity, text, *, reply_to=None):
        self.external_writes.append(
            {"kind": "send", "chat_id": entity.id, "size": len(text)}
        )
        raise FloodWaitError("private-post-effect-detail")


class StructuredSafeFailureTests(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.store = StructuredSafePersistentWriteStore(
            Path(self.td.name) / "writes.sqlite3"
        )

    def tearDown(self):
        self.td.cleanup()

    def preview(self):
        return self.store.create_preview(
            "SEND", {"target": "@target_user", "text": "hello"}, now=100
        )

    def test_safe_floodwait_preserves_429_and_retry_after(self):
        client = ResolveFloodClient()
        adapter = PhaseAwareTelegramWriteAdapter(cfg(), lambda: client)
        preview = self.preview()

        with self.assertRaises(WriteSafetyMetadataError) as ctx:
            self.store.commit(
                preview.token,
                expected_action="SEND",
                idempotency_key="safe-floodwait-001",
                external_write=lambda payload: adapter.send(
                    payload["target"], payload["text"]
                ).__dict__,
                now=101,
            )

        self.assertEqual("telegram_flood_wait", ctx.exception.code)
        self.assertEqual(429, ctx.exception.status)
        self.assertEqual(30, ctx.exception.retry_after_seconds)
        self.assertEqual(
            {
                "error": "telegram_flood_wait",
                "status": 429,
                "retry_after_seconds": 30,
            },
            structured_safe_write_error(ctx.exception),
        )
        self.assertEqual(
            TransactionState.FAILED_SAFE.value,
            self.store.transaction_state("safe-floodwait-001"),
        )
        self.assertEqual([], client.external_writes)
        self.assertNotIn("private-preflight-detail", str(ctx.exception))

    def test_legacy_safe_failure_remains_backward_compatible_502(self):
        preview = self.preview()

        def external(_payload):
            raise SafeNoSideEffectFailure("legacy_safe_failure")

        with self.assertRaises(WriteSafetyMetadataError) as ctx:
            self.store.commit(
                preview.token,
                expected_action="SEND",
                idempotency_key="legacy-safe-001",
                external_write=external,
                now=101,
            )
        self.assertEqual(502, ctx.exception.status)
        self.assertIsNone(ctx.exception.retry_after_seconds)
        self.assertEqual(
            {"error": "legacy_safe_failure", "status": 502},
            structured_safe_write_error(ctx.exception),
        )

    def test_post_effect_floodwait_still_becomes_ambiguous(self):
        client = PostEffectFloodClient()
        adapter = PhaseAwareTelegramWriteAdapter(cfg(), lambda: client)
        preview = self.preview()

        def external(payload):
            receipt = adapter.send(payload["target"], payload["text"])
            return {
                "operation": receipt.operation,
                "message_ids": list(receipt.message_ids),
                "chat_id": receipt.chat_id,
                "count": receipt.count,
            }

        with self.assertRaises(ReconciliationRequired):
            self.store.commit(
                preview.token,
                expected_action="SEND",
                idempotency_key="post-effect-001",
                external_write=external,
                now=101,
            )
        self.assertEqual(1, len(client.external_writes))
        self.assertEqual(
            TransactionState.AMBIGUOUS.value,
            self.store.transaction_state("post-effect-001"),
        )

    def test_safe_metadata_is_bounded(self):
        failure = SafeWriteMetadataFailure(
            "telegram_flood_wait",
            status=9999,
            retry_after_seconds=9999,
        )
        self.assertEqual(502, failure.status)
        self.assertEqual(600, failure.retry_after_seconds)

        error = WriteSafetyMetadataError(
            "telegram_flood_wait",
            status=429,
            retry_after_seconds=9999,
        )
        self.assertEqual(
            {
                "error": "telegram_flood_wait",
                "status": 429,
                "retry_after_seconds": 600,
            },
            structured_safe_write_error(error),
        )

    def test_structured_serializer_never_uses_exception_text(self):
        error = WriteSafetyMetadataError(
            "private_file_preflight_failed",
            status=503,
        )
        rendered = str(structured_safe_write_error(error))
        self.assertNotIn("/home/", rendered)
        self.assertNotIn("session", rendered.casefold())


if __name__ == "__main__":
    unittest.main()
