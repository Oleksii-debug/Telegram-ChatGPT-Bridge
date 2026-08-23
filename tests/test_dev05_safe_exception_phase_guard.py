from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from ops.phase_aware_write_adapter import PhaseAwareTelegramWriteAdapter
from ops.structured_safe_write import SafeWriteMetadataFailure, StructuredSafePersistentWriteStore
from ops.telegram_write_adapter import (
    DeterministicFakeTelegramClient,
    TelegramContractError,
    TelegramRuntimeConfig,
)
from ops.write_safety import ReconciliationRequired, SafeNoSideEffectFailure, TransactionState


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


class PreEffectSafeClient(DeterministicFakeTelegramClient):
    async def get_entity(self, ref):
        raise SafeWriteMetadataFailure(
            "telegram_flood_wait", status=429, retry_after_seconds=7
        )


class PostEffectSafeClient(DeterministicFakeTelegramClient):
    async def send_message(self, entity, text, *, reply_to=None):
        self.external_writes.append(
            {"kind": "send", "chat_id": entity.id, "size": len(text)}
        )
        # Deliberately throw the nominally safe type *after* the adapter has
        # crossed its mutating boundary. Exception class must not override phase.
        raise SafeWriteMetadataFailure(
            "telegram_flood_wait", status=429, retry_after_seconds=7
        )


class SafeExceptionPhaseGuardTests(unittest.TestCase):
    def test_safe_exception_before_boundary_remains_proven_safe(self):
        client = PreEffectSafeClient()
        adapter = PhaseAwareTelegramWriteAdapter(cfg(), lambda: client)

        with self.assertRaises(SafeNoSideEffectFailure) as ctx:
            adapter.send("@target_user", "hello")

        self.assertEqual("telegram_flood_wait", ctx.exception.code)
        self.assertEqual([], client.external_writes)

    def test_same_safe_exception_after_boundary_is_not_safe(self):
        client = PostEffectSafeClient()
        adapter = PhaseAwareTelegramWriteAdapter(cfg(), lambda: client)

        with self.assertRaises(TelegramContractError) as ctx:
            adapter.send("@target_user", "hello")

        self.assertEqual("telegram_operation_failed", ctx.exception.code)
        self.assertEqual(502, ctx.exception.status)
        self.assertEqual(1, len(client.external_writes))
        self.assertNotIsInstance(ctx.exception, SafeNoSideEffectFailure)

    def test_post_boundary_safe_exception_becomes_ambiguous_and_never_resends(self):
        client = PostEffectSafeClient()
        adapter = PhaseAwareTelegramWriteAdapter(cfg(), lambda: client)

        with tempfile.TemporaryDirectory() as td:
            store = StructuredSafePersistentWriteStore(Path(td) / "writes.sqlite3")
            preview = store.create_preview(
                "SEND", {"target": "@target_user", "text": "hello"}, now=100
            )

            def external(payload):
                receipt = adapter.send(payload["target"], payload["text"])
                return {
                    "operation": receipt.operation,
                    "message_ids": list(receipt.message_ids),
                    "chat_id": receipt.chat_id,
                    "count": receipt.count,
                }

            with self.assertRaises(ReconciliationRequired):
                store.commit(
                    preview.token,
                    expected_action="SEND",
                    idempotency_key="phase-safe-exception-001",
                    external_write=external,
                    now=101,
                )

            self.assertEqual(1, len(client.external_writes))
            self.assertEqual(
                TransactionState.AMBIGUOUS.value,
                store.transaction_state("phase-safe-exception-001"),
            )

            retry_calls = []
            with self.assertRaises(ReconciliationRequired):
                store.commit(
                    preview.token,
                    expected_action="SEND",
                    idempotency_key="phase-safe-exception-001",
                    external_write=lambda payload: retry_calls.append(payload) or {},
                    now=102,
                )
            self.assertEqual([], retry_calls)
            self.assertEqual(1, len(client.external_writes))


if __name__ == "__main__":
    unittest.main()
