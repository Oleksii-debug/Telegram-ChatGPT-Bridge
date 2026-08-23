from __future__ import annotations

import asyncio
import json
import tempfile
import threading
import unittest
from pathlib import Path

from bridge.phase_aware_write_app import PhaseAwareUnifiedBridgeApplication
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

    def test_legacy_safe_failure_is_generic_502_not_public_code_passthrough(self):
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
        self.assertEqual("external_write_rejected", ctx.exception.code)
        self.assertEqual(502, ctx.exception.status)
        self.assertIsNone(ctx.exception.retry_after_seconds)
        self.assertEqual(
            {"error": "external_write_rejected", "status": 502},
            structured_safe_write_error(ctx.exception),
        )
        self.assertEqual(
            TransactionState.FAILED_SAFE.value,
            self.store.transaction_state("legacy-safe-001"),
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

    def test_cancelled_external_callback_is_durably_ambiguous(self):
        preview = self.preview()
        calls = []

        def external(_payload):
            calls.append("entered")
            raise asyncio.CancelledError()

        with self.assertRaises(asyncio.CancelledError):
            self.store.commit(
                preview.token,
                expected_action="SEND",
                idempotency_key="cancelled-effect-001",
                external_write=external,
                now=101,
            )

        self.assertEqual(["entered"], calls)
        self.assertEqual(
            TransactionState.AMBIGUOUS.value,
            self.store.transaction_state("cancelled-effect-001"),
        )
        with self.assertRaises(ReconciliationRequired):
            self.store.commit(
                preview.token,
                expected_action="SEND",
                idempotency_key="cancelled-effect-001",
                external_write=external,
                now=102,
            )
        self.assertEqual(["entered"], calls)

    def test_concurrent_retry_during_cancelled_effect_never_duplicates(self):
        preview = self.preview()
        entered = threading.Event()
        release = threading.Event()
        calls = []
        worker_errors: list[BaseException] = []

        def external(_payload):
            calls.append("entered")
            entered.set()
            if not release.wait(timeout=2):
                raise RuntimeError("synthetic test coordination timeout")
            raise asyncio.CancelledError()

        def first_commit():
            try:
                self.store.commit(
                    preview.token,
                    expected_action="SEND",
                    idempotency_key="cancelled-race-001",
                    external_write=external,
                    now=101,
                )
            except BaseException as exc:  # test harness captures cancellation.
                worker_errors.append(exc)

        worker = threading.Thread(target=first_commit, daemon=True)
        worker.start()
        self.assertTrue(entered.wait(timeout=2))

        with self.assertRaises(WriteSafetyError) as ctx:
            self.store.commit(
                preview.token,
                expected_action="SEND",
                idempotency_key="cancelled-race-001",
                external_write=external,
                now=101,
            )
        self.assertEqual("write_in_progress", ctx.exception.code)
        self.assertEqual(["entered"], calls)

        release.set()
        worker.join(timeout=2)
        self.assertFalse(worker.is_alive())
        self.assertEqual(1, len(worker_errors))
        self.assertIsInstance(worker_errors[0], asyncio.CancelledError)
        self.assertEqual(
            TransactionState.AMBIGUOUS.value,
            self.store.transaction_state("cancelled-race-001"),
        )

        with self.assertRaises(ReconciliationRequired):
            self.store.commit(
                preview.token,
                expected_action="SEND",
                idempotency_key="cancelled-race-001",
                external_write=external,
                now=102,
            )
        self.assertEqual(["entered"], calls)

    def test_http_write_error_preserves_safe_retry_after(self):
        app = PhaseAwareUnifiedBridgeApplication()
        captured: dict[str, object] = {}

        def start_response(status, headers):
            captured["status"] = status
            captured["headers"] = list(headers)

        body = app._write_error(
            start_response,
            WriteSafetyMetadataError(
                "telegram_flood_wait",
                status=429,
                retry_after_seconds=30,
            ),
            "synthetic-request-id",
        )
        payload = json.loads(b"".join(body).decode("utf-8"))
        headers = dict(captured["headers"])

        self.assertEqual("429 Too Many Requests", captured["status"])
        self.assertEqual("30", headers.get("Retry-After"))
        self.assertEqual("no-store", headers.get("Cache-Control"))
        self.assertFalse(payload["ok"])
        self.assertEqual("telegram_flood_wait", payload["error"]["code"])
        self.assertEqual(30, payload["error"]["retry_after_seconds"])
        rendered = json.dumps(payload, ensure_ascii=False)
        self.assertNotIn("/home/", rendered)
        self.assertNotIn("synthetic-session-reference", rendered)
        self.assertNotIn("private-preflight-detail", rendered)

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
