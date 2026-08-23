from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from bridge.phase_aware_write_app import PhaseAwareUnifiedBridgeApplication
from ops.structured_safe_write import (
    SafeWriteMetadataFailure,
    StructuredSafePersistentWriteStore,
    WriteSafetyMetadataError,
    structured_safe_write_error,
)
from ops.write_safety import SafeNoSideEffectFailure, TransactionState


class ErrorCodePrivacyTests(unittest.TestCase):
    def test_metadata_failure_rejects_private_path_as_public_code(self):
        failure = SafeWriteMetadataFailure(
            "/home/private/session/account-label",
            status=503,
        )
        self.assertEqual("external_write_rejected", failure.code)
        rendered = str(structured_safe_write_error(
            WriteSafetyMetadataError(failure.code, status=failure.status)
        ))
        self.assertNotIn("/home/", rendered)
        self.assertNotIn("account-label", rendered)

    def test_legacy_safe_failure_private_code_is_sanitized_before_endpoint(self):
        with tempfile.TemporaryDirectory() as td:
            store = StructuredSafePersistentWriteStore(Path(td) / "writes.sqlite3")
            preview = store.create_preview(
                "SEND",
                {"target": "@target_user", "text": "hello"},
                now=100,
            )

            def external(_payload):
                raise SafeNoSideEffectFailure(
                    "PRIVATE_CHAT_LABEL:/srv/private/session"
                )

            with self.assertRaises(WriteSafetyMetadataError) as ctx:
                store.commit(
                    preview.token,
                    expected_action="SEND",
                    idempotency_key="privacy-code-001",
                    external_write=external,
                    now=101,
                )

            self.assertEqual("external_write_rejected", ctx.exception.code)
            self.assertEqual(
                TransactionState.FAILED_SAFE.value,
                store.transaction_state("privacy-code-001"),
            )
            rendered = json.dumps(
                structured_safe_write_error(ctx.exception),
                ensure_ascii=False,
            )
            self.assertNotIn("PRIVATE_CHAT_LABEL", rendered)
            self.assertNotIn("/srv/private", rendered)

    def test_wsgi_error_code_fallback_cannot_expose_private_label(self):
        app = PhaseAwareUnifiedBridgeApplication()
        captured = {}

        def start_response(status, headers, *args):
            captured["status"] = status
            captured["headers"] = list(headers)

        exc = WriteSafetyMetadataError(
            "Користувач Приватний /home/private",
            status=503,
        )
        body = b"".join(
            app._write_error(start_response, exc, "request-privacy-001")
        )
        payload = json.loads(body.decode("utf-8"))

        self.assertTrue(captured["status"].startswith("503 "))
        self.assertEqual(
            "external_write_rejected",
            payload["error"]["code"],
        )
        rendered = json.dumps(payload, ensure_ascii=False)
        self.assertNotIn("Користувач Приватний", rendered)
        self.assertNotIn("/home/private", rendered)


if __name__ == "__main__":
    unittest.main()
