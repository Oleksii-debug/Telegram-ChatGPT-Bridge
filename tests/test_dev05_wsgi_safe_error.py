from __future__ import annotations

import json
import unittest

from bridge.phase_aware_write_app import PhaseAwareUnifiedBridgeApplication
from ops.structured_safe_write import WriteSafetyMetadataError
from ops.write_safety import WriteSafetyError


class StructuredSafeWSGIErrorTests(unittest.TestCase):
    @staticmethod
    def _render(app, exc):
        captured = {}

        def start_response(status, headers, *args):
            captured["status"] = status
            captured["headers"] = list(headers)
            captured["extra"] = args

        body = b"".join(app._write_error(start_response, exc, "request-safe-001"))
        return captured, json.loads(body.decode("utf-8"))

    def test_proven_safe_floodwait_reaches_http_429_and_retry_after(self):
        app = PhaseAwareUnifiedBridgeApplication()
        captured, payload = self._render(
            app,
            WriteSafetyMetadataError(
                "telegram_flood_wait",
                status=429,
                retry_after_seconds=17,
            ),
        )

        self.assertEqual("429 Too Many Requests", captured["status"])
        headers = dict(captured["headers"])
        self.assertEqual("17", headers.get("Retry-After"))
        self.assertEqual("no-store", headers.get("Cache-Control"))
        self.assertFalse(payload["ok"])
        self.assertEqual("telegram_flood_wait", payload["error"]["code"])
        self.assertEqual(17, payload["error"]["retry_after_seconds"])
        self.assertEqual("request-safe-001", payload["request_id"])

    def test_non_metadata_write_error_delegates_to_canonical_serializer(self):
        app = PhaseAwareUnifiedBridgeApplication()
        captured, payload = self._render(
            app,
            WriteSafetyError("preview_action_mismatch", status=409),
        )

        self.assertTrue(captured["status"].startswith("409 "))
        headers = dict(captured["headers"])
        self.assertNotIn("Retry-After", headers)
        self.assertEqual("preview_action_mismatch", payload["error"]["code"])
        self.assertNotIn("retry_after_seconds", payload["error"])


if __name__ == "__main__":
    unittest.main()
