from __future__ import annotations

import ast
import inspect
import json
import unittest

from ops import telegram_write_adapter
from ops.telegram_write_adapter import TelegramContractError
from ops.write_endpoint_policy import _SAFE_TELEGRAM_PUBLIC_ERRORS, structured_write_error


class _ForeignError(RuntimeError):
    def __init__(self, code: str, *, status: int = 400, retry_after: int | None = None) -> None:
        super().__init__("foreign exception text must never be public")
        self.code = code
        self.status = status
        self.retry_after = retry_after


class Dev07WriteErrorPrivacyTests(unittest.TestCase):
    def test_foreign_exception_metadata_is_not_a_public_channel(self) -> None:
        private = "synthetic_private_marker_do_not_emit"
        result = structured_write_error(_ForeignError(private, status=400, retry_after=17))
        encoded = json.dumps(result, sort_keys=True)
        self.assertEqual(result, {"error": "internal_bridge_error", "status": 500})
        self.assertNotIn(private, encoded)
        self.assertNotIn("17", encoded)

    def test_foreign_exception_cannot_spoof_known_safe_code(self) -> None:
        result = structured_write_error(_ForeignError("telegram_timeout", status=504))
        self.assertEqual(result, {"error": "internal_bridge_error", "status": 500})

    def test_forged_telegram_contract_unknown_code_fails_closed(self) -> None:
        private = "synthetic_private_contract_code"
        result = structured_write_error(TelegramContractError(private, status=400))
        self.assertEqual(result, {"error": "internal_bridge_error", "status": 500})
        self.assertNotIn(private, json.dumps(result, sort_keys=True))

    def test_known_code_requires_exact_reviewed_status(self) -> None:
        result = structured_write_error(TelegramContractError("telegram_timeout", status=400))
        self.assertEqual(result, {"error": "internal_bridge_error", "status": 500})

    def test_reviewed_flood_wait_keeps_only_bounded_retry_metadata(self) -> None:
        result = structured_write_error(TelegramContractError("telegram_flood_wait", status=429, retry_after=37))
        self.assertEqual(
            result,
            {"error": "telegram_flood_wait", "status": 429, "retry_after_seconds": 37},
        )
        excessive = structured_write_error(TelegramContractError("telegram_flood_wait", status=429, retry_after=601))
        self.assertEqual(excessive, {"error": "telegram_flood_wait", "status": 429})

    def test_adapter_literal_error_contract_exactly_matches_public_allowlist(self) -> None:
        source = inspect.getsource(telegram_write_adapter)
        tree = ast.parse(source)
        emitted: set[str] = set()
        dynamic_calls = 0
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            name = func.id if isinstance(func, ast.Name) else func.attr if isinstance(func, ast.Attribute) else ""
            if name != "TelegramContractError":
                continue
            if not node.args or not isinstance(node.args[0], ast.Constant) or not isinstance(node.args[0].value, str):
                dynamic_calls += 1
                continue
            emitted.add(node.args[0].value)
        self.assertEqual(dynamic_calls, 0, "TelegramContractError code must remain a literal reviewed contract")
        self.assertEqual(emitted, set(_SAFE_TELEGRAM_PUBLIC_ERRORS))


if __name__ == "__main__":
    unittest.main()
