from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from bridge.app import BridgeApplication, ReadAppConfig
from bridge.errors import BridgeError
from bridge.integrated_app import UnifiedBridgeApplication
from ops.openapi_registry import OPERATIONS
from tests.test_finalwave46_request_parser_fuzz import (
    _AllowReadLimiter,
    _AllowWriteLimiter,
    _ExplodingCoordinator,
    _SpyBackend,
    _TEST_AUTH,
    _invoke,
    _parser_environ,
)


class _OversupplyingStream:
    def read(self, size: int = -1):
        del size
        return b"{}EXTRA"


class _TextStream:
    def read(self, size: int = -1):
        del size
        return "{}"


class _BrokenStream:
    def read(self, size: int = -1):
        del size
        raise RuntimeError("PRIVATE_STREAM_FAILURE_SENTINEL_FINALWAVE46")


class Finalwave46ParserResilienceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.backend = _SpyBackend()
        self.read_app = BridgeApplication(
            config=ReadAppConfig(auth_secret=_TEST_AUTH, private_root=self.root),
            backend=self.backend,
            rate_limiter=_AllowReadLimiter(),
        )
        self.unified = UnifiedBridgeApplication(
            read_app=self.read_app,
            write_limiter=_AllowWriteLimiter(),
        )
        self.write_spy = _ExplodingCoordinator()
        self.unified.write_coordinator = self.write_spy

    def _write_row_counts(self) -> tuple[int, int]:
        db = self.root / "state" / "writes.sqlite3"
        with sqlite3.connect(str(db)) as con:
            previews = con.execute("SELECT COUNT(*) FROM previews").fetchone()[0]
            idempotency = con.execute("SELECT COUNT(*) FROM idempotency").fetchone()[0]
        return int(previews), int(idempotency)

    def test_concurrent_malformed_requests_are_bounded_and_state_free(self):
        paths = [spec.path for spec in OPERATIONS] * 4

        def one(path: str) -> tuple[str, str]:
            result = _invoke(self.unified, path=path, raw=b'{"nested":')
            return str(result["status"]), str(result["json"]["error"]["code"])

        with ThreadPoolExecutor(max_workers=12) as pool:
            results = list(pool.map(one, paths))

        self.assertTrue(results)
        self.assertTrue(all(status.startswith("400") and code == "malformed_json" for status, code in results))
        self.assertEqual(0, self.backend.calls)
        self.assertEqual(0, self.write_spy.calls)
        self.assertEqual((0, 0), self._write_row_counts())

    def test_rejected_write_body_survives_application_reconstruction_without_state(self):
        write_paths = [spec.path for spec in OPERATIONS if spec.action]
        self.assertTrue(write_paths)
        for path in write_paths:
            result = _invoke(self.unified, path=path, raw=b'{"broken":')
            self.assertTrue(str(result["status"]).startswith("400"))
            self.assertEqual("malformed_json", result["json"]["error"]["code"])
        self.assertEqual((0, 0), self._write_row_counts())

        backend2 = _SpyBackend()
        read2 = BridgeApplication(
            config=ReadAppConfig(auth_secret=_TEST_AUTH, private_root=self.root),
            backend=backend2,
            rate_limiter=_AllowReadLimiter(),
        )
        unified2 = UnifiedBridgeApplication(read_app=read2, write_limiter=_AllowWriteLimiter())
        spy2 = _ExplodingCoordinator()
        unified2.write_coordinator = spy2
        for path in write_paths:
            result = _invoke(unified2, path=path, raw=b'{"broken":')
            self.assertTrue(str(result["status"]).startswith("400"))
            self.assertEqual("malformed_json", result["json"]["error"]["code"])
        self.assertEqual(0, backend2.calls)
        self.assertEqual(0, spy2.calls)
        self.assertEqual((0, 0), self._write_row_counts())

    def test_nested_duplicate_shape_utf8_and_top_level_types_are_controlled(self):
        cases = (
            (b'{"outer":{"x":1,"x":2}}', "duplicate_field"),
            (b"[]", "invalid_json_shape"),
            (b"null", "invalid_json_shape"),
            (b'"string"', "invalid_json_shape"),
            (b"\xff", "invalid_utf8"),
        )
        for raw, code in cases:
            with self.subTest(raw=raw):
                with self.assertRaises(BridgeError) as raised:
                    self.read_app._read_json(_parser_environ(raw))
                self.assertEqual(code, raised.exception.code)

    def test_wsgi_stream_contract_failures_are_controlled_without_private_error_text(self):
        with self.assertRaises(BridgeError) as oversupply:
            self.read_app._read_json(
                _parser_environ(b"", content_length="2", stream=_OversupplyingStream())
            )
        self.assertEqual("invalid_content_length", oversupply.exception.code)

        with self.assertRaises(BridgeError) as wrong_type:
            self.read_app._read_json(
                _parser_environ(b"", content_length="2", stream=_TextStream())
            )
        self.assertEqual("invalid_request_body", wrong_type.exception.code)

        result = _invoke(
            self.unified,
            path=OPERATIONS[0].path,
            content_length="2",
            stream=_BrokenStream(),
        )
        self.assertTrue(str(result["status"]).startswith("400"))
        self.assertEqual("invalid_request_body", result["json"]["error"]["code"])
        encoded = result["raw"].decode("utf-8")
        self.assertNotIn("PRIVATE_STREAM_FAILURE_SENTINEL_FINALWAVE46", encoded)
        self.assertNotIn("RuntimeError", encoded)
        self.assertNotIn("Traceback", encoded)
        self.assertEqual(0, self.backend.calls)
        self.assertEqual(0, self.write_spy.calls)

    def test_valid_content_type_parameters_and_boundary_body_remain_compatible(self):
        raw = json.dumps({"limit": 1}, separators=(",", ":")).encode("ascii")
        parsed = self.read_app._read_json(
            _parser_environ(raw, content_type="Application/JSON; charset=UTF-8")
        )
        self.assertEqual({"limit": 1}, parsed)

        exact = b" " * (self.read_app.config.max_json_bytes - 2) + b"{}"
        parsed = self.read_app._read_json(_parser_environ(exact))
        self.assertEqual({}, parsed)


if __name__ == "__main__":
    unittest.main()
