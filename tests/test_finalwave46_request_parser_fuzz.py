from __future__ import annotations

import io
import json
import tempfile
import unittest
from pathlib import Path

from bridge.app import BridgeApplication, ReadAppConfig
from bridge.errors import BridgeError
from bridge.integrated_app import UnifiedBridgeApplication
from bridge.security import RateLimitDecision
from ops.openapi_registry import OPERATIONS


_TEST_AUTH = "dummy-test-bearer-value-000000000046"


class _AllowReadLimiter:
    def check(self, actor: str) -> RateLimitDecision:
        del actor
        return RateLimitDecision(True, remaining=9)


class _AllowWriteLimiter:
    def consume(self, actor_sha256: str, operation_id: str) -> tuple[int, int]:
        del actor_sha256, operation_id
        return (1, 0)


class _PoisonStream:
    def __init__(self) -> None:
        self.read_count = 0

    def read(self, size: int = -1) -> bytes:
        self.read_count += 1
        raise AssertionError(f"request body must not be read (size={size})")


class _SpyBackend:
    def __init__(self) -> None:
        self.calls = 0

    def _called(self):
        self.calls += 1
        raise AssertionError("backend must not be reached by rejected request")

    def list_dialogs(self, **kwargs):
        del kwargs
        return self._called()

    def history(self, **kwargs):
        del kwargs
        return self._called()

    def search(self, **kwargs):
        del kwargs
        return self._called()

    def get_message(self, **kwargs):
        del kwargs
        return self._called()

    def download_media(self, **kwargs):
        del kwargs
        return self._called()


class _ExplodingCoordinator:
    def __init__(self) -> None:
        self.calls = 0

    def preview(self, *args, **kwargs):
        del args, kwargs
        self.calls += 1
        raise AssertionError("write preview state must not be reached by rejected request")

    def commit(self, *args, **kwargs):
        del args, kwargs
        self.calls += 1
        raise AssertionError("write commit state must not be reached by rejected request")


def _invoke(app, *, path: str, raw: bytes = b"{}", token: str | None = _TEST_AUTH,
            content_type: str | None = "application/json", content_length: str | None = None,
            stream=None) -> dict[str, object]:
    body_stream = stream if stream is not None else io.BytesIO(raw)
    environ: dict[str, object] = {
        "REQUEST_METHOD": "POST",
        "PATH_INFO": path,
        "QUERY_STRING": "",
        "wsgi.input": body_stream,
    }
    if content_type is not None:
        environ["CONTENT_TYPE"] = content_type
    if content_length is not None:
        environ["CONTENT_LENGTH"] = content_length
    elif stream is None:
        environ["CONTENT_LENGTH"] = str(len(raw))
    if token is not None:
        environ["HTTP_AUTHORIZATION"] = "Bearer " + token

    captured: dict[str, object] = {}

    def start_response(status, headers):
        captured["status"] = status
        captured["headers"] = dict(headers)

    response = b"".join(app(environ, start_response))
    captured["raw"] = response
    captured["json"] = json.loads(response.decode("utf-8"))
    return captured


def _parser_environ(raw: bytes, *, content_length: str | None = None,
                    content_type: str | None = "application/json", stream=None) -> dict[str, object]:
    environ: dict[str, object] = {
        "wsgi.input": stream if stream is not None else io.BytesIO(raw),
    }
    if content_type is not None:
        environ["CONTENT_TYPE"] = content_type
    if content_length is not None:
        environ["CONTENT_LENGTH"] = content_length
    elif stream is None:
        environ["CONTENT_LENGTH"] = str(len(raw))
    return environ


class Finalwave46ParserFuzzTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.backend = _SpyBackend()
        self.read_app = BridgeApplication(
            config=ReadAppConfig(
                auth_secret=_TEST_AUTH,
                private_root=Path(self.tmp.name),
            ),
            backend=self.backend,
            rate_limiter=_AllowReadLimiter(),
        )
        self.unified = UnifiedBridgeApplication(
            read_app=self.read_app,
            write_limiter=_AllowWriteLimiter(),
        )
        self.write_spy = _ExplodingCoordinator()
        self.unified.write_coordinator = self.write_spy

    def assert_error(self, result: dict[str, object], status: int, code: str) -> None:
        self.assertTrue(str(result["status"]).startswith(str(status)), result)
        payload = result["json"]
        self.assertIsInstance(payload, dict)
        self.assertEqual(code, payload["error"]["code"])
        serialized = result["raw"].decode("utf-8")
        self.assertNotIn("Traceback", serialized)
        self.assertNotIn("AssertionError", serialized)

    def test_authentication_precedes_body_read_for_every_action_operation(self):
        self.assertEqual(17, len(OPERATIONS))
        for spec in OPERATIONS:
            for token in (None, "wrong-test-bearer-value-000000000046"):
                poison = _PoisonStream()
                with self.subTest(operation=spec.operation_id, token_present=token is not None):
                    result = _invoke(
                        self.unified,
                        path=spec.path,
                        token=token,
                        content_length="999999999",
                        stream=poison,
                    )
                    self.assert_error(result, 404, "not_found")
                    self.assertEqual(0, poison.read_count)
        self.assertEqual(0, self.backend.calls)
        self.assertEqual(0, self.write_spy.calls)

    def test_size_limit_precedes_body_read_for_every_action_operation(self):
        for spec in OPERATIONS:
            poison = _PoisonStream()
            with self.subTest(operation=spec.operation_id):
                result = _invoke(
                    self.unified,
                    path=spec.path,
                    content_length=str(self.read_app.config.max_json_bytes + 1),
                    stream=poison,
                )
                self.assert_error(result, 413, "request_too_large")
                self.assertEqual(0, poison.read_count)
        self.assertEqual(0, self.backend.calls)
        self.assertEqual(0, self.write_spy.calls)

    def test_malformed_and_unknown_bodies_never_reach_business_state(self):
        private_marker = "PRIVATE_BODY_SENTINEL_FINALWAVE46"
        for spec in OPERATIONS:
            with self.subTest(operation=spec.operation_id, vector="malformed"):
                raw = ("{\"value\":\"" + private_marker + "\",").encode("utf-8")
                result = _invoke(self.unified, path=spec.path, raw=raw)
                self.assert_error(result, 400, "malformed_json")
                self.assertNotIn(private_marker, result["raw"].decode("utf-8"))
            with self.subTest(operation=spec.operation_id, vector="unknown-field"):
                raw = b'{"__finalwave46_unknown__":1}'
                result = _invoke(self.unified, path=spec.path, raw=raw)
                self.assert_error(result, 400, "unknown_field")
        self.assertEqual(0, self.backend.calls)
        self.assertEqual(0, self.write_spy.calls)

    def test_content_type_and_length_smuggling_matrix_fails_closed(self):
        bad_content_types = (
            None,
            "",
            "text/plain",
            "application/json, application/json",
            "application/json,text/plain",
        )
        for value in bad_content_types:
            with self.subTest(content_type=value):
                with self.assertRaises(BridgeError) as raised:
                    self.read_app._read_json(_parser_environ(b"{}", content_type=value))
                self.assertEqual(415, raised.exception.status)
                self.assertEqual("invalid_content_type", raised.exception.code)

        bad_lengths = (None, "", "-1", "+2", " 2", "2 ", "2,2", "2, 2", "٢")
        for value in bad_lengths:
            poison = _PoisonStream()
            with self.subTest(content_length=value):
                with self.assertRaises(BridgeError) as raised:
                    self.read_app._read_json(
                        _parser_environ(b"", content_length=value, stream=poison)
                    )
                self.assertEqual("invalid_content_length", raised.exception.code)
                self.assertEqual(0, poison.read_count)

    def test_zero_and_short_content_length_obey_wsgi_framing(self):
        poison = _PoisonStream()
        parsed = self.read_app._read_json(
            _parser_environ(b"", content_length="0", stream=poison)
        )
        self.assertEqual({}, parsed)
        self.assertEqual(0, poison.read_count)

        stream = io.BytesIO(b"{}TRAILING-REQUEST-BYTES")
        parsed = self.read_app._read_json(
            _parser_environ(b"", content_length="2", stream=stream)
        )
        self.assertEqual({}, parsed)
        self.assertEqual(2, stream.tell())
        self.assertEqual(b"TRAILING-REQUEST-BYTES", stream.read())

        with self.assertRaises(BridgeError) as raised:
            self.read_app._read_json(_parser_environ(b"{", content_length="2"))
        self.assertEqual("incomplete_body", raised.exception.code)

    def test_nonfinite_and_extreme_numbers_are_rejected(self):
        vectors = (
            b'{"limit":NaN}',
            b'{"limit":Infinity}',
            b'{"limit":-Infinity}',
            b'{"limit":1e999}',
        )
        for raw in vectors:
            with self.subTest(raw=raw):
                with self.assertRaises(BridgeError) as raised:
                    self.read_app._read_json(_parser_environ(raw))
                self.assertEqual("invalid_json_number", raised.exception.code)

        huge_integer = b'{"limit":' + (b"9" * 5000) + b"}"
        with self.assertRaises(BridgeError) as raised:
            self.read_app._read_json(_parser_environ(huge_integer))
        self.assertEqual("malformed_json", raised.exception.code)

    def test_surrogates_are_rejected_in_values_and_object_keys(self):
        for raw in (b'{"value":"\\ud800"}', b'{"\\udfff":1}'):
            with self.subTest(raw=raw):
                with self.assertRaises(BridgeError) as raised:
                    self.read_app._read_json(_parser_environ(raw))
                self.assertEqual("invalid_json_string", raised.exception.code)

        valid = '{"value":"Привіт 😀"}'.encode("utf-8")
        self.assertEqual("Привіт 😀", self.read_app._read_json(_parser_environ(valid))["value"])

    def test_declared_depth_and_node_caps_and_parser_recursion_are_controlled(self):
        def nested_object(depth: int) -> bytes:
            return (("{\"x\":" * depth) + "0" + ("}" * depth)).encode("ascii")

        with self.assertRaises(BridgeError) as depth_error:
            self.read_app._read_json(_parser_environ(nested_object(self.read_app.config.max_json_depth + 1)))
        self.assertEqual(413, depth_error.exception.status)
        self.assertEqual("json_depth_limit", depth_error.exception.code)

        node_payload = {"items": list(range(self.read_app.config.max_json_nodes + 1))}
        node_raw = json.dumps(node_payload, separators=(",", ":")).encode("ascii")
        with self.assertRaises(BridgeError) as node_error:
            self.read_app._read_json(_parser_environ(node_raw))
        self.assertEqual(413, node_error.exception.status)
        self.assertEqual("json_node_limit", node_error.exception.code)

        # Force the JSON decoder's own recursion boundary before our tree walk.
        pathological = nested_object(1500)
        with self.assertRaises(BridgeError) as recursion_error:
            self.read_app._read_json(_parser_environ(pathological))
        self.assertEqual(413, recursion_error.exception.status)
        self.assertEqual("json_depth_limit", recursion_error.exception.code)


if __name__ == "__main__":
    unittest.main()
