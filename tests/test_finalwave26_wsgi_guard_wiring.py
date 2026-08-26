"""FINALWAVE-26 production WSGI wiring regressions."""
from __future__ import annotations

import io
import sys
import unittest
from unittest import mock

from bridge.action_request_guard import ActionRequestGuard


class _SentinelApplication:
    def __init__(self):
        self.calls = 0

    def __call__(self, environ, start_response):
        del environ
        self.calls += 1
        start_response("204 No Content", [("Content-Length", "0")])
        return [b""]


class Finalwave26WsgiGuardWiringTests(unittest.TestCase):
    def tearDown(self):
        from bridge import runtime_wsgi

        runtime_wsgi.reset_runtime_application_for_tests()

    def test_lazy_runtime_builder_is_wrapped_exactly_once(self):
        from bridge import runtime_wsgi

        runtime_wsgi.reset_runtime_application_for_tests()
        sentinel = _SentinelApplication()
        captured = {}

        def start_response(status, headers):
            captured["status"] = status
            captured["headers"] = dict(headers)

        environ = {
            "REQUEST_METHOD": "GET",
            "PATH_INFO": "/health",
            "QUERY_STRING": "",
            "CONTENT_TYPE": "",
            "CONTENT_LENGTH": "0",
            "wsgi.input": io.BytesIO(b""),
        }
        with mock.patch("bridge.runtime.build_production_application_from_env", return_value=sentinel) as builder:
            body1 = b"".join(runtime_wsgi.application(environ, start_response))
            body2 = b"".join(runtime_wsgi.application(environ, start_response))
        self.assertEqual(b"", body1)
        self.assertEqual(b"", body2)
        self.assertEqual("204 No Content", captured["status"])
        builder.assert_called_once_with()
        self.assertIsInstance(runtime_wsgi._default_application, ActionRequestGuard)
        self.assertIs(runtime_wsgi._default_application.application, sentinel)
        self.assertEqual(2, sentinel.calls)

    def test_recovered_passenger_import_contract_still_resolves_guarded_runtime_wrapper(self):
        import bridge
        import bridge.app as app_module
        import passenger_wsgi
        from bridge import runtime_wsgi

        before = {name for name in sys.modules if name == "telethon" or name.startswith("telethon.")}
        self.assertIs(passenger_wsgi.application, runtime_wsgi.application)
        self.assertIs(bridge.application, runtime_wsgi.application)
        self.assertIs(app_module.application, runtime_wsgi.application)
        after = {name for name in sys.modules if name == "telethon" or name.startswith("telethon.")}
        self.assertEqual(before, after)


if __name__ == "__main__":
    unittest.main()
