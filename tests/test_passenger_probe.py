# -*- coding: utf-8 -*-
from __future__ import annotations

import io
import json
import urllib.error
import urllib.request
import unittest
from unittest import mock

from ops import passenger_probe
from ops.release_guard import SafetyError


class _Headers:
    def __init__(self, content_type="application/json"):
        self.content_type = content_type
    def get(self, name, default=""):
        return self.content_type if name.casefold() == "content-type" else default


class _Response:
    def __init__(self, body: bytes, status=200, content_type="application/json"):
        self._body = body
        self.status = status
        self.headers = _Headers(content_type)
    def __enter__(self):
        return self
    def __exit__(self, *args):
        return False
    def read(self, limit=-1):
        return self._body if limit < 0 else self._body[:limit]


class _RedirectSimulationOpener:
    """Simulate a 302 response and expose whether a handler creates a follow-up."""

    def __init__(self, handler, endpoint, location):
        self.handler = handler
        self.endpoint = endpoint
        self.location = location
        self.redirected_request = None

    def open(self, request, timeout):
        self.redirected_request = self.handler.redirect_request(
            request,
            None,
            302,
            "Found",
            {"Location": self.location},
            self.location,
        )
        if self.redirected_request is not None:
            raise AssertionError("challenged Passenger probe attempted a redirected request")
        raise urllib.error.HTTPError(self.endpoint, 302, "Found", {"Location": self.location}, io.BytesIO(b""))


class PassengerProbeTests(unittest.TestCase):
    ENDPOINT = "https://tg-api.rukadopomogy.org.ua/health"
    CHALLENGE = "a" * 64

    @staticmethod
    def health(*, ready=False):
        components = {
            "auth": "configured",
            "backend": "configured" if ready else "unconfigured",
            "storage": "configured",
            "read_rate_limit": "configured",
            "write_store": "configured",
            "write_rate_limit": "configured",
            "telegram_writer": "configured" if ready else "unconfigured",
        }
        return json.dumps({"ok": True, "service": "telegram-bridge", "ready": ready, "components": components}).encode()

    def test_exact_production_health_endpoint_only(self):
        self.assertEqual(self.ENDPOINT, passenger_probe.validate_probe_endpoint(self.ENDPOINT))
        bad = (
            "http://tg-api.rukadopomogy.org.ua/health",
            "https://evil.example/health",
            "https://tg-api.rukadopomogy.org.ua:444/health",
            "https://tg-api.rukadopomogy.org.ua/health?x=1",
            "https://tg-api.rukadopomogy.org.ua/other",
            "https://u:p@tg-api.rukadopomogy.org.ua/health",
            "file:///health",
        )
        for value in bad:
            with self.subTest(value=value), self.assertRaises(SafetyError):
                passenger_probe.validate_probe_endpoint(value)

    def test_invalid_challenge_or_timeout_fail_before_network(self):
        with mock.patch.object(passenger_probe, "_open_no_redirect") as opener:
            with self.assertRaises(SafetyError):
                passenger_probe.dispatch_challenged_health_probe(self.ENDPOINT, "bad")
            with self.assertRaises(SafetyError):
                passenger_probe.dispatch_challenged_health_probe(self.ENDPOINT, self.CHALLENGE, timeout=0)
        opener.assert_not_called()

    def test_success_is_bounded_and_raw_challenge_not_returned(self):
        with mock.patch.object(passenger_probe, "_open_no_redirect", return_value=_Response(self.health())) as opener:
            result = passenger_probe.dispatch_challenged_health_probe(self.ENDPOINT, self.CHALLENGE)
        self.assertEqual("PASS", result.status)
        self.assertEqual(200, result.http_status)
        self.assertEqual("PROBE_HEALTH_REQUEST_CONFIRMED", result.reason_code)
        self.assertNotIn(self.CHALLENGE, repr(result))
        request = opener.call_args.args[0]
        self.assertEqual(self.CHALLENGE, request.headers.get("X-telegram-bridge-evidence-challenge"))

    def test_redirect_handler_refuses_to_construct_follow_up_request(self):
        handler = passenger_probe._RejectRedirectHandler()
        request = urllib.request.Request(
            self.ENDPOINT,
            headers={passenger_probe.CHALLENGE_HEADER: self.CHALLENGE},
            method="GET",
        )
        redirected = handler.redirect_request(
            request,
            None,
            302,
            "Found",
            {"Location": "https://example.invalid/capture"},
            "https://example.invalid/capture",
        )
        self.assertIsNone(redirected)
        self.assertEqual(self.CHALLENGE, request.headers.get("X-telegram-bridge-evidence-challenge"))

    def test_cross_origin_redirect_is_fail_closed_without_challenge_forward(self):
        handler = passenger_probe._RejectRedirectHandler()
        fake = _RedirectSimulationOpener(handler, self.ENDPOINT, "https://example.invalid/capture")
        with mock.patch.object(passenger_probe.urllib.request, "build_opener", return_value=fake) as builder:
            result = passenger_probe.dispatch_challenged_health_probe(self.ENDPOINT, self.CHALLENGE)
        self.assertEqual("FAIL", result.status)
        self.assertEqual(302, result.http_status)
        self.assertEqual("PROBE_REDIRECT_REJECTED", result.reason_code)
        self.assertIsNone(fake.redirected_request)
        self.assertNotIn(self.CHALLENGE, repr(result))
        self.assertEqual(1, builder.call_count)
        installed_handler = builder.call_args.args[0]
        self.assertIsInstance(installed_handler, passenger_probe._RejectRedirectHandler)

    def test_same_origin_redirect_is_also_rejected(self):
        handler = passenger_probe._RejectRedirectHandler()
        fake = _RedirectSimulationOpener(handler, self.ENDPOINT, self.ENDPOINT)
        with mock.patch.object(passenger_probe.urllib.request, "build_opener", return_value=fake):
            result = passenger_probe.dispatch_challenged_health_probe(self.ENDPOINT, self.CHALLENGE)
        self.assertEqual("PROBE_REDIRECT_REJECTED", result.reason_code)
        self.assertIsNone(fake.redirected_request)

    def test_wrong_health_identity_non_json_and_oversize_fail_bounded(self):
        cases = (
            (_Response(b'{}'), "PROBE_HEALTH_IDENTITY_INVALID"),
            (_Response(b"plain", content_type="text/plain"), "PROBE_HEALTH_IDENTITY_INVALID"),
            (_Response(b"x" * (passenger_probe.MAX_BODY + 1)), "PROBE_RESPONSE_TOO_LARGE"),
        )
        for response, reason in cases:
            with self.subTest(reason=reason), mock.patch.object(passenger_probe, "_open_no_redirect", return_value=response):
                result = passenger_probe.dispatch_challenged_health_probe(self.ENDPOINT, self.CHALLENGE)
                self.assertEqual("FAIL", result.status)
                self.assertEqual(reason, result.reason_code)
                self.assertNotIn(self.CHALLENGE, repr(result))

    def test_http_error_and_network_error_never_copy_body_or_exception(self):
        secretish = b"private-response-should-never-copy"
        error = urllib.error.HTTPError(self.ENDPOINT, 403, "private-error", {}, io.BytesIO(secretish))
        with mock.patch.object(passenger_probe, "_open_no_redirect", side_effect=error):
            result = passenger_probe.dispatch_challenged_health_probe(self.ENDPOINT, self.CHALLENGE)
        self.assertEqual("PROBE_HTTP_REJECTED", result.reason_code)
        self.assertNotIn("private", repr(result).casefold())
        with mock.patch.object(passenger_probe, "_open_no_redirect", side_effect=OSError("private-network-detail")):
            result = passenger_probe.dispatch_challenged_health_probe(self.ENDPOINT, self.CHALLENGE)
        self.assertEqual("PROBE_NETWORK_FAILURE", result.reason_code)
        self.assertNotIn("private", repr(result).casefold())

    def test_health_components_are_bounded_and_semantic(self):
        payload = json.loads(self.health())
        self.assertTrue(passenger_probe._bounded_health_identity(self.health(), "application/json"))
        payload["components"]["surprise"] = "configured"
        # Passenger serving proof must match the same exact seven-component
        # health contract used by the lifecycle validator. Unknown components
        # fail closed even when their value looks otherwise acceptable.
        self.assertFalse(passenger_probe._bounded_health_identity(json.dumps(payload).encode(), "application/json"))
        payload["components"]["surprise"] = "secret-state"
        self.assertFalse(passenger_probe._bounded_health_identity(json.dumps(payload).encode(), "application/json"))


if __name__ == "__main__":
    unittest.main()
