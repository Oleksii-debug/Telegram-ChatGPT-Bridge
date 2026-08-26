# -*- coding: utf-8 -*-
"""FINALWAVE-48 cross-layer outbound-network boundary regressions."""
from __future__ import annotations

import inspect
import unittest
import urllib.request
from unittest import mock

from bridge.errors import BridgeError
from bridge.integrated_app import UnifiedBridgeApplication
from ops import file_send_policy, passenger_probe
from ops.openapi_registry import build_action_openapi, registry_by_operation_id
from ops.release_guard import SafetyError


_FORBIDDEN_OUTBOUND_INPUT_KEYS = {
    "url",
    "uri",
    "href",
    "host",
    "hostname",
    "endpoint",
    "callback",
    "redirect",
    "redirect_url",
    "source_url",
    "file_url",
}


def _schema_property_names(node):
    names = set()
    if isinstance(node, dict):
        props = node.get("properties")
        if isinstance(props, dict):
            names.update(str(key).casefold() for key in props)
        for value in node.values():
            names.update(_schema_property_names(value))
    elif isinstance(node, list):
        for value in node:
            names.update(_schema_property_names(value))
    return names


class _DripResponse:
    status = 200
    headers = {"Content-Type": "application/json"}

    def read1(self, limit=-1):
        del limit
        return b"x"


class PublicActionOutboundBoundaryTests(unittest.TestCase):
    def test_action_request_schemas_expose_no_arbitrary_outbound_url_fields(self):
        schema = build_action_openapi("https://tg-api.rukadopomogy.org.ua")
        for path, methods in schema["paths"].items():
            for method, operation in methods.items():
                with self.subTest(path=path, method=method):
                    request_schema = operation["requestBody"]["content"]["application/json"]["schema"]
                    keys = _schema_property_names(request_schema)
                    self.assertTrue(
                        keys.isdisjoint(_FORBIDDEN_OUTBOUND_INPUT_KEYS),
                        f"Action request exposes outbound target field(s): {sorted(keys & _FORBIDDEN_OUTBOUND_INPUT_KEYS)}",
                    )

    def test_send_files_runtime_rejects_url_inside_file_reference(self):
        spec = registry_by_operation_id("previewTelegramFiles")
        body = {
            "chat": "Saved Messages",
            "files": [{
                "file_ref": "opaque-file-ref",
                "sha256": "a" * 64,
                "size": 1,
                "url": "https://example.com/payload",
            }],
        }
        with self.assertRaises(BridgeError) as ctx:
            UnifiedBridgeApplication._preview_payload(spec, body)
        self.assertEqual("unknown_field", ctx.exception.code)

    def test_send_files_runtime_rejects_top_level_outbound_target(self):
        spec = registry_by_operation_id("previewTelegramFiles")
        body = {
            "chat": "Saved Messages",
            "files": [{"file_ref": "opaque-file-ref", "sha256": "a" * 64, "size": 1}],
            "url": "https://example.com/payload",
        }
        with self.assertRaises(BridgeError) as ctx:
            UnifiedBridgeApplication._preview_payload(spec, body)
        self.assertEqual("unknown_field", ctx.exception.code)

    def test_legacy_file_policy_contains_no_http_client_or_dns_resolver(self):
        source = inspect.getsource(file_send_policy)
        for forbidden in ("urllib.request", "socket.getaddrinfo", "requests.get(", "http.client"):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, source)

    def test_passenger_probe_rejects_ip_case_trailing_dot_punycode_and_url_extras(self):
        bad = (
            "https://1.1.1.1/health",
            "https://127.0.0.1/health",
            "https://[::1]/health",
            "HTTPS://TG-API.RUKADOPOMOGY.ORG.UA/health",
            "https://tg-api.rukadopomogy.org.ua./health",
            "https://xn--tg-api-rukadopomogy-9gc.example/health",
            "https://user:pass@tg-api.rukadopomogy.org.ua/health",
            "https://tg-api.rukadopomogy.org.ua/health?q=1",
            "https://tg-api.rukadopomogy.org.ua/health#frag",
            "https://tg-api.rukadopomogy.org.ua:8443/health",
            "https://tg-api.rukadopomogy.org.ua/other",
        )
        for endpoint in bad:
            with self.subTest(endpoint=endpoint), self.assertRaises(SafetyError):
                passenger_probe.validate_probe_endpoint(endpoint)
        self.assertEqual(
            passenger_probe.PRODUCTION_ENDPOINT,
            passenger_probe.validate_probe_endpoint("https://tg-api.rukadopomogy.org.ua:443/health"),
        )

    def test_passenger_opener_disables_ambient_proxy_and_redirects(self):
        fake_opener = mock.Mock()
        fake_opener.open.return_value = "sentinel"
        request = urllib.request.Request(passenger_probe.PRODUCTION_ENDPOINT)
        with mock.patch.object(passenger_probe.urllib.request, "build_opener", return_value=fake_opener) as builder:
            self.assertEqual("sentinel", passenger_probe._open_no_redirect(request, timeout=1))
        handlers = builder.call_args.args
        self.assertIsInstance(handlers[0], passenger_probe._RejectRedirectHandler)
        proxy_handlers = [item for item in handlers if isinstance(item, urllib.request.ProxyHandler)]
        self.assertEqual(1, len(proxy_handlers))
        self.assertEqual({}, proxy_handlers[0].proxies)

    def test_slow_drip_response_hits_total_read_deadline(self):
        ticks = iter((0.0, 0.25, 0.75, 1.01))
        with self.assertRaises(TimeoutError):
            passenger_probe._read_bounded_response(
                _DripResponse(),
                deadline=1.0,
                clock=lambda: next(ticks),
            )

    def test_timeout_reason_is_bounded_and_does_not_reflect_exception(self):
        challenge = "a" * 64
        with mock.patch.object(passenger_probe, "_open_no_redirect", side_effect=TimeoutError("private-timeout-detail")):
            result = passenger_probe.dispatch_challenged_health_probe(
                passenger_probe.PRODUCTION_ENDPOINT,
                challenge,
            )
        self.assertEqual("PROBE_TIMEOUT", result.reason_code)
        self.assertNotIn("private", repr(result).casefold())

    def test_dns_trust_model_explicitly_disclaims_pinning(self):
        self.assertIn("NO_DNS_PINNING", passenger_probe.DNS_TRUST_MODEL)
        self.assertEqual("tg-api.rukadopomogy.org.ua", passenger_probe.PRODUCTION_HOST)


if __name__ == "__main__":
    unittest.main()