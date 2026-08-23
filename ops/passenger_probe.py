# -*- coding: utf-8 -*-
"""Bounded HTTPS probe for challenged Passenger serving-request evidence.

The raw one-time challenge exists only in the caller's memory and in the single
HTTPS request header. This module never serializes it, logs it, or returns it.
A PASS requires the exact current Telegram Bridge seven-component health
contract; final Passenger proof additionally requires the private runtime,
binding and consumed-receipt artifacts validated by DEV_B.

Redirects are deliberately disabled. The challenge is proof material bound to
the exact production origin and must never be replayed or forwarded to a
redirect target, even when that target looks otherwise harmless.
"""
from __future__ import annotations

import json
import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass

from ops.release_guard import SafetyError

PRODUCTION_HOST = "tg-api.rukadopomogy.org.ua"
HEALTH_PATH = "/health"
CHALLENGE_HEADER = "X-Telegram-Bridge-Evidence-Challenge"
CHALLENGE_RE = re.compile(r"^[0-9a-f]{64}$")
MAX_BODY = 32 * 1024
MAX_TIMEOUT = 20.0
_REDIRECT_CODES = frozenset({301, 302, 303, 307, 308})
EXPECTED_HEALTH_COMPONENTS = frozenset({
    "auth",
    "backend",
    "storage",
    "read_rate_limit",
    "write_store",
    "write_rate_limit",
    "telegram_writer",
})
EXPECTED_COMPONENT_STATES = frozenset({"configured", "unconfigured"})


@dataclass(frozen=True)
class ProbeResult:
    status: str
    http_status: int | None
    reason_code: str


class _RejectRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Never create a follow-up request from a challenged evidence request."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401 - stdlib signature
        return None


def _open_no_redirect(request: urllib.request.Request, *, timeout: float):
    """Open exactly one HTTPS request with redirect processing disabled."""
    opener = urllib.request.build_opener(_RejectRedirectHandler())
    return opener.open(request, timeout=timeout)


def validate_probe_endpoint(url: str) -> str:
    if not isinstance(url, str) or len(url) > 512:
        raise SafetyError("Passenger probe endpoint invalid")
    parsed = urllib.parse.urlsplit(url)
    if (
        parsed.scheme != "https"
        or parsed.hostname != PRODUCTION_HOST
        or parsed.port not in {None, 443}
        or parsed.path != HEALTH_PATH
        or parsed.query
        or parsed.fragment
        or parsed.username
        or parsed.password
    ):
        raise SafetyError("Passenger probe endpoint is not exact production health")
    return url


def validate_probe_transport(endpoint: str, timeout: float) -> tuple[str, float]:
    """Validate every local transport parameter before evidence is armed.

    One-shot callers persist an owner-private marker. They must be able to
    reject deterministic local configuration errors before that state exists;
    otherwise a typo can strand a marker even though no HTTPS request ran.
    """
    endpoint = validate_probe_endpoint(endpoint)
    if (
        not isinstance(timeout, (int, float))
        or isinstance(timeout, bool)
        or not 0.1 <= float(timeout) <= MAX_TIMEOUT
    ):
        raise SafetyError("Passenger probe timeout invalid")
    return endpoint, float(timeout)


def _bounded_health_identity(body: bytes, content_type: str) -> bool:
    if len(body) > MAX_BODY or "json" not in content_type.casefold():
        return False
    try:
        data = json.loads(body.decode("utf-8", "strict"))
    except (UnicodeError, json.JSONDecodeError):
        return False
    if not isinstance(data, dict) or set(data) != {"ok", "service", "ready", "components"}:
        return False
    if data.get("ok") is not True or data.get("service") != "telegram-bridge" or not isinstance(data.get("ready"), bool):
        return False
    components = data.get("components")
    if not isinstance(components, dict) or set(components) != EXPECTED_HEALTH_COMPONENTS:
        return False
    if any(value not in EXPECTED_COMPONENT_STATES for value in components.values()):
        return False
    computed_ready = all(value == "configured" for value in components.values())
    return data["ready"] is computed_ready


def dispatch_challenged_health_probe(
    endpoint: str,
    raw_challenge: str,
    *,
    timeout: float = 5.0,
) -> ProbeResult:
    endpoint, timeout_value = validate_probe_transport(endpoint, timeout)
    if not isinstance(raw_challenge, str) or not CHALLENGE_RE.fullmatch(raw_challenge):
        raise SafetyError("Passenger probe challenge invalid")

    request = urllib.request.Request(
        endpoint,
        headers={
            "Accept": "application/json",
            "User-Agent": "TelegramBridgePassengerEvidenceProbe/1",
            CHALLENGE_HEADER: raw_challenge,
        },
        method="GET",
    )
    try:
        with _open_no_redirect(request, timeout=timeout_value) as response:
            status = int(response.status)
            body = response.read(MAX_BODY + 1)
            content_type = response.headers.get("Content-Type", "")
    except urllib.error.HTTPError as exc:
        try:
            code = int(exc.code)
        except (TypeError, ValueError):
            code = None
        reason = "PROBE_REDIRECT_REJECTED" if code in _REDIRECT_CODES else "PROBE_HTTP_REJECTED"
        return ProbeResult("FAIL", code, reason)
    except (OSError, ValueError):
        return ProbeResult("FAIL", None, "PROBE_NETWORK_FAILURE")
    finally:
        # Python cannot promise physical memory zeroization; only reference
        # lifetime and serialization/logging boundaries are claimed here.
        raw_challenge = ""

    if len(body) > MAX_BODY:
        return ProbeResult("FAIL", status, "PROBE_RESPONSE_TOO_LARGE")
    if status != 200:
        return ProbeResult("FAIL", status, "PROBE_STATUS_INVALID")
    if not _bounded_health_identity(body, content_type):
        return ProbeResult("FAIL", status, "PROBE_HEALTH_IDENTITY_INVALID")
    return ProbeResult("PASS", status, "PROBE_HEALTH_REQUEST_CONFIRMED")
