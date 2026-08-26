# -*- coding: utf-8 -*-
"""Bounded HTTPS probe for challenged Passenger serving-request evidence.

The raw one-time challenge exists only in the caller's memory and in the single
HTTPS request header. This module never serializes it, logs it, or returns it.
A PASS requires the exact current Telegram Bridge seven-component health
contract; final Passenger proof additionally requires the private runtime,
binding and consumed-receipt artifacts validated by DEV_B.

Outbound-network boundary:
- only the canonical production HTTPS host and /health path are accepted;
- absent port or explicit 443 are normalized to the same canonical endpoint;
- userinfo, query, fragment, alternate host/path/port, IP literals, trailing-dot
  hosts and lookalikes are rejected before network I/O;
- redirects and ambient HTTP(S) proxy routing are disabled;
- response size and connect/read timing are bounded.

This is deliberately NOT a DNS-pinning claim. The hostname is a code constant,
not user input. Resolution and TLS trust remain the host OS / public-PKI trust
boundary; a future user-controlled outbound fetcher would require a separately
audited address-bound transport rather than resolve-then-connect validation.
"""
from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Callable

from ops.release_guard import SafetyError

PRODUCTION_HOST = "tg-api.rukadopomogy.org.ua"
HEALTH_PATH = "/health"
PRODUCTION_ENDPOINT = f"https://{PRODUCTION_HOST}{HEALTH_PATH}"
DNS_TRUST_MODEL = "FIXED_HOST_OS_RESOLVER_PUBLIC_PKI_NO_DNS_PINNING"
CHALLENGE_HEADER = "X-Telegram-Bridge-Evidence-Challenge"
CHALLENGE_RE = re.compile(r"^[0-9a-f]{64}$")
MAX_BODY = 32 * 1024
MAX_TIMEOUT = 20.0
READ_CHUNK = 8 * 1024
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

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _open_no_redirect(request: urllib.request.Request, *, timeout: float):
    """Open exactly one direct HTTPS request with redirects and proxies disabled."""
    opener = urllib.request.build_opener(
        _RejectRedirectHandler(),
        urllib.request.ProxyHandler({}),
    )
    return opener.open(request, timeout=timeout)


def validate_probe_endpoint(url: str) -> str:
    if not isinstance(url, str) or len(url) > 512:
        raise SafetyError("Passenger probe endpoint invalid")
    parsed = urllib.parse.urlsplit(url)
    allowed_netlocs = {PRODUCTION_HOST, f"{PRODUCTION_HOST}:443"}
    if (
        parsed.scheme != "https"
        or parsed.netloc not in allowed_netlocs
        or parsed.hostname != PRODUCTION_HOST
        or parsed.port not in {None, 443}
        or parsed.path != HEALTH_PATH
        or parsed.query
        or parsed.fragment
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise SafetyError("Passenger probe endpoint is not exact production health")
    return PRODUCTION_ENDPOINT


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


def _set_response_socket_timeout(response: object, timeout: float) -> None:
    """Best-effort bind the urllib response socket to the remaining deadline."""
    queue = [response]
    seen: set[int] = set()
    for _ in range(8):
        if not queue:
            return
        current = queue.pop(0)
        marker = id(current)
        if marker in seen:
            continue
        seen.add(marker)
        setter = getattr(current, "settimeout", None)
        if callable(setter):
            try:
                setter(max(0.001, timeout))
            except (OSError, ValueError):
                pass
            return
        for attr in ("fp", "raw", "_sock"):
            child = getattr(current, attr, None)
            if child is not None:
                queue.append(child)


def _read_bounded_response(
    response: object,
    *,
    deadline: float,
    clock: Callable[[], float] = time.monotonic,
) -> bytes:
    """Read at most MAX_BODY+1 bytes and stop when the total read deadline expires."""
    body = bytearray()
    reader = getattr(response, "read1", None)
    if not callable(reader):
        remaining = deadline - clock()
        if remaining <= 0:
            raise TimeoutError("Passenger probe response deadline exceeded")
        _set_response_socket_timeout(response, remaining)
        chunk = getattr(response, "read")(MAX_BODY + 1)
        if deadline - clock() < 0:
            raise TimeoutError("Passenger probe response deadline exceeded")
        if not isinstance(chunk, (bytes, bytearray)):
            raise OSError("Passenger probe response was not bytes")
        return bytes(chunk)
    while len(body) < MAX_BODY + 1:
        remaining = deadline - clock()
        if remaining <= 0:
            raise TimeoutError("Passenger probe response deadline exceeded")
        _set_response_socket_timeout(response, remaining)
        want = min(READ_CHUNK, MAX_BODY + 1 - len(body))
        chunk = reader(want)
        if not chunk:
            break
        if not isinstance(chunk, (bytes, bytearray)):
            raise OSError("Passenger probe response was not bytes")
        body.extend(chunk)
    return bytes(body)


def dispatch_challenged_health_probe(
    endpoint: str,
    raw_challenge: str,
    *,
    timeout: float = 5.0,
) -> ProbeResult:
    endpoint = validate_probe_endpoint(endpoint)
    if not isinstance(raw_challenge, str) or not CHALLENGE_RE.fullmatch(raw_challenge):
        raise SafetyError("Passenger probe challenge invalid")
    if not isinstance(timeout, (int, float)) or isinstance(timeout, bool) or not 0.1 <= float(timeout) <= MAX_TIMEOUT:
        raise SafetyError("Passenger probe timeout invalid")

    timeout_f = float(timeout)
    deadline = time.monotonic() + timeout_f
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
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return ProbeResult("FAIL", None, "PROBE_TIMEOUT")
        with _open_no_redirect(request, timeout=remaining) as response:
            status = int(response.status)
            body = _read_bounded_response(response, deadline=deadline)
            content_type = response.headers.get("Content-Type", "")
    except urllib.error.HTTPError as exc:
        try:
            code = int(exc.code)
        except (TypeError, ValueError):
            code = None
        reason = "PROBE_REDIRECT_REJECTED" if code in _REDIRECT_CODES else "PROBE_HTTP_REJECTED"
        return ProbeResult("FAIL", code, reason)
    except TimeoutError:
        return ProbeResult("FAIL", None, "PROBE_TIMEOUT")
    except (OSError, ValueError):
        return ProbeResult("FAIL", None, "PROBE_NETWORK_FAILURE")
    finally:
        raw_challenge = ""

    if len(body) > MAX_BODY:
        return ProbeResult("FAIL", status, "PROBE_RESPONSE_TOO_LARGE")
    if status != 200:
        return ProbeResult("FAIL", status, "PROBE_STATUS_INVALID")
    if not _bounded_health_identity(body, content_type):
        return ProbeResult("FAIL", status, "PROBE_HEALTH_IDENTITY_INVALID")
    return ProbeResult("PASS", status, "PROBE_HEALTH_REQUEST_CONFIRMED")