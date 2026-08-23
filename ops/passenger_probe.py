# -*- coding: utf-8 -*-
"""Bounded HTTPS probe for challenged Passenger serving-request evidence.

The raw one-time challenge exists only in the caller's memory and in the single
HTTPS request header.  This module never serializes it, logs it, or returns it.
A PASS means the exact production health endpoint answered with the bounded
Telegram Bridge health identity; final Passenger proof still requires the
private runtime/binding/consumed-receipt artifacts validated by DEV_B.
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


@dataclass(frozen=True)
class ProbeResult:
    status: str
    http_status: int | None
    reason_code: str


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


def _bounded_health_identity(body: bytes, content_type: str) -> bool:
    if len(body) > MAX_BODY or "json" not in content_type.casefold():
        return False
    try:
        data = json.loads(body.decode("utf-8", "strict"))
    except (UnicodeError, json.JSONDecodeError):
        return False
    if not isinstance(data, dict) or data.get("ok") is not True or data.get("service") != "telegram-bridge":
        return False
    if not isinstance(data.get("ready"), bool):
        return False
    components = data.get("components")
    if not isinstance(components, dict) or not components or len(components) > 16:
        return False
    if any(not isinstance(key, str) or value not in {"configured", "unconfigured"} for key, value in components.items()):
        return False
    return True


def dispatch_challenged_health_probe(
    endpoint: str,
    raw_challenge: str,
    *,
    timeout: float = 5.0,
) -> ProbeResult:
    validate_probe_endpoint(endpoint)
    if not isinstance(raw_challenge, str) or not CHALLENGE_RE.fullmatch(raw_challenge):
        raise SafetyError("Passenger probe challenge invalid")
    if not isinstance(timeout, (int, float)) or isinstance(timeout, bool) or not 0.1 <= float(timeout) <= MAX_TIMEOUT:
        raise SafetyError("Passenger probe timeout invalid")

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
        with urllib.request.urlopen(request, timeout=float(timeout)) as response:
            status = int(response.status)
            body = response.read(MAX_BODY + 1)
            content_type = response.headers.get("Content-Type", "")
    except urllib.error.HTTPError as exc:
        # Never copy response bodies or arbitrary text into evidence/status.
        return ProbeResult("FAIL", int(exc.code), "PROBE_HTTP_REJECTED")
    except (OSError, ValueError):
        return ProbeResult("FAIL", None, "PROBE_NETWORK_FAILURE")
    finally:
        # Drop the local reference as soon as urllib has constructed/dispatched
        # the request.  Python cannot guarantee memory zeroization, so no stronger
        # claim is made.
        raw_challenge = ""

    if len(body) > MAX_BODY:
        return ProbeResult("FAIL", status, "PROBE_RESPONSE_TOO_LARGE")
    if status != 200:
        return ProbeResult("FAIL", status, "PROBE_STATUS_INVALID")
    if not _bounded_health_identity(body, content_type):
        return ProbeResult("FAIL", status, "PROBE_HEALTH_IDENTITY_INVALID")
    return ProbeResult("PASS", status, "PROBE_HEALTH_REQUEST_CONFIRMED")
