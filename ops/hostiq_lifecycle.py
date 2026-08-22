# -*- coding: utf-8 -*-
"""Non-auto-armed HOSTiQ lifecycle hooks for audited deployment integration.

All executable/reference files must live under an owner-controlled private
control root. Public Git alone cannot arm or trigger these hooks. Private file
reads/execution use TOCTOU-resistant descriptor-based access.
"""
from __future__ import annotations

import hashlib
import json
import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

try:
    from ops.release_guard import SafetyError
except ImportError:
    class SafetyError(RuntimeError):
        pass

from ops.private_control import read_private_text, run_private_executable, validate_private_file

SHA40 = re.compile(r"^[0-9a-f]{40}$")
MAX_HTTP_BODY = 32 * 1024
DEFAULT_TIMEOUT = 5.0
SAFE_PRIVATE_HOOK_NAMES = {"restart", "rollback"}
SETUP_PATH_RE = re.compile(r"/setup-[A-Za-z0-9_-]{16,}", re.IGNORECASE)
EXPECTED_HEALTH_COMPONENTS = {
    "auth",
    "backend",
    "storage",
    "read_rate_limit",
    "write_store",
    "write_rate_limit",
    "telegram_writer",
}
EXPECTED_COMPONENT_STATES = {"configured", "unconfigured"}
CANDIDATE_READ_PROBE_PATH = "/api/v1/dialogs/list"


@dataclass(frozen=True)
class HookResult:
    name: str
    status: str
    code: int | None = None
    detail_code: str | None = None


def run_private_hook(root: Path, hook: Path, *, expected_name: str, timeout: float = 20.0) -> HookResult:
    if expected_name not in SAFE_PRIVATE_HOOK_NAMES:
        raise SafetyError("unsupported private hook name")
    try:
        rc = run_private_executable(root, hook, timeout=timeout)
    except SafetyError:
        raise
    if rc == -1:
        return HookResult(expected_name, "FAIL", None, "HOOK_TIMEOUT")
    if rc != 0:
        return HookResult(expected_name, "FAIL", rc, "HOOK_NONZERO")
    return HookResult(expected_name, "PASS", 0, "HOOK_OK")


def validate_endpoint_url(url: str, *, expected_host: str = "tg-api.rukadopomogy.org.ua") -> str:
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https" or parsed.hostname != expected_host or parsed.username or parsed.password or parsed.fragment:
        raise SafetyError("runtime verification endpoint invalid")
    if parsed.port not in {None, 443}:
        raise SafetyError("runtime verification endpoint port invalid")
    if SETUP_PATH_RE.search(parsed.path):
        raise SafetyError("private setup route must never be used as lifecycle evidence endpoint")
    return url


def _request(url: str, *, timeout: float, token: str | None = None) -> tuple[int, bytes, str]:
    validate_endpoint_url(url)
    headers = {"Accept": "application/json", "User-Agent": "TelegramBridgeRuntimeVerifier/1"}
    if token is not None:
        headers["Authorization"] = "Bearer " + token
    request = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read(MAX_HTTP_BODY + 1)
            status = int(response.status)
            content_type = response.headers.get("Content-Type", "")
    except urllib.error.HTTPError as exc:
        body = exc.read(MAX_HTTP_BODY + 1)
        status = int(exc.code)
        content_type = exc.headers.get("Content-Type", "") if exc.headers else ""
    if len(body) > MAX_HTTP_BODY:
        raise SafetyError("smoke response body too large")
    return status, body, content_type


def _request_post_empty_json(url: str, *, timeout: float, token: str) -> tuple[int, bytes, str]:
    validate_endpoint_url(url)
    parsed = urllib.parse.urlsplit(url)
    if parsed.path != CANDIDATE_READ_PROBE_PATH or parsed.query:
        raise SafetyError("authenticated candidate probe endpoint invalid")
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "User-Agent": "TelegramBridgeRuntimeVerifier/1",
        "Authorization": "Bearer " + token,
    }
    request = urllib.request.Request(url, headers=headers, data=b"{}", method="POST")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read(MAX_HTTP_BODY + 1)
            status = int(response.status)
            content_type = response.headers.get("Content-Type", "")
    except urllib.error.HTTPError as exc:
        body = exc.read(MAX_HTTP_BODY + 1)
        status = int(exc.code)
        content_type = exc.headers.get("Content-Type", "") if exc.headers else ""
    if len(body) > MAX_HTTP_BODY:
        raise SafetyError("smoke response body too large")
    return status, body, content_type


def _candidate_health_payload(data: object) -> tuple[bool, bool]:
    if not isinstance(data, dict) or set(data) != {"ok", "service", "ready", "components"}:
        raise SafetyError("candidate health schema invalid")
    if data["ok"] is not True or data["service"] != "telegram-bridge" or not isinstance(data["ready"], bool):
        raise SafetyError("candidate health identity invalid")
    components = data["components"]
    if not isinstance(components, dict) or set(components) != EXPECTED_HEALTH_COMPONENTS:
        raise SafetyError("candidate health components invalid")
    if any(value not in EXPECTED_COMPONENT_STATES for value in components.values()):
        raise SafetyError("candidate health component state invalid")
    computed_ready = all(value == "configured" for value in components.values())
    if data["ready"] is not computed_ready:
        raise SafetyError("candidate health readiness inconsistent")
    return bool(data["ready"]), computed_ready


def health_check(url: str, *, timeout: float = DEFAULT_TIMEOUT, allow_bootstrap_not_ready: bool = False) -> HookResult:
    """Validate the integrated candidate's meaningful bounded health contract."""
    try:
        status, body, ctype = _request(url, timeout=timeout)
        if status != 200:
            return HookResult("health", "FAIL", status, "HEALTH_STATUS")
        if "json" not in ctype.casefold():
            return HookResult("health", "FAIL", status, "HEALTH_NOT_JSON")
        data = json.loads(body.decode("utf-8"))
        ready, _ = _candidate_health_payload(data)
        if ready:
            return HookResult("health", "PASS", status, "HEALTH_READY")
        if allow_bootstrap_not_ready:
            return HookResult("health", "PASS", status, "HEALTH_BOOTSTRAP_NOT_READY")
        return HookResult("health", "FAIL", status, "HEALTH_NOT_READY")
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError, SafetyError):
        return HookResult("health", "FAIL", None, "HEALTH_EXCEPTION")


def unauthenticated_smoke(url: str, *, timeout: float = DEFAULT_TIMEOUT) -> HookResult:
    try:
        status, body, _ = _request(url, timeout=timeout)
        if status not in {401, 403, 404}:
            return HookResult("unauth_smoke", "FAIL", status, "UNAUTH_NOT_REJECTED")
        lowered = body[:4096].decode("utf-8", errors="ignore").casefold()
        if "traceback (most recent call last)" in lowered or "tg_session_string" in lowered or "api_hash" in lowered:
            return HookResult("unauth_smoke", "FAIL", status, "UNAUTH_LEAK_SIGNATURE")
        return HookResult("unauth_smoke", "PASS", status, "UNAUTH_REJECTED")
    except (OSError, ValueError, SafetyError):
        return HookResult("unauth_smoke", "FAIL", None, "UNAUTH_EXCEPTION")


def _read_private_bearer(private_root: Path, token_file: Path) -> str:
    token = read_private_text(private_root, token_file, max_bytes=512).strip()
    if len(token) < 24 or len(token) > 512 or any(ch.isspace() for ch in token):
        raise SafetyError("private bearer reference invalid")
    return token


def authenticated_smoke(url: str, *, private_root: Path, token_file: Path, timeout: float = DEFAULT_TIMEOUT) -> HookResult:
    try:
        token = _read_private_bearer(private_root, token_file)
        status, body, ctype = _request(url, timeout=timeout, token=token)
        token = ""
        if status != 200 or "json" not in ctype.casefold():
            return HookResult("auth_smoke", "FAIL", status, "AUTH_STATUS_OR_TYPE")
        data = json.loads(body.decode("utf-8"))
        if not isinstance(data, dict):
            return HookResult("auth_smoke", "FAIL", status, "AUTH_SHAPE")
        if not (data.get("status") in {"ok", "ready"} or data.get("ok") is True):
            return HookResult("auth_smoke", "FAIL", status, "AUTH_SHAPE")
        return HookResult("auth_smoke", "PASS", status, "AUTH_OK")
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError, SafetyError):
        return HookResult("auth_smoke", "FAIL", None, "AUTH_EXCEPTION")


def candidate_authenticated_read_smoke(
    url: str,
    *,
    private_root: Path,
    token_file: Path,
    timeout: float = DEFAULT_TIMEOUT,
    allow_backend_unconfigured: bool = False,
) -> HookResult:
    """Authenticated POST probe for the integrated read API without live writes."""
    try:
        token = _read_private_bearer(private_root, token_file)
        status, body, ctype = _request_post_empty_json(url, timeout=timeout, token=token)
        token = ""
        if "json" not in ctype.casefold():
            return HookResult("auth_smoke", "FAIL", status, "AUTH_NOT_JSON")
        data = json.loads(body.decode("utf-8"))
        if status == 200:
            if isinstance(data, dict) and data.get("ok") is True and isinstance(data.get("data"), dict):
                return HookResult("auth_smoke", "PASS", status, "AUTH_READ_OK")
            return HookResult("auth_smoke", "FAIL", status, "AUTH_SHAPE")
        if allow_backend_unconfigured and status == 503:
            if (
                isinstance(data, dict)
                and data.get("ok") is False
                and isinstance(data.get("error"), dict)
                and set(data["error"]).issuperset({"code"})
                and data["error"].get("code") == "telegram_backend_unconfigured"
            ):
                return HookResult("auth_smoke", "PASS", status, "AUTH_ACCEPTED_BACKEND_NOT_READY")
        return HookResult("auth_smoke", "FAIL", status, "AUTH_STATUS_OR_SHAPE")
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError, SafetyError):
        return HookResult("auth_smoke", "FAIL", None, "AUTH_EXCEPTION")


def running_identity(private_root: Path, sha_file: Path, expected_sha: str) -> HookResult:
    if not SHA40.fullmatch(expected_sha):
        raise SafetyError("expected release SHA invalid")
    try:
        actual = read_private_text(private_root, sha_file, max_bytes=64).strip().casefold()
    except (OSError, UnicodeError, SafetyError):
        return HookResult("identity", "FAIL", None, "IDENTITY_REFERENCE_INVALID")
    if not SHA40.fullmatch(actual):
        return HookResult("identity", "FAIL", None, "IDENTITY_FILE_INVALID")
    if actual != expected_sha:
        return HookResult("identity", "FAIL", None, "IDENTITY_MISMATCH")
    return HookResult("identity", "PASS", None, "IDENTITY_MATCH")


def endpoint_hash(url: str) -> str:
    validate_endpoint_url(url)
    return hashlib.sha256(url.encode("utf-8")).hexdigest()


def lifecycle_failure_matrix() -> tuple[str, ...]:
    return (
        "RESTART_FAILURE", "IDENTITY_MISMATCH", "HEALTH_FAILURE",
        "UNAUTH_SMOKE_FAILURE", "AUTH_SMOKE_FAILURE", "RESUME_FAILURE",
        "ROLLBACK_HEALTH_FAILURE",
    )


def verify_serving_state(*, health: HookResult, identity: HookResult,
                         unauth: HookResult, auth: HookResult | None = None) -> HookResult:
    checks = [health, identity, unauth] + ([] if auth is None else [auth])
    if all(item.status == "PASS" for item in checks):
        return HookResult("resume", "PASS", None, "SERVING_STATE_CONFIRMED")
    return HookResult("resume", "FAIL", None, "SERVING_STATE_INCOMPLETE")


def orchestrate_lifecycle(*, restart: Callable[[], HookResult], identity: Callable[[], HookResult],
                          health: Callable[[], HookResult], unauth: Callable[[], HookResult],
                          auth: Callable[[], HookResult] | None, rollback: Callable[[], HookResult],
                          rollback_health: Callable[[], HookResult]) -> dict:
    completed: list[str] = []
    failed_stage: str | None = None
    for stage, call in (("restart", restart), ("identity", identity), ("health", health), ("unauth_smoke", unauth)):
        result = call()
        if result.status not in {"PASS", "FAIL"}:
            raise SafetyError("lifecycle hook returned invalid status")
        if result.status != "PASS":
            failed_stage = stage
            break
        completed.append(stage)
    if failed_stage is None and auth is not None:
        result = auth()
        if result.status not in {"PASS", "FAIL"}:
            raise SafetyError("lifecycle hook returned invalid status")
        if result.status != "PASS":
            failed_stage = "auth_smoke"
        else:
            completed.append("auth_smoke")
    if failed_stage is None:
        return {"status": "READY_FOR_AUDIT", "rollback_attempted": False,
                "completed_stages": completed, "failed_stage": None, "secret_values_recorded": False}
    rb = rollback(); rb_health = rollback_health()
    if rb.status not in {"PASS", "FAIL"} or rb_health.status not in {"PASS", "FAIL"}:
        raise SafetyError("rollback hook returned invalid status")
    status = "ROLLED_BACK" if rb.status == "PASS" and rb_health.status == "PASS" else "CRITICAL_ROLLBACK_FAILED"
    return {"status": status, "rollback_attempted": True,
            "completed_stages": completed, "failed_stage": failed_stage, "secret_values_recorded": False}
