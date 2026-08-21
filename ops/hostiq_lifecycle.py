# -*- coding: utf-8 -*-
"""Non-auto-armed HOSTiQ lifecycle hooks for audited deployment integration.

All executable/token/SHA references must live under an owner-controlled private
control root.  Public Git alone cannot arm or trigger these hooks.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess
import urllib.error
import urllib.request
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

try:
    from ops.release_guard import SafetyError
except ImportError:
    class SafetyError(RuntimeError):
        pass

SHA40 = re.compile(r"^[0-9a-f]{40}$")
MAX_HTTP_BODY = 32 * 1024
DEFAULT_TIMEOUT = 5.0
SAFE_PRIVATE_HOOK_NAMES = {"restart", "rollback"}
SETUP_PATH_RE = re.compile(r"/setup-[A-Za-z0-9_-]{16,}", re.IGNORECASE)

@dataclass(frozen=True)
class HookResult:
    name: str
    status: str
    code: int | None = None
    detail_code: str | None = None


def validate_private_root(root: Path) -> Path:
    root = Path(os.path.abspath(os.fspath(root.expanduser())))
    if root.is_symlink():
        raise SafetyError("private control root must not be a symlink")
    st = root.lstat()
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.getuid() or stat.S_IMODE(st.st_mode) & 0o077:
        raise SafetyError("unsafe private control root")
    return root


def _inside(root: Path, child: Path) -> Path:
    root = validate_private_root(root)
    child = Path(os.path.abspath(os.fspath(child.expanduser())))
    try:
        rel = child.relative_to(root)
    except ValueError as exc:
        raise SafetyError("private hook path escapes control root") from exc
    cursor = root
    for part in rel.parts:
        cursor = cursor / part
        if cursor.is_symlink():
            raise SafetyError("symlink component in private hook path")
    return child


def validate_private_file(root: Path, path: Path, *, require_executable: bool = False, allow_empty: bool = False) -> Path:
    path = _inside(root, path)
    st = path.lstat()
    if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
        raise SafetyError("unsafe private hook topology")
    if st.st_uid != os.getuid():
        raise SafetyError("private hook owner mismatch")
    mode = stat.S_IMODE(st.st_mode)
    if mode & 0o077:
        raise SafetyError("private hook permissions too broad")
    if require_executable and not (mode & 0o100):
        raise SafetyError("private hook is not owner-executable")
    if not allow_empty and st.st_size == 0:
        raise SafetyError("private hook/reference file is empty")
    return path


def run_private_hook(root: Path, hook: Path, *, expected_name: str, timeout: float = 20.0) -> HookResult:
    if expected_name not in SAFE_PRIVATE_HOOK_NAMES:
        raise SafetyError("unsupported private hook name")
    hook = validate_private_file(root, hook, require_executable=True)
    try:
        proc = subprocess.run([str(hook)], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL, timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        return HookResult(expected_name, "FAIL", None, "HOOK_TIMEOUT")
    if proc.returncode != 0:
        return HookResult(expected_name, "FAIL", proc.returncode, "HOOK_NONZERO")
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


def health_check(url: str, *, timeout: float = DEFAULT_TIMEOUT) -> HookResult:
    try:
        status, body, ctype = _request(url, timeout=timeout)
        if status != 200:
            return HookResult("health", "FAIL", status, "HEALTH_STATUS")
        if "json" not in ctype.casefold():
            return HookResult("health", "FAIL", status, "HEALTH_NOT_JSON")
        data = json.loads(body.decode("utf-8"))
        if not isinstance(data, dict) or not (data.get("status") == "ok" or data.get("ok") is True):
            return HookResult("health", "FAIL", status, "HEALTH_SHAPE")
        return HookResult("health", "PASS", status, "HEALTH_OK")
    except (OSError, ValueError, json.JSONDecodeError, SafetyError):
        return HookResult("health", "FAIL", None, "HEALTH_EXCEPTION")


def unauthenticated_smoke(url: str, *, timeout: float = DEFAULT_TIMEOUT) -> HookResult:
    try:
        status, body, _ = _request(url, timeout=timeout)
        if status not in {401, 403, 404}:
            return HookResult("unauth_smoke", "FAIL", status, "UNAUTH_NOT_REJECTED")
        # Never serialize body; reject obvious server error/private-page signatures only by boolean decision.
        lowered = body[:4096].decode("utf-8", errors="ignore").casefold()
        if "traceback (most recent call last)" in lowered or "tg_session_string" in lowered or "api_hash" in lowered:
            return HookResult("unauth_smoke", "FAIL", status, "UNAUTH_LEAK_SIGNATURE")
        return HookResult("unauth_smoke", "PASS", status, "UNAUTH_REJECTED")
    except (OSError, ValueError, SafetyError):
        return HookResult("unauth_smoke", "FAIL", None, "UNAUTH_EXCEPTION")


def authenticated_smoke(url: str, *, private_root: Path, token_file: Path, timeout: float = DEFAULT_TIMEOUT) -> HookResult:
    try:
        token_path = validate_private_file(private_root, token_file)
        token = token_path.read_text(encoding="utf-8").strip()
        if len(token) < 24 or len(token) > 512 or any(ch.isspace() for ch in token):
            raise SafetyError("private bearer reference invalid")
        status, body, ctype = _request(url, timeout=timeout, token=token)
        token = ""  # minimize lifetime of reference
        if status != 200 or "json" not in ctype.casefold():
            return HookResult("auth_smoke", "FAIL", status, "AUTH_STATUS_OR_TYPE")
        data = json.loads(body.decode("utf-8"))
        if not isinstance(data, dict):
            return HookResult("auth_smoke", "FAIL", status, "AUTH_SHAPE")
        # Only test safe structural status keys; never return body content.
        if not (data.get("status") in {"ok", "ready"} or data.get("ok") is True):
            return HookResult("auth_smoke", "FAIL", status, "AUTH_SHAPE")
        return HookResult("auth_smoke", "PASS", status, "AUTH_OK")
    except (OSError, ValueError, json.JSONDecodeError, SafetyError):
        return HookResult("auth_smoke", "FAIL", None, "AUTH_EXCEPTION")


def running_identity(private_root: Path, sha_file: Path, expected_sha: str) -> HookResult:
    if not SHA40.fullmatch(expected_sha):
        raise SafetyError("expected release SHA invalid")
    try:
        sha_file = validate_private_file(private_root, sha_file)
        actual = sha_file.read_text(encoding="ascii").strip().casefold()
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
