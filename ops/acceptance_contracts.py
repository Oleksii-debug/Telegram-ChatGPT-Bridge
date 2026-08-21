# -*- coding: utf-8 -*-
"""Reusable synthetic QA/security/accessibility contracts for Telegram Bridge.

These contracts exercise deterministic safety semantics without real Telegram,
HOSTiQ credentials, private files or production secrets. They are prerequisite
engineering evidence only; they never constitute product or deployment PASS.
"""
from __future__ import annotations

import hashlib
import hmac
import io
import json
import math
import re
import threading
import time
import unicodedata
import urllib.parse
import zipfile
from dataclasses import dataclass, field
from html.parser import HTMLParser
from pathlib import PurePosixPath
from typing import Any, Callable, Iterable, Mapping, Sequence

from ops.acceptance_harness import CRITERIA
from ops import evidence_privacy as privacy


class ContractError(RuntimeError):
    pass


class ControlledInputError(ContractError):
    def __init__(self, error_code: str, status_code: int):
        super().__init__(error_code)
        self.error_code = error_code
        self.status_code = status_code


_PATH_CONFUSABLE_SEPARATORS = {"∕", "⁄", "／", "＼", "⧵"}
_WINDOWS_DRIVE_RE = re.compile(r"^[A-Za-z]:")
_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,80}$")
_IDEMPOTENCY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


def _fully_unquote(value: str, rounds: int = 3) -> str:
    current = value
    for _ in range(rounds):
        decoded = urllib.parse.unquote(current, errors="strict")
        if decoded == current:
            break
        current = decoded
    return current


def safe_relative_path(value: str) -> str:
    """Return canonical NFC POSIX path or fail closed on traversal/alias forms."""
    if not isinstance(value, str) or not value:
        raise ContractError("unsafe relative path")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
        raise ContractError("unsafe relative path")
    if "\\" in value or any(ch in value for ch in _PATH_CONFUSABLE_SEPARATORS):
        raise ContractError("unsafe relative path")
    decoded = _fully_unquote(value)
    if decoded != value and ("\\" in decoded or any(ch in decoded for ch in _PATH_CONFUSABLE_SEPARATORS)):
        raise ContractError("unsafe relative path")
    if decoded != value:
        decoded_parts = decoded.replace("\\", "/").split("/")
        if decoded.count("/") != value.count("/") or "\\" in decoded or any(part in {".", ".."} for part in decoded_parts):
            raise ContractError("unsafe relative path")
    normalized = unicodedata.normalize("NFC", decoded)
    if normalized.startswith("/") or normalized.startswith("//") or _WINDOWS_DRIVE_RE.match(normalized):
        raise ContractError("unsafe relative path")
    raw_parts = normalized.split("/")
    if any(part in {"", ".", ".."} for part in raw_parts):
        raise ContractError("unsafe relative path")
    path = PurePosixPath(normalized)
    if path.is_absolute() or ".." in path.parts:
        raise ContractError("unsafe relative path")
    return path.as_posix()


def authorization_outcome(*, auth_present: bool, auth_matches: bool) -> str:
    if not auth_present:
        return "MISSING_AUTH"
    if not auth_matches:
        return "WRONG_AUTH"
    return "AUTHORIZED"


def bearer_auth_outcome(header: str | None, *, expected_token_sha256: str) -> str:
    if not isinstance(expected_token_sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", expected_token_sha256):
        raise ValueError("expected token hash required")
    if header is None or header == "":
        return "MISSING_AUTH"
    if not isinstance(header, str) or header.strip() != header:
        return "MALFORMED_AUTH"
    match = re.fullmatch(r"Bearer ([^\s]{1,512})", header)
    if not match:
        return "MALFORMED_AUTH"
    provided_sha = hashlib.sha256(match.group(1).encode("utf-8")).hexdigest()
    return "AUTHORIZED" if hmac.compare_digest(provided_sha, expected_token_sha256) else "WRONG_AUTH"


def parse_json_object(raw: bytes | str, *, content_length: int | None = None, max_bytes: int = 65_536) -> dict[str, Any]:
    if isinstance(raw, str):
        encoded = raw.encode("utf-8")
    elif isinstance(raw, bytes):
        encoded = raw
    else:
        raise ControlledInputError("INVALID_JSON", 400)
    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes <= 0:
        raise ValueError("max_bytes must be positive")
    if content_length is not None:
        if isinstance(content_length, bool) or not isinstance(content_length, int) or content_length < 0:
            raise ControlledInputError("INVALID_CONTENT_LENGTH", 400)
        if content_length > max_bytes:
            raise ControlledInputError("PAYLOAD_TOO_LARGE", 413)
        if content_length != len(encoded):
            raise ControlledInputError("INVALID_CONTENT_LENGTH", 400)
    if len(encoded) > max_bytes:
        raise ControlledInputError("PAYLOAD_TOO_LARGE", 413)
    try:
        text = encoded.decode("utf-8")
        payload = json.loads(text)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ControlledInputError("INVALID_JSON", 400) from exc
    if not isinstance(payload, dict):
        raise ControlledInputError("INVALID_JSON_SHAPE", 400)
    return payload


def bounded_int(value: Any, *, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum or value > maximum:
        raise ControlledInputError("INPUT_OUT_OF_RANGE", 400)
    return value


@dataclass(frozen=True)
class RateLimitDecision:
    allowed: bool
    remaining: int
    retry_after_seconds: int
    window_start: int


class FixedWindowRateLimiter:
    def __init__(self, limit: int, *, window_seconds: int = 60, clock: Callable[[], float] | None = None):
        if not isinstance(limit, int) or isinstance(limit, bool) or limit <= 0:
            raise ValueError("positive integer rate limit required")
        if not isinstance(window_seconds, int) or isinstance(window_seconds, bool) or window_seconds <= 0:
            raise ValueError("positive integer window required")
        self.limit = limit
        self.window_seconds = window_seconds
        self.clock = clock or time.time
        self._buckets: dict[str, tuple[int, int]] = {}

    def _decision(self, actor_hash: str, now: float | None = None) -> RateLimitDecision:
        if not isinstance(actor_hash, str) or not actor_hash or len(actor_hash) > 128 or any(ch.isspace() for ch in actor_hash):
            raise ValueError("stable actor hash required")
        current = self.clock() if now is None else now
        if isinstance(current, bool) or not isinstance(current, (int, float)) or not math.isfinite(float(current)) or current < 0:
            raise ValueError("non-negative finite clock value required")
        window_index = int(float(current) // self.window_seconds)
        window_start = window_index * self.window_seconds
        prior_window, count = self._buckets.get(actor_hash, (window_index, 0))
        if prior_window != window_index:
            count = 0
        if count >= self.limit:
            retry_after = max(1, int(math.ceil(window_start + self.window_seconds - float(current))))
            self._buckets[actor_hash] = (window_index, count)
            return RateLimitDecision(False, 0, retry_after, window_start)
        count += 1
        self._buckets[actor_hash] = (window_index, count)
        return RateLimitDecision(True, self.limit - count, 0, window_start)

    def consume(self, actor_hash: str, *, now: float | None = None) -> tuple[bool, int]:
        decision = self._decision(actor_hash, now)
        return decision.allowed, decision.remaining

    def consume_with_metadata(self, actor_hash: str, *, now: float | None = None) -> RateLimitDecision:
        return self._decision(actor_hash, now)


class FakeTelegramAuthFlow:
    """No phone/code/password values are accepted; only outcome booleans."""
    def request_code(self, *, flood_wait: bool = False, rpc_failure: bool = False) -> str:
        if flood_wait:
            return "FLOOD_WAIT"
        if rpc_failure:
            return "RPC_ERROR"
        return "CODE_REQUESTED"

    def sign_in(self, *, code_valid: bool, requires_2fa: bool = False,
                second_factor_valid: bool = True, flood_wait: bool = False,
                rpc_failure: bool = False) -> str:
        if flood_wait:
            return "FLOOD_WAIT"
        if rpc_failure:
            return "RPC_ERROR"
        if not code_valid:
            return "INVALID_CODE"
        if requires_2fa and not second_factor_valid:
            return "INVALID_2FA"
        return "AUTHORIZED"


TELEGRAM_FAKE_OUTCOMES = {
    "OK", "TIMEOUT", "FLOOD_WAIT", "RPC_ERROR", "UNAUTHORIZED_SESSION",
    "LOCK_TIMEOUT", "CANCELLED", "PARTIAL_MEDIA_FAILURE",
}


class FakeTelegramOperationState:
    def __init__(self):
        self.state = "READY"
        self.checkpoint = 0

    def advance(self, checkpoint: int) -> None:
        if checkpoint < self.checkpoint:
            raise ContractError("checkpoint regression")
        self.checkpoint = checkpoint
        self.state = "RUNNING"

    def run_outcome(self, outcome: str) -> dict[str, Any]:
        if outcome not in TELEGRAM_FAKE_OUTCOMES:
            raise ValueError("unsupported synthetic Telegram outcome")
        if outcome == "OK":
            self.state = "COMPLETED"
            return {"state": self.state, "recoverable": True, "checkpoint": self.checkpoint}
        if outcome == "CANCELLED":
            self.state = "CANCELLED"
        elif outcome == "UNAUTHORIZED_SESSION":
            self.state = "BLOCKED"
        else:
            self.state = "RETRYABLE"
        return {"state": self.state, "recoverable": True, "checkpoint": self.checkpoint}


@dataclass(frozen=True)
class SyntheticMessage:
    message_id: int
    dialog_id: int
    sender_id: int
    text: str
    timestamp: int


class SyntheticMessageStore:
    def __init__(self, messages: Iterable[SyntheticMessage]):
        self.messages = sorted(list(messages), key=lambda item: (item.timestamp, item.message_id))

    def list_dialogs(self) -> list[int]:
        return sorted({item.dialog_id for item in self.messages})

    def history(self, dialog_id: int, *, offset: int = 0, limit: int = 50) -> list[SyntheticMessage]:
        if offset < 0 or limit <= 0 or limit > 100:
            raise ContractError("invalid pagination")
        rows = [item for item in self.messages if item.dialog_id == dialog_id]
        return rows[offset:offset + limit]

    def search(self, *, dialog_id: int | None = None, sender_id: int | None = None,
               text: str | None = None, date_from: int | None = None,
               date_to: int | None = None) -> list[SyntheticMessage]:
        rows = self.messages
        if dialog_id is not None:
            rows = [item for item in rows if item.dialog_id == dialog_id]
        if sender_id is not None:
            rows = [item for item in rows if item.sender_id == sender_id]
        if text is not None:
            query = text.casefold()
            rows = [item for item in rows if query in item.text.casefold()]
        if date_from is not None:
            rows = [item for item in rows if item.timestamp >= date_from]
        if date_to is not None:
            rows = [item for item in rows if item.timestamp <= date_to]
        return list(rows)


@dataclass(frozen=True)
class SyntheticMedia:
    file_id: str
    kind: str
    content: bytes

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.content).hexdigest()


class SyntheticDownloadJob:
    def __init__(self, items: Iterable[SyntheticMedia]):
        self.items = list(items)
        self.completed: dict[str, bytes] = {}
        self.failed = False
        self._requested: list[str] = []
        self._cursor = 0

    def _match(self, file_id: str) -> SyntheticMedia | None:
        return next((item for item in self.items if item.file_id == file_id), None)

    def download_one(self, file_id: str, expected_sha256: str) -> bytes:
        match = self._match(file_id)
        if match is None:
            raise ContractError("file not found")
        if match.sha256 != expected_sha256:
            raise ContractError("file hash mismatch")
        self.completed.setdefault(file_id, match.content)
        return self.completed[file_id]

    def start_bulk(self, file_ids: Iterable[str]) -> None:
        self._requested = list(dict.fromkeys(file_ids))
        self._cursor = 0
        self.failed = False

    def run_next(self) -> bool:
        if self.failed:
            return False
        while self._cursor < len(self._requested):
            file_id = self._requested[self._cursor]
            self._cursor += 1
            match = self._match(file_id)
            if match is None:
                continue
            self.download_one(file_id, match.sha256)
            return True
        return False

    def bulk(self, file_ids: Iterable[str]) -> dict[str, bytes]:
        self.start_bulk(file_ids)
        while self.run_next():
            pass
        return {file_id: self.completed[file_id] for file_id in self._requested if file_id in self.completed}

    def mark_interrupted(self) -> None:
        self.failed = True

    def resume(self) -> dict[str, bytes]:
        self.failed = False
        while self.run_next():
            pass
        if self._requested:
            return {file_id: self.completed[file_id] for file_id in self._requested if file_id in self.completed}
        return dict(self.completed)

    @property
    def pending_count(self) -> int:
        return max(0, len(self._requested) - self._cursor)


def _iter_archive_entries(files: Mapping[str, bytes] | Iterable[tuple[str, bytes]]) -> list[tuple[str, bytes]]:
    return list(files.items()) if isinstance(files, Mapping) else list(files)


def build_zip(files: Mapping[str, bytes] | Iterable[tuple[str, bytes]], *,
              max_members: int = 100, max_member_bytes: int = 10_000_000,
              max_total_bytes: int = 50_000_000) -> bytes:
    entries = _iter_archive_entries(files)
    if len(entries) > max_members:
        raise ContractError("archive member limit exceeded")
    buffer = io.BytesIO()
    seen: set[str] = set()
    collision_keys: set[str] = set()
    total = 0
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, content in entries:
            if not isinstance(content, bytes):
                raise ContractError("archive content must be bytes")
            if len(content) > max_member_bytes:
                raise ContractError("archive member size limit exceeded")
            total += len(content)
            if total > max_total_bytes:
                raise ContractError("archive expanded size limit exceeded")
            safe = safe_relative_path(name)
            collision_key = unicodedata.normalize("NFC", safe).casefold()
            if safe in seen or collision_key in collision_keys:
                raise ContractError("duplicate archive entry")
            seen.add(safe)
            collision_keys.add(collision_key)
            archive.writestr(safe, content)
    payload = buffer.getvalue()
    with zipfile.ZipFile(io.BytesIO(payload), "r") as archive:
        if len(archive.infolist()) != len(seen) or sorted(archive.namelist()) != sorted(seen) or archive.testzip() is not None:
            raise ContractError("zip validation failed")
    return payload


def private_file_access(*, authorized: bool) -> str:
    return "PRIVATE_FILE_ALLOWED" if authorized else "PRIVATE_FILE_DENIED"


@dataclass
class PrivateFileRecord:
    file_id: str
    path_sha256: str
    content_sha256: str
    max_downloads: int
    downloads: int = 0
    deleted: bool = False


class SignedPrivateFileStore:
    """Synthetic HMAC model. No server path or secret is exposed in decisions."""
    def __init__(self, secret: bytes):
        if not isinstance(secret, bytes) or len(secret) < 16:
            raise ValueError("synthetic signing key must be at least 16 bytes")
        self._secret = bytes(secret)
        self._records: dict[str, PrivateFileRecord] = {}

    def add(self, *, file_id: str, relative_path: str, content_sha256: str, max_downloads: int = 1) -> None:
        if not _ID_RE.fullmatch(file_id):
            raise ContractError("invalid file id")
        canonical = safe_relative_path(relative_path)
        if not re.fullmatch(r"[0-9a-f]{64}", content_sha256):
            raise ContractError("content hash required")
        if not isinstance(max_downloads, int) or isinstance(max_downloads, bool) or max_downloads <= 0:
            raise ContractError("positive download cap required")
        self._records[file_id] = PrivateFileRecord(
            file_id=file_id,
            path_sha256=hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
            content_sha256=content_sha256,
            max_downloads=max_downloads,
        )

    def _signature(self, file_id: str, expires_at: int) -> str:
        return hmac.new(self._secret, f"{file_id}|{expires_at}".encode("utf-8"), hashlib.sha256).hexdigest()

    def issue(self, file_id: str, *, expires_at: int) -> str:
        if file_id not in self._records or expires_at <= 0:
            raise ContractError("cannot issue file token")
        return f"{file_id}.{expires_at}.{self._signature(file_id, expires_at)}"

    def delete(self, file_id: str) -> None:
        if file_id in self._records:
            self._records[file_id].deleted = True

    def authorize(self, token: str, *, now: int, authorized: bool,
                  requested_file_id: str | None = None, relative_path: str | None = None) -> str:
        if not authorized:
            return "UNAUTHORIZED"
        try:
            file_id, expires_text, signature = token.split(".", 2)
            expires_at = int(expires_text)
        except (ValueError, AttributeError):
            return "INVALID_SIGNATURE"
        if not _ID_RE.fullmatch(file_id) or not hmac.compare_digest(self._signature(file_id, expires_at), signature):
            return "INVALID_SIGNATURE"
        if now > expires_at:
            return "EXPIRED"
        record = self._records.get(file_id)
        if record is None:
            return "NOT_FOUND"
        if record.deleted:
            return "DELETED"
        if requested_file_id is not None and requested_file_id != file_id:
            return "FILE_ID_MISMATCH"
        if relative_path is not None:
            try:
                canonical = safe_relative_path(relative_path)
            except ContractError:
                return "PATH_MISMATCH"
            path_sha = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
            if not hmac.compare_digest(path_sha, record.path_sha256):
                return "PATH_MISMATCH"
        if record.downloads >= record.max_downloads:
            return "DOWNLOAD_LIMIT"
        record.downloads += 1
        return "ALLOWED"


@dataclass
class PreviewRecord:
    action: str
    target_sha256: str
    payload_sha256: str
    expires_at: int
    used: bool = False


@dataclass(frozen=True)
class IdempotencyRecord:
    request_sha256: str
    result: str


class PreviewCommitStore:
    def __init__(self):
        self._counter = 0
        self._records: dict[str, PreviewRecord] = {}
        self._idempotency: dict[str, IdempotencyRecord] = {}
        self._lock = threading.Lock()

    @staticmethod
    def _request_fingerprint(record: PreviewRecord) -> str:
        material = json.dumps(
            {"action": record.action, "target_sha256": record.target_sha256, "payload_sha256": record.payload_sha256},
            sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        ).encode("ascii")
        return hashlib.sha256(material).hexdigest()

    def create_preview(self, *, action: str, target_sha256: str, payload_sha256: str,
                       now: int, ttl_seconds: int = 300) -> str:
        if ttl_seconds <= 0 or ttl_seconds > 3600:
            raise ContractError("invalid preview TTL")
        for digest in (target_sha256, payload_sha256):
            if len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest):
                raise ContractError("hash-bound preview required")
        if action not in {"SEND", "REPLY", "FORWARD", "SEND_FILE", "SEND_FILES"}:
            raise ContractError("unsupported preview action")
        self._counter += 1
        opaque = hashlib.sha256(f"{self._counter}|{action}|{target_sha256}|{payload_sha256}|{now}".encode()).hexdigest()
        self._records[opaque] = PreviewRecord(action, target_sha256, payload_sha256, now + ttl_seconds)
        return opaque

    def commit(self, preview_key: str, *, now: int, idempotency_key: str) -> str:
        if not isinstance(idempotency_key, str) or not _IDEMPOTENCY_RE.fullmatch(idempotency_key):
            return "INVALID_IDEMPOTENCY_KEY"
        with self._lock:
            record = self._records.get(preview_key)
            if record is None:
                return "INVALID_PREVIEW"
            fingerprint = self._request_fingerprint(record)
            prior = self._idempotency.get(idempotency_key)
            if prior is not None:
                if not hmac.compare_digest(prior.request_sha256, fingerprint):
                    return "IDEMPOTENCY_CONFLICT"
                return prior.result
            if now > record.expires_at:
                return "EXPIRED_PREVIEW"
            if record.used:
                return "USED_PREVIEW"
            record.used = True
            self._idempotency[idempotency_key] = IdempotencyRecord(fingerprint, "COMMITTED")
            return "COMMITTED"

    def audit_metadata(self, preview_key: str) -> dict[str, Any]:
        record = self._records[preview_key]
        return {
            "operation_kind": record.action,
            "target_sha256": record.target_sha256,
            "payload_sha256": record.payload_sha256,
            "used": record.used,
        }

    def export_state(self) -> dict[str, Any]:
        with self._lock:
            return {
                "counter": self._counter,
                "records": {
                    key: {
                        "action": item.action,
                        "target_sha256": item.target_sha256,
                        "payload_sha256": item.payload_sha256,
                        "expires_at": item.expires_at,
                        "used": item.used,
                    }
                    for key, item in self._records.items()
                },
                "idempotency": {
                    key: {"request_sha256": item.request_sha256, "result": item.result}
                    for key, item in self._idempotency.items()
                },
            }

    @classmethod
    def from_state(cls, state: Mapping[str, Any]) -> "PreviewCommitStore":
        try:
            copied = json.loads(json.dumps(state, ensure_ascii=True))
        except (TypeError, ValueError) as exc:
            raise ContractError("invalid synthetic idempotency state") from exc
        store = cls()
        if not isinstance(copied, dict) or not isinstance(copied.get("counter"), int):
            raise ContractError("invalid synthetic idempotency state")
        store._counter = copied["counter"]
        records = copied.get("records", {})
        if not isinstance(records, dict):
            raise ContractError("invalid synthetic idempotency state")
        for key, raw in records.items():
            if not re.fullmatch(r"[0-9a-f]{64}", key) or not isinstance(raw, dict):
                raise ContractError("invalid synthetic preview state")
            action = raw.get("action")
            target = raw.get("target_sha256")
            payload = raw.get("payload_sha256")
            expires = raw.get("expires_at")
            used = raw.get("used")
            if action not in {"SEND", "REPLY", "FORWARD", "SEND_FILE", "SEND_FILES"}:
                raise ContractError("invalid synthetic preview state")
            if not isinstance(target, str) or not re.fullmatch(r"[0-9a-f]{64}", target):
                raise ContractError("invalid synthetic preview state")
            if not isinstance(payload, str) or not re.fullmatch(r"[0-9a-f]{64}", payload):
                raise ContractError("invalid synthetic preview state")
            if not isinstance(expires, int) or isinstance(expires, bool) or not isinstance(used, bool):
                raise ContractError("invalid synthetic preview state")
            store._records[key] = PreviewRecord(action, target, payload, expires, used)
        idempotency = copied.get("idempotency", {})
        if not isinstance(idempotency, dict):
            raise ContractError("invalid synthetic idempotency state")
        for key, raw in idempotency.items():
            if not _IDEMPOTENCY_RE.fullmatch(key) or not isinstance(raw, dict):
                raise ContractError("invalid synthetic idempotency record")
            digest = raw.get("request_sha256")
            result = raw.get("result")
            if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest) or result != "COMMITTED":
                raise ContractError("invalid synthetic idempotency record")
            store._idempotency[key] = IdempotencyRecord(digest, result)
        return store


class ResumableJob:
    def __init__(self, *, timeout_ms: int):
        if timeout_ms <= 0:
            raise ValueError("timeout required")
        self.timeout_ms = timeout_ms
        self.checkpoint = 0
        self.state = "READY"

    def advance(self, checkpoint: int) -> None:
        if checkpoint < self.checkpoint:
            raise ContractError("job checkpoint cannot move backward")
        self.checkpoint = checkpoint
        self.state = "RUNNING"

    def fail(self) -> None:
        self.state = "RETRYABLE"

    def resume(self) -> int:
        if self.state not in {"RETRYABLE", "RUNNING", "READY"}:
            raise ContractError("job is not resumable")
        self.state = "RUNNING"
        return self.checkpoint

    def complete(self) -> None:
        self.state = "COMPLETED"


@dataclass(frozen=True)
class RoutePolicy:
    operation_id: str
    path: str
    method: str
    access: str
    kind: str
    preview_operation_id: str | None = None

    def __post_init__(self) -> None:
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]{0,79}", self.operation_id):
            raise ValueError("invalid operation id")
        if not isinstance(self.path, str) or not self.path.startswith("/"):
            raise ValueError("invalid route path")
        method = self.method.upper()
        if method not in {"GET", "POST", "PUT", "PATCH", "DELETE"}:
            raise ValueError("invalid route method")
        if self.access not in {"PUBLIC", "PROTECTED"}:
            raise ValueError("invalid route access")
        if self.kind not in {"READ", "PREVIEW", "COMMIT", "WRITE"}:
            raise ValueError("invalid operation kind")
        object.__setattr__(self, "method", method)


DEFAULT_PUBLIC_ALLOWLIST = frozenset({("GET", "/health")})
_PRIVATE_SETUP_PATTERN = re.compile(r"/setup(?:[-_/][A-Za-z0-9_-]+)?", re.I)
_SECRET_ROUTE_PATTERN = re.compile(r"/setup-[A-Za-z0-9_-]{8,}", re.I)


def build_route_registry(routes: Iterable[RoutePolicy]) -> dict[tuple[str, str], RoutePolicy]:
    registry: dict[tuple[str, str], RoutePolicy] = {}
    operation_ids: set[str] = set()
    for route in routes:
        key = (route.method, route.path)
        if key in registry or route.operation_id in operation_ids:
            raise ContractError("duplicate route registry entry")
        registry[key] = route
        operation_ids.add(route.operation_id)
    for route in registry.values():
        if route.kind in {"COMMIT", "WRITE"}:
            if not route.preview_operation_id:
                raise ContractError("write/commit route missing preview pairing")
            paired = next((r for r in registry.values() if r.operation_id == route.preview_operation_id), None)
            if paired is None or paired.kind != "PREVIEW" or paired.access != "PROTECTED":
                raise ContractError("write/commit route has invalid preview pairing")
    return registry


def _schema_operations(schema: dict[str, Any]) -> dict[tuple[str, str], dict[str, Any]]:
    result: dict[tuple[str, str], dict[str, Any]] = {}
    paths = schema.get("paths")
    if not isinstance(paths, dict):
        return result
    for path, item in paths.items():
        if not isinstance(path, str) or not isinstance(item, dict):
            continue
        for method, operation in item.items():
            method_upper = str(method).upper()
            if method_upper in {"GET", "POST", "PUT", "PATCH", "DELETE"} and isinstance(operation, dict):
                result[(method_upper, path)] = operation
    return result


def _inferred_kind(method: str, path: str) -> str:
    folded = path.rstrip("/").casefold()
    if method == "GET":
        return "READ"
    if folded.endswith("/preview"):
        return "PREVIEW"
    if folded.endswith("/commit"):
        return "COMMIT"
    return "WRITE"


def _inferred_preview_path(path: str) -> str:
    folded = path.rstrip("/")
    if folded.casefold().endswith("/commit"):
        return folded[:-7] + "/preview"
    return folded + "/preview"


def _contains_private_setup_material(schema: dict[str, Any]) -> bool:
    paths = schema.get("paths")
    if isinstance(paths, dict) and any(_PRIVATE_SETUP_PATTERN.search(str(path)) for path in paths):
        return True
    try:
        encoded = json.dumps({k: v for k, v in schema.items() if k != "paths"}, ensure_ascii=False)
    except (TypeError, ValueError):
        return True
    return bool(_SECRET_ROUTE_PATTERN.search(encoded))


def validate_openapi_contract(schema: dict[str, Any], *,
                              route_registry: Iterable[RoutePolicy] | None = None,
                              public_allowlist: frozenset[tuple[str, str]] = DEFAULT_PUBLIC_ALLOWLIST) -> list[str]:
    errors: list[str] = []
    if not isinstance(schema, dict) or not str(schema.get("openapi", "")).startswith("3."):
        return ["OPENAPI_VERSION"]
    paths = schema.get("paths")
    if not isinstance(paths, dict) or not paths:
        return ["PATHS_MISSING"]
    if _contains_private_setup_material(schema):
        errors.append("PRIVATE_SETUP_ROUTE_EXPOSED")
    operations = _schema_operations(schema)
    registry = build_route_registry(route_registry) if route_registry is not None else None
    if registry is not None:
        for key in operations:
            if key not in registry:
                errors.append("OPENAPI_OPERATION_NOT_IN_ROUTE_REGISTRY")
        for key in registry:
            if key not in operations:
                errors.append("ROUTE_REGISTRY_OPERATION_MISSING")
    for (method, path), operation in operations.items():
        if registry is not None and (method, path) not in registry:
            continue
        if registry is not None:
            policy = registry[(method, path)]
            access, kind = policy.access, policy.kind
        else:
            access = "PUBLIC" if (method, path) in public_allowlist else "PROTECTED"
            kind = _inferred_kind(method, path)
        if access == "PROTECTED" and not operation.get("security"):
            errors.append("PROTECTED_WITHOUT_SECURITY")
        if access == "PUBLIC" and (method, path) not in public_allowlist:
            errors.append("UNAPPROVED_PUBLIC_OPERATION")
        if "responses" not in operation or not isinstance(operation.get("responses"), dict):
            errors.append("RESPONSES_MISSING")
        if kind in {"COMMIT", "WRITE"}:
            if registry is not None:
                preview_id = registry[(method, path)].preview_operation_id
                paired = next((r for r in registry.values() if r.operation_id == preview_id), None)
                if paired is None or (paired.method, paired.path) not in operations:
                    errors.append("WRITE_WITHOUT_PREVIEW_ROUTE")
            else:
                preview_path = _inferred_preview_path(path)
                if ("POST", preview_path) not in operations:
                    errors.append("WRITE_WITHOUT_PREVIEW_ROUTE")
        if operation.get("x-protected") is False and access == "PROTECTED":
            errors.append("SELF_MARKER_CONTRADICTS_POLICY")
        if operation.get("x-write-operation") is False and kind in {"COMMIT", "WRITE"}:
            errors.append("SELF_MARKER_CONTRADICTS_POLICY")
    return sorted(set(errors))


ERROR_RESPONSE_CODES = frozenset({"400", "401", "409", "429", "500", "503"})
FORBIDDEN_ERROR_PROPERTIES = {"traceback", "stack", "stacktrace", "message_body", "file_content", "token", "session", "api_hash"}


def validate_structured_error_responses(schema: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    for operation in _schema_operations(schema).values():
        responses = operation.get("responses", {})
        if not isinstance(responses, dict):
            errors.append("RESPONSES_MISSING")
            continue
        for code in ERROR_RESPONSE_CODES.intersection(str(k) for k in responses):
            response = responses.get(code)
            if not isinstance(response, dict):
                errors.append("INVALID_ERROR_RESPONSE")
                continue
            content = response.get("content")
            if not isinstance(content, dict) or "application/json" not in content:
                errors.append("ERROR_RESPONSE_NOT_JSON")
                continue
            media = content["application/json"]
            schema_obj = media.get("schema") if isinstance(media, dict) else None
            if not isinstance(schema_obj, dict):
                errors.append("ERROR_RESPONSE_SCHEMA_MISSING")
                continue
            required = set(schema_obj.get("required", [])) if isinstance(schema_obj.get("required", []), list) else set()
            properties = schema_obj.get("properties", {}) if isinstance(schema_obj.get("properties", {}), dict) else {}
            if "error" not in required or "error" not in properties:
                errors.append("ERROR_CODE_FIELD_REQUIRED")
            if FORBIDDEN_ERROR_PROPERTIES.intersection(str(k).casefold() for k in properties):
                errors.append("PRIVATE_ERROR_FIELD_EXPOSED")
    return sorted(set(errors))


@dataclass
class _A11yElement:
    tag: str
    attrs: dict[str, str | None]
    index: int
    hidden: bool
    text_parts: list[str] = field(default_factory=list)
    nested_label_index: int | None = None

    @property
    def text(self) -> str:
        return " ".join(part.strip() for part in self.text_parts if part.strip()).strip()


class _AccessibilityParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.elements: list[_A11yElement] = []
        self.stack: list[_A11yElement] = []
        self._index = 0

    @staticmethod
    def _is_hidden(tag: str, attrs: dict[str, str | None], ancestor_hidden: bool) -> bool:
        if ancestor_hidden or "hidden" in attrs or str(attrs.get("aria-hidden", "")).casefold() == "true":
            return True
        if tag == "input" and str(attrs.get("type", "")).casefold() == "hidden":
            return True
        style = str(attrs.get("style", "")).replace(" ", "").casefold()
        return "display:none" in style or "visibility:hidden" in style

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        data = {str(key).casefold(): value for key, value in attrs}
        ancestor_hidden = any(item.hidden for item in self.stack)
        element = _A11yElement(tag.casefold(), data, self._index, self._is_hidden(tag.casefold(), data, ancestor_hidden))
        self._index += 1
        labels = [item for item in self.stack if item.tag == "label" and not item.hidden]
        if labels:
            element.nested_label_index = labels[-1].index
        self.elements.append(element)
        self.stack.append(element)

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)
        self.handle_endtag(tag)

    def handle_data(self, data: str) -> None:
        if not data.strip() or any(item.hidden for item in self.stack):
            return
        for item in self.stack:
            item.text_parts.append(data)

    def handle_endtag(self, tag: str) -> None:
        folded = tag.casefold()
        for index in range(len(self.stack) - 1, -1, -1):
            if self.stack[index].tag == folded:
                del self.stack[index:]
                return


def _tabindex(element: _A11yElement) -> int | None:
    raw = element.attrs.get("tabindex")
    if raw is None:
        return None
    try:
        return int(raw)
    except (TypeError, ValueError):
        return 10**9


def _native_focusable(element: _A11yElement) -> bool:
    if element.hidden or "disabled" in element.attrs:
        return False
    if element.tag in {"input", "select", "textarea", "button"}:
        return element.tag != "input" or str(element.attrs.get("type", "")).casefold() != "hidden"
    if element.tag == "a":
        return bool(element.attrs.get("href"))
    if "contenteditable" in element.attrs and str(element.attrs.get("contenteditable", "")).casefold() in {"", "true"}:
        return True
    return False


def _focusable(element: _A11yElement) -> bool:
    if element.hidden or "disabled" in element.attrs:
        return False
    ti = _tabindex(element)
    if ti is not None:
        return ti >= 0 and ti != 10**9
    if _native_focusable(element):
        return True
    return str(element.attrs.get("role", "")).casefold() in {"button", "link", "checkbox", "radio", "switch", "tab"}


def _id_map(elements: Sequence[_A11yElement]) -> dict[str, _A11yElement]:
    result: dict[str, _A11yElement] = {}
    for element in elements:
        raw = element.attrs.get("id")
        if raw and raw not in result:
            result[str(raw)] = element
    return result


def _label_map(elements: Sequence[_A11yElement]) -> dict[str, list[_A11yElement]]:
    result: dict[str, list[_A11yElement]] = {}
    for element in elements:
        if element.tag == "label" and not element.hidden and element.attrs.get("for"):
            result.setdefault(str(element.attrs["for"]), []).append(element)
    return result


def _accessible_name(element: _A11yElement, *, ids: dict[str, _A11yElement], labels: dict[str, list[_A11yElement]], elements: Sequence[_A11yElement]) -> str:
    aria_label = element.attrs.get("aria-label")
    if aria_label is not None:
        return str(aria_label).strip()
    labelledby = element.attrs.get("aria-labelledby")
    if labelledby is not None:
        refs = str(labelledby).split()
        if not refs or any(ref not in ids or ids[ref].hidden for ref in refs):
            return ""
        return " ".join(ids[ref].text for ref in refs).strip()
    element_id = element.attrs.get("id")
    if element_id and str(element_id) in labels:
        return " ".join(label.text for label in labels[str(element_id)]).strip()
    if element.nested_label_index is not None:
        nested = next((item for item in elements if item.index == element.nested_label_index), None)
        if nested is not None:
            return nested.text
    if element.tag in {"button", "a"}:
        return element.text
    if element.tag == "input":
        input_type = str(element.attrs.get("type", "text")).casefold()
        if input_type in {"submit", "button", "reset"}:
            return str(element.attrs.get("value", "")).strip()
        if input_type == "image":
            return str(element.attrs.get("alt", "")).strip()
    return ""


def _rule(rule_id: str, passed: bool, count: int) -> dict[str, Any]:
    return {"rule_id": rule_id, "status": "PASS" if passed else "FAIL", "findings_count": int(count)}


def analyze_accessibility(html: str) -> dict[str, Any]:
    if not isinstance(html, str):
        raise ValueError("HTML text required")
    parser = _AccessibilityParser()
    parser.feed(html)
    elements = parser.elements
    ids = _id_map(elements)
    labels = _label_map(elements)
    controls = [e for e in elements if e.tag in {"input", "select", "textarea"} and not e.hidden and "disabled" not in e.attrs]
    interactive = [e for e in elements if _focusable(e)]
    label_failures = 0
    for element in controls:
        if not _accessible_name(element, ids=ids, labels=labels, elements=elements):
            label_failures += 1
        labelledby = element.attrs.get("aria-labelledby")
        if labelledby is not None and any(ref not in ids for ref in str(labelledby).split()):
            label_failures += 1
    name_failures = 0
    names: list[tuple[str, str]] = []
    for element in interactive:
        name = _accessible_name(element, ids=ids, labels=labels, elements=elements)
        if not name:
            name_failures += 1
        else:
            role = str(element.attrs.get("role") or element.tag).casefold()
            names.append((role, name.casefold()))
    duplicate_ambiguous = sum(1 for item in set(names) if names.count(item) > 1)
    headings = [int(e.tag[1]) for e in elements if re.fullmatch(r"h[1-6]", e.tag) and not e.hidden]
    heading_failures = 0 if headings and 1 in headings else 1
    heading_failures += sum(1 for previous, current in zip(headings, headings[1:]) if current - previous > 1)
    tabindex_failures = 0
    positive: list[tuple[int, int]] = []
    focus_reachability_failures = 0
    for element in elements:
        ti = _tabindex(element)
        if ti == 10**9:
            tabindex_failures += 1
        elif ti is not None and ti > 0:
            positive.append((ti, element.index))
        if str(element.attrs.get("data-essential", "")).casefold() == "true" and not _focusable(element):
            focus_reachability_failures += 1
    tabindex_failures += len(positive)
    if len({item[0] for item in positive}) != len(positive):
        tabindex_failures += 1
    non_native_failures = 0
    pointer_only_failures = 0
    for element in elements:
        attrs = element.attrs
        is_native = element.tag in {"button", "input", "select", "textarea", "a"}
        has_click = "onclick" in attrs
        has_key = any(name in attrs for name in ("onkeydown", "onkeyup", "onkeypress"))
        if has_click and not is_native:
            ti = _tabindex(element)
            role = str(attrs.get("role", "")).casefold()
            if role not in {"button", "link", "checkbox", "radio", "switch", "tab"} or ti is None or ti < 0 or not has_key:
                non_native_failures += 1
        if any(name in attrs for name in ("onmouseover", "onmouseenter", "ondrag", "ondragstart", "ondrop")) and not has_key and "onfocus" not in attrs:
            pointer_only_failures += 1
    live_regions = [e for e in elements if not e.hidden and (str(e.attrs.get("role", "")).casefold() in {"status", "alert"} or str(e.attrs.get("aria-live", "")).casefold() in {"polite", "assertive"})]
    live_failures = sum(1 for region in live_regions if not region.text and not region.attrs.get("id"))
    error_regions = [e for e in elements if str(e.attrs.get("role", "")).casefold() == "alert" or "error" in str(e.attrs.get("id", "")).casefold()]
    error_assoc_failures = 0
    for element in controls:
        if str(element.attrs.get("aria-invalid", "")).casefold() != "true":
            continue
        ref_value = element.attrs.get("aria-errormessage") or element.attrs.get("aria-describedby")
        refs = str(ref_value).split() if ref_value else []
        if not refs or any(ref not in ids for ref in refs):
            error_assoc_failures += 1
    if error_regions and any(not region.text and not region.attrs.get("id") for region in error_regions):
        error_assoc_failures += 1
    labels_present = label_failures == 0
    accessible_names_present = name_failures == 0
    heading_order_valid = heading_failures == 0
    tab_order_valid = tabindex_failures == 0 and focus_reachability_failures == 0
    non_native_keyboard_safe = non_native_failures == 0
    mouse_only_absent = non_native_failures == 0 and pointer_only_failures == 0
    status_messages_accessible = live_failures == 0 and bool(live_regions)
    error_associations_valid = error_assoc_failures == 0
    keyboard_structure_valid = tab_order_valid and non_native_keyboard_safe and mouse_only_absent
    rules = [
        _rule("A11Y_LABEL", labels_present, label_failures),
        _rule("A11Y_NAME", accessible_names_present, name_failures),
        _rule("A11Y_DUPLICATE_NAME", duplicate_ambiguous == 0, duplicate_ambiguous),
        _rule("A11Y_HEADING", heading_order_valid, heading_failures),
        _rule("A11Y_TAB_ORDER", tab_order_valid, tabindex_failures + focus_reachability_failures),
        _rule("A11Y_NON_NATIVE_KEYBOARD", non_native_keyboard_safe, non_native_failures),
        _rule("A11Y_POINTER_ONLY", pointer_only_failures == 0, pointer_only_failures),
        _rule("A11Y_LIVE_REGION", status_messages_accessible, live_failures + (0 if live_regions else 1)),
        _rule("A11Y_ERROR_ASSOC", error_associations_valid, error_assoc_failures),
    ]
    return {
        "keyboard_operable": keyboard_structure_valid,
        "keyboard_structure_valid": keyboard_structure_valid,
        "labels_present": labels_present,
        "accessible_names_present": accessible_names_present,
        "ambiguous_names_absent": duplicate_ambiguous == 0,
        "heading_order_valid": heading_order_valid,
        "tab_order_valid": tab_order_valid,
        "focus_reachable": focus_reachability_failures == 0,
        "status_messages_accessible": status_messages_accessible,
        "error_associations_valid": error_associations_valid,
        "mouse_only_absent": mouse_only_absent,
        "focusable_count": len(interactive),
        "rule_results": rules,
        "structural_only": True,
        "human_nvda_pass": False,
    }


SYNTHETIC_EXECUTABLE = {
    "B1", "B2", "B3", "B5", "B7", "B8", "C3", "C4", "C6",
    "D1", "D2", "D3", "D4", "D5", "D6", "E1", "E2", "E3", "E4", "E5", "E6",
    "F1", "F2", "F3", "F4", "F5", "F6", "F7", "F8", "G1", "G2", "G3", "G4", "G5",
    "H3", "H4", "H5", "I2", "I3", "I4", "I5", "I7", "J2", "J3", "J5",
}
LIVE_EXTERNAL = {"H2", "J1", "J4", "J6", "K1", "K2", "K3", "K4", "K5"}
CRITERION_TEST_MAP: dict[str, tuple[str, ...]] = {criterion: tuple() for criterion in CRITERIA}
CRITERION_TEST_MAP.update({
    "B1": ("test_acceptance_contracts.SecurityContractsTests.test_bearer_auth_matrix",),
    "B2": ("test_acceptance_contracts.SecurityContractsTests.test_bearer_auth_matrix",),
    "B3": ("test_acceptance_harness.SanitizationTests.test_exception_chain_and_subprocess_text_are_never_copied",),
    "B5": ("test_acceptance_contracts.SecurityContractsTests.test_path_traversal_adversarial_matrix",),
    "B7": ("test_acceptance_contracts.SecurityContractsTests.test_malformed_json_and_ranges_are_controlled",),
    "B8": ("test_acceptance_contracts.SecurityContractsTests.test_rate_limit_window_rollover_actor_and_retry_after",),
    "C3": ("test_acceptance_contracts.TelegramFakeTests.test_setup_code_2fa_floodwait_rpc_contracts",),
    "C4": ("test_acceptance_contracts.TelegramFakeTests.test_setup_code_2fa_floodwait_rpc_contracts",),
    "C6": ("test_acceptance_contracts.TelegramFakeTests.test_error_matrix_preserves_recoverable_checkpoint",),
    "D1": ("test_acceptance_contracts.ReadContractsTests.test_dialogs_history_pagination_and_ordering",),
    "D2": ("test_acceptance_contracts.ReadContractsTests.test_dialogs_history_pagination_and_ordering",),
    "D3": ("test_acceptance_contracts.ReadContractsTests.test_search_filters_unicode_and_empty_results",),
    "D4": ("test_acceptance_contracts.ReadContractsTests.test_search_filters_unicode_and_empty_results",),
    "D5": ("test_acceptance_contracts.ReadContractsTests.test_search_filters_unicode_and_empty_results",),
    "D6": ("test_acceptance_contracts.ReadContractsTests.test_search_filters_unicode_and_empty_results",),
    "E1": ("test_acceptance_contracts.MediaContractsTests.test_single_download_validates_expected_hash",),
    "E2": ("test_acceptance_contracts.MediaContractsTests.test_single_download_validates_expected_hash",),
    "E3": ("test_acceptance_contracts.MediaContractsTests.test_bulk_download_deduplicates",),
    "E4": ("test_acceptance_contracts.MediaContractsTests.test_zip_valid_crc_unicode_caps_and_traversal",),
    "E5": ("test_acceptance_contracts.MediaContractsTests.test_interrupted_download_actually_resumes_pending_work",),
    "E6": ("test_acceptance_contracts.PrivateFileContractsTests.test_signed_private_file_adversarial_matrix",),
    "F1": ("test_acceptance_contracts.WriteContractsTests.test_preview_commit_families_and_audit_metadata",),
    "F2": ("test_acceptance_contracts.WriteContractsTests.test_preview_commit_families_and_audit_metadata",),
    "F3": ("test_acceptance_contracts.WriteContractsTests.test_preview_commit_families_and_audit_metadata",),
    "F4": ("test_acceptance_contracts.WriteContractsTests.test_preview_commit_families_and_audit_metadata",),
    "F5": ("test_acceptance_contracts.WriteContractsTests.test_preview_commit_single_use_and_idempotency",),
    "F6": ("test_acceptance_contracts.WriteContractsTests.test_concurrent_same_request_commits_once_semantically",),
    "F7": ("test_acceptance_contracts.WriteContractsTests.test_expired_invalid_and_mismatched_idempotency_fail_safely",),
    "F8": ("test_acceptance_contracts.WriteContractsTests.test_preview_commit_families_and_audit_metadata",),
    "G1": ("test_acceptance_contracts.WriteContractsTests.test_idempotency_fingerprint_and_retry_after_expiry",),
    "G2": ("test_acceptance_contracts.WriteContractsTests.test_idempotency_restart_state",),
    "G3": ("test_acceptance_contracts.ReliabilityContractsTests.test_resumable_job_timeout_checkpoint_and_no_backward_move",),
    "G4": ("test_acceptance_contracts.TelegramFakeTests.test_error_matrix_preserves_recoverable_checkpoint",),
    "G5": ("test_acceptance_contracts.MediaContractsTests.test_interrupted_download_actually_resumes_pending_work",),
    "H3": ("test_acceptance_contracts.OpenApiContractsTests.test_registry_defaults_protected_without_self_marker",),
    "H4": ("test_acceptance_contracts.OpenApiContractsTests.test_orphan_write_and_commit_routes_are_rejected",),
    "H5": ("test_acceptance_contracts.OpenApiContractsTests.test_structured_error_response_policy",),
    "I2": ("test_acceptance_contracts.AccessibilityContractsTests.test_labels_nested_aria_and_broken_refs",),
    "I3": ("test_acceptance_contracts.AccessibilityContractsTests.test_accessible_names_and_icon_only_controls",),
    "I4": ("test_acceptance_contracts.AccessibilityContractsTests.test_tab_order_hidden_disabled_and_positive_tabindex",),
    "I5": ("test_acceptance_contracts.AccessibilityContractsTests.test_heading_policy_missing_h1_jump_and_multiple_h1",),
    "I7": ("test_acceptance_contracts.AccessibilityContractsTests.test_non_native_mouse_only_controls_require_keyboard_semantics",),
    "J2": ("test_audit_round9.RealNonLiveTransactionIntegrationTests.test_successful_non_live_deploy",),
    "J3": ("test_audit_round9.RealNonLiveTransactionIntegrationTests.test_candidate_auth_failure_rolls_back_to_healthy_previous_release",),
    "J5": ("test_audit_round9.RealNonLiveTransactionIntegrationTests.test_candidate_auth_failure_rolls_back_to_healthy_previous_release",),
})


def coverage_report() -> list[dict[str, Any]]:
    report: list[dict[str, Any]] = []
    for criterion in sorted(CRITERIA, key=lambda item: (item[0], int(item[1:]))):
        if criterion in SYNTHETIC_EXECUTABLE:
            status = "SYNTHETIC_EXECUTABLE"
        elif criterion in LIVE_EXTERNAL:
            status = "LIVE_EXTERNAL_REQUIRED"
        else:
            status = "REAL_SOURCE_REQUIRED"
        report.append({"criterion": criterion, "coverage": status, "tests": list(CRITERION_TEST_MAP[criterion])})
    return report


def validate_coverage_mapping() -> None:
    if set(CRITERION_TEST_MAP) != set(CRITERIA):
        raise ContractError("coverage map criterion drift")
    report = coverage_report()
    if len(report) != len(CRITERIA) or len({item["criterion"] for item in report}) != len(CRITERIA):
        raise ContractError("coverage map duplicate/missing criterion")
    for item in report:
        if item["coverage"] == "SYNTHETIC_EXECUTABLE" and not item["tests"]:
            raise ContractError("synthetic coverage lacks executable test mapping")
        if item["coverage"] not in {"SYNTHETIC_EXECUTABLE", "REAL_SOURCE_REQUIRED", "LIVE_EXTERNAL_REQUIRED"}:
            raise ContractError("invalid coverage class")
        if item["criterion"].startswith("K") and item["coverage"] != "LIVE_EXTERNAL_REQUIRED":
            raise ContractError("final user scenario cannot be synthetic")
        if "PASS" in item["coverage"]:
            raise ContractError("coverage class cannot claim product PASS")


def build_acceptance_run_summary(*, code_sha: str, environment_class: str,
                                 passed_count: int, failed_count: int, blocked_count: int,
                                 evidence_refs: Iterable[str]) -> dict[str, Any]:
    if not isinstance(code_sha, str) or not re.fullmatch(r"[0-9a-f]{40}", code_sha):
        raise ValueError("exact Git SHA required")
    privacy.validate_environment_class(environment_class)
    counts = [passed_count, failed_count, blocked_count]
    if any(isinstance(value, bool) or not isinstance(value, int) or value < 0 for value in counts):
        raise ValueError("non-negative result counts required")
    refs = [privacy.validate_evidence_ref(ref) for ref in evidence_refs]
    if len(refs) > privacy.MAX_LIST_ITEMS:
        raise ValueError("too many evidence references")
    summary = {
        "schema_version": 1,
        "code_sha": code_sha,
        "environment_class": environment_class,
        "test_count": sum(counts),
        "passed_count": passed_count,
        "failed_count": failed_count,
        "blocked_count": blocked_count,
        "evidence_refs": list(refs),
    }
    privacy.validate_aggregate_payload(summary)
    return summary


def final_scenario_definition(criterion: str) -> dict[str, Any]:
    if criterion not in {"K1", "K2", "K3", "K4", "K5"}:
        raise ValueError("not a final user scenario")
    requires_write = criterion == "K5"
    return {
        "criterion": criterion,
        "requires_live_telegram": True,
        "requires_audited_deployed_sha": True,
        "requires_explicit_write_approval": requires_write,
        "synthetic_pass_allowed": False,
    }


validate_coverage_mapping()
