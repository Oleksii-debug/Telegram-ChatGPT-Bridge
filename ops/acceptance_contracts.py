# -*- coding: utf-8 -*-
"""Reusable synthetic acceptance contracts for Telegram Bridge.

These contracts exercise deterministic safety semantics without real Telegram,
HOSTiQ, private files or production credentials. They are harness infrastructure,
not product PASS and not evidence of deployed behavior.
"""
from __future__ import annotations

import hashlib
import io
import json
import time
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import PurePosixPath
from typing import Any, Iterable

from ops.acceptance_harness import CRITERIA


class ContractError(RuntimeError):
    pass


def safe_relative_path(value: str) -> str:
    if not isinstance(value, str) or not value or "\\" in value:
        raise ContractError("unsafe relative path")
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or any(part in {"", "."} for part in path.parts):
        raise ContractError("unsafe relative path")
    return path.as_posix()


def authorization_outcome(*, auth_present: bool, auth_matches: bool) -> str:
    if not auth_present:
        return "MISSING_AUTH"
    if not auth_matches:
        return "WRONG_AUTH"
    return "AUTHORIZED"


class FixedWindowRateLimiter:
    def __init__(self, limit: int):
        if not isinstance(limit, int) or isinstance(limit, bool) or limit <= 0:
            raise ValueError("positive integer rate limit required")
        self.limit = limit
        self._counts: dict[str, int] = {}

    def consume(self, actor_hash: str) -> tuple[bool, int]:
        count = self._counts.get(actor_hash, 0)
        if count >= self.limit:
            return False, 0
        count += 1
        self._counts[actor_hash] = count
        return True, self.limit - count


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

    def download_one(self, file_id: str, expected_sha256: str) -> bytes:
        match = next((item for item in self.items if item.file_id == file_id), None)
        if match is None:
            raise ContractError("file not found")
        if match.sha256 != expected_sha256:
            raise ContractError("file hash mismatch")
        self.completed.setdefault(file_id, match.content)
        return self.completed[file_id]

    def bulk(self, file_ids: Iterable[str]) -> dict[str, bytes]:
        requested = list(dict.fromkeys(file_ids))
        result: dict[str, bytes] = {}
        for file_id in requested:
            match = next((item for item in self.items if item.file_id == file_id), None)
            if match is None:
                continue
            result[file_id] = self.download_one(file_id, match.sha256)
        return result

    def mark_interrupted(self) -> None:
        self.failed = True

    def resume(self) -> dict[str, bytes]:
        self.failed = False
        return dict(self.completed)


def build_zip(files: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    seen: set[str] = set()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, content in sorted(files.items()):
            safe = safe_relative_path(name)
            if safe in seen:
                raise ContractError("duplicate archive entry")
            seen.add(safe)
            archive.writestr(safe, content)
    payload = buffer.getvalue()
    with zipfile.ZipFile(io.BytesIO(payload), "r") as archive:
        if sorted(archive.namelist()) != sorted(seen):
            raise ContractError("zip validation failed")
        if archive.testzip() is not None:
            raise ContractError("zip CRC validation failed")
    return payload


def private_file_access(*, authorized: bool) -> str:
    return "PRIVATE_FILE_ALLOWED" if authorized else "PRIVATE_FILE_DENIED"


@dataclass
class PreviewRecord:
    action: str
    target_sha256: str
    payload_sha256: str
    expires_at: int
    used: bool = False


class PreviewCommitStore:
    def __init__(self):
        self._counter = 0
        self._records: dict[str, PreviewRecord] = {}
        self._idempotency: dict[str, str] = {}

    def create_preview(self, *, action: str, target_sha256: str, payload_sha256: str,
                       now: int, ttl_seconds: int = 300) -> str:
        if ttl_seconds <= 0 or ttl_seconds > 3600:
            raise ContractError("invalid preview TTL")
        for digest in (target_sha256, payload_sha256):
            if len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest):
                raise ContractError("hash-bound preview required")
        if action not in {"SEND", "REPLY", "FORWARD", "SEND_FILE"}:
            raise ContractError("unsupported preview action")
        self._counter += 1
        opaque = hashlib.sha256(f"{self._counter}|{action}|{target_sha256}|{payload_sha256}|{now}".encode()).hexdigest()
        self._records[opaque] = PreviewRecord(action, target_sha256, payload_sha256, now + ttl_seconds)
        return opaque

    def commit(self, preview_key: str, *, now: int, idempotency_key: str) -> str:
        record = self._records.get(preview_key)
        if record is None:
            return "INVALID_PREVIEW"
        if now > record.expires_at:
            return "EXPIRED_PREVIEW"
        if idempotency_key in self._idempotency:
            return self._idempotency[idempotency_key]
        if record.used:
            return "USED_PREVIEW"
        record.used = True
        self._idempotency[idempotency_key] = "COMMITTED"
        return "COMMITTED"

    def audit_metadata(self, preview_key: str) -> dict[str, Any]:
        record = self._records[preview_key]
        return {
            "operation_kind": record.action,
            "target_sha256": record.target_sha256,
            "payload_sha256": record.payload_sha256,
            "used": record.used,
        }


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


def validate_openapi_contract(schema: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if not isinstance(schema, dict) or not str(schema.get("openapi", "")).startswith("3."):
        return ["OPENAPI_VERSION"]
    paths = schema.get("paths")
    if not isinstance(paths, dict) or not paths:
        return ["PATHS_MISSING"]
    if any("setup" in str(path).casefold() for path in paths):
        errors.append("PRIVATE_SETUP_ROUTE_EXPOSED")
    for path, item in paths.items():
        if not isinstance(item, dict):
            errors.append("INVALID_PATH_ITEM")
            continue
        for method, operation in item.items():
            if method.lower() not in {"get", "post", "put", "patch", "delete"}:
                continue
            if not isinstance(operation, dict):
                errors.append("INVALID_OPERATION")
                continue
            protected = operation.get("x-protected") is True
            if protected and not operation.get("security"):
                errors.append("PROTECTED_WITHOUT_SECURITY")
            write = operation.get("x-write-operation") is True
            if write and operation.get("x-preview-commit") is not True:
                errors.append("WRITE_WITHOUT_PREVIEW_COMMIT")
            if "responses" not in operation:
                errors.append("RESPONSES_MISSING")
    return sorted(set(errors))


class _AccessibilityParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.inputs: list[dict[str, str | None]] = []
        self.label_fors: set[str] = set()
        self.buttons: list[dict[str, str | None]] = []
        self.headings: list[int] = []
        self.mouse_only = False
        self._button_text: list[str] = []
        self._in_button = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        data = dict(attrs)
        if tag in {"input", "select", "textarea"}:
            self.inputs.append(data)
        elif tag == "label" and data.get("for"):
            self.label_fors.add(str(data["for"]))
        elif tag == "button":
            self.buttons.append(data)
            self._button_text.append("")
            self._in_button = True
        elif tag in {"h1", "h2", "h3", "h4", "h5", "h6"}:
            self.headings.append(int(tag[1]))
        if "onclick" in data and not any(key in data for key in ("onkeydown", "onkeyup", "onkeypress")) and tag not in {"button", "a", "input"}:
            self.mouse_only = True

    def handle_data(self, data: str) -> None:
        if self._in_button and self._button_text:
            self._button_text[-1] += data

    def handle_endtag(self, tag: str) -> None:
        if tag == "button":
            self._in_button = False


def analyze_accessibility(html: str) -> dict[str, bool]:
    parser = _AccessibilityParser()
    parser.feed(html)
    labels_present = all(
        bool(item.get("aria-label")) or bool(item.get("id") and item.get("id") in parser.label_fors)
        for item in parser.inputs
    )
    button_names = all(
        bool(item.get("aria-label")) or bool(text.strip())
        for item, text in zip(parser.buttons, parser._button_text)
    )
    heading_order = True
    for previous, current in zip(parser.headings, parser.headings[1:]):
        if current - previous > 1:
            heading_order = False
            break
    return {
        "keyboard_operable": not parser.mouse_only,
        "labels_present": labels_present,
        "accessible_names_present": button_names,
        "heading_order_valid": heading_order,
        "mouse_only_absent": not parser.mouse_only,
    }


SYNTHETIC_EXECUTABLE = {
    "B1", "B2", "B5", "B7", "B8",
    "C3", "C4", "C6",
    "D1", "D2", "D3", "D4", "D5", "D6",
    "E1", "E2", "E3", "E4", "E5", "E6",
    "F1", "F2", "F3", "F4", "F5", "F6", "F7", "F8",
    "G1", "G2", "G3", "G4", "G5",
    "H1", "H3", "H4", "H5",
    "I1", "I2", "I3", "I4", "I5", "I6", "I7",
    "J2", "J3", "J5",
}
LIVE_EXTERNAL = {"H2", "J1", "J4", "J6", "K1", "K2", "K3", "K4", "K5"}


def coverage_report() -> list[dict[str, str]]:
    report = []
    for criterion in sorted(CRITERIA, key=lambda item: (item[0], int(item[1:]))):
        if criterion in SYNTHETIC_EXECUTABLE:
            status = "SYNTHETIC_EXECUTABLE"
        elif criterion in LIVE_EXTERNAL:
            status = "LIVE_EXTERNAL_REQUIRED"
        else:
            status = "REAL_SOURCE_REQUIRED"
        report.append({"criterion": criterion, "coverage": status})
    return report


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
