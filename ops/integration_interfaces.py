# -*- coding: utf-8 -*-
"""Stable cross-lane contracts for Telegram Bridge integration.

This module intentionally contains interfaces and bounded value objects only.
It does not import DEV2-DEV5 implementations, perform Telegram/network I/O, or
carry production secrets/private Telegram content.

The vocabulary here is an adapter contract for the integrated candidate.  It
must represent the canonical DEV3 read route identifiers/access classes and
DEV4 Action/write identifiers without changing their runtime safety semantics.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Literal, Mapping, Protocol

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
# DEV3 uses dotted lowercase operation IDs (``dialogs.list``); DEV4 Action uses
# lower-camel IDs (``listTelegramDialogs``).  Accept exactly those reviewed
# grammars plus the historical lowercase snake form used by shared contracts.
OPERATION_ID_RE = re.compile(
    r"^(?:[a-z][a-z0-9_]{2,79}|[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+|[a-z][A-Za-z0-9]{2,79})$"
)
SAFE_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE"}
SAFE_ROUTE_CLASSES = {
    "PUBLIC_HEALTH",
    "PROTECTED_READ",
    "PROTECTED_OR_SIGNED",
    "PROTECTED_WRITE",
    "PRIVATE_SETUP",
}


def _require_sha256(value: str, label: str) -> str:
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        raise ValueError(f"{label} must be an exact SHA-256")
    return value


@dataclass(frozen=True)
class PageRequest:
    limit: int = 50
    cursor: str | None = None

    def __post_init__(self) -> None:
        if isinstance(self.limit, bool) or not isinstance(self.limit, int) or not (1 <= self.limit <= 100):
            raise ValueError("page limit must be between 1 and 100")
        if self.cursor is not None:
            if not isinstance(self.cursor, str) or not (1 <= len(self.cursor) <= 1024):
                raise ValueError("cursor must be bounded text")
            if any(ord(ch) < 32 or ord(ch) == 127 for ch in self.cursor):
                raise ValueError("cursor contains control characters")


@dataclass(frozen=True)
class PageResult:
    items: tuple[Mapping[str, Any], ...]
    next_cursor: str | None = None
    scanned: int = 0

    def __post_init__(self) -> None:
        if isinstance(self.scanned, bool) or not isinstance(self.scanned, int) or self.scanned < 0:
            raise ValueError("scanned count must be non-negative")


@dataclass(frozen=True)
class RateLimitOutcome:
    allowed: bool
    remaining: int
    retry_after_seconds: int
    window_seconds: int
    limit: int

    def __post_init__(self) -> None:
        if not isinstance(self.allowed, bool):
            raise ValueError("allowed must be boolean")
        for name in ("remaining", "retry_after_seconds", "window_seconds", "limit"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError(f"{name} must be a non-negative integer")
        if self.window_seconds <= 0 or self.limit <= 0 or self.remaining > self.limit:
            raise ValueError("invalid rate-limit bounds")


@dataclass(frozen=True)
class WritePreview:
    preview_sha256: str
    operation_kind: str
    target_sha256: str
    payload_sha256: str
    expires_at: int

    def __post_init__(self) -> None:
        for value, label in (
            (self.preview_sha256, "preview"),
            (self.target_sha256, "target"),
            (self.payload_sha256, "payload"),
        ):
            _require_sha256(value, label)
        if self.operation_kind not in {"SEND", "REPLY", "FORWARD", "SEND_FILES"}:
            raise ValueError("unsupported write operation")
        if isinstance(self.expires_at, bool) or not isinstance(self.expires_at, int) or self.expires_at < 0:
            raise ValueError("preview expiry must be a non-negative integer")


@dataclass(frozen=True)
class WriteCommitResult:
    result_code: str
    operation_sha256: str

    def __post_init__(self) -> None:
        if self.result_code not in {
            "COMMITTED", "IDEMPOTENCY_CONFLICT", "RECONCILE_REQUIRED",
            "EXPIRED_PREVIEW", "USED_PREVIEW", "INVALID_PREVIEW", "IDEMPOTENCY_RETIRED",
        }:
            raise ValueError("unsupported write result code")
        _require_sha256(self.operation_sha256, "operation")


@dataclass(frozen=True)
class RoutePolicy:
    method: str
    path_template: str
    operation_id: str
    classification: Literal[
        "PUBLIC_HEALTH", "PROTECTED_READ", "PROTECTED_OR_SIGNED", "PROTECTED_WRITE", "PRIVATE_SETUP"
    ]
    preview_commit_required: bool = False

    def __post_init__(self) -> None:
        method = self.method.upper()
        object.__setattr__(self, "method", method)
        if method not in SAFE_METHODS:
            raise ValueError("unsupported route method")
        if not isinstance(self.path_template, str) or not self.path_template.startswith("/") or len(self.path_template) > 160:
            raise ValueError("invalid route template")
        if ".." in self.path_template or "?" in self.path_template or "#" in self.path_template:
            raise ValueError("route template must be canonical")
        if not isinstance(self.operation_id, str) or not OPERATION_ID_RE.fullmatch(self.operation_id):
            raise ValueError("invalid operation id")
        if self.classification not in SAFE_ROUTE_CLASSES:
            raise ValueError("unknown route classification")
        if not isinstance(self.preview_commit_required, bool):
            raise ValueError("preview flag must be boolean")
        if self.classification == "PROTECTED_WRITE" and not self.preview_commit_required:
            raise ValueError("protected writes require preview/commit")
        if self.classification != "PROTECTED_WRITE" and self.preview_commit_required:
            raise ValueError("preview/commit flag is only valid for protected writes")


class ReadService(Protocol):
    def list_dialogs(self, page: PageRequest) -> PageResult: ...
    def search(self, query: Mapping[str, Any], page: PageRequest) -> PageResult: ...


class MediaService(Protocol):
    def metadata(self, file_id_sha256: str) -> Mapping[str, Any]: ...


class RateLimitService(Protocol):
    def consume(self, actor_id: str) -> RateLimitOutcome: ...


class WriteService(Protocol):
    def preview(self, operation: Mapping[str, Any]) -> WritePreview: ...
    def commit(self, preview_sha256: str, idempotency_key: str) -> WriteCommitResult: ...


class WriteTransactionStore(Protocol):
    def begin_commit(self, preview_key: str, *, now: int, idempotency_key: str) -> str: ...
    def record_external_result(
        self, preview_key: str, *, now: int, idempotency_key: str, result: str = "COMMITTED"
    ) -> str: ...
    def export_state(self) -> Mapping[str, Any]: ...


class RoutePolicyRegistry(Protocol):
    def policies(self) -> tuple[RoutePolicy, ...]: ...


class SourceEvidenceProvider(Protocol):
    def non_secret_reconciliation(self) -> Mapping[str, Any]: ...


class RuntimeEvidenceProvider(Protocol):
    def non_secret_identity(self) -> Mapping[str, Any]: ...


class AcceptanceEvidenceSink(Protocol):
    def emit(self, payload: Mapping[str, Any]) -> None: ...
