"""Structured, privacy-safe application errors."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping


@dataclass(frozen=True)
class ErrorDescriptor:
    status: int
    code: str
    message: str
    retry_after_seconds: int | None = None


class BridgeError(Exception):
    """Expected API failure with bounded public metadata.

    ``details`` is intentionally restricted to small scalar values; callers
    must never pass exception strings, message bodies, chat names, file paths,
    credentials, or other private content.
    """

    def __init__(
        self,
        message: str,
        *,
        status: int = 400,
        code: str = "bad_request",
        retry_after_seconds: int | None = None,
        details: Mapping[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.message = str(message)[:240]
        self.status = int(status)
        self.code = str(code)[:80]
        self.retry_after_seconds = retry_after_seconds
        self.details = self._safe_details(details or {})

    @staticmethod
    def _safe_details(details: Mapping[str, Any]) -> dict[str, Any]:
        safe: dict[str, Any] = {}
        allowed = {"field", "limit", "count", "status", "reason", "retryable"}
        for key, value in details.items():
            if key not in allowed:
                continue
            if isinstance(value, bool):
                safe[key] = value
            elif isinstance(value, int) and -(2**31) <= value <= 2**31 - 1:
                safe[key] = value
            elif isinstance(value, str) and len(value) <= 80 and all(ord(ch) >= 32 for ch in value):
                safe[key] = value
        return safe

    def public_payload(self, request_id: str) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "ok": False,
            "request_id": request_id,
            "error": {"code": self.code, "message": self.message},
        }
        if self.retry_after_seconds is not None:
            payload["error"]["retry_after_seconds"] = int(self.retry_after_seconds)
        if self.details:
            payload["error"]["details"] = self.details
        return payload


class HiddenNotFound(BridgeError):
    def __init__(self) -> None:
        super().__init__("Not found", status=404, code="not_found")
