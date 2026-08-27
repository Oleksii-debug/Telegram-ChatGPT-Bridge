"""Structured, privacy-safe application errors."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Mapping


MAX_PUBLIC_RETRY_AFTER_SECONDS = 600
_ALLOWED_HTTP_STATUSES = {400, 404, 405, 409, 413, 415, 429, 500, 502, 503, 504}
_CODE_RE = re.compile(r"^[a-z][a-z0-9_]{0,79}$")
_DETAIL_ID_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,80}$")


@dataclass(frozen=True)
class ErrorDescriptor:
    status: int
    code: str
    message: str
    retry_after_seconds: int | None = None


def _bounded_retry(status: int, value: Any) -> int | None:
    if status != 429:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        return 1
    return min(value, MAX_PUBLIC_RETRY_AFTER_SECONDS)


class BridgeError(Exception):
    """Expected API failure with bounded, typed public metadata.

    Foreign exception strings are not accepted by the WSGI/backend boundaries.
    This class additionally constrains code/status, Retry-After and ``details``
    so paths, SQL fragments and free-form private text cannot be smuggled through
    auxiliary metadata.
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
        requested_status = status if isinstance(status, int) and not isinstance(status, bool) else 500
        requested_code = code if isinstance(code, str) else ""
        if requested_status not in _ALLOWED_HTTP_STATUSES or _CODE_RE.fullmatch(requested_code) is None:
            self.status = 500
            self.code = "internal_error"
            self.message = "Internal server error"
            self.details = {}
        else:
            self.status = requested_status
            self.code = requested_code
            text = str(message)
            if any(ch in text for ch in "\r\n\x00"):
                self.status = 500
                self.code = "internal_error"
                self.message = "Internal server error"
                self.details = {}
            else:
                self.message = text[:240]
                self.details = self._safe_details(details or {})
        self.retry_after_seconds = _bounded_retry(self.status, retry_after_seconds)
        super().__init__(self.code)

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
            elif isinstance(value, str) and _DETAIL_ID_RE.fullmatch(value):
                safe[key] = value
        return safe

    def public_payload(self, request_id: str) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "ok": False,
            "request_id": request_id,
            "error": {"code": self.code, "message": self.message},
        }
        if self.retry_after_seconds is not None:
            payload["error"]["retry_after_seconds"] = self.retry_after_seconds
        if self.details:
            payload["error"]["details"] = self.details
        return payload


class HiddenNotFound(BridgeError):
    def __init__(self) -> None:
        super().__init__("Not found", status=404, code="not_found")
