"""Strict request validation shared by read endpoints."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from .errors import BridgeError

MAX_TEXT_QUERY = 512
MAX_ENTITY_REF = 256
MAX_LIST_ITEMS = 32


def require_dict(value: Any, field: str = "body") -> dict[str, Any]:
    if not isinstance(value, dict):
        raise BridgeError(f"{field} must be an object", code="invalid_json_shape", details={"field": field})
    return value


def bounded_int(value: Any, *, field: str, default: int, minimum: int, maximum: int) -> int:
    if value is None:
        return default
    # JSON-facing integer fields are intentionally strict. Floats and numeric
    # strings are rejected rather than silently truncated/coerced.
    if isinstance(value, bool) or not isinstance(value, int):
        raise BridgeError(f"{field} must be an integer", code="invalid_integer", details={"field": field})
    if value < minimum or value > maximum:
        raise BridgeError(
            f"{field} is outside the allowed range",
            code="invalid_range",
            details={"field": field, "limit": maximum},
        )
    return value


def bounded_text(value: Any, *, field: str, maximum: int = MAX_TEXT_QUERY, allow_empty: bool = True) -> str:
    if value is None:
        if allow_empty:
            return ""
        raise BridgeError(f"{field} is required", code="field_required", details={"field": field})
    if not isinstance(value, str):
        raise BridgeError(f"{field} must be text", code="invalid_text", details={"field": field})
    if len(value) > maximum:
        raise BridgeError(f"{field} is too long", code="text_too_long", details={"field": field, "limit": maximum})
    if not allow_empty and not value.strip():
        raise BridgeError(f"{field} is required", code="field_required", details={"field": field})
    if any(ord(character) == 0 or 0xD800 <= ord(character) <= 0xDFFF for character in value):
        raise BridgeError(f"{field} contains invalid characters", code="invalid_text", details={"field": field})
    return value


def entity_ref(value: Any, *, field: str = "chat") -> str:
    raw = bounded_text(value, field=field, maximum=MAX_ENTITY_REF, allow_empty=False).strip()
    if any(character in raw for character in "\r\n\x00"):
        raise BridgeError(f"{field} is invalid", code="invalid_entity", details={"field": field})
    return raw


def bool_value(value: Any, *, field: str, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    raise BridgeError(f"{field} must be boolean", code="invalid_boolean", details={"field": field})


def string_list(value: Any, *, field: str, allowed: set[str] | None = None) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or len(value) > MAX_LIST_ITEMS:
        raise BridgeError(f"{field} must be a bounded list", code="invalid_list", details={"field": field, "limit": MAX_LIST_ITEMS})
    output: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item or len(item) > 64:
            raise BridgeError(f"{field} contains an invalid value", code="invalid_list", details={"field": field})
        normalized = item.casefold()
        if allowed is not None and normalized not in allowed:
            raise BridgeError(f"{field} contains an unsupported value", code="invalid_list", details={"field": field})
        output.append(normalized)
    return tuple(dict.fromkeys(output))


def parse_datetime(value: Any, *, field: str) -> datetime | None:
    if value in (None, ""):
        return None
    if not isinstance(value, str) or len(value) > 64:
        raise BridgeError(f"{field} must be ISO 8601", code="invalid_date", details={"field": field})
    raw = value.strip()
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError as exc:
        raise BridgeError(f"{field} must be ISO 8601", code="invalid_date", details={"field": field}) from exc
    if parsed.tzinfo is None:
        raise BridgeError(f"{field} must include a timezone", code="timezone_required", details={"field": field})
    return parsed.astimezone(timezone.utc)


@dataclass(frozen=True)
class DateRange:
    start: datetime | None
    end: datetime | None

    def contains(self, value: datetime) -> bool:
        current = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        current = current.astimezone(timezone.utc)
        # Contract: both endpoints are inclusive.
        if self.start is not None and current < self.start:
            return False
        if self.end is not None and current > self.end:
            return False
        return True


def date_range(start: Any, end: Any) -> DateRange:
    parsed = DateRange(parse_datetime(start, field="date_from"), parse_datetime(end, field="date_to"))
    if parsed.start and parsed.end and parsed.start > parsed.end:
        raise BridgeError("date_from must not be after date_to", code="invalid_date_range")
    return parsed


def normalize_search_text(value: str) -> str:
    return value.casefold()


def validate_file_ref(value: Any) -> str:
    raw = bounded_text(value, field="file_ref", maximum=128, allow_empty=False)
    if not re.fullmatch(r"[A-Za-z0-9_-]{16,128}", raw):
        raise BridgeError("Invalid file reference", status=404, code="file_not_found")
    return raw
