"""Metadata-only audit sink for read operations."""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any


_ALLOWED_FIELDS = {
    "request_id",
    "status",
    "count",
    "scanned",
    "route",
    "method",
    "job_id",
    "file_count",
    "byte_count",
    "error_code",
    "retry_after_seconds",
}


class AuditLog:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path
        self.events: list[dict[str, Any]] = []
        if path is not None:
            path.parent.mkdir(parents=True, exist_ok=True)
            try:
                os.chmod(path.parent, 0o700)
            except OSError:
                pass

    def write(self, event: str, **fields: Any) -> None:
        safe: dict[str, Any] = {"ts": int(time.time()), "event": str(event)[:64]}
        for key, value in fields.items():
            if key not in _ALLOWED_FIELDS:
                continue
            if isinstance(value, bool):
                safe[key] = value
            elif isinstance(value, int) and -(2**31) <= value <= 2**31 - 1:
                safe[key] = value
            elif isinstance(value, str) and len(value) <= 128 and value.isascii() and all(ord(ch) >= 32 for ch in value):
                safe[key] = value
        self.events.append(dict(safe))
        if self.path is not None:
            line = json.dumps(safe, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n"
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(line)
