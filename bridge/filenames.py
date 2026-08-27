"""Unicode-normalized, cross-platform-safe private file display names."""

from __future__ import annotations

import re
import unicodedata
from pathlib import Path

_INVALID_ASCII = re.compile(r'[\x00-\x1f\x7f<>:"|?*]+')
_WHITESPACE = re.compile(r"\s+")
_BIDI_CONTROLS = {
    "\u200e",
    "\u200f",
    "\u202a",
    "\u202b",
    "\u202c",
    "\u202d",
    "\u202e",
    "\u2066",
    "\u2067",
    "\u2068",
    "\u2069",
}
_WINDOWS_RESERVED = {
    "con",
    "prn",
    "aux",
    "nul",
    "clock$",
    *(f"com{index}" for index in range(1, 10)),
    *(f"lpt{index}" for index in range(1, 10)),
}


def _basename(value: str) -> str:
    """Return one path-independent component for POSIX and Windows-like input."""
    return value.replace("\\", "/").split("/")[-1]


def _truncate_preserving_suffix(value: str, limit: int) -> str:
    if len(value) <= limit:
        return value
    suffix = Path(value).suffix
    if suffix and len(suffix) <= min(32, limit // 2):
        stem_limit = max(1, limit - len(suffix))
        return value[:stem_limit].rstrip(" .") + suffix
    return value[:limit].rstrip(" .")


def safe_filename(name: str | None, fallback: str = "file.bin", *, limit: int = 180) -> str:
    """Sanitize a user/Telegram supplied filename without creating a path.

    Names are normalized to NFC before collision handling, traversal components
    are discarded, ASCII control/Windows-invalid characters and bidi override
    controls are neutralized, and Windows device names are prefixed.  The
    result is safe as display/archive metadata; private on-disk names remain
    independent opaque random names.
    """
    if isinstance(limit, bool) or not isinstance(limit, int) or not 16 <= limit <= 255:
        raise ValueError("filename limit is outside the safe range")
    fallback_text = unicodedata.normalize("NFC", str(fallback or "file.bin"))
    raw = unicodedata.normalize("NFC", str(name if name not in (None, "") else fallback_text))
    candidate = _basename(raw)
    candidate = "".join("_" if char in _BIDI_CONTROLS else char for char in candidate)
    candidate = _INVALID_ASCII.sub("_", candidate)
    candidate = _WHITESPACE.sub(" ", candidate).strip(" .")
    if candidate in {"", ".", ".."}:
        candidate = _basename(fallback_text).strip(" .") or "file.bin"
    device_stem = candidate.split(".", 1)[0].rstrip(" .").casefold()
    if device_stem in _WINDOWS_RESERVED:
        candidate = "_" + candidate
    candidate = _truncate_preserving_suffix(candidate, limit)
    return candidate or "file.bin"


def filename_collision_key(name: str) -> str:
    """Cross-platform collision key used by archive member allocation."""
    return unicodedata.normalize("NFC", name).casefold()
