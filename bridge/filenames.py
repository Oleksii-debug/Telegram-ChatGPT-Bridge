"""Unicode-normalized, cross-platform-safe private file display names."""

from __future__ import annotations

import re
import unicodedata
from pathlib import Path

# Leave headroom below common 255-byte POSIX component limits so archive
# collision suffixes can be added without producing names that are valid ZIP
# metadata but fail when extracted to a normal filesystem.
PORTABLE_FILENAME_UTF8_BYTES = 240

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
# These code points are not path separators to Python, but are confusable with
# slash/backslash in filenames shown to a user or extracted by heterogeneous
# clients.  Neutralizing them is deliberately narrower than general homoglyph
# folding so legitimate Cyrillic and other scripts remain intact.
_PATH_SEPARATOR_CONFUSABLES = {
    "\u2044",  # FRACTION SLASH
    "\u2215",  # DIVISION SLASH
    "\u29f5",  # REVERSE SOLIDUS OPERATOR
    "\u29f8",  # BIG SOLIDUS
    "\ufe68",  # SMALL REVERSE SOLIDUS
    "\uff0f",  # FULLWIDTH SOLIDUS
    "\uff3c",  # FULLWIDTH REVERSE SOLIDUS
}
# Invisible formatting controls that are unsafe or misleading in a filename.
# ZWJ/ZWNJ are intentionally not included because they are part of legitimate
# emoji/script grapheme sequences.
_INVISIBLE_FILENAME_CONTROLS = {
    "\u00ad",  # SOFT HYPHEN
    "\u200b",  # ZERO WIDTH SPACE
    "\u2060",  # WORD JOINER
    "\ufeff",  # ZERO WIDTH NO-BREAK SPACE / BOM
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


def _take_prefix(value: str, *, char_limit: int, byte_limit: int) -> str:
    """Take a strict-UTF-8 prefix within both character and byte budgets."""
    if char_limit <= 0 or byte_limit <= 0:
        return ""
    output: list[str] = []
    used_bytes = 0
    for character in value:
        encoded = character.encode("utf-8", "strict")
        if len(output) >= char_limit or used_bytes + len(encoded) > byte_limit:
            break
        output.append(character)
        used_bytes += len(encoded)
    return "".join(output)


def _usable_suffix(value: str, limit: int) -> str:
    suffix = Path(value).suffix
    if not suffix or len(suffix) > min(32, limit // 2):
        return ""
    if len(suffix.encode("utf-8", "strict")) > min(64, PORTABLE_FILENAME_UTF8_BYTES // 2):
        return ""
    return suffix


def _truncate_preserving_suffix(value: str, limit: int) -> str:
    if len(value) <= limit and len(value.encode("utf-8", "strict")) <= PORTABLE_FILENAME_UTF8_BYTES:
        return value
    suffix = _usable_suffix(value, limit)
    stem = value[: -len(suffix)] if suffix else value
    char_budget = limit - len(suffix)
    byte_budget = PORTABLE_FILENAME_UTF8_BYTES - len(suffix.encode("utf-8", "strict"))
    prefix = _take_prefix(stem, char_limit=char_budget, byte_limit=byte_budget).rstrip(" .")
    if not prefix:
        prefix = _take_prefix("file", char_limit=char_budget, byte_limit=byte_budget)
    return prefix + suffix


def _neutralize_filename_controls(value: str) -> str:
    output: list[str] = []
    for character in value:
        category = unicodedata.category(character)
        if (
            character in _BIDI_CONTROLS
            or character in _PATH_SEPARATOR_CONFUSABLES
            or character in _INVISIBLE_FILENAME_CONTROLS
            or category in {"Cc", "Cs"}
        ):
            output.append("_")
        else:
            output.append(character)
    return "".join(output)


def _is_windows_reserved(candidate: str) -> bool:
    stem = candidate.split(".", 1)[0].rstrip(" .")
    # Windows compatibility names include forms such as fullwidth CON and
    # superscript COM¹/LPT¹ on some consumers.  NFKC is used only for the
    # reservation decision; the displayed Unicode spelling is otherwise kept.
    device_key = unicodedata.normalize("NFKC", stem).casefold()
    return device_key in _WINDOWS_RESERVED


def safe_filename(name: str | None, fallback: str = "file.bin", *, limit: int = 180) -> str:
    """Sanitize a user/Telegram supplied filename without creating a path.

    Names are normalized to NFC before collision handling. Traversal components,
    path-separator confusables, invalid Unicode surrogates, dangerous controls,
    Windows-invalid characters and device names are neutralized. Results are
    bounded by both code-point length and strict UTF-8 byte length.

    This policy applies to filenames/display/archive metadata only. Message text
    is not passed through this function and remains byte-for-byte semantic text.
    """
    if isinstance(limit, bool) or not isinstance(limit, int) or not 16 <= limit <= 255:
        raise ValueError("filename limit is outside the safe range")

    fallback_text = unicodedata.normalize("NFC", str(fallback or "file.bin"))
    raw = unicodedata.normalize("NFC", str(name if name not in (None, "") else fallback_text))
    candidate = _basename(raw)
    candidate = _neutralize_filename_controls(candidate)
    candidate = _INVALID_ASCII.sub("_", candidate)
    candidate = _WHITESPACE.sub(" ", candidate).strip(" .")

    if candidate in {"", ".", ".."}:
        candidate = _neutralize_filename_controls(_basename(fallback_text))
        candidate = _INVALID_ASCII.sub("_", candidate)
        candidate = _WHITESPACE.sub(" ", candidate).strip(" .") or "file.bin"

    if _is_windows_reserved(candidate):
        candidate = "_" + candidate
    candidate = _truncate_preserving_suffix(candidate, limit)
    # Re-check after truncation in case a future policy change exposes a device
    # stem at the boundary.
    if _is_windows_reserved(candidate):
        candidate = _truncate_preserving_suffix("_" + candidate, limit)
    return candidate or "file.bin"


def filename_collision_key(name: str) -> str:
    """Cross-platform collision key used by archive member allocation.

    Compatibility normalization is intentionally stronger than display-name
    normalization so A/a, NFC/NFD and width/compatibility variants cannot become
    duplicate members on consumers with different normalization behavior.
    """
    normalized = unicodedata.normalize("NFKC", str(name))
    return unicodedata.normalize("NFKC", normalized.casefold()).rstrip(" .")


def disambiguated_filename(name: str, index: int, *, limit: int = 180) -> str:
    """Return a bounded safe collision variant whose numeric marker survives truncation."""
    if isinstance(index, bool) or not isinstance(index, int) or index < 2:
        raise ValueError("filename collision index must be an integer >= 2")
    if isinstance(limit, bool) or not isinstance(limit, int) or not 16 <= limit <= 255:
        raise ValueError("filename limit is outside the safe range")

    base = safe_filename(name, "file", limit=limit)
    suffix = _usable_suffix(base, limit)
    stem = base[: -len(suffix)] if suffix else base
    marker = f" ({index})"
    tail = marker + suffix
    char_budget = limit - len(tail)
    byte_budget = PORTABLE_FILENAME_UTF8_BYTES - len(tail.encode("utf-8", "strict"))
    prefix = _take_prefix(stem, char_limit=char_budget, byte_limit=byte_budget).rstrip(" .")
    if not prefix:
        prefix = _take_prefix("file", char_limit=char_budget, byte_limit=byte_budget)
    return safe_filename(prefix + tail, "file", limit=limit)
