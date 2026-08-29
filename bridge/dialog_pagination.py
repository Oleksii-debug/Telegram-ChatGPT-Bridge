"""Production dialog-pagination hardening for the Telethon read backend.

This module is imported lazily by the runtime WSGI composition. It performs no
network activity at import time. The installer replaces only
``TelethonReadBackend.list_dialogs`` with restart-safe bounded continuation using
Telethon's native dialog offsets while preserving pinned-prefix semantics.
"""
from __future__ import annotations

import inspect
from datetime import datetime
from typing import Any

from .backend import TelethonReadBackend
from .errors import BridgeError
from .models import Page, canonical_timestamp, decode_cursor, encode_cursor
from .validation import normalize_search_text


def _supports_dialog_offsets(method: Any) -> bool:
    try:
        params = inspect.signature(method).parameters
    except (TypeError, ValueError):
        return False
    return all(name in params for name in ("offset_date", "offset_id", "offset_peer", "ignore_pinned"))


def _decode_dialog_server_cursor(
    backend: TelethonReadBackend,
    cursor: str | None,
    signature: str,
) -> tuple[tuple[str, int, int] | None, int | None] | None:
    decoded = decode_cursor(cursor)
    if decoded is None:
        return None
    if set(decoded) != {"v", "scope", "sig", "offset", "after"}:
        raise backend._invalid_cursor()
    if decoded.get("v") != 4 or decoded.get("scope") != "dialogs" or decoded.get("sig") != signature:
        raise backend._invalid_cursor()
    offset = decoded.get("offset")
    after = decoded.get("after")
    if after is not None and (
        isinstance(after, bool)
        or not isinstance(after, int)
        or after == 0
        or abs(after) > 2**63 - 1
    ):
        raise backend._invalid_cursor()
    if offset is None:
        if after is None:
            raise backend._invalid_cursor()
        return None, after
    if not isinstance(offset, list) or len(offset) != 3:
        raise backend._invalid_cursor()
    stamp, message_id, peer_id = offset
    if not isinstance(stamp, str) or not stamp or len(stamp) > 64:
        raise backend._invalid_cursor()
    try:
        if canonical_timestamp(stamp) != stamp:
            raise ValueError
    except Exception as exc:
        raise backend._invalid_cursor(exc) from exc
    if isinstance(message_id, bool) or not isinstance(message_id, int) or message_id < 0 or message_id > 2**63 - 1:
        raise backend._invalid_cursor()
    if isinstance(peer_id, bool) or not isinstance(peer_id, int) or peer_id == 0 or abs(peer_id) > 2**63 - 1:
        raise backend._invalid_cursor()
    return (stamp, message_id, peer_id), after


def _dialog_server_offset(dialog: Any) -> tuple[str, int, int]:
    message = getattr(dialog, "message", None)
    date = getattr(message, "date", None)
    message_id = getattr(message, "id", None)
    peer_id = getattr(dialog, "id", None)
    if not isinstance(date, datetime):
        raise BridgeError(
            "Telegram dialog continuation lacks a message date",
            status=502,
            code="telegram_dialog_continuation_invalid",
            details={"retryable": True},
        )
    if isinstance(message_id, bool) or not isinstance(message_id, int) or message_id < 0:
        raise BridgeError(
            "Telegram dialog continuation lacks a message id",
            status=502,
            code="telegram_dialog_continuation_invalid",
            details={"retryable": True},
        )
    if isinstance(peer_id, bool) or not isinstance(peer_id, int) or peer_id == 0:
        raise BridgeError(
            "Telegram dialog continuation lacks a marked peer id",
            status=502,
            code="telegram_dialog_continuation_invalid",
            details={"retryable": True},
        )
    return canonical_timestamp(date) or "1970-01-01T00:00:00Z", message_id, peer_id


async def _collect_dialogs(iterator: Any) -> list[Any]:
    if hasattr(iterator, "__aiter__"):
        return [item async for item in iterator]
    return list(iterator)


def _deep_dialog_list_dialogs(
    self: TelethonReadBackend,
    *,
    limit: int,
    cursor: str | None,
    query: str,
    unread_only: bool,
) -> Page:
    async def work() -> Page:
        needle = normalize_search_text(query.strip())
        signature = self._cursor_signature("dialogs-v4", needle, "1" if unread_only else "0")
        state = _decode_dialog_server_cursor(self, cursor, signature)

        async with self._client_session() as client:
            method = client.iter_dialogs
            if state is not None and not _supports_dialog_offsets(method):
                raise BridgeError(
                    "Telegram dialog continuation is unavailable",
                    status=502,
                    code="telegram_dialog_continuation_unsupported",
                    details={"retryable": False},
                )

            fetch_limit = self.config.dialog_scan_limit
            kwargs: dict[str, Any] = {"limit": fetch_limit}
            window_offset, after_peer_id = state or (None, None)
            if window_offset is not None:
                stamp, offset_id, peer_id = window_offset
                try:
                    offset_peer = await self._maybe_await(client.get_input_entity(peer_id))
                except Exception as exc:
                    raise BridgeError(
                        "Telegram dialog continuation peer is unavailable",
                        status=502,
                        code="telegram_dialog_continuation_peer_unavailable",
                        details={"retryable": True},
                    ) from exc
                kwargs.update(
                    offset_date=datetime.fromisoformat(stamp.replace("Z", "+00:00")),
                    offset_id=offset_id,
                    offset_peer=offset_peer,
                    ignore_pinned=True,
                )

            raw_window = await _collect_dialogs(method(**kwargs))
            raw = raw_window
            if after_peer_id is not None:
                for index, dialog in enumerate(raw_window):
                    if getattr(dialog, "id", None) == after_peer_id:
                        raw = raw_window[index + 1 :]
                        break
                else:
                    raise BridgeError(
                        "Telegram dialog continuation boundary changed",
                        status=502,
                        code="telegram_dialog_continuation_changed",
                        details={"retryable": True},
                    )

            matches: list[tuple[Any, Any]] = []
            seen: set[str] = set()
            for dialog in raw:
                record = self._dialog_record(dialog)
                dedupe_key = str(getattr(dialog, "id", record.id))
                if dedupe_key in seen:
                    continue
                seen.add(dedupe_key)
                if needle and needle not in normalize_search_text(f"{record.title} {record.username or ''} {record.id}"):
                    continue
                if unread_only and record.unread_count <= 0:
                    continue
                matches.append((record, dialog))

            page_pairs = matches[:limit]
            page = [record for record, _ in page_pairs]
            next_offset: tuple[str, int, int] | None = None
            next_after: int | None = None
            if len(matches) > limit and page_pairs:
                # Stay inside the same bounded raw window until every visible
                # peer in that window has been offered. This is essential while
                # the initial pinned prefix may still be present.
                next_offset = window_offset
                next_after = _dialog_server_offset(page_pairs[-1][1])[2]
            elif len(raw_window) >= fetch_limit and raw_window:
                # Sparse filters may yield short or empty visible pages. Move by
                # the final raw server dialog so pagination cannot get trapped in
                # one bounded prefix.
                if bool(getattr(raw_window[-1], "pinned", False)):
                    raise BridgeError(
                        "Telegram dialog scan bound ends inside the pinned prefix",
                        status=400,
                        code="telegram_dialog_scan_limit_too_small",
                        details={"retryable": False},
                    )
                next_offset = _dialog_server_offset(raw_window[-1])

            next_cursor = None
            if next_offset is not None or next_after is not None:
                next_cursor = encode_cursor(
                    {
                        "v": 4,
                        "scope": "dialogs",
                        "sig": signature,
                        "offset": list(next_offset) if next_offset is not None else None,
                        "after": next_after,
                    }
                )
            return Page(tuple(page), next_cursor, len(raw_window))

    return self._run(work())


def install_dialog_pagination() -> None:
    """Install the hardened list-dialogs implementation exactly once."""
    if getattr(TelethonReadBackend.list_dialogs, "_task3_dialog_pagination_v4", False):
        return
    setattr(_deep_dialog_list_dialogs, "_task3_dialog_pagination_v4", True)
    TelethonReadBackend.list_dialogs = _deep_dialog_list_dialogs


__all__ = ["install_dialog_pagination"]
