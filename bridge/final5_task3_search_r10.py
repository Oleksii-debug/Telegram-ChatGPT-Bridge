"""FINAL5 Task3 current-base search correctness candidate.

Isolated specialist overlay for canonical parent
893554e4c8a0758ae6549ef24fa7a9442ee128dc. It does not wire production,
authorize Telegram, or perform network activity at import time.

The candidate preserves canonical global SearchGlobal behavior while proving two
narrow semantics for later W01 adaptation:
* requested Telethon search/offset constraints must be explicitly supported and
  are forwarded exactly once; an internal TypeError is never retried broadly;
* scoped continuation uses Telethon's exclusive offset_id so page 2+ does not
  rescan the same newest bounded prefix.
"""
from __future__ import annotations

import unicodedata
from datetime import datetime
from typing import Any

from .backend import TelethonReadBackend
from .errors import BridgeError
from .models import MessageRecord, Page, canonical_timestamp, encode_cursor, message_sort_key, stable_message_sort
from .validation import DateRange, normalize_search_text


class Final5Task3SearchR10Backend(TelethonReadBackend):
    async def _iter_messages(
        self,
        client: Any,
        entity: Any,
        limit: int,
        *,
        search: str = "",
        offset_id: int | None = None,
    ) -> list[Any]:
        method = client.iter_messages
        kwargs: dict[str, Any] = {"limit": limit}
        if search:
            if not self._supports_named_parameter(method, "search"):
                raise BridgeError(
                    "Telegram client does not support constrained search",
                    status=503,
                    code="telegram_search_unsupported",
                )
            kwargs["search"] = search
        if offset_id is not None:
            if not self._supports_named_parameter(method, "offset_id"):
                raise BridgeError(
                    "Telegram client does not support search continuation",
                    status=503,
                    code="telegram_search_continuation_unsupported",
                )
            kwargs["offset_id"] = offset_id
        iterator = method(entity, **kwargs)
        if hasattr(iterator, "__aiter__"):
            return [item async for item in iterator]
        return list(iterator)

    @staticmethod
    def _scoped_cursor(signature: str, boundary: tuple[str, int, str] | None) -> str | None:
        if boundary is None:
            return None
        return encode_cursor(
            {
                "v": 2,
                "scope": "search",
                "sig": signature,
                "boundary": list(boundary),
            }
        )

    def search(
        self,
        *,
        chat: str | None,
        sender: str | None,
        text: str,
        dates: DateRange,
        limit: int,
        cursor: str | None,
        scan_limit: int,
    ) -> Page:
        if chat is None:
            return super().search(
                chat=chat,
                sender=sender,
                text=text,
                dates=dates,
                limit=limit,
                cursor=cursor,
                scan_limit=scan_limit,
            )

        async def work() -> Page:
            needle = normalize_search_text(text.strip())
            sender_raw = sender.strip() if sender else ""
            sender_cf = normalize_search_text(sender_raw.lstrip("@")) if sender_raw else ""
            signature = self._cursor_signature(
                "search",
                chat.strip(),
                sender_cf,
                needle,
                canonical_timestamp(dates.start) or "",
                canonical_timestamp(dates.end) or "",
                str(scan_limit),
            )
            boundary = self._message_boundary(cursor, "search", signature)
            budget = min(scan_limit, self.config.search_scan_limit)

            async with self._client_session() as client:
                entity = await self._resolve(client, chat)
                method = client.iter_messages
                supports_offset = self._supports_named_parameter(method, "offset_id")
                if boundary is not None and not supports_offset:
                    raise BridgeError(
                        "Telegram client does not support search continuation",
                        status=503,
                        code="telegram_search_continuation_unsupported",
                    )
                offset_id = boundary[1] if boundary is not None else None
                server_search = unicodedata.normalize("NFKC", text.strip()) if text.strip() else ""
                messages = await self._iter_messages(
                    client,
                    entity,
                    budget,
                    search=server_search,
                    offset_id=offset_id,
                )
                chat_id = str(getattr(entity, "id", chat))
                require_sender_details = bool(sender_cf and not sender_cf.lstrip("-").isdigit())
                records: list[MessageRecord] = [
                    await self._message_record(
                        message,
                        chat_id,
                        require_sender_details=require_sender_details,
                    )
                    for message in messages
                ]
                records = stable_message_sort(records, reverse=True)
                filtered: list[MessageRecord] = []
                for record in records:
                    stamp = datetime.fromisoformat(record.timestamp.replace("Z", "+00:00"))
                    if not dates.contains(stamp):
                        continue
                    if needle and needle not in normalize_search_text(record.text):
                        continue
                    if sender_cf:
                        stable = record.sender
                        hay = "" if stable is None else normalize_search_text(
                            f"{stable.id} {stable.username or ''} {stable.display_name or ''}"
                        )
                        if sender_cf not in hay:
                            continue
                    filtered.append(record)

                page = filtered[:limit]
                next_boundary: tuple[str, int, str] | None = None
                if len(filtered) > limit and page:
                    next_boundary = message_sort_key(page[-1])
                elif len(messages) == budget and records:
                    # A full raw chunk is not proof of Telegram exhaustion. Move
                    # the server offset to the oldest raw row so sparse local
                    # sender/date filters can continue without rescanning.
                    next_boundary = message_sort_key(records[-1])

                return Page(
                    tuple(page),
                    self._scoped_cursor(signature, next_boundary),
                    len(messages),
                )

        return self._run(work())


__all__ = ["Final5Task3SearchR10Backend"]
