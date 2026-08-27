"""FINAL5 Task3 current-head search correctness candidate.

This isolated specialist overlay does not modify the canonical branch. It keeps
canonical raw SearchGlobal behavior for global searches while repairing two
current-head scoped-search seams:

* constrained ``iter_messages`` calls are made once; a TypeError raised inside
  the client is never retried after silently dropping search/offset arguments;
* chat-scoped continuation uses Telethon's exclusive ``offset_id`` when the
  client explicitly supports it, and advances by the last raw scanned message
  when local filters consume a full bounded chunk.

No Telegram credentials or network activity are used at import time.
"""
from __future__ import annotations

import unicodedata
from datetime import datetime
from typing import Any

from .backend import TelethonReadBackend
from .models import MessageRecord, Page, canonical_timestamp, encode_cursor, message_sort_key, stable_message_sort
from .validation import DateRange, normalize_search_text


class Final5Task3TelethonReadBackend(TelethonReadBackend):
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
        if search and self._supports_named_parameter(method, "search"):
            kwargs["search"] = search
        if offset_id is not None and self._supports_named_parameter(method, "offset_id"):
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
                supports_offset = self._supports_named_parameter(client.iter_messages, "offset_id")
                offset_id = boundary[1] if boundary is not None and supports_offset else None
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

                if boundary is not None and not supports_offset:
                    filtered = [record for record in filtered if message_sort_key(record) < boundary]

                page = filtered[:limit]
                next_boundary: tuple[str, int, str] | None = None
                if len(filtered) > limit and page:
                    next_boundary = message_sort_key(page[-1])
                elif supports_offset and len(messages) == budget and records:
                    # A full raw chunk is not proof of exhaustion. Advancing to
                    # the last raw row preserves sparse sender/date filtering
                    # without rescanning the same newest prefix on the next page.
                    next_boundary = message_sort_key(records[-1])

                return Page(
                    tuple(page),
                    self._scoped_cursor(signature, next_boundary),
                    len(messages),
                )

        return self._run(work())


__all__ = ["Final5Task3TelethonReadBackend"]
