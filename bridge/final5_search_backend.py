"""FINAL5 Task3 Telethon search correctness overlay.

This isolated backend repairs two source-verifiable seams without changing the
canonical branch directly:

* real Telethon global search is always given a legal server-side constraint
  (non-empty ``search``, ``from_user``, or an empty messages filter);
* chat-scoped search cursors use Telethon's exclusive ``offset_id`` when the
  client explicitly supports it, so later pages do not rescan the same newest
  bounded prefix.

Global cross-dialog deep continuation is deliberately *not* claimed solved by
this module. Telethon's public global iterator does not expose all raw
``SearchGlobal`` continuation state, so a later private cursor-state design is
still required before that HIGH can be closed truthfully.

No Telethon import or network activity occurs at module import time.
"""
from __future__ import annotations

import unicodedata
from datetime import datetime
from typing import Any

from .backend import TelethonReadBackend
from .errors import BridgeError
from .models import (
    EntityRef,
    MessageRecord,
    Page,
    canonical_timestamp,
    encode_cursor,
    message_sort_key,
    stable_message_sort,
)
from .validation import DateRange, normalize_search_text


class Final5TelethonReadBackend(TelethonReadBackend):
    """Narrow production candidate for global constraints + scoped continuation."""

    @staticmethod
    def _looks_like_username(ref: str) -> bool:
        candidate = ref.lstrip("@")
        return bool(candidate) and len(candidate) <= 32 and all(
            ch.isascii() and (ch.isalnum() or ch == "_") for ch in candidate
        )

    async def _resolve_global_sender(self, client: Any, ref: str) -> Any:
        raw = ref.strip()
        needle = normalize_search_text(raw.lstrip("@"))
        if not needle:
            raise BridgeError("Sender is required", code="invalid_sender")

        direct_hint = raw.startswith("@") or raw.lstrip("-").isdigit() or self._looks_like_username(raw)
        if direct_hint:
            target: Any = int(raw) if raw.lstrip("-").isdigit() else raw.lstrip("@")
            getter = getattr(client, "get_entity", None)
            if callable(getter):
                try:
                    entity = await self._maybe_await(getter(target))
                except Exception as exc:
                    if not (isinstance(exc, ValueError) or exc.__class__.__name__ in self._ENTITY_NOT_FOUND_ERRORS):
                        raise
                else:
                    if self._entity_kind(entity) != "user":
                        raise BridgeError("Sender reference is not a person", code="sender_not_person")
                    return entity

        dialogs = await self._iter_dialogs(client, self.config.dialog_scan_limit)
        ranked: dict[str, tuple[int, Any]] = {}
        for dialog in dialogs:
            entity = getattr(dialog, "entity", dialog)
            if self._entity_kind(entity) != "user":
                continue
            entity_id = str(getattr(entity, "id", ""))
            username = normalize_search_text(str(getattr(entity, "username", None) or ""))
            display_name = normalize_search_text(self._entity_title(entity))
            normalized_id = normalize_search_text(entity_id)
            exact = needle in {normalized_id, username, display_name}
            combined = normalize_search_text(
                f"{entity_id} {getattr(entity, 'username', None) or ''} {self._entity_title(entity)}"
            )
            partial = bool(needle and needle in combined)
            score = 2 if exact else 1 if partial else 0
            if score:
                key = entity_id or f"object:{id(entity)}"
                previous = ranked.get(key)
                if previous is None or score > previous[0]:
                    ranked[key] = (score, entity)

        if ranked:
            best_score = max(score for score, _ in ranked.values())
            best = [entity for score, entity in ranked.values() if score == best_score]
            if len(best) == 1:
                return best[0]
            raise BridgeError(
                "Sender reference is ambiguous",
                code="sender_ambiguous",
                details={"match_count": len(best)},
            )
        raise BridgeError("Sender not found", status=404, code="sender_not_found")

    @staticmethod
    def _global_empty_filter() -> Any:
        """Create Telethon's empty messages filter only at operation time."""
        try:
            from telethon.tl.types import InputMessagesFilterEmpty
        except Exception as exc:  # pragma: no cover - production dependency boundary
            raise BridgeError(
                "Telegram global search filter is unavailable",
                status=503,
                code="telegram_global_search_unsupported",
                details={"retryable": False},
            ) from exc
        return InputMessagesFilterEmpty()

    async def _iter_search_messages(
        self,
        client: Any,
        entity: Any,
        limit: int,
        *,
        search: str,
        from_user: Any | None = None,
        empty_filter: Any | None = None,
        offset_id: int | None = None,
    ) -> list[Any]:
        method = client.iter_messages
        kwargs: dict[str, Any] = {"limit": limit}
        if search:
            if not self._supports_named_parameter(method, "search"):
                raise BridgeError(
                    "Telegram client does not support server search",
                    status=503,
                    code="telegram_search_unsupported",
                    details={"retryable": False},
                )
            kwargs["search"] = search
        if from_user is not None:
            if not self._supports_named_parameter(method, "from_user"):
                raise BridgeError(
                    "Telegram client does not support global sender search",
                    status=503,
                    code="telegram_global_sender_unsupported",
                    details={"retryable": False},
                )
            kwargs["from_user"] = from_user
        if empty_filter is not None:
            if not self._supports_named_parameter(method, "filter"):
                raise BridgeError(
                    "Telegram client does not support constrained global search",
                    status=503,
                    code="telegram_global_search_unsupported",
                    details={"retryable": False},
                )
            kwargs["filter"] = empty_filter
        if offset_id is not None:
            if not self._supports_named_parameter(method, "offset_id"):
                raise BridgeError(
                    "Telegram client does not support search continuation",
                    status=503,
                    code="telegram_search_continuation_unsupported",
                    details={"retryable": False},
                )
            kwargs["offset_id"] = offset_id

        iterator = method(entity, **kwargs)
        if hasattr(iterator, "__aiter__"):
            return [item async for item in iterator]
        return list(iterator)

    @classmethod
    def _bind_resolved_sender(cls, record: MessageRecord, sender_entity: Any) -> MessageRecord | None:
        expected_id = str(getattr(sender_entity, "id", ""))
        if not expected_id:
            raise BridgeError(
                "Resolved sender has no stable identifier",
                status=502,
                code="telegram_sender_identity_invalid",
            )
        if record.sender is not None and record.sender.id and record.sender.id != expected_id:
            return None
        resolved = EntityRef(
            id=expected_id,
            kind=cls._entity_kind(sender_entity),
            display_name=cls._entity_title(sender_entity),
            username=cls._optional_text(getattr(sender_entity, "username", None)),
        )
        return MessageRecord(
            id=record.id,
            chat_id=record.chat_id,
            timestamp=record.timestamp,
            text=record.text,
            sender=resolved,
            outgoing=record.outgoing,
            reply_to_message_id=record.reply_to_message_id,
            media=record.media,
        )

    @staticmethod
    def _cursor_for_boundary(scope: str, signature: str, boundary: tuple[str, int, str] | None) -> str | None:
        if boundary is None:
            return None
        stamp, message_id, chat_id = boundary
        return encode_cursor(
            {
                "v": 2,
                "scope": scope,
                "sig": signature,
                "boundary": [stamp, message_id, chat_id],
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
        async def work() -> Page:
            needle = normalize_search_text(text.strip())
            sender_raw = sender.strip() if sender else ""
            sender_cf = normalize_search_text(sender_raw.lstrip("@")) if sender_raw else ""
            signature = self._cursor_signature(
                "search",
                (chat or "").strip(),
                sender_cf,
                needle,
                canonical_timestamp(dates.start) or "",
                canonical_timestamp(dates.end) or "",
                str(scan_limit),
            )
            boundary = self._message_boundary(cursor, "search", signature)
            budget = min(scan_limit, self.config.search_scan_limit)

            async with self._client_session() as client:
                entity = await self._resolve(client, chat) if chat else None
                server_search = unicodedata.normalize("NFKC", text.strip()) if text.strip() else ""
                resolved_global_sender: Any | None = None
                empty_filter: Any | None = None
                offset_id: int | None = None
                scoped_server_continuation = bool(
                    entity is not None and self._supports_named_parameter(client.iter_messages, "offset_id")
                )

                if entity is None:
                    if sender_raw and not server_search:
                        resolved_global_sender = await self._resolve_global_sender(client, sender_raw)
                    elif not server_search:
                        empty_filter = self._global_empty_filter()
                elif boundary is not None and scoped_server_continuation:
                    offset_id = boundary[1]

                messages = await self._iter_search_messages(
                    client,
                    entity,
                    budget,
                    search=server_search,
                    from_user=resolved_global_sender,
                    empty_filter=empty_filter,
                    offset_id=offset_id,
                )
                chat_id = str(getattr(entity, "id", chat or "global"))
                require_sender_details = bool(
                    sender_cf
                    and resolved_global_sender is None
                    and not sender_cf.lstrip("-").isdigit()
                )
                records: list[MessageRecord] = []
                for message in messages:
                    raw_record = await self._message_record(
                        message,
                        chat_id,
                        require_sender_details=require_sender_details,
                    )
                    if resolved_global_sender is not None:
                        bound = self._bind_resolved_sender(raw_record, resolved_global_sender)
                        if bound is None:
                            continue
                        raw_record = bound
                    records.append(raw_record)

                records = stable_message_sort(records, reverse=True)
                filtered: list[MessageRecord] = []
                for record in records:
                    stamp = datetime.fromisoformat(record.timestamp.replace("Z", "+00:00"))
                    if not dates.contains(stamp):
                        continue
                    if needle and needle not in normalize_search_text(record.text):
                        continue
                    if sender_cf and resolved_global_sender is None:
                        stable = record.sender
                        hay = (
                            ""
                            if stable is None
                            else normalize_search_text(
                                f"{stable.id} {stable.username or ''} {stable.display_name or ''}"
                            )
                        )
                        if sender_cf not in hay:
                            continue
                    filtered.append(record)

                # Global cursors and legacy scoped clients retain local boundary
                # filtering. Real Telethon scoped cursors move the server iterator
                # itself with exclusive offset_id and must not filter twice.
                if boundary is not None and (entity is None or not scoped_server_continuation):
                    filtered = [record for record in filtered if message_sort_key(record) < boundary]

                page = filtered[:limit]
                next_boundary: tuple[str, int, str] | None = None
                if len(filtered) > limit and page:
                    next_boundary = message_sort_key(page[-1])
                elif scoped_server_continuation and len(messages) == budget and records:
                    # Budget exhaustion does not prove end-of-chat. Advance to
                    # the last raw scanned message so sparse local filters cannot
                    # hide older matches behind a full server page.
                    next_boundary = message_sort_key(records[-1])

                return Page(
                    tuple(page),
                    self._cursor_for_boundary("search", signature, next_boundary),
                    len(messages),
                )

        return self._run(work())


def build_production_application_from_env() -> Any:
    """Select this backend through the canonical runtime composition factory."""
    from . import runtime_composition

    original = runtime_composition.TelethonReadBackend
    runtime_composition.TelethonReadBackend = Final5TelethonReadBackend
    try:
        return runtime_composition.build_production_application_from_env()
    finally:
        runtime_composition.TelethonReadBackend = original


__all__ = ["Final5TelethonReadBackend", "build_production_application_from_env"]
