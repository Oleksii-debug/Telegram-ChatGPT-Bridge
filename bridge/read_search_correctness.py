"""Narrow Telethon read/search correctness overlay for BURST01-05.

This module repairs the one global-search shape that Telethon cannot execute as
an unconstrained SearchGlobal request: ``entity=None`` with a sender filter but
no text/filter. It deliberately delegates every other read operation to the
canonical :class:`TelethonReadBackend`, preserving DEV03 history/keyset/Unicode
work byte-for-byte.

No Telegram dependency is imported here and no network activity occurs at
module import time.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any

from .backend import TelethonReadBackend
from .errors import BridgeError
from .models import EntityRef, MessageRecord, Page, canonical_timestamp, message_sort_key, stable_message_sort
from .validation import DateRange, normalize_search_text


class GlobalSenderTelethonReadBackend(TelethonReadBackend):
    """Telethon backend with bounded, server-constrained global sender search."""

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

        # Stable numeric IDs and username-like references get the normal
        # Telethon entity resolver first. A failed username hint is allowed to
        # fall back to the bounded dialog index so display-name queries keep
        # working without guessing or scanning all Telegram history.
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

    async def _iter_global_sender_messages(self, client: Any, sender_entity: Any, limit: int) -> list[Any]:
        method = client.iter_messages
        if not self._supports_named_parameter(method, "from_user"):
            # Never drop the sender constraint and retry globally. Doing so is
            # invalid under Telethon and could turn a precise request into an
            # accidental broad scan in a non-Telethon compatibility client.
            raise BridgeError(
                "Telegram client does not support global sender search",
                status=503,
                code="telegram_global_sender_unsupported",
                details={"retryable": False},
            )
        iterator = method(None, limit=limit, from_user=sender_entity)
        if hasattr(iterator, "__aiter__"):
            return [item async for item in iterator]
        return list(iterator)

    @classmethod
    def _bind_resolved_sender(cls, record: MessageRecord, sender_entity: Any) -> MessageRecord | None:
        """Bind server-filtered rows to the already resolved sender identity.

        ``iter_messages(None, from_user=...)`` is the authoritative sender
        constraint. A secondary ``message.get_sender()`` is optional metadata
        and may fail under entity-cache/RPC/FloodWait conditions. We therefore
        use the resolved entity as the stable output identity instead of turning
        that optional metadata failure into a false empty result or failed read.
        A contradictory stable sender ID is rejected defensively.
        """

        expected_id = str(getattr(sender_entity, "id", ""))
        if not expected_id:
            raise BridgeError("Resolved sender has no stable identifier", status=502, code="telegram_sender_identity_invalid")
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
        # Text-backed global search is already legal Telethon SearchGlobal and
        # chat-scoped search is legal regardless of text. Only sender-only
        # global search needs the from_user path below.
        if chat is not None or not sender or text.strip():
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
            sender_raw = sender.strip()
            sender_cf = normalize_search_text(sender_raw.lstrip("@"))
            signature = self._cursor_signature(
                "search",
                "",
                sender_cf,
                "",
                canonical_timestamp(dates.start) or "",
                canonical_timestamp(dates.end) or "",
                str(scan_limit),
            )
            boundary = self._message_boundary(cursor, "search", signature)
            async with self._client_session() as client:
                sender_entity = await self._resolve_global_sender(client, sender_raw)
                messages = await self._iter_global_sender_messages(
                    client,
                    sender_entity,
                    min(scan_limit, self.config.search_scan_limit),
                )
                records: list[MessageRecord] = []
                for message in messages:
                    raw_record = await self._message_record(message, "global", require_sender_details=False)
                    record = self._bind_resolved_sender(raw_record, sender_entity)
                    if record is not None:
                        records.append(record)

                filtered: list[MessageRecord] = []
                for record in records:
                    stamp = datetime.fromisoformat(record.timestamp.replace("Z", "+00:00"))
                    if not dates.contains(stamp):
                        continue
                    filtered.append(record)
                filtered = stable_message_sort(filtered, reverse=True)
                if boundary is not None:
                    filtered = [record for record in filtered if message_sort_key(record) < boundary]
                page = filtered[:limit]
                has_more = len(filtered) > limit
                return Page(
                    tuple(page),
                    self._message_next_cursor("search", signature, page, has_more=has_more),
                    len(messages),
                )

        return self._run(work())


def build_production_application_from_env() -> Any:
    """Build the canonical runtime with this narrow backend selected.

    The existing runtime owns all secret/session/rate-limit/write construction.
    We replace only its backend class before dependency construction; no private
    value is read or copied here.
    """

    from . import runtime as runtime_module

    runtime_module.TelethonReadBackend = GlobalSenderTelethonReadBackend
    return runtime_module.build_production_application_from_env()


__all__ = ["GlobalSenderTelethonReadBackend", "build_production_application_from_env"]
