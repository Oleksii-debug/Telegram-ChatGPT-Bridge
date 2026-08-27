"""Isolated FINAL5 Task3 candidate for truthful Telegram global search continuation.

Based on canonical PR #9 exact SHA f3e83a35c99d634ff775ee0b5a2a2cc368e1f1a1.
No production wiring or Telegram write behavior is changed by this module.
"""
from __future__ import annotations

import unicodedata
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from .backend import TelethonReadBackend
from .errors import BridgeError
from .models import Page, canonical_timestamp, decode_cursor, encode_cursor
from .validation import DateRange, normalize_search_text


@dataclass(frozen=True)
class GlobalContinuation:
    offset_id: int
    peer_kind: str
    peer_id: int
    offset_rate: int


class GlobalSearchR8Backend(TelethonReadBackend):
    """Use Telegram's real SearchGlobal continuation tuple without leaking access hashes."""

    @staticmethod
    def _peer_parts(message: Any) -> tuple[str, int]:
        peer = getattr(message, "peer_id", None)
        for kind, attr in (("user", "user_id"), ("chat", "chat_id"), ("channel", "channel_id")):
            value = getattr(peer, attr, None)
            if isinstance(value, int) and value > 0:
                return kind, value
        raise BridgeError("Telegram global result lacks a stable peer", status=502, code="telegram_global_peer_missing")

    @classmethod
    def _decode_global_cursor(cls, token: str | None, signature: str) -> GlobalContinuation | None:
        obj = decode_cursor(token)
        if obj is None:
            return None
        if set(obj) != {"v", "scope", "sig", "tg"} or obj.get("v") != 3 or obj.get("scope") != "search-global" or obj.get("sig") != signature:
            raise cls._invalid_cursor()
        tg = obj.get("tg")
        if not isinstance(tg, dict) or set(tg) != {"offset_id", "peer_kind", "peer_id", "offset_rate"}:
            raise cls._invalid_cursor()
        oi, pk, pi, rate = tg["offset_id"], tg["peer_kind"], tg["peer_id"], tg["offset_rate"]
        if isinstance(oi, bool) or not isinstance(oi, int) or oi <= 0:
            raise cls._invalid_cursor()
        if pk not in {"user", "chat", "channel"}:
            raise cls._invalid_cursor()
        if isinstance(pi, bool) or not isinstance(pi, int) or pi <= 0:
            raise cls._invalid_cursor()
        if isinstance(rate, bool) or not isinstance(rate, int) or rate < 0:
            raise cls._invalid_cursor()
        return GlobalContinuation(oi, pk, pi, rate)

    @staticmethod
    def _encode_global_cursor(signature: str, state: GlobalContinuation) -> str:
        return encode_cursor({"v": 3, "scope": "search-global", "sig": signature, "tg": {
            "offset_id": state.offset_id, "peer_kind": state.peer_kind,
            "peer_id": state.peer_id, "offset_rate": state.offset_rate,
        }})

    @staticmethod
    async def _input_peer(client: Any, types: Any, state: GlobalContinuation | None) -> Any:
        if state is None:
            return types.InputPeerEmpty()
        ctor = {"user": types.PeerUser, "chat": types.PeerChat, "channel": types.PeerChannel}[state.peer_kind]
        resolver = getattr(client, "get_input_entity", None)
        if not callable(resolver):
            raise BridgeError("Telegram client cannot restore global continuation peer", status=503, code="telegram_global_peer_restore_unsupported")
        value = resolver(ctor(state.peer_id))
        return await TelethonReadBackend._maybe_await(value)

    async def _search_global_chunk(self, client: Any, *, query: str, limit: int, state: GlobalContinuation | None, max_date: Any) -> tuple[list[Any], GlobalContinuation | None]:
        try:
            from telethon import functions, types
        except Exception as exc:
            raise BridgeError("Telethon global search support is unavailable", status=503, code="telegram_global_search_unsupported") from exc
        peer = await self._input_peer(client, types, state)
        request = functions.messages.SearchGlobalRequest(
            q=query,
            filter=types.InputMessagesFilterEmpty(),
            min_date=None,
            max_date=max_date,
            offset_rate=0 if state is None else state.offset_rate,
            offset_peer=peer,
            offset_id=0 if state is None else state.offset_id,
            limit=limit,
        )
        result = await self._maybe_await(client(request))
        messages = list(getattr(result, "messages", ()) or ())
        if not messages:
            return [], None
        kind, peer_id = self._peer_parts(messages[-1])
        next_rate = int(getattr(result, "next_rate", 0) or 0)
        return messages, GlobalContinuation(int(getattr(messages[-1], "id", 0) or 0), kind, peer_id, max(0, next_rate))

    def search(self, *, chat: str | None, sender: str | None, text: str, dates: DateRange, limit: int, cursor: str | None, scan_limit: int) -> Page:
        if chat:
            return super().search(chat=chat, sender=sender, text=text, dates=dates, limit=limit, cursor=cursor, scan_limit=scan_limit)

        async def work() -> Page:
            needle = normalize_search_text(text.strip())
            sender_cf = normalize_search_text((sender or "").strip().lstrip("@"))
            signature = self._cursor_signature("search-global-r8", sender_cf, needle, canonical_timestamp(dates.start) or "", canonical_timestamp(dates.end) or "", str(scan_limit))
            state = self._decode_global_cursor(cursor, signature)
            server_query = unicodedata.normalize("NFKC", text.strip()) if text.strip() else ""
            max_date = dates.end + timedelta(seconds=1) if dates.end is not None else None
            scanned = 0
            output = []
            exhausted = False
            async with self._client_session() as client:
                while len(output) < limit and scanned < min(scan_limit, self.config.search_scan_limit):
                    remaining = min(limit - len(output), min(scan_limit, self.config.search_scan_limit) - scanned, 100)
                    raw, next_state = await self._search_global_chunk(client, query=server_query, limit=remaining, state=state, max_date=max_date)
                    scanned += len(raw)
                    if not raw:
                        exhausted = True
                        state = None
                        break
                    for msg in raw:
                        record = await self._message_record(msg, str(getattr(msg, "chat_id", None) or "global"), require_sender_details=bool(sender_cf and not sender_cf.lstrip("-").isdigit()))
                        stamp = __import__("datetime").datetime.fromisoformat(record.timestamp.replace("Z", "+00:00"))
                        if not dates.contains(stamp):
                            continue
                        if needle and needle not in normalize_search_text(record.text):
                            continue
                        if sender_cf:
                            s = record.sender
                            hay = "" if s is None else normalize_search_text(f"{s.id} {s.username or ''} {s.display_name or ''}")
                            if sender_cf not in hay:
                                continue
                        output.append(record)
                    state = next_state
                    if len(raw) < remaining or state is None:
                        exhausted = True
                        break
            next_cursor = None if exhausted or not output or state is None else self._encode_global_cursor(signature, state)
            return Page(tuple(output), next_cursor, scanned)

        return self._run(work())


__all__ = ["GlobalContinuation", "GlobalSearchR8Backend"]
