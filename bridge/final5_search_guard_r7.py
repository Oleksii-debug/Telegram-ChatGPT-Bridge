"""FINAL5 Task3 current-base Telethon search safety candidate.

This isolated specialist overlay is based on canonical PR #9 exact head
f3e83a35c99d634ff775ee0b5a2a2cc368e1f1a1. It intentionally does not claim
functional global deep pagination. It closes two fail-open correctness seams:

* constrained ``iter_messages`` calls are never retried after silently dropping
  ``search`` or ``offset_id`` when a client raises ``TypeError``;
* a global cross-dialog second-page cursor is rejected before client/network
  access instead of treating the Bridge's local message boundary as Telegram's
  restart-safe SearchGlobal continuation state.

True global deep pagination remains a separate HIGH item because Telegram uses
an offset_id + offset_peer + offset_rate continuation tuple.
"""
from __future__ import annotations

from typing import Any

from .backend import TelethonReadBackend
from .errors import BridgeError


class GuardedTelethonReadBackend(TelethonReadBackend):
    """Fail closed when requested Telethon search semantics cannot be proved."""

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
                    "Telegram client does not support server search",
                    status=503,
                    code="telegram_search_unsupported",
                    details={"retryable": False},
                )
            kwargs["search"] = search

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

    def search(
        self,
        *,
        chat: str | None,
        sender: str | None,
        text: str,
        dates: Any,
        limit: int,
        cursor: str | None,
        scan_limit: int,
    ) -> Any:
        if chat is None and cursor:
            raise BridgeError(
                "Global Telegram search continuation is not yet restart-safe",
                status=503,
                code="telegram_global_search_continuation_unsupported",
                details={"retryable": False},
            )
        return super().search(
            chat=chat,
            sender=sender,
            text=text,
            dates=dates,
            limit=limit,
            cursor=cursor,
            scan_limit=scan_limit,
        )


__all__ = ["GuardedTelethonReadBackend"]
