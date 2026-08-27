"""FINAL5 Task3 isolated Telethon search safety candidate.

This specialist overlay is based on the exact canonical PR #9 head recorded in
its PR. It fixes two fail-open correctness seams without modifying canonical:

* constrained ``iter_messages`` calls are never retried after dropping
  ``search``/``offset_id`` when a client raises ``TypeError``;
* global cross-dialog continuation is rejected instead of pretending that the
  Bridge's local message boundary is a restart-safe Telegram SearchGlobal
  continuation token.

The second rule is intentionally conservative. Real global deep pagination
requires the Telegram continuation tuple (offset_id, offset_peer, offset_rate)
and is still a product gap; this candidate prevents silent gaps/duplicates
until that tuple is represented and audited.
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
