"""FINAL5 Task3 guard for truthful real-Telegram global search semantics.

Telegram messages.searchGlobal rejects an empty q with SEARCH_QUERY_EMPTY.  The
stacked R8/R9 candidate previously allowed sender-only/date-only fake tests to
reach SearchGlobalRequest(q=""), which cannot work against Telegram.  Until a
separate bounded cross-dialog implementation exists, fail closed before any RPC
instead of presenting synthetic success as real capability.
"""
from __future__ import annotations

from .errors import BridgeError
from .final5_global_search_r8 import GlobalSearchR8Backend
from .models import Page
from .validation import DateRange


class GlobalSearchR10Backend(GlobalSearchR8Backend):
    """Preserve R8/R9 continuation semantics and reject invalid empty global RPCs."""

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
        if chat is None and not text.strip():
            raise BridgeError(
                "Telegram global search requires non-empty text; sender-only/date-only global search needs a separate bounded cross-dialog implementation",
                status=400,
                code="telegram_global_empty_query_unsupported",
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


__all__ = ["GlobalSearchR10Backend"]
