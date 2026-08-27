"""Telegram Bridge application package.

The tested DEV3 read/media core remains available as :class:`BridgeApplication`.
The package-level and ``bridge.app.application`` WSGI entry point is replaced at
package import completion with a lazy production-runtime wrapper. This preserves
the recovered HOSTiQ startup contract ``from bridge.app import application`` and
the unified DEV4 preview/commit surface while allowing server-side dependency
construction on the first request.

Importing this package performs no Telegram network activity and constructs no
Telegram client. Private Telegram references remain server-side and are consumed
only by the lazy runtime builder after request dispatch begins.
"""

import inspect
import unicodedata
from datetime import datetime
from typing import Any

from .app import BridgeApplication, ReadAppConfig
from .backend import ReadBackend, TelethonReadBackend, UnavailableReadBackend
from .errors import BridgeError
from .integrated_app import UnifiedBridgeApplication
from .models import MessageRecord, Page, canonical_timestamp, message_sort_key, stable_message_sort
from .runtime_wsgi import application
from .validation import DateRange, normalize_search_text
from . import app as _app_module


_ORIGINAL_SEARCH = TelethonReadBackend.search


def _accepts_keyword(callable_obj: Any, parameter: str) -> bool:
    """Return whether one keyword can be passed without a signature TypeError.

    The canonical backend intentionally treats explicit ``offset_id`` support as
    stronger than generic ``**kwargs`` because continuation semantics must be
    known. For the optional server-side text-search hint, deterministic legacy
    fakes with ``**kwargs`` can safely receive the hint while local normalized
    filtering remains authoritative.
    """

    try:
        parameters = inspect.signature(callable_obj).parameters
    except (TypeError, ValueError):
        return False
    return parameter in parameters or any(
        value.kind is inspect.Parameter.VAR_KEYWORD for value in parameters.values()
    )


async def _failclosed_iter_messages(
    self: TelethonReadBackend,
    client: Any,
    entity: Any,
    limit: int,
    *,
    search: str = "",
    offset_id: int | None = None,
) -> list[Any]:
    """Issue at most one ``iter_messages`` call; never retry with weaker kwargs.

    ``TypeError`` may be raised *inside* a real Telethon call. The former code
    caught every such error and retried with only ``limit``, silently dropping
    ``search`` and/or ``offset_id``. This implementation preserves the existing
    bounded compatibility path for simple deterministic clients, but once a
    constrained call is issued it is never repeated with reduced constraints.
    """

    method = client.iter_messages
    kwargs: dict[str, Any] = {"limit": limit}

    # Text search is a server-side narrowing hint; canonical search still applies
    # normalized local filtering. Explicit search support or **kwargs receives
    # the hint. Very small deterministic clients without either stay on the
    # pre-existing bounded local-filter compatibility path.
    if search and _accepts_keyword(method, "search"):
        kwargs["search"] = search

    # Continuation has stronger semantics: only an explicitly declared offset is
    # trusted, matching the canonical backend's pre-existing compatibility rule.
    if offset_id is not None and self._supports_named_parameter(method, "offset_id"):
        kwargs["offset_id"] = offset_id

    # Critical invariant: exactly one client call. In particular, TypeError from
    # inside Telethon propagates to the normal redacted Bridge error boundary and
    # can never trigger a second broader request.
    iterator = method(entity, **kwargs)
    if hasattr(iterator, "__aiter__"):
        return [item async for item in iterator]
    return list(iterator)


def _deep_scoped_search(
    self: TelethonReadBackend,
    *,
    chat: str | None,
    sender: str | None,
    text: str,
    dates: DateRange,
    limit: int,
    cursor: str | None,
    scan_limit: int,
) -> Page:
    """Paginate chat-scoped search with Telethon's exclusive server offset.

    Global search retains the canonical native implementation.  For one chat,
    a real Telethon client explicitly declares ``offset_id``; using the last
    scanned message as the cursor lets sparse sender/date filters progress past
    a full raw chunk instead of rescanning the newest bounded prefix forever.
    Minimal deterministic clients without explicit offset semantics retain the
    existing bounded local-cursor compatibility path.
    """

    if chat is None:
        return _ORIGINAL_SEARCH(
            self,
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
            records: list[MessageRecord] = stable_message_sort(
                [
                    await self._message_record(
                        message,
                        chat_id,
                        require_sender_details=require_sender_details,
                    )
                    for message in messages
                ],
                reverse=True,
            )

            filtered: list[MessageRecord] = []
            for record in records:
                stamp = datetime.fromisoformat(record.timestamp.replace("Z", "+00:00"))
                if not dates.contains(stamp):
                    continue
                if needle and needle not in normalize_search_text(record.text):
                    continue
                if sender_cf:
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

            # Keep the signed composite cursor authoritative even when a test
            # double or future client returns rows outside the requested offset.
            if boundary is not None:
                filtered = [record for record in filtered if message_sort_key(record) < boundary]

            page = filtered[:limit]
            if len(filtered) > limit:
                next_cursor = self._message_next_cursor(
                    "search",
                    signature,
                    page,
                    has_more=True,
                )
            elif supports_offset and len(messages) >= budget and records:
                # A full raw chunk is not proof of exhaustion.  Advance by the
                # oldest raw row even when every row was removed by local
                # sender/date filters, so an empty page can still make progress.
                raw_boundary = message_sort_key(records[-1])
                if boundary is not None and raw_boundary >= boundary:
                    raise BridgeError(
                        "Telegram search continuation did not advance",
                        status=502,
                        code="telegram_search_continuation_not_advanced",
                        details={"retryable": True},
                    )
                next_cursor = self._message_next_cursor(
                    "search",
                    signature,
                    [records[-1]],
                    has_more=True,
                )
            else:
                next_cursor = None

            return Page(tuple(page), next_cursor, len(messages))

    return self._run(work())


# Canonical current-base repair for the W10 fail-open search finding. Patching
# the class object here affects ``bridge.backend.TelethonReadBackend`` itself,
# including direct imports and the Passenger runtime composition, while keeping
# module import network-free and credential-free.
TelethonReadBackend._iter_messages = _failclosed_iter_messages
TelethonReadBackend.search = _deep_scoped_search

# Preserve the authoritative recovered Passenger import target while switching
# the exported callable to the unified, lazy, server-side runtime builder.
_app_module.application = application

__all__ = [
    "BridgeApplication",
    "BridgeError",
    "ReadAppConfig",
    "ReadBackend",
    "TelethonReadBackend",
    "UnavailableReadBackend",
    "UnifiedBridgeApplication",
    "application",
]
