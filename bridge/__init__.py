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

from typing import Any

from .app import BridgeApplication, ReadAppConfig
from .backend import ReadBackend, TelethonReadBackend, UnavailableReadBackend
from .errors import BridgeError
from .integrated_app import UnifiedBridgeApplication
from .runtime_wsgi import application
from . import app as _app_module


async def _failclosed_iter_messages(
    self: TelethonReadBackend,
    client: Any,
    entity: Any,
    limit: int,
    *,
    search: str = "",
    offset_id: int | None = None,
) -> list[Any]:
    """Issue exactly one constrained iter_messages call and never broaden it.

    A ``TypeError`` can originate inside a real Telethon call. Retrying after
    removing ``search`` or ``offset_id`` would silently widen a query or restart
    continuation pagination. Required constraints therefore fail closed before
    the client call when the callable signature cannot support them, and an
    internal ``TypeError`` is allowed to propagate to the normal Bridge error
    boundary without a second, weaker Telegram request.
    """

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


# Canonical current-base repair for the W10 fail-open search finding. Patching
# the class object here affects ``bridge.backend.TelethonReadBackend`` itself,
# including direct imports and the Passenger runtime composition, while keeping
# module import network-free and credential-free.
TelethonReadBackend._iter_messages = _failclosed_iter_messages

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
