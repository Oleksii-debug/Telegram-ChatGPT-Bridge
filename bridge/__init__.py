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
from typing import Any

from .app import BridgeApplication, ReadAppConfig
from .backend import ReadBackend, TelethonReadBackend, UnavailableReadBackend
from .errors import BridgeError
from .integrated_app import UnifiedBridgeApplication
from .runtime_wsgi import application
from . import app as _app_module


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
