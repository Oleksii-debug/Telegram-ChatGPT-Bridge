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
import sqlite3
import time
from pathlib import Path
from typing import Any

from .app import BridgeApplication, ReadAppConfig
from .backend import ReadBackend, TelethonReadBackend, UnavailableReadBackend
from .errors import BridgeError
from .integrated_app import UnifiedBridgeApplication
from .runtime_wsgi import application
from .storage import _sqlite_lock_contention
from . import app as _app_module
from . import runtime as _runtime_module

_ORIGINAL_RATE_CONNECT = _runtime_module._SQLiteFixedWindowStore._connect
_RATE_BOOTSTRAP_RETRY_SECONDS = 0.025
_RATE_BOOTSTRAP_TIMEOUT_SECONDS = 5.0


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


def _race_safe_validate_rate_sidecars(self: Any) -> None:
    """Validate SQLite sidecars while tolerating their legitimate removal.

    WAL and SHM leaves are ephemeral.  Another Passenger worker may close the
    last SQLite connection between observing a sidecar pathname and validating
    its inode.  Absence at the validation point is therefore benign; every
    sidecar that is still present continues through the canonical owner, mode,
    type, symlink and hardlink checks.
    """

    for suffix in ("-wal", "-shm"):
        path = Path(str(self.database_path) + suffix)
        try:
            _runtime_module._validate_private_regular(path)
        except FileNotFoundError:
            continue


def _race_safe_rate_connect(self: Any) -> Any:
    """Retry only numeric SQLite lock contention during concurrent cold start.

    The canonical connection routine already fails closed for unsafe topology,
    ownership, permissions, corruption and every non-contention SQLite error.
    Multiple Passenger workers can nevertheless contend while the first one
    switches a new database into WAL mode.  Retry that exact BUSY/LOCKED class
    for a bounded interval; never classify by mutable exception text.
    """

    deadline = time.monotonic() + _RATE_BOOTSTRAP_TIMEOUT_SECONDS
    while True:
        try:
            return _ORIGINAL_RATE_CONNECT(self)
        except _runtime_module.RuntimeBootstrapError as exc:
            cause = exc.__cause__
            if (
                exc.code != "rate_limit_database_unavailable"
                or not isinstance(cause, sqlite3.OperationalError)
                or not _sqlite_lock_contention(cause)
                or time.monotonic() >= deadline
            ):
                raise
            time.sleep(_RATE_BOOTSTRAP_RETRY_SECONDS)


# Canonical current-base repair for the W10 fail-open search finding. Patching
# the class object here affects ``bridge.backend.TelethonReadBackend`` itself,
# including direct imports and the Passenger runtime composition, while keeping
# module import network-free and credential-free.
TelethonReadBackend._iter_messages = _failclosed_iter_messages

# SQLite WAL/SHM leaves can disappear when another process closes the last
# connection.  Remove the exists->lstat TOCTOU without weakening validation for
# a sidecar inode that is present at the actual validation point.
_runtime_module._SQLiteFixedWindowStore._validate_sidecars = _race_safe_validate_rate_sidecars
_runtime_module._SQLiteFixedWindowStore._connect = _race_safe_rate_connect

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
