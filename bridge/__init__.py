"""Telegram Bridge application package.

The tested DEV3 read/media core remains available as :class:`BridgeApplication`.
The package-level and ``bridge.app.application`` WSGI entry point is replaced at
package import completion with the lazy unified integration entry point.  This
preserves the recovered HOSTiQ startup contract ``from bridge.app import
application`` while allowing the audited candidate to add DEV4 preview/commit
routing without changing Passenger bootstrap text.

Importing this package performs no Telegram network activity and constructs no
Telegram client. Production adapters remain dependency-injected/server-side.
"""

from .app import BridgeApplication, ReadAppConfig
from .backend import ReadBackend, TelethonReadBackend, UnavailableReadBackend
from .errors import BridgeError
from .integrated_app import UnifiedBridgeApplication, application
from . import app as _app_module

# Preserve the authoritative recovered Passenger import target while switching
# the exported callable to the unified, lazy, fail-closed integration layer.
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
