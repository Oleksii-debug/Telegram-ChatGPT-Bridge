"""Telegram Bridge read-side application package.

This package deliberately performs no Telegram network activity at import time.
Production adapters are injected into :class:`bridge.app.BridgeApplication`.
"""

from .app import BridgeApplication, application
from .backend import ReadBackend, TelethonReadBackend, UnavailableReadBackend
from .errors import BridgeError

__all__ = [
    "BridgeApplication",
    "BridgeError",
    "ReadBackend",
    "TelethonReadBackend",
    "UnavailableReadBackend",
    "application",
]
