"""HOSTiQ Passenger WSGI bootstrap for Telegram ChatGPT Bridge.

The recovered production contract imports ``bridge.app.application``. Importing
that target remains side-effect free: it constructs no Telegram client and
performs no network I/O. The ``bridge`` package binds that public import target
to the unified read/media/write WSGI application during package import.
"""

from bridge.app import application

__all__ = ["application"]
