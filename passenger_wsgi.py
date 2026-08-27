# -*- coding: utf-8 -*-
"""HOSTiQ Passenger entry point for the canonical Telegram Bridge release.

Import remains network-free and secret-value-free.  The evidence hook is inert
unless HOSTiQ/support creates the separately owner-private one-shot marker.  It
never authorizes deployment, Telegram access, or a live write.
"""

from pathlib import Path

from bridge.app import application
from ops.passenger_evidence_hook import collect_if_armed

_here = Path(__file__).resolve()
collect_if_armed(app_root=_here.parent, wsgi_file=_here)

__all__ = ["application"]
