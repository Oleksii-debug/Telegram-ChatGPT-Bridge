# -*- coding: utf-8 -*-
"""HOSTiQ Passenger entry point for the canonical Telegram Bridge release.

Importing this file must remain network-free and secret-value-free. Runtime
configuration is resolved by the bridge package/server-side private configuration;
Passenger only receives the stable recovered WSGI callable contract.
"""

from bridge.app import application

__all__ = ["application"]
