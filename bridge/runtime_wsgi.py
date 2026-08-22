"""Lazy WSGI wrapper that builds private production dependencies on first request.

The module itself imports no Telethon package and performs no network activity.
Any bootstrap failure is reduced to a stable non-secret response.
"""
from __future__ import annotations

from typing import Any, Callable, Iterable


_default_application: Any | None = None


def application(environ: dict[str, Any], start_response: Callable) -> Iterable[bytes]:
    global _default_application
    if _default_application is None:
        try:
            from .runtime import build_production_application_from_env

            _default_application = build_production_application_from_env()
        except Exception:
            raw = b'{"ok":false,"error":{"code":"startup_configuration_error","message":"Application configuration is invalid"}}'
            start_response(
                "500 Internal Server Error",
                [
                    ("Content-Type", "application/json; charset=utf-8"),
                    ("Content-Length", str(len(raw))),
                    ("Cache-Control", "no-store"),
                ],
            )
            return [raw]
    return _default_application(environ, start_response)


def reset_runtime_application_for_tests() -> None:
    """Test-only reset; performs no cleanup and must never be an API route."""
    global _default_application
    _default_application = None


__all__ = ["application"]
