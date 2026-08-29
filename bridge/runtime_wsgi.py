"""Lazy WSGI wrapper for private production dependency construction.

Module import itself is network-free and does not import Telethon. The first
request constructs the hardened production application from server-side private
references, then wraps it with request-attempt rate limiting before strict Action
request parsing. Any construction failure is reduced to a stable non-secret response.
"""
from __future__ import annotations

from typing import Any, Callable, Iterable


_default_application: Any | None = None


def application(environ: dict[str, Any], start_response: Callable) -> Iterable[bytes]:
    global _default_application
    if _default_application is None:
        try:
            from .preparse_rate_guard import PreparseRateLimitedActionGuard
            from .runtime_composition import build_production_application_from_env
            from .typed_dialog_identity import install_typed_dialog_identity

            install_typed_dialog_identity()
            _default_application = PreparseRateLimitedActionGuard(build_production_application_from_env())
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
    """Credential-free test helper; it is not mounted as an HTTP operation."""
    global _default_application
    _default_application = None


__all__ = ["application"]
