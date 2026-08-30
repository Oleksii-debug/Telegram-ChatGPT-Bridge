"""Lazy WSGI wrapper for private production dependency construction.

Module import itself is network-free and does not import Telethon. The first
request constructs the hardened production application from server-side private
references, then wraps it with request-attempt rate limiting before strict Action
request parsing. Any construction failure is reduced to a stable non-secret response.
"""
from __future__ import annotations

from typing import Any, Callable, Iterable


_default_application: Any | None = None


def _observe_passenger_serving_request(environ: dict[str, Any]) -> None:
    """Fail-isolated STRONG Passenger evidence observation for real health serving.

    The challenged request still uses the existing Passenger evidence protocol,
    but finalization is now gated by the descriptor-bound actual deployed release
    identity before runtime collection or any report/binding/receipt write.
    Ordinary evidence failures can never break the public health response;
    process-control BaseException subclasses still propagate.
    """

    if str(environ.get("REQUEST_METHOD") or "GET").upper() != "GET":
        return
    if str(environ.get("PATH_INFO") or "/") != "/health":
        return
    try:
        from pathlib import Path

        from ops.passenger_bound_evidence import collect_bound_if_armed_from_bridge_app

        collect_bound_if_armed_from_bridge_app(
            Path(__file__).with_name("app.py"),
            environ=environ,
        )
    except Exception:
        return


def application(environ: dict[str, Any], start_response: Callable) -> Iterable[bytes]:
    global _default_application
    if _default_application is None:
        try:
            from .dialog_pagination import install_dialog_pagination
            from .preparse_rate_guard import PreparseRateLimitedActionGuard
            from .runtime_composition import build_production_application_from_env
            from .typed_dialog_identity import install_typed_dialog_identity

            install_dialog_pagination()
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

    result = _default_application(environ, start_response)
    _observe_passenger_serving_request(environ)
    return result


def reset_runtime_application_for_tests() -> None:
    global _default_application
    _default_application = None


__all__ = ["application"]
