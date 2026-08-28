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

    The actual challenge validation and private evidence writes remain owned by
    ``ops.passenger_evidence_hook``.  This runtime boundary deliberately does not
    inspect, copy or log the raw challenge.  Ordinary evidence failures can never
    break the public health response; process-control BaseException subclasses
    still propagate.
    """

    if str(environ.get("REQUEST_METHOD") or "GET").upper() != "GET":
        return
    if str(environ.get("PATH_INFO") or "/") != "/health":
        return
    try:
        from pathlib import Path

        from ops.passenger_evidence_hook import collect_if_armed_from_bridge_app

        collect_if_armed_from_bridge_app(
            Path(__file__).with_name("app.py"),
            environ=environ,
        )
    except Exception:
        # Passenger evidence is observational and must never reduce application
        # availability.  The evidence adapter itself returns stable private
        # statuses; this outer boundary is a final fail-isolation layer.
        return


def application(environ: dict[str, Any], start_response: Callable) -> Iterable[bytes]:
    global _default_application
    if _default_application is None:
        try:
            from .preparse_rate_guard import PreparseRateLimitedActionGuard
            from .runtime_composition import build_production_application_from_env

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

    # The canonical health path calls ``start_response`` and returns its concrete
    # response list synchronously.  Observe the challenged serving request only
    # after that application dispatch succeeds; a construction/dispatch failure
    # must never be promoted into STRONG Passenger evidence.
    result = _default_application(environ, start_response)
    _observe_passenger_serving_request(environ)
    return result


def reset_runtime_application_for_tests() -> None:
    """Credential-free test helper; it is not mounted as an HTTP operation."""
    global _default_application
    _default_application = None


__all__ = ["application"]
