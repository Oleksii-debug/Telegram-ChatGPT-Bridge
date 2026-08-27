"""FINAL5 Task3 isolated fail-closed Telethon search candidate.

This specialist overlay fixes one current-canonical correctness seam without
modifying the canonical branch: constrained search must never retry a failed
Telethon call after silently dropping search/continuation arguments.
"""
from __future__ import annotations

from typing import Any

from .backend import TelethonReadBackend
from .errors import BridgeError


class FailClosedTelethonReadBackend(TelethonReadBackend):
    """Require supported server constraints and issue exactly one search call."""

    async def _iter_messages(
        self,
        client: Any,
        entity: Any,
        limit: int,
        *,
        search: str = "",
        offset_id: int | None = None,
    ) -> list[Any]:
        method = client.iter_messages
        kwargs: dict[str, Any] = {"limit": limit}

        if search:
            if not self._supports_named_parameter(method, "search"):
                raise BridgeError(
                    "Telegram client does not support server search",
                    status=503,
                    code="telegram_search_unsupported",
                    details={"retryable": False},
                )
            kwargs["search"] = search

        if offset_id is not None:
            if not self._supports_named_parameter(method, "offset_id"):
                raise BridgeError(
                    "Telegram client does not support search continuation",
                    status=503,
                    code="telegram_search_continuation_unsupported",
                    details={"retryable": False},
                )
            kwargs["offset_id"] = offset_id

        # Deliberately no TypeError retry with reduced kwargs. A TypeError can
        # originate inside a real client call; retrying without constraints can
        # widen the query and make bounded results semantically false.
        iterator = method(entity, **kwargs)
        if hasattr(iterator, "__aiter__"):
            return [item async for item in iterator]
        return list(iterator)


def build_production_application_from_env() -> Any:
    """Select this isolated backend through the canonical runtime factory."""
    from . import runtime_composition

    original = runtime_composition.TelethonReadBackend
    runtime_composition.TelethonReadBackend = FailClosedTelethonReadBackend
    try:
        return runtime_composition.build_production_application_from_env()
    finally:
        runtime_composition.TelethonReadBackend = original


__all__ = ["FailClosedTelethonReadBackend", "build_production_application_from_env"]
