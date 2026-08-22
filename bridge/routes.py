"""Canonical read-side route registry for Telegram Bridge.

The registry is intentionally independent from OpenAPI generation. DEV4/DEV5
can consume it as the application truth when validating a generated schema.
Unknown routes are never inferred from self-declared x-* metadata.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

AccessClass = Literal["public", "protected", "protected_or_signed"]
OperationClass = Literal["health", "read"]


@dataclass(frozen=True)
class RouteSpec:
    operation_id: str
    method: str
    relative_path: str
    access: AccessClass
    operation_class: OperationClass
    dynamic_tail: bool = False

    def concrete_path(self, api_prefix: str) -> str:
        if self.relative_path == "/health":
            return "/health"
        return api_prefix.rstrip("/") + self.relative_path

    def matches(self, method: str, path: str, api_prefix: str) -> bool:
        if method.upper() != self.method:
            return False
        base = self.concrete_path(api_prefix)
        if self.dynamic_tail:
            return path.startswith(base) and len(path) > len(base)
        return path == base


READ_ROUTE_REGISTRY: tuple[RouteSpec, ...] = (
    RouteSpec("health.get", "GET", "/health", "public", "health"),
    RouteSpec("dialogs.list", "POST", "/dialogs/list", "protected", "read"),
    RouteSpec("history.read", "POST", "/history/read", "protected", "read"),
    RouteSpec("search.read", "POST", "/search", "protected", "read"),
    RouteSpec("media.metadata", "POST", "/media/metadata", "protected", "read"),
    RouteSpec("downloads.single", "POST", "/downloads/single", "protected", "read"),
    RouteSpec("downloads.bulk", "POST", "/downloads/bulk", "protected", "read"),
    RouteSpec("downloads.resume", "POST", "/downloads/resume", "protected", "read"),
    RouteSpec("archives.create", "POST", "/archives/create", "protected", "read"),
    RouteSpec("files.metadata", "POST", "/files/get", "protected", "read"),
    RouteSpec("files.content", "GET", "/files/", "protected_or_signed", "read", dynamic_tail=True),
)


def validate_registry(registry: tuple[RouteSpec, ...] = READ_ROUTE_REGISTRY) -> None:
    ids: set[str] = set()
    keys: set[tuple[str, str, bool]] = set()
    for spec in registry:
        if not spec.operation_id or spec.operation_id in ids:
            raise ValueError("duplicate or empty operation id")
        if spec.method not in {"GET", "POST"}:
            raise ValueError("unsupported route method")
        if spec.access not in {"public", "protected", "protected_or_signed"}:
            raise ValueError("unsupported route access class")
        if spec.operation_class not in {"health", "read"}:
            raise ValueError("unsupported operation class")
        if not spec.relative_path.startswith("/") or ".." in spec.relative_path.split("/"):
            raise ValueError("unsafe route path")
        key = (spec.method, spec.relative_path, spec.dynamic_tail)
        if key in keys:
            raise ValueError("duplicate route definition")
        ids.add(spec.operation_id)
        keys.add(key)

    public = [spec for spec in registry if spec.access == "public"]
    if [(spec.method, spec.relative_path) for spec in public] != [("GET", "/health")]:
        raise ValueError("only GET /health may be public in the read registry")


validate_registry()


def resolve_route(method: str, path: str, api_prefix: str) -> RouteSpec | None:
    if not isinstance(method, str) or not isinstance(path, str) or not isinstance(api_prefix, str):
        return None
    for spec in READ_ROUTE_REGISTRY:
        if spec.matches(method.upper(), path, api_prefix):
            return spec
    return None


def known_path(path: str, api_prefix: str) -> bool:
    """Return whether a path is registered, independent of request method."""
    for spec in READ_ROUTE_REGISTRY:
        base = spec.concrete_path(api_prefix)
        if spec.dynamic_tail:
            if path.startswith(base) and len(path) > len(base):
                return True
        elif path == base:
            return True
    return False


def registry_snapshot(api_prefix: str = "/api/v1") -> tuple[dict[str, object], ...]:
    """Return non-secret deterministic metadata for schema/integration tests."""
    return tuple(
        {
            "operation_id": spec.operation_id,
            "method": spec.method,
            "path": spec.concrete_path(api_prefix) + ("{file_ref}" if spec.dynamic_tail else ""),
            "access": spec.access,
            "operation_class": spec.operation_class,
        }
        for spec in READ_ROUTE_REGISTRY
    )
