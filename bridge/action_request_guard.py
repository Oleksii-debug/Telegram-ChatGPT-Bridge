"""Strict ChatGPT Action write-request validation at the production WSGI boundary.

The canonical request schema lives in :mod:`ops.openapi_registry`. This guard
uses that exact schema before consequential write preview/commit normalization so
runtime code cannot silently coerce JSON types that the generated OpenAPI rejects.

Request framing/parser hardening and authenticated pre-parse B8 throttling are
owned by their dedicated specialist lanes; this module deliberately does not
duplicate those controls. No request values are logged or persisted here.
"""
from __future__ import annotations

import io
import json
import re
from collections.abc import Mapping
from typing import Any, Callable, Iterable

from .errors import BridgeError
from ops.openapi_registry import (
    OpenAPIContractError,
    OperationClass,
    OperationSpec,
    _request_schema,
    canonical_operation,
)


def _is_integer(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _type_matches(expected: str, value: Any) -> bool:
    if expected == "object":
        return isinstance(value, Mapping)
    if expected == "array":
        return isinstance(value, list)
    if expected == "string":
        return isinstance(value, str)
    if expected == "integer":
        return _is_integer(value)
    if expected == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if expected == "boolean":
        return isinstance(value, bool)
    if expected == "null":
        return value is None
    return False


def _validate_instance(instance: Any, schema: Mapping[str, Any], *, path: str = "$") -> list[str]:
    """Validate the bounded JSON-Schema subset emitted for Action requests.

    Error strings contain schema paths/categories only, never request values.
    Unknown/malformed schema constructs fail closed.
    """

    if not isinstance(schema, Mapping):
        return [f"SCHEMA_NOT_MAPPING:{path}"]
    errors: list[str] = []

    expected = schema.get("type")
    if not isinstance(expected, str) or not _type_matches(expected, instance):
        return [f"TYPE_MISMATCH:{path}:{expected}"]

    if "const" in schema:
        constant = schema["const"]
        if type(instance) is not type(constant) or instance != constant:
            errors.append(f"CONST_MISMATCH:{path}")

    enum = schema.get("enum")
    if enum is not None:
        if not isinstance(enum, list) or not any(type(instance) is type(item) and instance == item for item in enum):
            errors.append(f"ENUM_MISMATCH:{path}")

    if expected == "object":
        properties = schema.get("properties")
        if not isinstance(properties, Mapping):
            return errors + [f"OBJECT_PROPERTIES_INVALID:{path}"]
        required = schema.get("required", [])
        if not isinstance(required, list) or any(not isinstance(key, str) for key in required):
            return errors + [f"OBJECT_REQUIRED_INVALID:{path}"]
        for key in required:
            if key not in instance:
                errors.append(f"REQUIRED_MISSING:{path}.{key}")
        unknown = set(instance) - set(properties)
        if schema.get("additionalProperties") is False and unknown:
            errors.append(f"ADDITIONAL_PROPERTY:{path}:{len(unknown)}")
        for key, value in instance.items():
            child = properties.get(key)
            if isinstance(child, Mapping):
                errors.extend(_validate_instance(value, child, path=f"{path}.{key}"))
        return errors

    if expected == "array":
        minimum = schema.get("minItems")
        maximum = schema.get("maxItems")
        if _is_integer(minimum) and len(instance) < minimum:
            errors.append(f"ARRAY_TOO_SHORT:{path}")
        if _is_integer(maximum) and len(instance) > maximum:
            errors.append(f"ARRAY_TOO_LONG:{path}")
        if schema.get("uniqueItems") is True:
            seen: set[str] = set()
            for item in instance:
                marker = json.dumps(item, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
                if marker in seen:
                    errors.append(f"ARRAY_NOT_UNIQUE:{path}")
                    break
                seen.add(marker)
        child = schema.get("items")
        if not isinstance(child, Mapping):
            return errors + [f"ARRAY_ITEMS_SCHEMA_INVALID:{path}"]
        for index, item in enumerate(instance):
            errors.extend(_validate_instance(item, child, path=f"{path}[{index}]"))
        return errors

    if expected == "string":
        minimum = schema.get("minLength")
        maximum = schema.get("maxLength")
        if _is_integer(minimum) and len(instance) < minimum:
            errors.append(f"STRING_TOO_SHORT:{path}")
        if _is_integer(maximum) and len(instance) > maximum:
            errors.append(f"STRING_TOO_LONG:{path}")
        pattern = schema.get("pattern")
        if pattern is not None:
            if not isinstance(pattern, str):
                errors.append(f"PATTERN_SCHEMA_INVALID:{path}")
            else:
                try:
                    if re.fullmatch(pattern, instance) is None:
                        errors.append(f"PATTERN_MISMATCH:{path}")
                except re.error:
                    errors.append(f"PATTERN_SCHEMA_INVALID:{path}")
        return errors

    if expected in {"integer", "number"}:
        minimum = schema.get("minimum")
        maximum = schema.get("maximum")
        if isinstance(minimum, (int, float)) and not isinstance(minimum, bool) and instance < minimum:
            errors.append(f"NUMBER_TOO_SMALL:{path}")
        if isinstance(maximum, (int, float)) and not isinstance(maximum, bool) and instance > maximum:
            errors.append(f"NUMBER_TOO_LARGE:{path}")
        return errors

    if expected in {"boolean", "null"}:
        return errors

    return errors + [f"UNSUPPORTED_SCHEMA_TYPE:{path}:{expected}"]


def validate_action_request(spec: OperationSpec, body: Mapping[str, Any]) -> tuple[str, ...]:
    """Return stable, value-free request-contract errors for one canonical op."""

    try:
        schema = _request_schema(spec)
    except OpenAPIContractError as exc:
        return (str(exc),)
    return tuple(sorted(set(_validate_instance(body, schema))))


class ActionRequestGuard:
    """WSGI wrapper enforcing generated-OpenAPI types for all write Actions."""

    def __init__(self, application: Any):
        self.application = application

    @staticmethod
    def _canonicalize_body(environ: dict[str, Any], body: Mapping[str, Any]) -> dict[str, Any]:
        raw = json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        normalized = dict(environ)
        normalized["CONTENT_LENGTH"] = str(len(raw))
        normalized["wsgi.input"] = io.BytesIO(raw)
        return normalized

    def __call__(self, environ: dict[str, Any], start_response: Callable) -> Iterable[bytes]:
        method = str(environ.get("REQUEST_METHOD") or "GET").upper()
        path = str(environ.get("PATH_INFO") or "/")
        try:
            spec = canonical_operation(path, method)
        except OpenAPIContractError:
            return self.application(environ, start_response)

        if spec.operation_class not in {OperationClass.WRITE_PREVIEW, OperationClass.WRITE_COMMIT}:
            return self.application(environ, start_response)

        # Preserve the canonical hidden-404 authentication boundary and never
        # read the body before an authenticated write request is established.
        auth = getattr(getattr(self.application, "read_app", None), "auth", None)
        if auth is None:
            return self.application(environ, start_response)
        try:
            auth.require(environ)
        except Exception:
            return self.application(environ, start_response)

        read_app = self.application.read_app
        request_id = read_app._request_id()
        try:
            body = read_app._read_json(environ)
            errors = validate_action_request(spec, body)
            if errors:
                raise BridgeError(
                    "Request does not match the OpenAPI contract",
                    status=400,
                    code="invalid_request_contract",
                    details={"count": len(errors)},
                )
        except Exception as exc:
            return self.application._write_error(start_response, exc, request_id)

        return self.application(self._canonicalize_body(environ, body), start_response)


__all__ = ["ActionRequestGuard", "validate_action_request"]
