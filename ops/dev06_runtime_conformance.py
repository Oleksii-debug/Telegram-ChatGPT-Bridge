# -*- coding: utf-8 -*-
"""DEV06 Action compatibility and runtime-response conformance checks.

This module is intentionally source-only.  It consumes the authoritative DEV06
route/operation registry and generated document, corrects response-only schema
semantics that a ChatGPT Action client must observe, and validates captured WSGI
JSON responses without contacting Telegram or production.
"""
from __future__ import annotations

import copy
import re
from typing import Any, Mapping

from ops.dev06_api_contracts import (
    ApiContractError,
    ApiOperationClass,
    build_chatgpt_action_openapi as _build_registry_document,
    canonical_action,
    validate_chatgpt_action_schema,
)


class ResponseContractError(ApiContractError):
    """Fail-closed response/schema conformance error."""


def _operation(document: Mapping[str, Any], operation_id: str) -> Mapping[str, Any]:
    paths = document.get("paths")
    if not isinstance(paths, Mapping):
        raise ResponseContractError("PATHS_MISSING")
    found: list[Mapping[str, Any]] = []
    for item in paths.values():
        if not isinstance(item, Mapping):
            continue
        for operation in item.values():
            if isinstance(operation, Mapping) and operation.get("operationId") == operation_id:
                found.append(operation)
    if len(found) != 1:
        raise ResponseContractError("ACTION_OPERATION_NOT_UNIQUE")
    canonical_action(operation_id)
    return found[0]


def _response_schema(operation: Mapping[str, Any], status: str) -> Mapping[str, Any]:
    responses = operation.get("responses")
    if not isinstance(responses, Mapping):
        raise ResponseContractError("RESPONSES_MISSING")
    response = responses.get(status)
    if not isinstance(response, Mapping):
        raise ResponseContractError("RESPONSE_STATUS_UNDECLARED")
    content = response.get("content")
    if not isinstance(content, Mapping):
        raise ResponseContractError("RESPONSE_CONTENT_MISSING")
    json_content = content.get("application/json")
    if not isinstance(json_content, Mapping):
        raise ResponseContractError("JSON_RESPONSE_CONTENT_MISSING")
    schema = json_content.get("schema")
    if not isinstance(schema, Mapping):
        raise ResponseContractError("JSON_RESPONSE_SCHEMA_MISSING")
    return schema


def _success_data_schema(operation: Mapping[str, Any]) -> Mapping[str, Any]:
    schema = _response_schema(operation, "200")
    props = schema.get("properties")
    data = props.get("data") if isinstance(props, Mapping) else None
    if not isinstance(data, Mapping):
        raise ResponseContractError("SUCCESS_DATA_SCHEMA_MISSING")
    return data


def _remove_response_write_only(document: dict[str, Any]) -> None:
    """A preview token is returned *to* the Action client and cannot be writeOnly.

    The token is ephemeral/single-use, but OpenAPI ``writeOnly`` means a property
    is request-only and may be omitted by response consumers.  The runtime needs
    the client to receive the preview token so a later explicit commit can bind
    to the exact preview.  Sensitivity is enforced operationally by no-store and
    logging rules, not by lying about response directionality.
    """
    for operation_id in (
        "previewTelegramSend",
        "previewTelegramReply",
        "previewTelegramForward",
        "previewTelegramFiles",
    ):
        operation = _operation(document, operation_id)
        data = _success_data_schema(operation)
        props = data.get("properties")
        token = props.get("preview_token") if isinstance(props, Mapping) else None
        if not isinstance(token, dict):
            raise ResponseContractError("PREVIEW_TOKEN_RESPONSE_SCHEMA_MISSING")
        token.pop("writeOnly", None)
        token["description"] = (
            "Ephemeral single-use preview token returned by preview and supplied "
            "unchanged to the matching explicit commit. Do not log it."
        )


def validate_action_compatibility(document: Mapping[str, Any]) -> list[str]:
    errors = list(validate_chatgpt_action_schema(document))
    for operation_id in (
        "previewTelegramSend",
        "previewTelegramReply",
        "previewTelegramForward",
        "previewTelegramFiles",
    ):
        try:
            operation = _operation(document, operation_id)
            data = _success_data_schema(operation)
        except ResponseContractError as exc:
            errors.append(str(exc))
            continue
        props = data.get("properties")
        token = props.get("preview_token") if isinstance(props, Mapping) else None
        if not isinstance(token, Mapping):
            errors.append(f"PREVIEW_TOKEN_RESPONSE_SCHEMA_MISSING:{operation_id}")
            continue
        if token.get("writeOnly") is True:
            errors.append(f"PREVIEW_TOKEN_RESPONSE_MUST_NOT_BE_WRITE_ONLY:{operation_id}")
        if token.get("readOnly") is True:
            # The same opaque value is intentionally submitted to commit later;
            # readOnly here is also unnecessarily restrictive for Action clients.
            errors.append(f"PREVIEW_TOKEN_RESPONSE_MUST_NOT_BE_READ_ONLY:{operation_id}")

    # Consequential semantics remain registry-derived. Optional extension fields
    # are checked but are never treated as the security source of truth.
    for operation_id in (
        "commitTelegramSend",
        "commitTelegramReply",
        "commitTelegramForward",
        "commitTelegramFiles",
    ):
        try:
            operation = _operation(document, operation_id)
        except ResponseContractError as exc:
            errors.append(str(exc))
            continue
        route = canonical_action(operation_id)
        if route.operation_class is not ApiOperationClass.WRITE_COMMIT:
            errors.append(f"CANONICAL_COMMIT_CLASS_DRIFT:{operation_id}")
        if operation.get("x-openai-isConsequential") is not True:
            errors.append(f"COMMIT_CONSEQUENTIAL_MARKER_DRIFT:{operation_id}")
    return sorted(set(errors))


def build_compatible_chatgpt_action_openapi(base_url: str) -> dict[str, Any]:
    document = copy.deepcopy(_build_registry_document(base_url))
    _remove_response_write_only(document)
    errors = validate_action_compatibility(document)
    if errors:
        raise ResponseContractError(";".join(errors))
    return document


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
        return (isinstance(value, (int, float)) and not isinstance(value, bool))
    if expected == "boolean":
        return isinstance(value, bool)
    if expected == "null":
        return value is None
    return False


def validate_json_instance(instance: Any, schema: Mapping[str, Any], *, path: str = "$") -> list[str]:
    """Validate the bounded JSON-Schema subset generated by the DEV06 contract.

    This is intentionally not a general JSON Schema implementation. It supports
    only constructs emitted by this repository and fails closed on malformed
    schema structures that would weaken runtime-response checks.
    """
    errors: list[str] = []
    if not isinstance(schema, Mapping):
        return [f"SCHEMA_NOT_MAPPING:{path}"]

    any_of = schema.get("anyOf")
    if any_of is not None:
        if not isinstance(any_of, list) or not any_of:
            return [f"ANYOF_SCHEMA_INVALID:{path}"]
        if not any(not validate_json_instance(instance, branch, path=path) for branch in any_of if isinstance(branch, Mapping)):
            return [f"ANYOF_INSTANCE_MISMATCH:{path}"]
        return []

    if "const" in schema and instance != schema["const"]:
        errors.append(f"CONST_MISMATCH:{path}")
    enum = schema.get("enum")
    if enum is not None:
        if not isinstance(enum, list) or instance not in enum:
            errors.append(f"ENUM_MISMATCH:{path}")

    expected_type = schema.get("type")
    if not isinstance(expected_type, str) or not _type_matches(expected_type, instance):
        return errors + [f"TYPE_MISMATCH:{path}:{expected_type}"]

    if expected_type == "object":
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
            errors.append(f"ADDITIONAL_PROPERTY:{path}:{','.join(sorted(map(str, unknown)))}")
        for key, value in instance.items():
            child = properties.get(key)
            if isinstance(child, Mapping):
                errors.extend(validate_json_instance(value, child, path=f"{path}.{key}"))
        return errors

    if expected_type == "array":
        minimum = schema.get("minItems")
        maximum = schema.get("maxItems")
        if _is_integer(minimum) and len(instance) < minimum:
            errors.append(f"ARRAY_TOO_SHORT:{path}")
        if _is_integer(maximum) and len(instance) > maximum:
            errors.append(f"ARRAY_TOO_LONG:{path}")
        if schema.get("uniqueItems") is True:
            seen: set[str] = set()
            for value in instance:
                marker = repr(value)
                if marker in seen:
                    errors.append(f"ARRAY_NOT_UNIQUE:{path}")
                    break
                seen.add(marker)
        item_schema = schema.get("items")
        if not isinstance(item_schema, Mapping):
            return errors + [f"ARRAY_ITEMS_SCHEMA_INVALID:{path}"]
        for index, value in enumerate(instance):
            errors.extend(validate_json_instance(value, item_schema, path=f"{path}[{index}]"))
        return errors

    if expected_type == "string":
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
                    if re.search(pattern, instance) is None:
                        errors.append(f"PATTERN_MISMATCH:{path}")
                except re.error:
                    errors.append(f"PATTERN_SCHEMA_INVALID:{path}")
        return errors

    if expected_type in {"integer", "number"}:
        minimum = schema.get("minimum")
        maximum = schema.get("maximum")
        if isinstance(minimum, (int, float)) and instance < minimum:
            errors.append(f"NUMBER_BELOW_MINIMUM:{path}")
        if isinstance(maximum, (int, float)) and instance > maximum:
            errors.append(f"NUMBER_ABOVE_MAXIMUM:{path}")
    return errors


def validate_action_runtime_response(
    document: Mapping[str, Any],
    operation_id: str,
    status: int,
    headers: Mapping[str, Any],
    payload: Any,
) -> list[str]:
    """Validate a captured JSON Action response against the generated contract."""
    errors: list[str] = []
    try:
        operation = _operation(document, operation_id)
        schema = _response_schema(operation, str(int(status)))
    except (ResponseContractError, TypeError, ValueError) as exc:
        return [str(exc)]

    errors.extend(validate_json_instance(payload, schema))
    normalized = {str(key).casefold(): str(value) for key, value in headers.items()}
    content_type = normalized.get("content-type", "")
    if not content_type.casefold().startswith("application/json"):
        errors.append("ACTION_RESPONSE_CONTENT_TYPE_INVALID")

    retry_header = normalized.get("retry-after")
    if int(status) == 429:
        if retry_header is None:
            errors.append("RUNTIME_RETRY_AFTER_HEADER_MISSING")
        else:
            try:
                retry_value = int(retry_header)
            except ValueError:
                errors.append("RUNTIME_RETRY_AFTER_HEADER_INVALID")
            else:
                if not 1 <= retry_value <= 600:
                    errors.append("RUNTIME_RETRY_AFTER_HEADER_INVALID")
                error_obj = payload.get("error") if isinstance(payload, Mapping) else None
                body_retry = error_obj.get("retry_after_seconds") if isinstance(error_obj, Mapping) else None
                if body_retry != retry_value:
                    errors.append("RUNTIME_RETRY_AFTER_BODY_HEADER_DRIFT")
    elif retry_header is not None:
        errors.append("UNEXPECTED_RUNTIME_RETRY_AFTER_HEADER")
    return sorted(set(errors))
