# -*- coding: utf-8 -*-
"""Authoritative API/OpenAPI contracts for Telegram Bridge.

DEV06 owns this source-only contract layer.  It deliberately performs no network,
Telegram, HOSTiQ, credential, or production mutation.  Runtime/router and legacy
Action registries are treated as implementations that MUST match this registry,
not as independent sources of security truth.
"""
from __future__ import annotations

import copy
import json
from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping
from urllib.parse import urlsplit

from bridge.routes import READ_ROUTE_REGISTRY
from ops.openapi_registry import (
    OPERATIONS as LEGACY_ACTION_OPERATIONS,
    OperationClass as LegacyOperationClass,
    build_action_openapi as _legacy_build_action_openapi,
)


class ApiContractError(RuntimeError):
    """Fail-closed contract/parity error."""


class AccessPolicy(str, Enum):
    PUBLIC = "PUBLIC"
    BEARER = "BEARER"
    BEARER_OR_SIGNED = "BEARER_OR_SIGNED"


class ApiOperationClass(str, Enum):
    HEALTH = "HEALTH"
    READ = "READ"
    WRITE_PREVIEW = "WRITE_PREVIEW"
    WRITE_COMMIT = "WRITE_COMMIT"
    FILE_CONTENT = "FILE_CONTENT"


class ApiExposure(str, Enum):
    ACTION = "ACTION"
    RUNTIME_ONLY = "RUNTIME_ONLY"


@dataclass(frozen=True)
class RouteContract:
    method: str
    path: str
    runtime_operation_id: str
    operation_class: ApiOperationClass
    access: AccessPolicy
    exposure: ApiExposure
    action_operation_id: str | None = None
    write_action: str | None = None
    pair_operation_id: str | None = None

    @property
    def consequential(self) -> bool:
        return self.operation_class is ApiOperationClass.WRITE_COMMIT

    def key(self) -> tuple[str, str]:
        return self.method.upper(), self.path


API_PREFIX = "/api/v1"

CANONICAL_ROUTES: tuple[RouteContract, ...] = (
    RouteContract("GET", "/health", "health.get", ApiOperationClass.HEALTH, AccessPolicy.PUBLIC, ApiExposure.RUNTIME_ONLY),
    RouteContract("POST", f"{API_PREFIX}/dialogs/list", "dialogs.list", ApiOperationClass.READ, AccessPolicy.BEARER, ApiExposure.ACTION, "listTelegramDialogs"),
    RouteContract("POST", f"{API_PREFIX}/history/read", "history.read", ApiOperationClass.READ, AccessPolicy.BEARER, ApiExposure.ACTION, "readTelegramHistory"),
    RouteContract("POST", f"{API_PREFIX}/search", "search.read", ApiOperationClass.READ, AccessPolicy.BEARER, ApiExposure.ACTION, "searchTelegramMessages"),
    RouteContract("POST", f"{API_PREFIX}/media/metadata", "media.metadata", ApiOperationClass.READ, AccessPolicy.BEARER, ApiExposure.ACTION, "getTelegramMediaMetadata"),
    RouteContract("POST", f"{API_PREFIX}/downloads/single", "downloads.single", ApiOperationClass.READ, AccessPolicy.BEARER, ApiExposure.ACTION, "downloadTelegramMediaSingle"),
    RouteContract("POST", f"{API_PREFIX}/downloads/bulk", "downloads.bulk", ApiOperationClass.READ, AccessPolicy.BEARER, ApiExposure.ACTION, "downloadTelegramMediaBulk"),
    RouteContract("POST", f"{API_PREFIX}/downloads/resume", "downloads.resume", ApiOperationClass.READ, AccessPolicy.BEARER, ApiExposure.ACTION, "resumeTelegramDownload"),
    RouteContract("POST", f"{API_PREFIX}/archives/create", "archives.create", ApiOperationClass.READ, AccessPolicy.BEARER, ApiExposure.ACTION, "createTelegramArchive"),
    RouteContract("POST", f"{API_PREFIX}/files/get", "files.metadata", ApiOperationClass.READ, AccessPolicy.BEARER, ApiExposure.ACTION, "getStoredTelegramFile"),
    RouteContract("GET", f"{API_PREFIX}/files/{{file_ref}}", "files.content", ApiOperationClass.FILE_CONTENT, AccessPolicy.BEARER_OR_SIGNED, ApiExposure.RUNTIME_ONLY),
    RouteContract("POST", f"{API_PREFIX}/messages/send/preview", "previewTelegramSend", ApiOperationClass.WRITE_PREVIEW, AccessPolicy.BEARER, ApiExposure.ACTION, "previewTelegramSend", "SEND", "commitTelegramSend"),
    RouteContract("POST", f"{API_PREFIX}/messages/send/commit", "commitTelegramSend", ApiOperationClass.WRITE_COMMIT, AccessPolicy.BEARER, ApiExposure.ACTION, "commitTelegramSend", "SEND", "previewTelegramSend"),
    RouteContract("POST", f"{API_PREFIX}/messages/reply/preview", "previewTelegramReply", ApiOperationClass.WRITE_PREVIEW, AccessPolicy.BEARER, ApiExposure.ACTION, "previewTelegramReply", "REPLY", "commitTelegramReply"),
    RouteContract("POST", f"{API_PREFIX}/messages/reply/commit", "commitTelegramReply", ApiOperationClass.WRITE_COMMIT, AccessPolicy.BEARER, ApiExposure.ACTION, "commitTelegramReply", "REPLY", "previewTelegramReply"),
    RouteContract("POST", f"{API_PREFIX}/messages/forward/preview", "previewTelegramForward", ApiOperationClass.WRITE_PREVIEW, AccessPolicy.BEARER, ApiExposure.ACTION, "previewTelegramForward", "FORWARD", "commitTelegramForward"),
    RouteContract("POST", f"{API_PREFIX}/messages/forward/commit", "commitTelegramForward", ApiOperationClass.WRITE_COMMIT, AccessPolicy.BEARER, ApiExposure.ACTION, "commitTelegramForward", "FORWARD", "previewTelegramForward"),
    RouteContract("POST", f"{API_PREFIX}/files/send/preview", "previewTelegramFiles", ApiOperationClass.WRITE_PREVIEW, AccessPolicy.BEARER, ApiExposure.ACTION, "previewTelegramFiles", "SEND_FILES", "commitTelegramFiles"),
    RouteContract("POST", f"{API_PREFIX}/files/send/commit", "commitTelegramFiles", ApiOperationClass.WRITE_COMMIT, AccessPolicy.BEARER, ApiExposure.ACTION, "commitTelegramFiles", "SEND_FILES", "previewTelegramFiles"),
)

_BY_KEY = {route.key(): route for route in CANONICAL_ROUTES}
_BY_ACTION = {route.action_operation_id: route for route in CANONICAL_ROUTES if route.action_operation_id}
_BY_RUNTIME = {route.runtime_operation_id: route for route in CANONICAL_ROUTES}

_PRIVATE_PATH_WORDS = ("setup", "bootstrap", "authorize", "login", "2fa", "session")
_SECRET_FIELD_WORDS = {
    "api_hash", "tg_api_hash", "session_string", "tg_session_string",
    "telegram_2fa_password", "bridge_token", "setup_route",
    "private_key", "client_secret", "refresh_token", "cookie",
}
_REQUEST_ID = {"type": "string", "pattern": "^[0-9a-f]{16}$"}
_SHA256 = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
_FILE_REF = {"type": "string", "minLength": 1, "maxLength": 128}
_POSITIVE_ID = {"type": "integer", "minimum": 1}
_ERROR_STATUSES = ("400", "404", "409", "413", "415", "429", "500", "502", "503", "504")


def canonical_route(method: str, path: str) -> RouteContract:
    route = _BY_KEY.get((str(method).upper(), str(path)))
    if route is None:
        raise ApiContractError("UNKNOWN_ROUTE_FAIL_CLOSED")
    return route


def canonical_action(operation_id: str) -> RouteContract:
    route = _BY_ACTION.get(str(operation_id))
    if route is None:
        raise ApiContractError("UNKNOWN_ACTION_OPERATION_FAIL_CLOSED")
    return route


def canonical_runtime_operation(operation_id: str) -> RouteContract:
    route = _BY_RUNTIME.get(str(operation_id))
    if route is None:
        raise ApiContractError("UNKNOWN_RUNTIME_OPERATION_FAIL_CLOSED")
    return route


def _obj(properties: Mapping[str, Any], required: tuple[str, ...] = ()) -> dict[str, Any]:
    out: dict[str, Any] = {
        "type": "object",
        "additionalProperties": False,
        "properties": copy.deepcopy(dict(properties)),
    }
    if required:
        out["required"] = list(required)
    return out


def _nullable(schema: Mapping[str, Any]) -> dict[str, Any]:
    return {"anyOf": [copy.deepcopy(dict(schema)), {"type": "null"}]}


def _array(schema: Mapping[str, Any], *, maximum: int = 200, minimum: int = 0, unique: bool = False) -> dict[str, Any]:
    out: dict[str, Any] = {
        "type": "array",
        "minItems": minimum,
        "maxItems": maximum,
        "items": copy.deepcopy(dict(schema)),
    }
    if unique:
        out["uniqueItems"] = True
    return out


def validate_canonical_registry() -> list[str]:
    errors: list[str] = []
    if len(CANONICAL_ROUTES) != 19 or len(_BY_KEY) != 19 or len(_BY_RUNTIME) != 19:
        errors.append("CANONICAL_ROUTE_COUNT_OR_DUPLICATE")
    if len(_BY_ACTION) != 17:
        errors.append("ACTION_OPERATION_COUNT_OR_DUPLICATE")

    public = [route for route in CANONICAL_ROUTES if route.access is AccessPolicy.PUBLIC]
    if [(r.method, r.path, r.runtime_operation_id) for r in public] != [("GET", "/health", "health.get")]:
        errors.append("ONLY_HEALTH_MAY_BE_PUBLIC")

    for route in CANONICAL_ROUTES:
        if route.method not in {"GET", "POST"}:
            errors.append(f"METHOD_UNSUPPORTED:{route.runtime_operation_id}")
        lowered = route.path.casefold()
        if route.path != "/health" and not route.path.startswith(API_PREFIX + "/"):
            errors.append(f"PATH_OUTSIDE_API_PREFIX:{route.runtime_operation_id}")
        if any(word in lowered for word in _PRIVATE_PATH_WORDS):
            errors.append(f"PRIVATE_SURFACE_FORBIDDEN:{route.runtime_operation_id}")

        if route.exposure is ApiExposure.ACTION:
            if route.method != "POST":
                errors.append(f"ACTION_METHOD_MUST_BE_POST:{route.runtime_operation_id}")
            if route.access is not AccessPolicy.BEARER:
                errors.append(f"ACTION_MUST_REQUIRE_BEARER:{route.runtime_operation_id}")
            if not route.action_operation_id:
                errors.append(f"ACTION_ID_MISSING:{route.runtime_operation_id}")
        elif route.action_operation_id is not None:
            errors.append(f"RUNTIME_ONLY_ACTION_ID_PRESENT:{route.runtime_operation_id}")

        if route.operation_class in {ApiOperationClass.WRITE_PREVIEW, ApiOperationClass.WRITE_COMMIT}:
            if route.write_action not in {"SEND", "REPLY", "FORWARD", "SEND_FILES"}:
                errors.append(f"WRITE_ACTION_INVALID:{route.runtime_operation_id}")
            pair = _BY_ACTION.get(route.pair_operation_id or "")
            if pair is None:
                errors.append(f"WRITE_PAIR_MISSING:{route.runtime_operation_id}")
            else:
                if pair.write_action != route.write_action:
                    errors.append(f"WRITE_PAIR_ACTION_MISMATCH:{route.runtime_operation_id}")
                if pair.pair_operation_id != route.action_operation_id:
                    errors.append(f"WRITE_PAIR_NOT_RECIPROCAL:{route.runtime_operation_id}")
                if pair.operation_class is route.operation_class:
                    errors.append(f"WRITE_PAIR_CLASS_MISMATCH:{route.runtime_operation_id}")
        elif route.write_action or route.pair_operation_id:
            errors.append(f"NONWRITE_HAS_WRITE_METADATA:{route.runtime_operation_id}")

        if route.consequential is not (route.operation_class is ApiOperationClass.WRITE_COMMIT):
            errors.append(f"CONSEQUENTIAL_CLASS_MISMATCH:{route.runtime_operation_id}")

    return sorted(set(errors))


def _runtime_router_snapshot() -> dict[tuple[str, str], tuple[str, str, str]]:
    snapshot: dict[tuple[str, str], tuple[str, str, str]] = {}
    for spec in READ_ROUTE_REGISTRY:
        path = spec.concrete_path(API_PREFIX)
        if spec.dynamic_tail:
            path += "{file_ref}"
        key = (spec.method.upper(), path)
        snapshot[key] = (spec.operation_id, spec.access, spec.operation_class)
    return snapshot


def validate_runtime_parity() -> list[str]:
    errors = validate_canonical_registry()

    expected_read: dict[tuple[str, str], tuple[str, str, str]] = {}
    for route in CANONICAL_ROUTES:
        if route.operation_class not in {ApiOperationClass.HEALTH, ApiOperationClass.READ, ApiOperationClass.FILE_CONTENT}:
            continue
        access = {
            AccessPolicy.PUBLIC: "public",
            AccessPolicy.BEARER: "protected",
            AccessPolicy.BEARER_OR_SIGNED: "protected_or_signed",
        }[route.access]
        runtime_class = "health" if route.operation_class is ApiOperationClass.HEALTH else "read"
        expected_read[route.key()] = (route.runtime_operation_id, access, runtime_class)

    actual_read = _runtime_router_snapshot()
    if actual_read != expected_read:
        missing = sorted(set(expected_read) - set(actual_read))
        extra = sorted(set(actual_read) - set(expected_read))
        changed = sorted(key for key in set(actual_read) & set(expected_read) if actual_read[key] != expected_read[key])
        if missing:
            errors.append(f"RUNTIME_READ_ROUTE_MISSING:{len(missing)}")
        if extra:
            errors.append(f"RUNTIME_READ_ROUTE_EXTRA:{len(extra)}")
        if changed:
            errors.append(f"RUNTIME_READ_ROUTE_METADATA_DRIFT:{len(changed)}")

    legacy_by_key = {(spec.method.upper(), spec.path): spec for spec in LEGACY_ACTION_OPERATIONS}
    expected_action_keys = {route.key() for route in CANONICAL_ROUTES if route.exposure is ApiExposure.ACTION}
    if set(legacy_by_key) != expected_action_keys:
        errors.append("LEGACY_ACTION_ROUTE_SET_DRIFT")

    class_map = {
        ApiOperationClass.READ: LegacyOperationClass.READ,
        ApiOperationClass.WRITE_PREVIEW: LegacyOperationClass.WRITE_PREVIEW,
        ApiOperationClass.WRITE_COMMIT: LegacyOperationClass.WRITE_COMMIT,
    }
    for route in CANONICAL_ROUTES:
        if route.exposure is not ApiExposure.ACTION:
            continue
        legacy = legacy_by_key.get(route.key())
        if legacy is None:
            continue
        if legacy.operation_id != route.action_operation_id:
            errors.append(f"LEGACY_ACTION_ID_DRIFT:{route.runtime_operation_id}")
        if legacy.operation_class is not class_map[route.operation_class]:
            errors.append(f"LEGACY_OPERATION_CLASS_DRIFT:{route.runtime_operation_id}")
        if legacy.protected is not True:
            errors.append(f"LEGACY_PROTECTION_DRIFT:{route.runtime_operation_id}")
        if legacy.action != route.write_action:
            errors.append(f"LEGACY_WRITE_ACTION_DRIFT:{route.runtime_operation_id}")
        if legacy.pair_operation_id != route.pair_operation_id:
            errors.append(f"LEGACY_PAIR_DRIFT:{route.runtime_operation_id}")

    return sorted(set(errors))


def assert_runtime_parity() -> None:
    errors = validate_runtime_parity()
    if errors:
        raise ApiContractError(";".join(errors))


def _entity_schema() -> dict[str, Any]:
    return _obj({
        "id": {"type": "string", "minLength": 1, "maxLength": 256},
        "kind": {"type": "string", "minLength": 1, "maxLength": 32},
        "display_name": _nullable({"type": "string", "maxLength": 512}),
        "username": _nullable({"type": "string", "maxLength": 256}),
    }, ("id", "kind", "display_name", "username"))


def _media_schema() -> dict[str, Any]:
    return _obj({
        "type": {"type": "string", "minLength": 1, "maxLength": 32},
        "file_ref": copy.deepcopy(_FILE_REF),
        "name": _nullable({"type": "string", "maxLength": 180}),
        "mime_type": _nullable({"type": "string", "maxLength": 160}),
        "size": _nullable({"type": "integer", "minimum": 0, "maximum": 104857600}),
        "duration_seconds": _nullable({"type": "number", "minimum": 0}),
        "width": _nullable({"type": "integer", "minimum": 0}),
        "height": _nullable({"type": "integer", "minimum": 0}),
    }, ("type", "file_ref", "name", "mime_type", "size", "duration_seconds", "width", "height"))


def _message_schema(*, include_text: bool) -> dict[str, Any]:
    props: dict[str, Any] = {
        "id": copy.deepcopy(_POSITIVE_ID),
        "chat_id": {"type": "string", "minLength": 1, "maxLength": 256},
        "timestamp": {"type": "string", "format": "date-time"},
        "outgoing": {"type": "boolean"},
        "reply_to_message_id": _nullable(copy.deepcopy(_POSITIVE_ID)),
        "sender": _nullable(_entity_schema()),
        "media": _array(_media_schema(), maximum=64),
    }
    required = ["id", "chat_id", "timestamp", "outgoing", "reply_to_message_id", "sender", "media"]
    if include_text:
        props["text"] = {"type": "string", "maxLength": 4096}
        required.append("text")
    return _obj(props, tuple(required))


def _dialog_schema() -> dict[str, Any]:
    return _obj({
        "id": {"type": "string", "minLength": 1, "maxLength": 256},
        "kind": {"type": "string", "minLength": 1, "maxLength": 32},
        "title": {"type": "string", "maxLength": 512},
        "username": _nullable({"type": "string", "maxLength": 256}),
        "unread_count": {"type": "integer", "minimum": 0},
        "pinned": {"type": "boolean"},
        "last_message_at": _nullable({"type": "string", "format": "date-time"}),
    }, ("id", "kind", "title", "username", "unread_count", "pinned", "last_message_at"))


def _page_schema(item: Mapping[str, Any]) -> dict[str, Any]:
    return _obj({
        "items": _array(item, maximum=200),
        "next_cursor": _nullable({"type": "string", "maxLength": 1024}),
        "scanned": {"type": "integer", "minimum": 0, "maximum": 20000},
    }, ("items", "next_cursor", "scanned"))


def _file_metadata_schema() -> dict[str, Any]:
    return _obj({
        "file_ref": copy.deepcopy(_FILE_REF),
        "name": {"type": "string", "maxLength": 180},
        "mime_type": {"type": "string", "maxLength": 160},
        "size": {"type": "integer", "minimum": 0, "maximum": 786432000},
        "sha256": copy.deepcopy(_SHA256),
        "created_at": {"type": "integer", "minimum": 0},
    }, ("file_ref", "name", "mime_type", "size", "sha256", "created_at"))


def _file_access_schema() -> dict[str, Any]:
    schema = _file_metadata_schema()
    schema["properties"].update({
        "download_path": {"type": "string", "pattern": r"^/api/v1/files/[A-Za-z0-9_-]{1,128}$"},
        "signed_url": {"type": "string", "format": "uri", "maxLength": 2048},
        "expires_at": {"type": "integer", "minimum": 1},
    })
    required = list(schema["required"])
    required.append("download_path")
    schema["required"] = required
    return schema


def _download_job_schema() -> dict[str, Any]:
    failure = _obj({
        "item_id": {"type": "string", "minLength": 1, "maxLength": 128},
        "code": {"type": "string", "pattern": "^[a-z][a-z0-9_]{0,79}$"},
        "status": {"type": "integer", "minimum": 400, "maximum": 599},
        "retryable": {"type": "boolean"},
    }, ("item_id", "code", "status", "retryable"))
    return _obj({
        "job_id": {"type": "string", "minLength": 16, "maxLength": 128},
        "status": {"type": "string", "enum": ["complete", "partial", "failed"]},
        "files": _array(_file_metadata_schema(), maximum=100),
        "failures": _array(failure, maximum=100),
        "pending": {"type": "integer", "minimum": 0, "maximum": 100},
    }, ("job_id", "status", "files", "failures", "pending"))


def _preview_data_schema(route: RouteContract) -> dict[str, Any]:
    preview: dict[str, Any]
    if route.write_action == "SEND":
        preview = _obj({"chat": {"type": "string", "minLength": 1, "maxLength": 256}, "text": {"type": "string", "minLength": 1, "maxLength": 4096}}, ("chat", "text"))
    elif route.write_action == "REPLY":
        preview = _obj({"chat": {"type": "string", "minLength": 1, "maxLength": 256}, "reply_to_message_id": copy.deepcopy(_POSITIVE_ID), "text": {"type": "string", "minLength": 1, "maxLength": 4096}}, ("chat", "reply_to_message_id", "text"))
    elif route.write_action == "FORWARD":
        preview = _obj({"from_chat": {"type": "string", "minLength": 1, "maxLength": 256}, "to_chat": {"type": "string", "minLength": 1, "maxLength": 256}, "message_ids": _array(_POSITIVE_ID, maximum=100, minimum=1, unique=True)}, ("from_chat", "to_chat", "message_ids"))
    elif route.write_action == "SEND_FILES":
        file_item = _obj({"file_ref": copy.deepcopy(_FILE_REF), "sha256": copy.deepcopy(_SHA256), "size": {"type": "integer", "minimum": 1, "maximum": 104857600}}, ("file_ref", "sha256", "size"))
        preview = _obj({
            "chat": {"type": "string", "minLength": 1, "maxLength": 256},
            "files": _array(file_item, maximum=10, minimum=1),
            "caption": {"type": "string", "maxLength": 4096},
            "reply_to_message_id": copy.deepcopy(_POSITIVE_ID),
            "voice_note": {"type": "boolean"},
        }, ("chat", "files", "caption", "voice_note"))
    else:
        raise ApiContractError("PREVIEW_SCHEMA_WRITE_ACTION_UNKNOWN")
    return _obj({
        "preview_token": {"type": "string", "minLength": 24, "maxLength": 256, "writeOnly": True},
        "preview_id": {"type": "string", "minLength": 1, "maxLength": 128},
        "action": {"type": "string", "enum": [route.write_action]},
        "request_fingerprint": copy.deepcopy(_SHA256),
        "expires_at": {"type": "integer", "minimum": 1},
        "preview": preview,
    }, ("preview_token", "preview_id", "action", "request_fingerprint", "expires_at", "preview"))


def _commit_data_schema() -> dict[str, Any]:
    return _obj({
        "state": {"type": "string", "enum": ["COMMITTED"]},
        "idempotent_replay": {"type": "boolean"},
        "request_fingerprint": copy.deepcopy(_SHA256),
        "result": _obj({
            "operation": {"type": "string", "enum": ["SEND", "REPLY", "FORWARD", "SEND_FILES"]},
            "message_ids": _array(_POSITIVE_ID, maximum=100, minimum=1),
            "chat_id": _nullable({"type": "integer"}),
            "count": {"type": "integer", "minimum": 1, "maximum": 100},
        }, ("operation", "message_ids", "chat_id", "count")),
    }, ("state", "idempotent_replay", "request_fingerprint", "result"))


def _success_data_schema(route: RouteContract) -> dict[str, Any]:
    oid = route.action_operation_id
    if oid == "listTelegramDialogs":
        return _page_schema(_dialog_schema())
    if oid in {"readTelegramHistory", "searchTelegramMessages"}:
        return _page_schema(_message_schema(include_text=True))
    if oid == "getTelegramMediaMetadata":
        return _obj({
            "message_id": copy.deepcopy(_POSITIVE_ID),
            "chat_id": {"type": "string", "minLength": 1, "maxLength": 256},
            "timestamp": {"type": "string", "format": "date-time"},
            "media": _array(_media_schema(), maximum=64),
        }, ("message_id", "chat_id", "timestamp", "media"))
    if oid in {"downloadTelegramMediaSingle", "createTelegramArchive"}:
        return _file_metadata_schema()
    if oid in {"downloadTelegramMediaBulk", "resumeTelegramDownload"}:
        return _download_job_schema()
    if oid == "getStoredTelegramFile":
        return _file_access_schema()
    if route.operation_class is ApiOperationClass.WRITE_PREVIEW:
        return _preview_data_schema(route)
    if route.operation_class is ApiOperationClass.WRITE_COMMIT:
        return _commit_data_schema()
    raise ApiContractError(f"SUCCESS_SCHEMA_MISSING:{oid}")


def _success_envelope(route: RouteContract) -> dict[str, Any]:
    return _obj({
        "ok": {"type": "boolean", "const": True},
        "request_id": copy.deepcopy(_REQUEST_ID),
        "data": _success_data_schema(route),
    }, ("ok", "request_id", "data"))


def _error_detail_schema() -> dict[str, Any]:
    details = _obj({
        "field": {"type": "string", "maxLength": 80},
        "limit": {"type": "integer", "minimum": -(2**31), "maximum": 2**31 - 1},
        "count": {"type": "integer", "minimum": -(2**31), "maximum": 2**31 - 1},
        "status": {"type": "string", "maxLength": 80},
        "reason": {"type": "string", "maxLength": 80},
        "retryable": {"type": "boolean"},
    })
    return _obj({
        "code": {"type": "string", "minLength": 1, "maxLength": 80, "pattern": "^[A-Za-z0-9_.-]+$"},
        "message": {"type": "string", "minLength": 1, "maxLength": 240},
        "retry_after_seconds": {"type": "integer", "minimum": 1, "maximum": 600},
        "details": details,
    }, ("code", "message"))


def _error_envelope() -> dict[str, Any]:
    return _obj({
        "ok": {"type": "boolean", "const": False},
        "request_id": copy.deepcopy(_REQUEST_ID),
        "error": _error_detail_schema(),
    }, ("ok", "request_id", "error"))


def _operation_responses(route: RouteContract) -> dict[str, Any]:
    responses: dict[str, Any] = {
        "200": {
            "description": "Successful private bridge response",
            "content": {"application/json": {"schema": _success_envelope(route)}},
        }
    }
    descriptions = {
        "400": "Invalid request",
        "404": "Not found or unauthorized",
        "409": "Conflict or write/download state contention",
        "413": "Request or payload exceeds a bounded limit",
        "415": "Unsupported request content type",
        "429": "Bridge or Telegram rate/FloodWait response",
        "500": "Internal bridge error without private diagnostic leakage",
        "502": "Telegram/backend operation failed safely",
        "503": "Required bridge component is unavailable",
        "504": "Telegram/backend operation timed out",
    }
    for status in _ERROR_STATUSES:
        response: dict[str, Any] = {
            "description": descriptions[status],
            "content": {"application/json": {"schema": _error_envelope()}},
        }
        if status == "429":
            response["headers"] = {
                "Retry-After": {
                    "description": "Whole seconds until the client may retry.",
                    "required": True,
                    "schema": {"type": "integer", "minimum": 1, "maximum": 600},
                }
            }
        responses[status] = response
    return responses


def _server_url(base_url: str) -> str:
    parts = urlsplit(str(base_url).strip())
    if (
        parts.scheme.casefold() != "https"
        or not parts.hostname
        or parts.username
        or parts.password
        or parts.query
        or parts.fragment
        or parts.path not in {"", "/"}
    ):
        raise ApiContractError("HTTPS_SERVER_ROOT_REQUIRED")
    return f"https://{parts.netloc}"


def build_chatgpt_action_openapi(base_url: str) -> dict[str, Any]:
    """Build the Action schema from the DEV06 registry.

    Legacy request schemas are deliberately reused to avoid duplicating mature
    feature-lane validation bounds. Security classification, exposed routes,
    responses, error semantics, Retry-After, and consequential behavior are
    rebuilt and validated from CANONICAL_ROUTES.
    """
    assert_runtime_parity()
    server = _server_url(base_url)
    legacy = _legacy_build_action_openapi(server)
    legacy_paths = legacy.get("paths")
    if not isinstance(legacy_paths, Mapping):
        raise ApiContractError("LEGACY_OPENAPI_PATHS_INVALID")

    paths: dict[str, Any] = {}
    for route in CANONICAL_ROUTES:
        if route.exposure is not ApiExposure.ACTION:
            continue
        legacy_op = ((legacy_paths.get(route.path) or {}).get(route.method.lower()))
        if not isinstance(legacy_op, Mapping):
            raise ApiContractError(f"LEGACY_REQUEST_SCHEMA_MISSING:{route.action_operation_id}")
        request_body = copy.deepcopy(legacy_op.get("requestBody"))
        operation: dict[str, Any] = {
            "operationId": route.action_operation_id,
            "summary": str(legacy_op.get("summary") or route.action_operation_id),
            "description": str(legacy_op.get("description") or route.action_operation_id),
            "security": [{"BearerAuth": []}],
            "x-openai-isConsequential": route.consequential,
            "x-bridge-operation-class": route.operation_class.value,
            "x-bridge-runtime-operation-id": route.runtime_operation_id,
            "x-bridge-rate-class": "WRITE_OPERATION_SCOPED" if route.write_action else "AUTHENTICATED_READ_API",
            "requestBody": request_body,
            "responses": _operation_responses(route),
        }
        if route.write_action:
            operation["x-bridge-write-action"] = route.write_action
            operation["x-bridge-pair-operation-id"] = route.pair_operation_id
        paths.setdefault(route.path, {})[route.method.lower()] = operation

    schema = {
        "openapi": "3.1.0",
        "info": {
            "title": "Private Telegram Bridge",
            "version": "dev06-contract-v1",
            "description": (
                "Private personal Telegram user-account bridge for ChatGPT. "
                "All Action operations require bearer authentication. Writes "
                "use preview then an explicit consequential commit."
            ),
        },
        "servers": [{"url": server}],
        "security": [{"BearerAuth": []}],
        "paths": paths,
        "components": {
            "securitySchemes": {
                "BearerAuth": {
                    "type": "http",
                    "scheme": "bearer",
                    "bearerFormat": "opaque",
                }
            },
            "schemas": {
                "StructuredError": _error_envelope(),
            },
        },
    }
    assert_chatgpt_action_schema_safe(schema)
    return schema


def _scan_forbidden(value: Any, *, path: str = "$") -> list[str]:
    errors: list[str] = []
    if isinstance(value, Mapping):
        for raw_key, child in value.items():
            key = str(raw_key)
            if key.casefold() in _SECRET_FIELD_WORDS:
                errors.append(f"SECRET_FIELD_EXPOSED:{path}.{key}")
            errors.extend(_scan_forbidden(child, path=f"{path}.{key}"))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            errors.extend(_scan_forbidden(child, path=f"{path}[{index}]"))
    elif isinstance(value, str):
        lowered = value.casefold()
        if any(marker in lowered for marker in ("tg_api_hash", "session_string", "setup_route", "bearer example", "/setup/", "/bootstrap/", "/authorize/")):
            errors.append(f"PRIVATE_OR_SECRET_EXAMPLE:{path}")
    return errors


def _json_schema_at(operation: Mapping[str, Any], response_status: str | None = None) -> Mapping[str, Any] | None:
    if response_status is None:
        body = operation.get("requestBody")
        if not isinstance(body, Mapping):
            return None
        content = body.get("content")
    else:
        responses = operation.get("responses")
        if not isinstance(responses, Mapping):
            return None
        response = responses.get(response_status)
        if not isinstance(response, Mapping):
            return None
        content = response.get("content")
    if not isinstance(content, Mapping):
        return None
    json_content = content.get("application/json")
    if not isinstance(json_content, Mapping):
        return None
    schema = json_content.get("schema")
    return schema if isinstance(schema, Mapping) else None


def validate_chatgpt_action_schema(schema: Mapping[str, Any]) -> list[str]:
    errors = validate_runtime_parity()
    if not isinstance(schema, Mapping):
        return sorted(set(errors + ["SCHEMA_NOT_MAPPING"]))
    if schema.get("openapi") != "3.1.0":
        errors.append("OPENAPI_VERSION_INVALID")
    if schema.get("security") != [{"BearerAuth": []}]:
        errors.append("ROOT_BEARER_SECURITY_REQUIRED")

    servers = schema.get("servers")
    if not isinstance(servers, list) or len(servers) != 1 or not isinstance(servers[0], Mapping):
        errors.append("SERVER_URL_INVALID")
    else:
        try:
            _server_url(str(servers[0].get("url", "")))
        except ApiContractError:
            errors.append("SERVER_URL_INVALID")

    schemes = ((schema.get("components") or {}).get("securitySchemes") or {}) if isinstance(schema.get("components"), Mapping) else {}
    bearer = schemes.get("BearerAuth") if isinstance(schemes, Mapping) else None
    if not isinstance(bearer, Mapping) or bearer.get("type") != "http" or str(bearer.get("scheme", "")).casefold() != "bearer":
        errors.append("BEARER_SCHEME_INVALID")

    paths = schema.get("paths")
    if not isinstance(paths, Mapping):
        return sorted(set(errors + ["PATHS_MISSING"]))

    expected = {route.key(): route for route in CANONICAL_ROUTES if route.exposure is ApiExposure.ACTION}
    observed: dict[tuple[str, str], str] = {}
    for raw_path, raw_item in paths.items():
        path = str(raw_path)
        lowered = path.casefold()
        if any(word in lowered for word in _PRIVATE_PATH_WORDS):
            errors.append(f"PRIVATE_ACTION_SURFACE:{path}")
        if not isinstance(raw_item, Mapping):
            errors.append(f"PATH_ITEM_INVALID:{path}")
            continue
        for raw_method, raw_operation in raw_item.items():
            method = str(raw_method).upper()
            if method not in {"GET", "POST", "PUT", "PATCH", "DELETE"}:
                continue
            key = (method, path)
            route = expected.get(key)
            if route is None:
                errors.append(f"UNKNOWN_ACTION_ROUTE:{method}:{path}")
                continue
            if not isinstance(raw_operation, Mapping):
                errors.append(f"OPERATION_INVALID:{route.action_operation_id}")
                continue
            operation = raw_operation
            operation_id = str(operation.get("operationId") or "")
            observed[key] = operation_id
            if operation_id != route.action_operation_id:
                errors.append(f"OPERATION_ID_DRIFT:{route.action_operation_id}")
            if operation.get("security") != [{"BearerAuth": []}]:
                errors.append(f"OPERATION_BEARER_REQUIRED:{route.action_operation_id}")
            if operation.get("x-openai-isConsequential") is not route.consequential:
                errors.append(f"CONSEQUENTIAL_SEMANTICS_DRIFT:{route.action_operation_id}")

            request = _json_schema_at(operation)
            if not isinstance(request, Mapping):
                errors.append(f"REQUEST_SCHEMA_MISSING:{route.action_operation_id}")
            else:
                if request.get("type") != "object" or request.get("additionalProperties") is not False:
                    errors.append(f"REQUEST_SCHEMA_NOT_FAIL_CLOSED:{route.action_operation_id}")
                if route.operation_class is ApiOperationClass.WRITE_COMMIT:
                    required = set(request.get("required") or [])
                    needed = {"preview_token", "idempotency_key", "explicit_user_command"}
                    if not needed <= required:
                        errors.append(f"COMMIT_GATES_MISSING:{route.action_operation_id}")
                    props = request.get("properties")
                    explicit = props.get("explicit_user_command") if isinstance(props, Mapping) else None
                    if not isinstance(explicit, Mapping) or explicit.get("const") is not True:
                        errors.append(f"EXPLICIT_COMMIT_NOT_CONST_TRUE:{route.action_operation_id}")

            responses = operation.get("responses")
            if not isinstance(responses, Mapping):
                errors.append(f"RESPONSES_MISSING:{route.action_operation_id}")
                continue
            expected_statuses = {"200", *_ERROR_STATUSES}
            if set(responses) != expected_statuses:
                errors.append(f"RESPONSE_STATUS_SET_DRIFT:{route.action_operation_id}")

            success = _json_schema_at(operation, "200")
            if not isinstance(success, Mapping):
                errors.append(f"SUCCESS_SCHEMA_MISSING:{route.action_operation_id}")
            else:
                if set(success.get("required") or []) != {"ok", "request_id", "data"}:
                    errors.append(f"SUCCESS_ENVELOPE_DRIFT:{route.action_operation_id}")
                props = success.get("properties")
                ok = props.get("ok") if isinstance(props, Mapping) else None
                if not isinstance(ok, Mapping) or ok.get("const") is not True:
                    errors.append(f"SUCCESS_OK_CONST_DRIFT:{route.action_operation_id}")

            for status in _ERROR_STATUSES:
                error_schema = _json_schema_at(operation, status)
                if not isinstance(error_schema, Mapping):
                    errors.append(f"ERROR_SCHEMA_MISSING:{route.action_operation_id}:{status}")
                    continue
                if set(error_schema.get("required") or []) != {"ok", "request_id", "error"}:
                    errors.append(f"ERROR_ENVELOPE_DRIFT:{route.action_operation_id}:{status}")
                    continue
                props = error_schema.get("properties")
                err = props.get("error") if isinstance(props, Mapping) else None
                if not isinstance(err, Mapping) or not {"code", "message"} <= set(err.get("required") or []):
                    errors.append(f"STRUCTURED_ERROR_DRIFT:{route.action_operation_id}:{status}")

            rate_response = responses.get("429")
            rate_headers = rate_response.get("headers") if isinstance(rate_response, Mapping) else None
            retry = rate_headers.get("Retry-After") if isinstance(rate_headers, Mapping) else None
            if not isinstance(retry, Mapping) or retry.get("required") is not True:
                errors.append(f"RETRY_AFTER_HEADER_MISSING:{route.action_operation_id}")
            else:
                retry_schema = retry.get("schema")
                if not isinstance(retry_schema, Mapping) or retry_schema.get("type") != "integer" or retry_schema.get("minimum") != 1:
                    errors.append(f"RETRY_AFTER_HEADER_INVALID:{route.action_operation_id}")

    if set(observed) != set(expected):
        missing = set(expected) - set(observed)
        if missing:
            errors.append(f"ACTION_ROUTE_MISSING:{len(missing)}")
    if len(observed) != 17:
        errors.append("ACTION_ROUTE_COUNT_DRIFT")
    operation_ids = list(observed.values())
    if len(set(operation_ids)) != len(operation_ids):
        errors.append("DUPLICATE_ACTION_OPERATION_ID")

    errors.extend(_scan_forbidden(schema))
    return sorted(set(errors))


def assert_chatgpt_action_schema_safe(schema: Mapping[str, Any]) -> None:
    errors = validate_chatgpt_action_schema(schema)
    if errors:
        raise ApiContractError(";".join(errors))


def serialized_chatgpt_action_openapi(base_url: str) -> str:
    schema = build_chatgpt_action_openapi(base_url)
    return json.dumps(schema, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


# Deterministic source-only import gate. No network or credential access.
assert_runtime_parity()
