# -*- coding: utf-8 -*-
"""Canonical private Telegram Bridge operation registry and ChatGPT Action schema.

Operation safety comes from this registry, never from optional schema extensions.
Read/media names intentionally match the DEV3 /api/v1 interface. Write operations are
DEV4-owned preview/commit contracts and remain credential-free in source/CI.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from enum import Enum
from typing import Any, Iterable, Mapping
from urllib.parse import urlsplit


class OpenAPIContractError(RuntimeError):
    pass


class OperationClass(str, Enum):
    READ = "READ"
    WRITE_PREVIEW = "WRITE_PREVIEW"
    WRITE_COMMIT = "WRITE_COMMIT"


@dataclass(frozen=True)
class OperationSpec:
    path: str
    method: str
    operation_id: str
    operation_class: OperationClass
    protected: bool
    action: str | None = None
    pair_operation_id: str | None = None
    explicit_user_commit_required: bool = False
    k5_test_safe_destination_required: bool = False

    def key(self) -> tuple[str, str]:
        return self.path, self.method.lower()


API_PREFIX = "/api/v1"
OPERATIONS: tuple[OperationSpec, ...] = (
    # DEV3-compatible read/media surface.
    OperationSpec(f"{API_PREFIX}/dialogs/list", "post", "listTelegramDialogs", OperationClass.READ, True),
    OperationSpec(f"{API_PREFIX}/history/read", "post", "readTelegramHistory", OperationClass.READ, True),
    OperationSpec(f"{API_PREFIX}/search", "post", "searchTelegramMessages", OperationClass.READ, True),
    OperationSpec(f"{API_PREFIX}/media/metadata", "post", "getTelegramMediaMetadata", OperationClass.READ, True),
    OperationSpec(f"{API_PREFIX}/downloads/single", "post", "downloadTelegramMediaSingle", OperationClass.READ, True),
    OperationSpec(f"{API_PREFIX}/downloads/bulk", "post", "downloadTelegramMediaBulk", OperationClass.READ, True),
    OperationSpec(f"{API_PREFIX}/downloads/resume", "post", "resumeTelegramDownload", OperationClass.READ, True),
    OperationSpec(f"{API_PREFIX}/archives/create", "post", "createTelegramArchive", OperationClass.READ, True),
    OperationSpec(f"{API_PREFIX}/files/get", "post", "getStoredTelegramFile", OperationClass.READ, True),
    # DEV4 write preview/commit surface.
    OperationSpec(f"{API_PREFIX}/messages/send/preview", "post", "previewTelegramSend", OperationClass.WRITE_PREVIEW, True, "SEND", "commitTelegramSend"),
    OperationSpec(f"{API_PREFIX}/messages/send/commit", "post", "commitTelegramSend", OperationClass.WRITE_COMMIT, True, "SEND", "previewTelegramSend", True, True),
    OperationSpec(f"{API_PREFIX}/messages/reply/preview", "post", "previewTelegramReply", OperationClass.WRITE_PREVIEW, True, "REPLY", "commitTelegramReply"),
    OperationSpec(f"{API_PREFIX}/messages/reply/commit", "post", "commitTelegramReply", OperationClass.WRITE_COMMIT, True, "REPLY", "previewTelegramReply", True, True),
    OperationSpec(f"{API_PREFIX}/messages/forward/preview", "post", "previewTelegramForward", OperationClass.WRITE_PREVIEW, True, "FORWARD", "commitTelegramForward"),
    OperationSpec(f"{API_PREFIX}/messages/forward/commit", "post", "commitTelegramForward", OperationClass.WRITE_COMMIT, True, "FORWARD", "previewTelegramForward", True, True),
    OperationSpec(f"{API_PREFIX}/files/send/preview", "post", "previewTelegramFiles", OperationClass.WRITE_PREVIEW, True, "SEND_FILES", "commitTelegramFiles"),
    OperationSpec(f"{API_PREFIX}/files/send/commit", "post", "commitTelegramFiles", OperationClass.WRITE_COMMIT, True, "SEND_FILES", "previewTelegramFiles", True, True),
)

_REGISTRY = {item.key(): item for item in OPERATIONS}
_BY_ID = {item.operation_id: item for item in OPERATIONS}
if len(_REGISTRY) != len(OPERATIONS) or len(_BY_ID) != len(OPERATIONS):
    raise RuntimeError("duplicate canonical operation registry entry")

_PRIVATE_ROUTE_WORDS = {"setup", "bootstrap", "authorize", "login-code", "2fa", "session-string"}
_SECRET_FIELD_WORDS = {
    "api_hash", "session_string", "telegram_2fa_password", "bridge_token", "setup_route",
    "authorization", "cookie", "private_key", "client_secret", "refresh_token",
}


def canonical_operation(path: str, method: str) -> OperationSpec:
    spec = _REGISTRY.get((str(path), str(method).lower()))
    if spec is None:
        raise OpenAPIContractError("UNKNOWN_OPERATION_FAIL_CLOSED")
    return spec


def registry_by_operation_id(operation_id: str) -> OperationSpec:
    spec = _BY_ID.get(str(operation_id))
    if spec is None:
        raise OpenAPIContractError("UNKNOWN_OPERATION_ID_FAIL_CLOSED")
    return spec


def validate_registry() -> list[str]:
    errors: list[str] = []
    for spec in OPERATIONS:
        if not spec.path.startswith(API_PREFIX + "/") or any(word in spec.path.casefold() for word in _PRIVATE_ROUTE_WORDS):
            errors.append(f"PRIVATE_OR_INVALID_ROUTE:{spec.operation_id}")
        if spec.method.lower() != "post":
            errors.append(f"UNSUPPORTED_METHOD:{spec.operation_id}")
        if not spec.protected:
            errors.append(f"PRIVATE_BRIDGE_OPERATION_MUST_BE_PROTECTED:{spec.operation_id}")
        if spec.operation_class in {OperationClass.WRITE_PREVIEW, OperationClass.WRITE_COMMIT}:
            if spec.action not in {"SEND", "REPLY", "FORWARD", "SEND_FILES"}:
                errors.append(f"WRITE_ACTION_MISSING:{spec.operation_id}")
            pair = _BY_ID.get(spec.pair_operation_id or "")
            if pair is None or pair.action != spec.action or pair.operation_class == spec.operation_class:
                errors.append(f"WRITE_PAIR_INVALID:{spec.operation_id}")
        if spec.operation_class is OperationClass.WRITE_COMMIT and not spec.explicit_user_commit_required:
            errors.append(f"COMMIT_NOT_EXPLICIT:{spec.operation_id}")
    return sorted(set(errors))


def _obj(properties: Mapping[str, Any], required: Iterable[str] = ()) -> dict[str, Any]:
    out: dict[str, Any] = {"type": "object", "additionalProperties": False, "properties": dict(properties)}
    req = list(required)
    if req:
        out["required"] = req
    return out


def _ref(name: str) -> dict[str, str]:
    return {"$ref": f"#/components/schemas/{name}"}


def _target() -> dict[str, Any]:
    return {"type": "string", "minLength": 1, "maxLength": 256, "description": "Telegram numeric ID, @username, https://t.me/username, or Saved Messages alias."}


def _download_item_schema() -> dict[str, Any]:
    return _obj({
        "chat": _target(),
        "message_id": {"type": "integer", "minimum": 1},
        "file_ref": {"type": "string", "minLength": 1, "maxLength": 128},
        "name": {"type": "string", "maxLength": 180},
        "mime_type": {"type": "string", "maxLength": 160},
        "expected_size": {"type": "integer", "minimum": 0, "maximum": 104857600},
        "expected_sha256": {"type": "string", "pattern": "^[0-9A-Fa-f]{64}$"},
    }, ("chat", "message_id", "file_ref"))


def _request_schema(spec: OperationSpec) -> dict[str, Any]:
    positive_id = {"type": "integer", "minimum": 1}
    target = _target()
    oid = spec.operation_id

    if oid == "listTelegramDialogs":
        return _obj({"limit": {"type": "integer", "minimum": 1, "maximum": 200}, "cursor": {"type": "string", "maxLength": 1024}, "query": {"type": "string", "maxLength": 256}, "unread_only": {"type": "boolean"}})
    if oid == "readTelegramHistory":
        return _obj({"chat": target, "limit": {"type": "integer", "minimum": 1, "maximum": 200}, "cursor": {"type": "string", "maxLength": 1024}}, ("chat",))
    if oid == "searchTelegramMessages":
        return _obj({"chat": target, "sender": target, "text": {"type": "string", "maxLength": 512}, "date_from": {"type": "string", "format": "date-time"}, "date_to": {"type": "string", "format": "date-time"}, "limit": {"type": "integer", "minimum": 1, "maximum": 200}, "cursor": {"type": "string", "maxLength": 1024}, "scan_limit": {"type": "integer", "minimum": 1, "maximum": 2000}})
    if oid == "getTelegramMediaMetadata":
        return _obj({"chat": target, "message_id": positive_id}, ("chat", "message_id"))
    if oid == "downloadTelegramMediaSingle":
        return _download_item_schema()
    if oid == "downloadTelegramMediaBulk":
        return _obj({"items": {"type": "array", "minItems": 1, "maxItems": 100, "items": _download_item_schema()}}, ("items",))
    if oid == "resumeTelegramDownload":
        return _obj({"job_id": {"type": "string", "minLength": 1, "maxLength": 128}}, ("job_id",))
    if oid == "createTelegramArchive":
        return _obj({"file_refs": {"type": "array", "minItems": 1, "maxItems": 200, "uniqueItems": True, "items": {"type": "string", "minLength": 1, "maxLength": 128}}, "name": {"type": "string", "maxLength": 180}}, ("file_refs",))
    if oid == "getStoredTelegramFile":
        return _obj({"file_ref": {"type": "string", "minLength": 1, "maxLength": 128}}, ("file_ref",))

    if spec.operation_class is OperationClass.WRITE_COMMIT:
        return _obj({
            "preview_token": {"type": "string", "minLength": 24, "maxLength": 256, "writeOnly": True},
            "idempotency_key": {"type": "string", "minLength": 8, "maxLength": 200, "writeOnly": True},
            "explicit_user_command": {"type": "boolean", "const": True, "description": "Must reflect an explicit current user instruction to commit this exact preview."},
        }, ("preview_token", "idempotency_key", "explicit_user_command"))

    if spec.action == "SEND":
        return _obj({"chat": target, "text": {"type": "string", "minLength": 1, "maxLength": 4096}}, ("chat", "text"))
    if spec.action == "REPLY":
        return _obj({"chat": target, "reply_to_message_id": positive_id, "text": {"type": "string", "minLength": 1, "maxLength": 4096}}, ("chat", "reply_to_message_id", "text"))
    if spec.action == "FORWARD":
        return _obj({"from_chat": target, "to_chat": target, "message_ids": {"type": "array", "minItems": 1, "maxItems": 100, "uniqueItems": True, "items": positive_id}}, ("from_chat", "to_chat", "message_ids"))
    if spec.action == "SEND_FILES":
        file_ref = _obj({"file_ref": {"type": "string", "minLength": 1, "maxLength": 128}, "sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"}, "size": {"type": "integer", "minimum": 1, "maximum": 104857600}}, ("file_ref", "sha256", "size"))
        return _obj({"chat": target, "files": {"type": "array", "minItems": 1, "maxItems": 10, "items": file_ref}, "caption": {"type": "string", "maxLength": 4096}, "reply_to_message_id": positive_id, "voice_note": {"type": "boolean"}}, ("chat", "files"))
    raise OpenAPIContractError(f"REQUEST_SCHEMA_MISSING:{spec.operation_id}")


_SUMMARIES = {
    "listTelegramDialogs": "List Telegram dialogs",
    "readTelegramHistory": "Read Telegram history",
    "searchTelegramMessages": "Search Telegram messages",
    "getTelegramMediaMetadata": "Get Telegram media metadata",
    "downloadTelegramMediaSingle": "Download one Telegram media item",
    "downloadTelegramMediaBulk": "Download multiple Telegram media items",
    "resumeTelegramDownload": "Resume a Telegram download job",
    "createTelegramArchive": "Create a private Telegram file archive",
    "getStoredTelegramFile": "Get one private stored Telegram file",
    "previewTelegramSend": "Preview a Telegram send",
    "commitTelegramSend": "Commit an explicitly approved Telegram send",
    "previewTelegramReply": "Preview a Telegram reply",
    "commitTelegramReply": "Commit an explicitly approved Telegram reply",
    "previewTelegramForward": "Preview a Telegram forward",
    "commitTelegramForward": "Commit an explicitly approved Telegram forward",
    "previewTelegramFiles": "Preview sending files to Telegram",
    "commitTelegramFiles": "Commit an explicitly approved Telegram file send",
}


def build_action_openapi(base_url: str) -> dict[str, Any]:
    parts = urlsplit(str(base_url).strip())
    if parts.scheme.lower() != "https" or not parts.hostname or parts.username or parts.password or parts.query or parts.fragment:
        raise OpenAPIContractError("HTTPS_SERVER_URL_REQUIRED")
    if parts.path not in {"", "/"}:
        raise OpenAPIContractError("SERVER_URL_MUST_NOT_EMBED_PRIVATE_ROUTE")
    paths: dict[str, Any] = {}
    for spec in OPERATIONS:
        consequential = spec.operation_class is OperationClass.WRITE_COMMIT
        description = _SUMMARIES[spec.operation_id]
        if spec.operation_class is OperationClass.WRITE_PREVIEW:
            description += ". This creates a short-lived preview only and performs no Telegram write."
        elif spec.operation_class is OperationClass.WRITE_COMMIT:
            description += ". Call only after the user explicitly commands the exact preview to be committed; never infer approval from a draft or prior turn."
        operation: dict[str, Any] = {
            "operationId": spec.operation_id,
            "summary": _SUMMARIES[spec.operation_id],
            "description": description,
            "security": [{"BearerAuth": []}],
            "x-openai-isConsequential": consequential,
            "requestBody": {"required": True, "content": {"application/json": {"schema": _request_schema(spec)}}},
            "responses": {
                "200": {"description": "Successful private bridge response", "content": {"application/json": {"schema": _ref("SuccessResponse")}}},
                "400": {"description": "Invalid request", "content": {"application/json": {"schema": _ref("ErrorResponse")}}},
                "404": {"description": "Not found or unauthorized", "content": {"application/json": {"schema": _ref("ErrorResponse")}}},
                "409": {"description": "Preview/idempotency/write-state conflict", "content": {"application/json": {"schema": _ref("ErrorResponse")}}},
                "429": {"description": "Rate/FloodWait response", "content": {"application/json": {"schema": _ref("ErrorResponse")}}},
                "503": {"description": "Private bridge dependency unavailable", "content": {"application/json": {"schema": _ref("ErrorResponse")}}},
            },
            # Informational only; validator classification comes from OPERATIONS.
            "x-bridge-operation-class": spec.operation_class.value,
        }
        if spec.action:
            operation["x-bridge-write-action"] = spec.action
        if spec.pair_operation_id:
            operation["x-bridge-pair-operation-id"] = spec.pair_operation_id
        if spec.explicit_user_commit_required:
            operation["x-bridge-explicit-user-commit-required"] = True
        if spec.k5_test_safe_destination_required:
            operation["x-bridge-k5-test-safe-destination-required"] = True
        paths.setdefault(spec.path, {})[spec.method.lower()] = operation

    return {
        "openapi": "3.1.0",
        "info": {"title": "Private Telegram Bridge", "version": "dev4-contract-v2", "description": "Private personal Telegram user-account bridge for ChatGPT. Writes require preview plus an explicit commit command."},
        "servers": [{"url": f"https://{parts.netloc}"}],
        "security": [{"BearerAuth": []}],
        "paths": paths,
        "components": {
            "securitySchemes": {"BearerAuth": {"type": "http", "scheme": "bearer", "bearerFormat": "opaque"}},
            "schemas": {
                "SuccessResponse": _obj({"request_id": {"type": "string"}, "status": {"type": "string"}}),
                "ErrorResponse": _obj({"request_id": {"type": "string"}, "error": {"type": "string", "minLength": 1, "maxLength": 128}, "retry_after_seconds": {"type": "integer", "minimum": 1, "maximum": 600}}, ("error",)),
                "K5TestSafeDestination": _obj({"alias": {"type": "string", "pattern": "^test-safe:[A-Za-z0-9_-]{1,64}$", "description": "Opaque preconfigured test alias selected only after independent audit; never a real destination in public source."}}, ("alias",)),
            },
        },
    }


def _scan_forbidden_content(value: Any, *, path: str = "$") -> list[str]:
    errors: list[str] = []
    if isinstance(value, Mapping):
        for key, child in value.items():
            if str(key).casefold() in _SECRET_FIELD_WORDS:
                errors.append(f"SECRET_FIELD_EXPOSED:{path}.{key}")
            errors.extend(_scan_forbidden_content(child, path=f"{path}.{key}"))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            errors.extend(_scan_forbidden_content(child, path=f"{path}[{index}]"))
    elif isinstance(value, str):
        cf = value.casefold()
        if "bearer " in cf or "tg_api_hash" in cf or "session_string" in cf or "setup_route" in cf:
            errors.append(f"SECRET_OR_PRIVATE_EXAMPLE:{path}")
        if any(word in cf for word in ("/setup/", "/bootstrap/", "/authorize/")):
            errors.append(f"PRIVATE_SETUP_ROUTE_EXPOSED:{path}")
    return errors


def validate_action_openapi(schema: Mapping[str, Any]) -> list[str]:
    errors = validate_registry()
    if not isinstance(schema, Mapping) or not str(schema.get("openapi", "")).startswith("3.1"):
        return sorted(set(errors + ["OPENAPI_VERSION"]))
    paths = schema.get("paths")
    if not isinstance(paths, Mapping):
        return sorted(set(errors + ["PATHS_MISSING"]))

    actual: set[tuple[str, str]] = set()
    operation_ids: set[str] = set()
    for path, item in paths.items():
        if not isinstance(item, Mapping):
            errors.append(f"INVALID_PATH_ITEM:{path}")
            continue
        if any(word in str(path).casefold() for word in _PRIVATE_ROUTE_WORDS):
            errors.append(f"PRIVATE_SETUP_ROUTE_EXPOSED:{path}")
        for method, operation in item.items():
            if str(method).lower() not in {"get", "post", "put", "patch", "delete"}:
                continue
            key = (str(path), str(method).lower())
            actual.add(key)
            spec = _REGISTRY.get(key)
            if spec is None:
                errors.append(f"UNKNOWN_SCHEMA_OPERATION:{method}:{path}")
                continue
            if not isinstance(operation, Mapping):
                errors.append(f"INVALID_OPERATION:{spec.operation_id}")
                continue
            operation_id = operation.get("operationId")
            if operation_id != spec.operation_id:
                errors.append(f"OPERATION_ID_MISMATCH:{spec.operation_id}")
            elif operation_id in operation_ids:
                errors.append(f"DUPLICATE_OPERATION_ID:{operation_id}")
            else:
                operation_ids.add(str(operation_id))
            if spec.protected and operation.get("security") != [{"BearerAuth": []}]:
                errors.append(f"PROTECTED_WITHOUT_BEARER:{spec.operation_id}")
            if "responses" not in operation:
                errors.append(f"RESPONSES_MISSING:{spec.operation_id}")
            if spec.operation_class is OperationClass.WRITE_PREVIEW and operation.get("x-openai-isConsequential") is not False:
                errors.append(f"PREVIEW_MUST_NOT_BE_CONSEQUENTIAL:{spec.operation_id}")
            if spec.operation_class is OperationClass.WRITE_COMMIT:
                if operation.get("x-openai-isConsequential") is not True:
                    errors.append(f"COMMIT_MUST_BE_CONSEQUENTIAL:{spec.operation_id}")
                body = (((operation.get("requestBody") or {}).get("content") or {}).get("application/json") or {}).get("schema") or {}
                required = set(body.get("required") or []) if isinstance(body, Mapping) else set()
                if {"preview_token", "idempotency_key", "explicit_user_command"} - required:
                    errors.append(f"COMMIT_GATES_MISSING:{spec.operation_id}")
                props = body.get("properties") if isinstance(body, Mapping) else None
                explicit = props.get("explicit_user_command") if isinstance(props, Mapping) else None
                if not isinstance(explicit, Mapping) or explicit.get("const") is not True:
                    errors.append(f"EXPLICIT_USER_COMMAND_NOT_CONST_TRUE:{spec.operation_id}")
    for key in set(_REGISTRY) - actual:
        errors.append(f"REGISTRY_OPERATION_UNDOCUMENTED:{key[1]}:{key[0]}")

    schemes = ((schema.get("components") or {}).get("securitySchemes") or {}) if isinstance(schema.get("components"), Mapping) else {}
    bearer = schemes.get("BearerAuth") if isinstance(schemes, Mapping) else None
    if not isinstance(bearer, Mapping) or bearer.get("type") != "http" or str(bearer.get("scheme", "")).casefold() != "bearer":
        errors.append("BEARER_SCHEME_INVALID")
    servers = schema.get("servers")
    if not isinstance(servers, list) or len(servers) != 1 or not isinstance(servers[0], Mapping):
        errors.append("SERVER_URL_INVALID")
    else:
        parts = urlsplit(str(servers[0].get("url", "")))
        if parts.scheme.lower() != "https" or not parts.hostname or parts.path not in {"", "/"} or parts.query or parts.fragment or parts.username or parts.password:
            errors.append("SERVER_URL_INVALID")
    errors.extend(_scan_forbidden_content(schema))
    return sorted(set(errors))


def assert_action_openapi_safe(schema: Mapping[str, Any]) -> None:
    errors = validate_action_openapi(schema)
    if errors:
        raise OpenAPIContractError(";".join(errors))


def serialized_action_openapi(base_url: str) -> str:
    schema = build_action_openapi(base_url)
    assert_action_openapi_safe(schema)
    return json.dumps(schema, ensure_ascii=False, sort_keys=True, separators=(",", ":"))