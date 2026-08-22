"""Unified WSGI integration layer for Telegram Bridge read/media/write operations.

This module composes the DEV3 read/media application with DEV4 preview/commit
write safety without performing Telegram I/O at import time.  The canonical
ChatGPT/private-API operation registry is ``ops.openapi_registry.OPERATIONS``.
DEV3's read route registry remains a compatibility-tested runtime router and is
validated here against every canonical READ operation so schema/runtime drift
fails at import/CI instead of being discovered in production.

Production safety defaults are fail-closed:
- no private root => no persistent preview/idempotency store;
- no explicit write limiter => write endpoints reject with 503;
- no injected Telegram writer => commit rejects before consuming a preview;
- preview never calls Telegram;
- commit crosses the external-effect boundary only inside PersistentWriteStore.
"""
from __future__ import annotations

import hashlib
from collections.abc import Mapping
from typing import Any, Callable, Iterable

from .app import BridgeApplication
from .backend import UnavailableReadBackend
from .errors import BridgeError, HiddenNotFound
from .routes import READ_ROUTE_REGISTRY
from .security import RejectingRateLimiter

from ops.openapi_registry import API_PREFIX, OPERATIONS, OperationClass, OperationSpec, canonical_operation, validate_registry
from ops.telegram_write_adapter import TelegramWriteAdapter
from ops.write_endpoint_policy import (
    EndpointContext,
    EndpointPolicyError,
    FixedWindowEndpointLimiter,
    WriteCoordinator,
    WriteEndpointPolicy,
    structured_write_error,
)
from ops.write_safety import PersistentWriteStore, WriteSafetyError


_AUTHENTICATED_WRITE_ACTOR = hashlib.sha256(b"authenticated-write-api-v1").hexdigest()


class _RejectingWriteLimiter:
    """Fail closed until a bounded write limiter is explicitly injected."""

    def consume(self, actor_sha256: str, operation_id: str) -> tuple[int, int]:
        del actor_sha256, operation_id
        raise EndpointPolicyError("write_rate_limiter_unconfigured", status=503)


def validate_unified_registry() -> tuple[tuple[str, str], ...]:
    """Validate canonical OpenAPI/runtime parity for all Action-visible READ routes.

    Health and the bearer/signed raw-file GET are intentionally not ChatGPT Action
    operations.  Write routes are dispatched directly from OPERATIONS, so they do
    not have a second runtime path table to drift from.
    """
    registry_errors = validate_registry()
    if registry_errors:
        raise RuntimeError("canonical operation registry invalid")

    schema_reads = {
        (spec.method.upper(), spec.path)
        for spec in OPERATIONS
        if spec.operation_class is OperationClass.READ
    }
    runtime_reads = {
        (spec.method, spec.concrete_path(API_PREFIX))
        for spec in READ_ROUTE_REGISTRY
        if spec.operation_class == "read" and not spec.dynamic_tail
    }
    if schema_reads != runtime_reads:
        raise RuntimeError("READ_ROUTE_OPENAPI_PARITY_MISMATCH")

    return tuple(sorted(schema_reads))


_UNIFIED_READ_PARITY = validate_unified_registry()


class UnifiedBridgeApplication:
    """One WSGI surface that preserves DEV3 reads and adds safe DEV4 writes."""

    def __init__(
        self,
        *,
        read_app: BridgeApplication | None = None,
        write_adapter: TelegramWriteAdapter | None = None,
        write_limiter: FixedWindowEndpointLimiter | Any | None = None,
        preview_ttl_seconds: int = 300,
    ) -> None:
        self.read_app = read_app or BridgeApplication()
        self.write_adapter = write_adapter
        self._write_limiter = write_limiter if write_limiter is not None else _RejectingWriteLimiter()
        self.write_store: PersistentWriteStore | None = None
        self.write_coordinator: WriteCoordinator | None = None

        private_root = self.read_app.config.private_root
        if private_root is not None:
            self.write_store = PersistentWriteStore(
                private_root.resolve() / "state" / "writes.sqlite3",
                preview_ttl_seconds=preview_ttl_seconds,
            )
            self.write_coordinator = WriteCoordinator(
                self.write_store,
                WriteEndpointPolicy(self._write_limiter),
            )

    @staticmethod
    def _operation_for_request(method: str, path: str) -> OperationSpec | None:
        try:
            return canonical_operation(path, method)
        except Exception:
            return None

    def _health(self, start_response: Callable) -> list[bytes]:
        components = {
            "auth": "configured" if self.read_app.auth else "unconfigured",
            "backend": "configured" if not isinstance(self.read_app.backend, UnavailableReadBackend) else "unconfigured",
            "storage": "configured" if self.read_app.files else "unconfigured",
            "read_rate_limit": "configured" if not isinstance(self.read_app.rate_limiter, RejectingRateLimiter) else "unconfigured",
            "write_store": "configured" if self.write_store else "unconfigured",
            "write_rate_limit": "configured" if not isinstance(self._write_limiter, _RejectingWriteLimiter) else "unconfigured",
            "telegram_writer": "configured" if self.write_adapter is not None else "unconfigured",
        }
        ready = all(value == "configured" for value in components.values())
        return self.read_app._respond(
            start_response,
            200,
            {"ok": True, "service": "telegram-bridge", "ready": ready, "components": components},
        )

    def _require_write_auth(self, environ: dict[str, Any]) -> EndpointContext:
        if self.read_app.auth is None:
            raise HiddenNotFound()
        self.read_app.auth.require(environ)
        # Deliberately use a fixed service-class hash, not a token-derived hash.
        return EndpointContext(authenticated=True, actor_sha256=_AUTHENTICATED_WRITE_ACTOR)

    @staticmethod
    def _preview_payload(spec: OperationSpec, body: dict[str, Any]) -> dict[str, Any]:
        action = spec.action
        if action == "SEND":
            BridgeApplication._only(body, {"chat", "text"})
            return {"target": body.get("chat"), "text": body.get("text")}
        if action == "REPLY":
            BridgeApplication._only(body, {"chat", "reply_to_message_id", "text"})
            return {
                "target": body.get("chat"),
                "reply_to_message_id": body.get("reply_to_message_id"),
                "text": body.get("text"),
            }
        if action == "FORWARD":
            BridgeApplication._only(body, {"from_chat", "to_chat", "message_ids"})
            return {
                "source": body.get("from_chat"),
                "target": body.get("to_chat"),
                "message_ids": body.get("message_ids"),
            }
        if action == "SEND_FILES":
            BridgeApplication._only(body, {"chat", "files", "caption", "reply_to_message_id", "voice_note"})
            raw_files = body.get("files")
            if isinstance(raw_files, list):
                for item in raw_files:
                    if not isinstance(item, Mapping):
                        raise BridgeError("Invalid file reference", status=400, code="invalid_file_reference")
                    unknown = set(item) - {"file_ref", "sha256", "size"}
                    if unknown:
                        raise BridgeError(
                            "File reference contains unsupported fields",
                            status=400,
                            code="unknown_field",
                            details={"count": len(unknown)},
                        )
            return {
                "target": body.get("chat"),
                "files": body.get("files"),
                "caption": body.get("caption", ""),
                "reply_to_message_id": body.get("reply_to_message_id"),
                "voice_note": body.get("voice_note", False),
            }
        raise BridgeError("Unsupported write operation", status=404, code="not_found")

    @staticmethod
    def _public_preview_payload(action: str, payload: Mapping[str, Any]) -> dict[str, Any]:
        if action == "SEND":
            return {"chat": payload.get("target"), "text": payload.get("text")}
        if action == "REPLY":
            return {
                "chat": payload.get("target"),
                "reply_to_message_id": payload.get("reply_to_message_id"),
                "text": payload.get("text"),
            }
        if action == "FORWARD":
            return {
                "from_chat": payload.get("source"),
                "to_chat": payload.get("target"),
                "message_ids": list(payload.get("message_ids") or []),
            }
        if action == "SEND_FILES":
            files = []
            for raw in payload.get("files") or []:
                if isinstance(raw, Mapping):
                    files.append(
                        {
                            "file_ref": raw.get("file_id"),
                            "sha256": raw.get("sha256"),
                            "size": raw.get("size"),
                        }
                    )
            out: dict[str, Any] = {
                "chat": payload.get("target"),
                "files": files,
                "caption": payload.get("caption", ""),
                "voice_note": bool(payload.get("voice_note", False)),
            }
            if payload.get("reply_to_message_id") is not None:
                out["reply_to_message_id"] = payload.get("reply_to_message_id")
            return out
        raise BridgeError("Unsupported write operation", status=404, code="not_found")

    @staticmethod
    def _receipt_metadata(receipt: Any, expected_action: str) -> dict[str, Any]:
        if isinstance(receipt, Mapping):
            operation = receipt.get("operation")
            message_ids = receipt.get("message_ids")
            chat_id = receipt.get("chat_id")
            count = receipt.get("count")
        else:
            operation = getattr(receipt, "operation", None)
            message_ids = getattr(receipt, "message_ids", None)
            chat_id = getattr(receipt, "chat_id", None)
            count = getattr(receipt, "count", None)

        if operation != expected_action:
            raise RuntimeError("telegram receipt operation mismatch")
        if not isinstance(message_ids, (tuple, list)) or not 1 <= len(message_ids) <= 100:
            raise RuntimeError("telegram receipt message IDs invalid")
        safe_ids: list[int] = []
        for raw in message_ids:
            if isinstance(raw, bool) or not isinstance(raw, int) or raw <= 0:
                raise RuntimeError("telegram receipt message ID invalid")
            safe_ids.append(raw)
        if isinstance(count, bool) or not isinstance(count, int) or count != len(safe_ids):
            raise RuntimeError("telegram receipt count mismatch")
        if chat_id is not None and (isinstance(chat_id, bool) or not isinstance(chat_id, int)):
            raise RuntimeError("telegram receipt chat ID invalid")
        return {
            "operation": operation,
            "message_ids": safe_ids,
            "chat_id": chat_id,
            "count": count,
        }

    def _execute_external_write(self, action: str, payload: dict[str, Any]) -> Mapping[str, Any]:
        adapter = self.write_adapter
        if adapter is None:
            # Caller checks this before PersistentWriteStore crosses CALLING.
            raise RuntimeError("writer unexpectedly unavailable")

        if action == "SEND":
            receipt = adapter.send(payload["target"], payload["text"])
        elif action == "REPLY":
            receipt = adapter.reply(payload["target"], payload["reply_to_message_id"], payload["text"])
        elif action == "FORWARD":
            receipt = adapter.forward(payload["source"], payload["target"], payload["message_ids"])
        elif action == "SEND_FILES":
            if self.read_app.files is None:
                raise RuntimeError("private file store unavailable")
            paths: list[str] = []
            for item in payload["files"]:
                record = self.read_app.files.get(item["file_id"])
                if record is None:
                    raise RuntimeError("registered private file unavailable")
                if record.sha256 != item["sha256"] or record.size != item["size"]:
                    raise RuntimeError("registered private file identity mismatch")
                paths.append(record.path)
            receipt = adapter.send_files(
                payload["target"],
                paths,
                caption=payload.get("caption", ""),
                reply_to_message_id=payload.get("reply_to_message_id"),
                voice_note=bool(payload.get("voice_note", False)),
            )
        else:
            raise RuntimeError("unsupported external write action")
        return self._receipt_metadata(receipt, action)

    def _write_error(self, start_response: Callable, exc: BaseException, request_id: str) -> list[bytes]:
        if isinstance(exc, BridgeError):
            return self.read_app._error(start_response, exc, request_id)
        meta = structured_write_error(exc)
        status = int(meta.get("status", 500))
        code = str(meta.get("error") or "internal_bridge_error")[:80]
        retry = meta.get("retry_after_seconds")
        if not isinstance(retry, int) or retry <= 0:
            retry = None
        if status == 503:
            message = "Write service is unavailable"
        elif status == 404:
            message = "Not found"
        elif status == 429:
            message = "Write rate limit exceeded"
        else:
            message = "Write request was rejected"
        return self.read_app._error(
            start_response,
            BridgeError(message, status=status, code=code, retry_after_seconds=retry),
            request_id,
        )

    def _handle_write(
        self,
        spec: OperationSpec,
        environ: dict[str, Any],
        start_response: Callable,
    ) -> Iterable[bytes]:
        request_id = self.read_app._request_id()
        try:
            context = self._require_write_auth(environ)
            if self.write_coordinator is None or self.write_store is None:
                raise BridgeError("Write store is not configured", status=503, code="write_store_unconfigured")

            body = self.read_app._read_json(environ)
            if spec.operation_class is OperationClass.WRITE_PREVIEW:
                private_payload = self._preview_payload(spec, body)
                preview = self.write_coordinator.preview(spec.operation_id, context, private_payload)
                public_payload = self._public_preview_payload(preview.action.value, preview.payload)
                self.read_app.audit.write(
                    "write_preview",
                    request_id=request_id,
                    route=spec.operation_id,
                    method="POST",
                    status=200,
                    file_count=len(public_payload.get("files", [])) if isinstance(public_payload.get("files"), list) else 0,
                )
                return self.read_app._respond(
                    start_response,
                    200,
                    {
                        "ok": True,
                        "request_id": request_id,
                        "data": {
                            "preview_token": preview.token,
                            "preview_id": preview.preview_id,
                            "action": preview.action.value,
                            "request_fingerprint": preview.request_fingerprint,
                            "expires_at": preview.expires_at,
                            "preview": public_payload,
                        },
                    },
                )

            if spec.operation_class is not OperationClass.WRITE_COMMIT:
                raise HiddenNotFound()
            self.read_app._only(body, {"preview_token", "idempotency_key", "explicit_user_command"})
            if self.write_adapter is None:
                # Do not reserve/consume the preview until a real writer exists.
                raise BridgeError("Telegram writer is not configured", status=503, code="telegram_writer_unconfigured")
            commit_context = EndpointContext(
                authenticated=context.authenticated,
                actor_sha256=context.actor_sha256,
                explicit_user_command=body.get("explicit_user_command") is True,
            )
            result = self.write_coordinator.commit(
                spec.operation_id,
                commit_context,
                preview_token=body.get("preview_token"),
                idempotency_key=body.get("idempotency_key"),
                external_write=lambda payload: self._execute_external_write(spec.action or "", payload),
            )
            self.read_app.audit.write(
                "write_commit",
                request_id=request_id,
                route=spec.operation_id,
                method="POST",
                status=200,
            )
            return self.read_app._respond(
                start_response,
                200,
                {
                    "ok": True,
                    "request_id": request_id,
                    "data": {
                        "state": result.state,
                        "idempotent_replay": result.idempotent_replay,
                        "request_fingerprint": result.request_fingerprint,
                        "result": result.result,
                    },
                },
            )
        except BaseException as exc:
            # Raw exception strings are never copied to the response or audit sink.
            return self._write_error(start_response, exc, request_id)

    def __call__(self, environ: dict[str, Any], start_response: Callable) -> Iterable[bytes]:
        method = str(environ.get("REQUEST_METHOD") or "GET").upper()
        path = str(environ.get("PATH_INFO") or "/")

        if method == "GET" and path == "/health":
            return self._health(start_response)

        spec = self._operation_for_request(method, path)
        if spec is None or spec.operation_class is OperationClass.READ:
            return self.read_app(environ, start_response)
        return self._handle_write(spec, environ, start_response)


_default_application: UnifiedBridgeApplication | None = None


def application(environ: dict[str, Any], start_response: Callable) -> Iterable[bytes]:
    """Lazy production-facing WSGI entry point; construction performs no Telegram I/O."""
    global _default_application
    if _default_application is None:
        try:
            _default_application = UnifiedBridgeApplication()
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
