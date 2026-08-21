"""Dependency-injected, read-only WSGI surface for Telegram Bridge.

Importing this module never connects to Telegram and never requires credentials.
The default application fails closed until server-side dependencies are injected
or configured. Write/send/forward operations intentionally do not exist here.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
from dataclasses import dataclass
from io import BytesIO
from pathlib import Path
from typing import Any, Callable, Iterable
from urllib.parse import parse_qs

from .archive import ArchiveBuilder
from .audit import AuditLog
from .backend import ReadBackend, UnavailableReadBackend
from .downloads import DownloadManager
from .errors import BridgeError, HiddenNotFound
from .models import MessageRecord
from .security import BearerGuard, FileSigner, RateLimiter, RejectingRateLimiter
from .storage import CheckpointStore, DownloadItem, FileRecordStore
from .validation import (
    bool_value,
    bounded_int,
    bounded_text,
    date_range,
    entity_ref,
    require_dict,
    validate_file_ref,
)

JSON_TYPE = "application/json; charset=utf-8"


@dataclass(frozen=True)
class ReadAppConfig:
    auth_secret: str | None = None
    file_signing_secret: str | None = None
    private_root: Path | None = None
    public_base_url: str = ""
    api_prefix: str = "/api/v1"
    max_json_bytes: int = 256 * 1024
    max_limit: int = 200
    max_search_scan: int = 2_000
    signed_file_ttl_seconds: int = 600

    @classmethod
    def from_env(cls) -> "ReadAppConfig":
        root = os.environ.get("BRIDGE_PRIVATE_ROOT")
        return cls(
            auth_secret=os.environ.get("BRIDGE_TOKEN") or None,
            file_signing_secret=os.environ.get("BRIDGE_FILE_SIGNING_SECRET") or None,
            private_root=Path(root) if root else None,
            public_base_url=(os.environ.get("BRIDGE_PUBLIC_BASE_URL") or "").rstrip("/"),
        )


class BridgeApplication:
    def __init__(
        self,
        *,
        config: ReadAppConfig | None = None,
        backend: ReadBackend | None = None,
        rate_limiter: RateLimiter | None = None,
        audit: AuditLog | None = None,
    ) -> None:
        self.config = config or ReadAppConfig.from_env()
        self.backend = backend or UnavailableReadBackend()
        self.rate_limiter = rate_limiter or RejectingRateLimiter()
        self.audit = audit or AuditLog()
        self.auth = BearerGuard(self.config.auth_secret) if self.config.auth_secret else None
        self.signer = FileSigner(self.config.file_signing_secret) if self.config.file_signing_secret else None

        self.files: FileRecordStore | None = None
        self.checkpoints: CheckpointStore | None = None
        self.downloads: DownloadManager | None = None
        self.archives: ArchiveBuilder | None = None
        if self.config.private_root is not None:
            private = self.config.private_root.resolve()
            private.mkdir(parents=True, exist_ok=True)
            self.files = FileRecordStore(private / "state" / "files.sqlite3", private / "files")
            self.checkpoints = CheckpointStore(private / "state" / "downloads.sqlite3")
            self.downloads = DownloadManager(
                backend=self.backend,
                files=self.files,
                checkpoints=self.checkpoints,
                staging_dir=private / "tmp" / "downloads",
            )
            self.archives = ArchiveBuilder(files=self.files, output_dir=private / "tmp" / "archives")

    @staticmethod
    def _request_id() -> str:
        return secrets.token_hex(8)

    @staticmethod
    def _json_bytes(payload: dict[str, Any]) -> bytes:
        return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def _respond(
        self,
        start_response: Callable,
        status: int,
        payload: dict[str, Any],
        *,
        extra_headers: Iterable[tuple[str, str]] = (),
    ) -> list[bytes]:
        raw = self._json_bytes(payload)
        headers = [
            ("Content-Type", JSON_TYPE),
            ("Content-Length", str(len(raw))),
            ("Cache-Control", "no-store"),
            ("X-Content-Type-Options", "nosniff"),
            ("Referrer-Policy", "no-referrer"),
        ]
        headers.extend(extra_headers)
        phrase = {
            200: "OK", 400: "Bad Request", 404: "Not Found", 405: "Method Not Allowed",
            413: "Payload Too Large", 415: "Unsupported Media Type", 429: "Too Many Requests",
            500: "Internal Server Error", 502: "Bad Gateway", 503: "Service Unavailable", 504: "Gateway Timeout",
        }.get(status, "Error")
        start_response(f"{status} {phrase}", headers)
        return [raw]

    def _error(self, start_response: Callable, error: BridgeError, request_id: str) -> list[bytes]:
        extra: list[tuple[str, str]] = []
        if error.retry_after_seconds is not None:
            extra.append(("Retry-After", str(max(1, int(error.retry_after_seconds)))))
        self.audit.write("request_error", request_id=request_id, status=error.status, error_code=error.code)
        return self._respond(start_response, error.status, error.public_payload(request_id), extra_headers=extra)

    def _require_auth_and_rate(self, environ: dict[str, Any]) -> None:
        if self.auth is None:
            raise HiddenNotFound()
        self.auth.require(environ)
        # Never use credentials, IP addresses, chat names, or message text as
        # public evidence. This actor is a coarse authenticated API bucket.
        decision = self.rate_limiter.check("authenticated-read-api")
        if not decision.allowed:
            raise BridgeError(
                "Rate limit exceeded",
                status=429,
                code="rate_limited",
                retry_after_seconds=decision.retry_after_seconds or 1,
            )

    def _read_json(self, environ: dict[str, Any]) -> dict[str, Any]:
        content_type = str(environ.get("CONTENT_TYPE") or "").split(";", 1)[0].strip().casefold()
        if content_type != "application/json":
            raise BridgeError("Content-Type must be application/json", status=415, code="invalid_content_type")
        raw_length = environ.get("CONTENT_LENGTH")
        if raw_length in (None, ""):
            raise BridgeError("Content-Length is required", code="invalid_content_length")
        else:
            try:
                length = int(str(raw_length))
            except ValueError as exc:
                raise BridgeError("Invalid Content-Length", code="invalid_content_length") from exc
        if length < 0:
            raise BridgeError("Invalid Content-Length", code="invalid_content_length")
        if length > self.config.max_json_bytes:
            raise BridgeError("Request body is too large", status=413, code="request_too_large")
        stream = environ.get("wsgi.input") or BytesIO()
        raw = stream.read(self.config.max_json_bytes + 1 if length == 0 else min(length, self.config.max_json_bytes + 1))
        if len(raw) > self.config.max_json_bytes:
            raise BridgeError("Request body is too large", status=413, code="request_too_large")
        if length and len(raw) != length:
            raise BridgeError("Incomplete request body", code="incomplete_body")
        try:
            text = raw.decode("utf-8", "strict")
        except UnicodeDecodeError as exc:
            raise BridgeError("Request body must be valid UTF-8", code="invalid_utf8") from exc
        try:
            value = json.loads(text or "{}")
        except json.JSONDecodeError as exc:
            raise BridgeError("Malformed JSON", code="malformed_json") from exc
        return require_dict(value)

    @staticmethod
    def _only(body: dict[str, Any], allowed: set[str]) -> None:
        unknown = sorted(set(body) - allowed)
        if unknown:
            raise BridgeError("Request contains unsupported fields", code="unknown_field", details={"count": len(unknown)})

    def _limit(self, body: dict[str, Any], default: int = 50) -> int:
        return bounded_int(body.get("limit"), field="limit", default=default, minimum=1, maximum=self.config.max_limit)

    @staticmethod
    def _item_id(*parts: Any) -> str:
        return hashlib.sha256("\x1f".join(str(p) for p in parts).encode("utf-8")).hexdigest()[:32]

    @staticmethod
    def _page_payload(page: Any, *, include_text: bool) -> dict[str, Any]:
        items = []
        for item in page.items:
            if isinstance(item, MessageRecord):
                items.append(item.to_dict(include_text=include_text))
            else:
                items.append(item.to_dict())
        return {"items": items, "next_cursor": page.next_cursor, "scanned": page.scanned}

    def _ensure_storage(self) -> None:
        if not all((self.files, self.checkpoints, self.downloads, self.archives)):
            raise BridgeError("Private storage is not configured", status=503, code="private_storage_unconfigured")

    def _handle_post(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        p = self.config.api_prefix
        if path == f"{p}/dialogs/list":
            self._only(body, {"limit", "cursor", "query", "unread_only"})
            page = self.backend.list_dialogs(
                limit=self._limit(body),
                cursor=bounded_text(body.get("cursor"), field="cursor", maximum=1024) or None,
                query=bounded_text(body.get("query"), field="query", maximum=256),
                unread_only=bool_value(body.get("unread_only"), field="unread_only"),
            )
            return self._page_payload(page, include_text=False)

        if path == f"{p}/history/read":
            self._only(body, {"chat", "limit", "cursor"})
            page = self.backend.history(
                chat=entity_ref(body.get("chat")),
                limit=self._limit(body),
                cursor=bounded_text(body.get("cursor"), field="cursor", maximum=1024) or None,
            )
            return self._page_payload(page, include_text=True)

        if path == f"{p}/search":
            self._only(body, {"chat", "sender", "text", "date_from", "date_to", "limit", "cursor", "scan_limit"})
            chat = entity_ref(body.get("chat")) if body.get("chat") not in (None, "") else None
            sender = entity_ref(body.get("sender"), field="sender") if body.get("sender") not in (None, "") else None
            text = bounded_text(body.get("text"), field="text", maximum=512)
            dates = date_range(body.get("date_from"), body.get("date_to"))
            if not any((chat, sender, text.strip(), dates.start, dates.end)):
                raise BridgeError("At least one search filter is required", code="search_filter_required")
            page = self.backend.search(
                chat=chat,
                sender=sender,
                text=text,
                dates=dates,
                limit=self._limit(body),
                cursor=bounded_text(body.get("cursor"), field="cursor", maximum=1024) or None,
                scan_limit=bounded_int(
                    body.get("scan_limit"), field="scan_limit", default=min(500, self.config.max_search_scan),
                    minimum=1, maximum=self.config.max_search_scan,
                ),
            )
            return self._page_payload(page, include_text=True)

        if path == f"{p}/media/metadata":
            self._only(body, {"chat", "message_id"})
            record = self.backend.get_message(
                chat=entity_ref(body.get("chat")),
                message_id=bounded_int(body.get("message_id"), field="message_id", default=0, minimum=1, maximum=2**63 - 1),
            )
            return {"message_id": record.id, "chat_id": record.chat_id, "timestamp": record.timestamp, "media": [m.to_dict() for m in record.media]}

        if path in {f"{p}/downloads/single", f"{p}/downloads/bulk"}:
            self._ensure_storage()
            raws: list[dict[str, Any]]
            if path.endswith("/single"):
                self._only(body, {"chat", "message_id", "file_ref", "name", "mime_type", "expected_size", "expected_sha256"})
                raws = [body]
            else:
                self._only(body, {"items"})
                if not isinstance(body.get("items"), list) or len(body["items"]) > 100:
                    raise BridgeError("items must be a bounded list", code="invalid_list", details={"field": "items", "limit": 100})
                raws = [require_dict(x, "item") for x in body["items"]]
            items: list[DownloadItem] = []
            for raw in raws:
                self._only(raw, {"chat", "message_id", "file_ref", "name", "mime_type", "expected_size", "expected_sha256"})
                chat = entity_ref(raw.get("chat"))
                mid = bounded_int(raw.get("message_id"), field="message_id", default=0, minimum=1, maximum=2**63 - 1)
                source_ref = validate_file_ref(raw.get("file_ref"))
                name = bounded_text(raw.get("name"), field="name", maximum=180) or f"message-{mid}.bin"
                mime = bounded_text(raw.get("mime_type"), field="mime_type", maximum=160) or "application/octet-stream"
                size = None if raw.get("expected_size") is None else bounded_int(raw.get("expected_size"), field="expected_size", default=0, minimum=0, maximum=100 * 1024 * 1024)
                digest = bounded_text(raw.get("expected_sha256"), field="expected_sha256", maximum=64) or None
                if digest and (len(digest) != 64 or any(c not in "0123456789abcdefABCDEF" for c in digest)):
                    raise BridgeError("expected_sha256 is invalid", code="invalid_hash")
                items.append(DownloadItem(self._item_id(chat, mid, source_ref), chat, mid, source_ref, name, mime, size, digest.lower() if digest else None))
            assert self.downloads is not None
            return self.downloads.start_single(items[0]) if path.endswith("/single") else self.downloads.start_bulk(items)

        if path == f"{p}/downloads/resume":
            self._only(body, {"job_id"})
            self._ensure_storage()
            job_id = bounded_text(body.get("job_id"), field="job_id", maximum=128, allow_empty=False)
            assert self.downloads is not None
            return self.downloads.resume(job_id)

        if path == f"{p}/archives/create":
            self._only(body, {"file_refs", "name"})
            self._ensure_storage()
            refs = body.get("file_refs")
            if not isinstance(refs, list) or not refs or len(refs) > 200:
                raise BridgeError("file_refs must be a bounded list", code="invalid_list", details={"field": "file_refs", "limit": 200})
            safe_refs = [validate_file_ref(ref) for ref in refs]
            name = bounded_text(body.get("name"), field="name", maximum=180) or "telegram-files.zip"
            assert self.archives is not None
            return self.archives.build(safe_refs, archive_name=name).public_metadata()

        if path == f"{p}/files/get":
            self._only(body, {"file_ref"})
            self._ensure_storage()
            ref = validate_file_ref(body.get("file_ref"))
            assert self.files is not None
            record = self.files.get(ref)
            if record is None:
                raise HiddenNotFound()
            payload = record.public_metadata()
            payload["download_path"] = f"{p}/files/{ref}"
            if self.signer is not None and self.config.public_base_url:
                url, exp = self.signer.issue(
                    base_url=self.config.public_base_url,
                    route_prefix=f"{p}/files",
                    file_ref=ref,
                    ttl_seconds=self.config.signed_file_ttl_seconds,
                )
                payload["signed_url"] = url
                payload["expires_at"] = exp
            return payload

        raise HiddenNotFound()

    def _serve_file(self, environ: dict[str, Any], start_response: Callable, path: str) -> list[bytes]:
        self._ensure_storage()
        prefix = f"{self.config.api_prefix}/files/"
        ref = validate_file_ref(path[len(prefix) :])
        authorized = False
        if self.auth is not None:
            try:
                self.auth.require(environ)
                authorized = True
            except HiddenNotFound:
                authorized = False
        if not authorized and self.signer is not None:
            query = parse_qs(str(environ.get("QUERY_STRING") or ""), keep_blank_values=True)
            authorized = self.signer.verify(ref, (query.get("exp") or [None])[0], (query.get("sig") or [None])[0])
        if not authorized:
            raise HiddenNotFound()
        assert self.files is not None
        record = self.files.get(ref)
        if record is None:
            raise HiddenNotFound()
        path_obj = Path(record.path)
        size = path_obj.stat().st_size
        headers = [
            ("Content-Type", record.mime_type or "application/octet-stream"),
            ("Content-Length", str(size)),
            ("Cache-Control", "private, no-store"),
            ("X-Content-Type-Options", "nosniff"),
            ("Content-Disposition", "attachment"),
        ]
        start_response("200 OK", headers)
        def body_iter():
            with path_obj.open("rb") as fh:
                while True:
                    chunk = fh.read(1024 * 1024)
                    if not chunk:
                        break
                    yield chunk
        return body_iter()

    def __call__(self, environ: dict[str, Any], start_response: Callable) -> list[bytes]:
        request_id = self._request_id()
        method = str(environ.get("REQUEST_METHOD") or "GET").upper()
        path = str(environ.get("PATH_INFO") or "/")
        try:
            if path == "/health":
                if method != "GET":
                    raise BridgeError("Method not allowed", status=405, code="method_not_allowed")
                components = {
                    "auth": "configured" if self.auth else "unconfigured",
                    "backend": "configured" if not isinstance(self.backend, UnavailableReadBackend) else "unconfigured",
                    "storage": "configured" if self.files else "unconfigured",
                    "rate_limit": "configured" if not isinstance(self.rate_limiter, RejectingRateLimiter) else "unconfigured",
                }
                ready = all(v == "configured" for v in components.values())
                return self._respond(start_response, 200, {"ok": True, "service": "telegram-bridge", "ready": ready, "components": components})

            if method == "GET" and path.startswith(f"{self.config.api_prefix}/files/"):
                return self._serve_file(environ, start_response, path)

            if method != "POST" or not path.startswith(f"{self.config.api_prefix}/"):
                raise HiddenNotFound()
            self._require_auth_and_rate(environ)
            body = self._read_json(environ)
            result = self._handle_post(path, body)
            self.audit.write("request_ok", request_id=request_id, route=path, method=method, status=200)
            return self._respond(start_response, 200, {"ok": True, "request_id": request_id, "data": result})
        except BridgeError as exc:
            return self._error(start_response, exc, request_id)
        except Exception:
            # Raw exception messages are deliberately not surfaced or audited.
            return self._error(start_response, BridgeError("Internal server error", status=500, code="internal_error"), request_id)


_default_app: BridgeApplication | None = None


def application(environ: dict[str, Any], start_response: Callable) -> list[bytes]:
    """Passenger/WSGI entry point. Construction is local-only and lazy."""
    global _default_app
    if _default_app is None:
        try:
            _default_app = BridgeApplication()
        except Exception:
            raw = b'{"ok":false,"error":{"code":"startup_configuration_error","message":"Application configuration is invalid"}}'
            start_response("500 Internal Server Error", [("Content-Type", JSON_TYPE), ("Content-Length", str(len(raw))), ("Cache-Control", "no-store")])
            return [raw]
    return _default_app(environ, start_response)
