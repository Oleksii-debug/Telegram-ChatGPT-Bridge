# -*- coding: utf-8 -*-
"""Opaque Bridge-file policy for Telegram send-files.

Canonical Telegram send-files uses private Bridge file references only. Legacy
external-URL entry points are retained as fail-closed compatibility stubs so a
future caller cannot accidentally turn validation helpers into an SSRF fetch
boundary.

There is intentionally no resolver, redirect walker or HTTP client here.
Resolve-then-connect IP checks are not DNS pinning and must not be represented as
such. Any future remote-URL ingestion feature requires a new independently
audited address-bound transport and is outside the current Action contract.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import PurePath
from typing import Iterable, Sequence


class FileSendPolicyError(RuntimeError):
    def __init__(self, code: str, *, status: int = 400):
        super().__init__(code)
        self.code = code
        self.status = status


_EXTERNAL_URL_DISABLED = "external_url_sources_disabled"


@dataclass(frozen=True)
class HttpsFetchPolicy:
    """Legacy compatibility shape; external fetching is disabled."""

    max_bytes: int = 100 * 1024 * 1024
    timeout_seconds: int = 20
    max_redirects: int = 0

    def __post_init__(self) -> None:
        if self.max_bytes <= 0 or self.max_bytes > 512 * 1024 * 1024:
            raise ValueError("bounded fetch size required")
        if self.timeout_seconds <= 0 or self.timeout_seconds > 60:
            raise ValueError("bounded fetch timeout required")
        if self.max_redirects != 0:
            raise ValueError("external URL redirects are disabled")


@dataclass(frozen=True)
class ExternalFileReference:
    """Legacy data shape only; canonical code cannot create one from a URL."""

    url: str
    url_sha256: str
    safe_name: str
    declared_size: int | None
    declared_mime: str | None


@dataclass(frozen=True)
class BridgeFileReference:
    file_id: str
    sha256: str
    size: int
    mime_type: str | None = None


_MIME_RE = re.compile(r"^[A-Za-z0-9!#$&^_.+-]+/[A-Za-z0-9!#$&^_.+-]+$")


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _reject_external_url() -> None:
    raise FileSendPolicyError(_EXTERNAL_URL_DISABLED, status=403)


def validate_resolved_ips(values: Iterable[str]) -> tuple[str, ...]:
    """Fail closed: separate DNS resolution is not an approved fetch boundary."""
    del values
    _reject_external_url()


def safe_filename(value: str) -> str:
    if not isinstance(value, str):
        raise FileSendPolicyError("invalid_file_name")
    name = value.strip()
    if not name or len(name) > 180 or any(ord(ch) < 32 for ch in name):
        raise FileSendPolicyError("invalid_file_name")
    if "/" in name or "\\" in name or name in {".", ".."}:
        raise FileSendPolicyError("invalid_file_name")
    if PurePath(name).name != name:
        raise FileSendPolicyError("invalid_file_name")
    return name


def validate_https_url(url: str) -> str:
    """Fail closed for every URL, including otherwise public HTTPS targets."""
    del url
    _reject_external_url()


def validate_redirect_chain(urls: Sequence[str], *, policy: HttpsFetchPolicy) -> tuple[str, ...]:
    """Fail closed; redirect-following external file ingestion is disabled."""
    del urls, policy
    _reject_external_url()


def make_external_reference(
    *,
    url: str,
    name: str,
    declared_size: int | None = None,
    declared_mime: str | None = None,
    policy: HttpsFetchPolicy | None = None,
) -> ExternalFileReference:
    """Fail closed; canonical SEND_FILES accepts only BridgeFileReference."""
    del url, name, declared_size, declared_mime, policy
    _reject_external_url()


def make_bridge_reference(*, file_id: str, sha256: str, size: int, mime_type: str | None = None) -> BridgeFileReference:
    if not isinstance(file_id, str) or not file_id or len(file_id) > 128 or any(ord(ch) < 32 for ch in file_id):
        raise FileSendPolicyError("invalid_bridge_file_id")
    if "/" in file_id or "\\" in file_id or file_id in {".", ".."}:
        raise FileSendPolicyError("invalid_bridge_file_id")
    digest = str(sha256 or "")
    if len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest):
        raise FileSendPolicyError("invalid_file_hash")
    if isinstance(size, bool):
        raise FileSendPolicyError("invalid_file_size")
    try:
        size_i = int(size)
    except (TypeError, ValueError) as exc:
        raise FileSendPolicyError("invalid_file_size") from exc
    if size_i <= 0 or size_i > 100 * 1024 * 1024:
        raise FileSendPolicyError("invalid_file_size", status=413 if size_i > 0 else 400)
    mime = None
    if mime_type not in (None, ""):
        if not isinstance(mime_type, str) or not _MIME_RE.fullmatch(mime_type):
            raise FileSendPolicyError("invalid_mime_type")
        mime = mime_type.lower()
    return BridgeFileReference(file_id, digest, size_i, mime)


def dedupe_bridge_files(files: Sequence[BridgeFileReference], *, max_count: int = 10, max_total_bytes: int = 250 * 1024 * 1024) -> tuple[BridgeFileReference, ...]:
    if max_count <= 0 or max_count > 100 or max_total_bytes <= 0:
        raise ValueError("bounded send-files policy required")
    out: list[BridgeFileReference] = []
    seen: set[tuple[str, str]] = set()
    for item in files:
        key = (item.file_id, item.sha256)
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    if not out:
        raise FileSendPolicyError("files_required")
    if len(out) > max_count:
        raise FileSendPolicyError("file_count_exceeded", status=413)
    if sum(item.size for item in out) > max_total_bytes:
        raise FileSendPolicyError("files_total_too_large", status=413)
    return tuple(out)


def validate_voice_note(files: Sequence[BridgeFileReference], *, voice_note: bool) -> None:
    if not voice_note:
        return
    if len(files) != 1:
        raise FileSendPolicyError("voice_note_requires_single_file")
    item = files[0]
    allowed = {"audio/ogg", "audio/opus", "audio/ogg; codecs=opus"}
    if item.mime_type not in allowed:
        raise FileSendPolicyError("voice_note_media_unsupported")


def external_audit_metadata(ref: ExternalFileReference) -> dict[str, object]:
    """Compatibility sanitizer for historical in-memory objects; not a fetch path."""
    return {
        "source_kind": "HTTPS_DISABLED",
        "url_sha256": ref.url_sha256,
        "declared_size": ref.declared_size,
        "mime_present": ref.declared_mime is not None,
    }


def bridge_audit_metadata(ref: BridgeFileReference) -> dict[str, object]:
    return {
        "source_kind": "BRIDGE_FILE",
        "file_id_sha256": _digest(ref.file_id),
        "sha256": ref.sha256,
        "size": ref.size,
        "mime_present": ref.mime_type is not None,
    }