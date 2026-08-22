# -*- coding: utf-8 -*-
"""Validation-only policy for Telegram send-files staging and external HTTPS references."""
from __future__ import annotations

import hashlib
import ipaddress
import re
from dataclasses import dataclass
from pathlib import PurePath
from typing import Iterable, Sequence
from urllib.parse import urlsplit, urlunsplit


class FileSendPolicyError(RuntimeError):
    def __init__(self, code: str, *, status: int = 400):
        super().__init__(code)
        self.code = code
        self.status = status


@dataclass(frozen=True)
class HttpsFetchPolicy:
    max_bytes: int = 100 * 1024 * 1024
    timeout_seconds: int = 20
    max_redirects: int = 3

    def __post_init__(self) -> None:
        if self.max_bytes <= 0 or self.max_bytes > 512 * 1024 * 1024:
            raise ValueError("bounded fetch size required")
        if self.timeout_seconds <= 0 or self.timeout_seconds > 60:
            raise ValueError("bounded fetch timeout required")
        if self.max_redirects < 0 or self.max_redirects > 5:
            raise ValueError("bounded redirect count required")


@dataclass(frozen=True)
class ExternalFileReference:
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


_HOST_RE = re.compile(r"^[A-Za-z0-9.-]{1,253}$")
_MIME_RE = re.compile(r"^[A-Za-z0-9!#$&^_.+-]+/[A-Za-z0-9!#$&^_.+-]+$")


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _public_ip(ip: ipaddress._BaseAddress) -> bool:
    return not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def validate_resolved_ips(values: Iterable[str]) -> tuple[str, ...]:
    parsed: list[str] = []
    for raw in values:
        try:
            ip = ipaddress.ip_address(str(raw))
        except ValueError as exc:
            raise FileSendPolicyError("external_host_resolution_invalid") from exc
        if not _public_ip(ip):
            raise FileSendPolicyError("external_host_private_network_blocked", status=403)
        parsed.append(ip.compressed)
    if not parsed:
        raise FileSendPolicyError("external_host_resolution_required")
    return tuple(parsed)


def safe_filename(value: str) -> str:
    if not isinstance(value, str):
        raise FileSendPolicyError("invalid_file_name")
    name = value.strip()
    if not name or len(name) > 180 or any(ord(ch) < 32 for ch in name):
        raise FileSendPolicyError("invalid_file_name")
    if "/" in name or "\\" in name or name in {".", ".."}:
        raise FileSendPolicyError("invalid_file_name")
    # PurePath catches platform-shaped basename attempts without touching the filesystem.
    if PurePath(name).name != name:
        raise FileSendPolicyError("invalid_file_name")
    return name


def validate_https_url(url: str) -> str:
    if not isinstance(url, str) or not url or len(url) > 2048 or any(ord(ch) < 32 for ch in url):
        raise FileSendPolicyError("invalid_external_url")
    parts = urlsplit(url)
    if parts.scheme.lower() != "https":
        raise FileSendPolicyError("https_required", status=403)
    if parts.username is not None or parts.password is not None:
        raise FileSendPolicyError("url_credentials_forbidden", status=403)
    if not parts.hostname or not _HOST_RE.fullmatch(parts.hostname):
        raise FileSendPolicyError("invalid_external_host")
    host = parts.hostname.lower().rstrip(".")
    if host in {"localhost", "localhost.localdomain"} or host.endswith(".localhost") or host.endswith(".local"):
        raise FileSendPolicyError("external_host_private_network_blocked", status=403)
    try:
        ip = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        ip = None
    if ip is not None and not _public_ip(ip):
        raise FileSendPolicyError("external_host_private_network_blocked", status=403)
    if parts.port not in (None, 443):
        raise FileSendPolicyError("external_port_forbidden", status=403)
    # Fragments are never sent to the server and are excluded from the bound reference.
    return urlunsplit(("https", parts.netloc.lower(), parts.path or "/", parts.query, ""))


def validate_redirect_chain(urls: Sequence[str], *, policy: HttpsFetchPolicy) -> tuple[str, ...]:
    if not urls:
        raise FileSendPolicyError("redirect_chain_empty")
    if len(urls) - 1 > policy.max_redirects:
        raise FileSendPolicyError("too_many_redirects", status=502)
    return tuple(validate_https_url(url) for url in urls)


def make_external_reference(
    *,
    url: str,
    name: str,
    declared_size: int | None = None,
    declared_mime: str | None = None,
    policy: HttpsFetchPolicy | None = None,
) -> ExternalFileReference:
    policy = policy or HttpsFetchPolicy()
    normalized_url = validate_https_url(url)
    file_name = safe_filename(name)
    size: int | None
    if declared_size is None:
        size = None
    else:
        if isinstance(declared_size, bool):
            raise FileSendPolicyError("invalid_declared_size")
        try:
            size = int(declared_size)
        except (TypeError, ValueError) as exc:
            raise FileSendPolicyError("invalid_declared_size") from exc
        if size < 0:
            raise FileSendPolicyError("invalid_declared_size")
        if size > policy.max_bytes:
            raise FileSendPolicyError("file_too_large", status=413)
    mime = None
    if declared_mime not in (None, ""):
        if not isinstance(declared_mime, str) or not _MIME_RE.fullmatch(declared_mime):
            raise FileSendPolicyError("invalid_mime_type")
        mime = declared_mime.lower()
    return ExternalFileReference(normalized_url, _digest(normalized_url), file_name, size, mime)


def make_bridge_reference(*, file_id: str, sha256: str, size: int, mime_type: str | None = None) -> BridgeFileReference:
    if not isinstance(file_id, str) or not file_id or len(file_id) > 128 or any(ord(ch) < 32 for ch in file_id):
        raise FileSendPolicyError("invalid_bridge_file_id")
    # Intentionally no path parameter exists in this API: only opaque BridgeStore IDs.
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
    return {
        "source_kind": "HTTPS",
        "url_sha256": ref.url_sha256,
        "declared_size": ref.declared_size,
        "mime_present": ref.declared_mime is not None,
        # No URL, host, filename or content.
    }


def bridge_audit_metadata(ref: BridgeFileReference) -> dict[str, object]:
    return {
        "source_kind": "BRIDGE_FILE",
        "file_id_sha256": _digest(ref.file_id),
        "sha256": ref.sha256,
        "size": ref.size,
        "mime_present": ref.mime_type is not None,
    }
