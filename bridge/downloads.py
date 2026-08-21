"""Bounded single/bulk media downloads with persistent resume checkpoints."""

from __future__ import annotations

import fcntl
import hashlib
import mimetypes
import os
import re
import secrets
import stat
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Iterator

from .backend import ReadBackend
from .errors import BridgeError
from .storage import CheckpointStore, DownloadItem, FileRecord, FileRecordStore


def safe_filename(name: str | None, fallback: str = "file.bin") -> str:
    raw = (name or fallback).replace("\\", "/")
    text = raw.split("/")[-1]
    text = re.sub(r"[\x00-\x1f<>:\"|?*]+", "_", text)
    text = re.sub(r"\s+", " ", text).strip(" .")
    if text in {"", ".", ".."}:
        text = fallback
    return text[:180]


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


@dataclass(frozen=True)
class DownloadLimits:
    max_single_bytes: int = 100 * 1024 * 1024
    max_bulk_files: int = 100
    max_bulk_bytes: int = 500 * 1024 * 1024

    def __post_init__(self) -> None:
        if (
            isinstance(self.max_single_bytes, bool)
            or isinstance(self.max_bulk_files, bool)
            or isinstance(self.max_bulk_bytes, bool)
            or self.max_single_bytes <= 0
            or not 1 <= self.max_bulk_files <= 500
            or self.max_bulk_bytes < self.max_single_bytes
        ):
            raise ValueError("invalid download limits")


class DownloadManager:
    def __init__(
        self,
        *,
        backend: ReadBackend,
        files: FileRecordStore,
        checkpoints: CheckpointStore,
        staging_dir: Path,
        limits: DownloadLimits | None = None,
    ) -> None:
        self.backend = backend
        self.files = files
        self.checkpoints = checkpoints
        self.staging_dir = staging_dir.resolve()
        self.limits = limits or DownloadLimits()
        self.staging_dir.mkdir(parents=True, exist_ok=True)
        self.lock_dir = self.staging_dir / ".locks"
        self.lock_dir.mkdir(parents=True, exist_ok=True)
        for directory in (self.staging_dir, self.lock_dir):
            try:
                os.chmod(directory, 0o700)
            except OSError:
                pass

    @contextmanager
    def _job_lock(self, job_id: str) -> Iterator[None]:
        """Serialize one job across threads/processes on the same POSIX host."""
        lock_name = hashlib.sha256(job_id.encode("utf-8")).hexdigest() + ".lock"
        lock_path = self.lock_dir / lock_name
        flags = os.O_CREAT | os.O_RDWR
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            fd = os.open(lock_path, flags, 0o600)
        except OSError as exc:
            raise BridgeError("Download job lock is unavailable", status=503, code="job_lock_unavailable") from exc
        try:
            info = os.fstat(fd)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.getuid()
                or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_size != 0
            ):
                raise BridgeError("Unsafe download job lock topology", status=500, code="job_lock_unsafe")
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise BridgeError("Download job is already running", status=409, code="job_busy", details={"retryable": True}) from exc
            yield
        finally:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            except OSError:
                pass
            os.close(fd)

    def _validate_items(self, items: Iterable[DownloadItem]) -> list[DownloadItem]:
        dedup: dict[tuple[str, int, str], DownloadItem] = {}
        total_expected = 0
        for item in items:
            key = (item.chat, int(item.message_id), item.source_file_ref)
            dedup.setdefault(key, item)
        selected = list(dedup.values())
        if not selected:
            raise BridgeError("No files selected", code="empty_download")
        if len(selected) > self.limits.max_bulk_files:
            raise BridgeError("Too many files selected", status=413, code="bulk_file_limit")
        if len({item.item_id for item in selected}) != len(selected):
            raise BridgeError("Download item identifiers collide", status=400, code="duplicate_item_id")
        for item in selected:
            if item.expected_size is not None:
                if item.expected_size < 0 or item.expected_size > self.limits.max_single_bytes:
                    raise BridgeError("File exceeds download size limit", status=413, code="file_too_large")
                total_expected += item.expected_size
        if total_expected > self.limits.max_bulk_bytes:
            raise BridgeError("Bulk download exceeds total size limit", status=413, code="bulk_size_limit")
        return selected

    def start_bulk(self, items: Iterable[DownloadItem]) -> dict[str, Any]:
        selected = self._validate_items(items)
        job_id = self.checkpoints.create(selected)
        return self.resume(job_id)

    def start_single(self, item: DownloadItem) -> dict[str, Any]:
        result = self.start_bulk([item])
        if result["status"] != "complete" or not result["files"]:
            if result.get("failures"):
                failure = result["failures"][0]
                raise BridgeError(
                    "File download failed",
                    status=int(failure.get("status", 502)),
                    code=str(failure.get("code") or "media_download_failed"),
                    details={"retryable": bool(failure.get("retryable", False))},
                )
            raise BridgeError("File download failed", status=502, code="media_download_failed")
        return result["files"][0]

    def _download_one(self, item: DownloadItem, *, job_id: str) -> FileRecord:
        name = safe_filename(item.name, f"message-{item.message_id}.bin")
        suffix = Path(name).suffix[:16]
        target = self.staging_dir / f"{job_id}_{secrets.token_hex(12)}{suffix}.part"
        if target.exists():
            raise BridgeError("Unsafe staging collision", status=500, code="staging_collision")
        returned: Path | None = None
        resolved: Path | None = None
        try:
            result = self.backend.download_media(
                chat=item.chat,
                message_id=int(item.message_id),
                file_ref=item.source_file_ref,
                destination=str(target),
            )
            returned = Path(str(result.get("path") or target))
            try:
                original_info = os.lstat(returned)
            except OSError as exc:
                raise BridgeError("Downloaded file is unavailable", status=502, code="media_download_failed") from exc
            if stat.S_ISLNK(original_info.st_mode) or not stat.S_ISREG(original_info.st_mode) or original_info.st_nlink != 1:
                raise BridgeError("Backend returned unsafe file topology", status=502, code="unsafe_backend_path")
            resolved = returned.resolve(strict=True)
            try:
                resolved.relative_to(self.staging_dir)
            except ValueError as exc:
                raise BridgeError("Backend returned unsafe download path", status=502, code="unsafe_backend_path") from exc
            resolved_info = os.lstat(resolved)
            if not stat.S_ISREG(resolved_info.st_mode) or resolved.is_symlink() or resolved_info.st_nlink != 1:
                raise BridgeError("Backend returned unsafe file topology", status=502, code="unsafe_backend_path")
            size = resolved_info.st_size
            if size > self.limits.max_single_bytes:
                raise BridgeError("Downloaded file exceeds size limit", status=413, code="file_too_large")
            if item.expected_size is not None and size != item.expected_size:
                raise BridgeError("Downloaded file size mismatch", status=502, code="file_size_mismatch")
            digest = _sha256(resolved)
            if item.expected_sha256 is not None and not secrets.compare_digest(digest, item.expected_sha256.lower()):
                raise BridgeError("Downloaded file hash mismatch", status=502, code="file_hash_mismatch")
            final = self.files.root / f"{secrets.token_hex(20)}{Path(name).suffix[:16]}"
            resolved.replace(final)
            try:
                os.chmod(final, 0o600)
            except OSError:
                pass
            mime = item.mime_type or mimetypes.guess_type(name)[0] or "application/octet-stream"
            return self.files.add(final, name=name, mime_type=mime)
        finally:
            # ``resolved`` continues to refer to the old staging path after
            # Path.replace(); therefore cleanup never deletes the final file
            # that was successfully registered under files.root.
            for candidate in {path for path in (target, returned, resolved) if path is not None}:
                try:
                    if candidate.exists() and candidate.is_file():
                        candidate.unlink()
                except OSError:
                    pass

    def _complete_files(self, payload: dict[str, Any]) -> list[FileRecord]:
        records: list[FileRecord] = []
        for file_ref in payload["results"].values():
            record = self.files.get(file_ref)
            if record is None:
                raise BridgeError(
                    "Completed download result is unavailable",
                    status=500,
                    code="checkpoint_result_missing",
                    details={"retryable": False},
                )
            records.append(record)
        return records

    def resume(self, job_id: str) -> dict[str, Any]:
        with self._job_lock(job_id):
            payload = self.checkpoints.load(job_id)
            if payload["status"] == "complete":
                records = self._complete_files(payload)
                return {
                    "job_id": job_id,
                    "status": "complete",
                    "files": [record.public_metadata() for record in records],
                    "failures": [],
                    "pending": 0,
                }

            payload["status"] = "running"
            self.checkpoints.save(payload)
            items = [DownloadItem(**raw) for raw in payload["items"]]
            for item in items:
                if item.item_id in payload["results"]:
                    continue
                payload["failures"].pop(item.item_id, None)
                try:
                    record = self._download_one(item, job_id=job_id)
                    current_total = sum(existing.size for existing in self._complete_files(payload))
                    if current_total + record.size > self.limits.max_bulk_bytes:
                        self.files.delete(record.file_ref)
                        raise BridgeError("Bulk download exceeds total size limit", status=413, code="bulk_size_limit")
                    payload["results"][item.item_id] = record.file_ref
                except BridgeError as exc:
                    payload["failures"][item.item_id] = {
                        "code": exc.code,
                        "status": exc.status,
                        "retryable": exc.status in {409, 429, 502, 503, 504},
                    }
                self.checkpoints.save(payload)

            pending_ids = [item.item_id for item in items if item.item_id not in payload["results"]]
            if not pending_ids:
                payload["status"] = "complete"
                payload["failures"] = {}
            elif payload["results"]:
                payload["status"] = "partial"
            else:
                payload["status"] = "failed"
            self.checkpoints.save(payload)
            records = self._complete_files(payload)
            return {
                "job_id": job_id,
                "status": payload["status"],
                "files": [record.public_metadata() for record in records],
                "failures": [
                    {"item_id": item_id, **info}
                    for item_id, info in sorted(payload["failures"].items())
                ],
                "pending": len(pending_ids),
            }
