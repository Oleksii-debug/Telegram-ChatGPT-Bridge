"""Bounded single/bulk media downloads with persistent resume checkpoints."""

from __future__ import annotations

import fcntl
import hashlib
import mimetypes
import os
import secrets
import stat
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Iterator

from .backend import ReadBackend
from .download_validation import DownloadValidationReceipts
from .errors import BridgeError
from .filenames import safe_filename
from .storage import CheckpointStore, DownloadItem, FileRecord, FileRecordStore


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
    _NON_RETRYABLE_FAILURE_CODES = {
        "bulk_file_limit",
        "bulk_size_limit",
        "checkpoint_result_mismatch",
        "download_result_changed",
        "download_result_collision",
        "duplicate_item_id",
        "file_hash_mismatch",
        "file_registry_collision",
        "file_size_mismatch",
        "file_too_large",
        "unsafe_backend_path",
        "unsafe_recovered_file",
        "validation_receipt_corrupt",
        "validation_receipt_unsafe",
    }

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
        # Persistent lock and validation controls belong beside the private
        # checkpoint DB, not inside ephemeral staging.
        control_root = self.checkpoints.db_path.parent
        self.lock_dir = control_root / ".download-locks"
        self.lock_dir.mkdir(parents=True, exist_ok=True)
        self.validation_receipts = DownloadValidationReceipts(
            control_root / ".download-validations"
        )
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
            raise BridgeError(
                "Download job lock is unavailable",
                status=503,
                code="job_lock_unavailable",
            ) from exc
        try:
            info = os.fstat(fd)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.getuid()
                or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_size != 0
            ):
                raise BridgeError(
                    "Unsafe download job lock topology",
                    status=500,
                    code="job_lock_unsafe",
                )
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise BridgeError(
                    "Download job is already running",
                    status=409,
                    code="job_busy",
                    details={"retryable": True},
                ) from exc
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
            raise BridgeError(
                "Download item identifiers collide",
                status=400,
                code="duplicate_item_id",
            )
        for item in selected:
            if item.expected_size is not None:
                if (
                    item.expected_size < 0
                    or item.expected_size > self.limits.max_single_bytes
                ):
                    raise BridgeError(
                        "File exceeds download size limit",
                        status=413,
                        code="file_too_large",
                    )
                total_expected += item.expected_size
        if total_expected > self.limits.max_bulk_bytes:
            raise BridgeError(
                "Bulk download exceeds total size limit",
                status=413,
                code="bulk_size_limit",
            )
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
            raise BridgeError(
                "File download failed",
                status=502,
                code="media_download_failed",
            )
        return result["files"][0]

    @classmethod
    def _retryable_failure(cls, error: BridgeError) -> bool:
        """Classify retry safety independently from broad HTTP status classes."""
        if error.code in cls._NON_RETRYABLE_FAILURE_CODES:
            return False
        return error.status in {409, 429, 502, 503, 504}

    @staticmethod
    def _origin_key(job_id: str, item_id: str) -> str:
        digest = hashlib.sha256(f"{job_id}\x00{item_id}".encode("utf-8")).hexdigest()
        return f"dl_{digest}"

    def _final_path(self, item: DownloadItem, *, job_id: str) -> Path:
        name = safe_filename(item.name, f"message-{item.message_id}.bin")
        suffix = Path(name).suffix[:16]
        origin = self._origin_key(job_id, item.item_id)
        return self.files.root / f".{origin}{suffix}"

    @staticmethod
    def _is_owned_staging_leaf(job_id: str, name: str) -> bool:
        """Recognize only exact manager-created target leaves for one job."""
        prefix = f"{job_id}_"
        if not isinstance(name, str) or not name.startswith(prefix):
            return False
        tail = name[len(prefix):]
        if len(tail) < 29:
            return False
        token = tail[:24]
        remainder = tail[24:]
        if len(token) != 24 or any(
            ch not in "0123456789abcdef" for ch in token
        ):
            return False
        if not remainder.endswith(".part"):
            return False
        suffix = remainder[:-5]
        if len(suffix) > 16:
            return False
        if suffix and (
            not suffix.startswith(".")
            or "/" in suffix
            or "\\" in suffix
            or "\x00" in suffix
        ):
            return False
        return True

    def _reconcile_job_staging(self, job_id: str) -> None:
        """Remove stale manager-owned staging leaves before any new Telegram I/O.

        The same-job flock is already held when this runs, so a matching target
        cannot belong to a live peer. Only exact manager-created target names are
        cleanup authority. Unknown topology or disk errors fail before backend
        effects rather than guessing about private data ownership.
        """
        try:
            entries = list(os.scandir(self.staging_dir))
        except OSError as exc:
            raise BridgeError(
                "Download staging recovery is unavailable",
                status=503,
                code="staging_recovery_unavailable",
                details={"retryable": True},
            ) from exc
        for entry in entries:
            if not self._is_owned_staging_leaf(job_id, entry.name):
                continue
            candidate = self.staging_dir / entry.name
            try:
                info = os.lstat(candidate)
            except FileNotFoundError:
                continue
            except OSError as exc:
                raise BridgeError(
                    "Download staging recovery is unavailable",
                    status=503,
                    code="staging_recovery_unavailable",
                    details={"retryable": True},
                ) from exc
            if not (
                stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)
            ):
                raise BridgeError(
                    "Unsafe stale download staging topology",
                    status=500,
                    code="staging_recovery_unsafe",
                )
            try:
                candidate.unlink()
            except FileNotFoundError:
                continue
            except OSError as exc:
                raise BridgeError(
                    "Download staging recovery is unavailable",
                    status=503,
                    code="staging_recovery_unavailable",
                    details={"retryable": True},
                ) from exc

    def _cleanup_staging_leaf(self, candidate: Path) -> None:
        """Remove only a staging-owned regular/symlink leaf; never arbitrary backend paths."""
        try:
            parent = candidate.parent.resolve(strict=True)
            parent.relative_to(self.staging_dir)
        except (OSError, ValueError):
            return
        try:
            info = os.lstat(candidate)
        except (FileNotFoundError, OSError):
            return
        if not (stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)):
            return
        try:
            candidate.unlink()
        except OSError:
            pass

    def _cleanup_final_leaf(self, final: Path) -> None:
        """Remove only the deterministic private result leaf without following it."""
        try:
            if final.parent.resolve(strict=True) != self.files.root:
                return
            info = os.lstat(final)
        except (FileNotFoundError, OSError):
            return
        if not (stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)):
            return
        try:
            final.unlink()
        except OSError:
            pass

    def _validate_recovered_record(
        self,
        item: DownloadItem,
        record: FileRecord,
    ) -> None:
        if record.size > self.limits.max_single_bytes:
            raise BridgeError(
                "Recovered file exceeds size limit",
                status=500,
                code="checkpoint_result_mismatch",
            )
        if item.expected_size is not None and record.size != item.expected_size:
            raise BridgeError(
                "Recovered file size does not match checkpoint",
                status=500,
                code="checkpoint_result_mismatch",
            )
        if item.expected_sha256 is not None and not secrets.compare_digest(
            record.sha256,
            item.expected_sha256.lower(),
        ):
            raise BridgeError(
                "Recovered file hash does not match checkpoint",
                status=500,
                code="checkpoint_result_mismatch",
            )

    def _validation_receipt(
        self,
        *,
        job_id: str,
        item: DownloadItem,
    ) -> tuple[int, str] | None:
        return self.validation_receipts.load(job_id, item.item_id)

    def _reject_changed_recovery(
        self,
        *,
        job_id: str,
        item: DownloadItem,
        final: Path,
        registered: FileRecord | None = None,
    ) -> None:
        if registered is not None:
            self.files.delete(registered.file_ref)
        else:
            self._cleanup_final_leaf(final)
        self.validation_receipts.clear(job_id, item.item_id)
        raise BridgeError(
            "Validated download bytes changed across restart",
            status=503,
            code="recovered_validation_mismatch",
            details={"retryable": True},
        )

    def _recover_existing(
        self,
        item: DownloadItem,
        *,
        job_id: str,
    ) -> FileRecord | None:
        """Recover durable move/registry crash windows without duplicate I/O."""
        origin = self._origin_key(job_id, item.item_id)
        registered = self.files.get_by_origin(origin)
        final = self._final_path(item, job_id=job_id)
        receipt = self._validation_receipt(job_id=job_id, item=item)
        if registered is not None:
            self._validate_recovered_record(item, registered)
            if receipt is not None and (
                receipt[0] != registered.size
                or not secrets.compare_digest(receipt[1], registered.sha256)
            ):
                self._reject_changed_recovery(
                    job_id=job_id,
                    item=item,
                    final=final,
                    registered=registered,
                )
            return registered

        try:
            info = os.lstat(final)
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise BridgeError(
                "Recovered file is unavailable",
                status=500,
                code="unsafe_recovered_file",
            ) from exc
        if (
            stat.S_ISLNK(info.st_mode)
            or not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
        ):
            raise BridgeError(
                "Recovered file topology is unsafe",
                status=500,
                code="unsafe_recovered_file",
            )
        if info.st_size > self.limits.max_single_bytes:
            raise BridgeError(
                "Recovered file exceeds size limit",
                status=500,
                code="checkpoint_result_mismatch",
            )
        if item.expected_size is not None and info.st_size != item.expected_size:
            raise BridgeError(
                "Recovered file size does not match checkpoint",
                status=500,
                code="checkpoint_result_mismatch",
            )
        digest = _sha256(final)
        if item.expected_sha256 is not None and not secrets.compare_digest(
            digest,
            item.expected_sha256.lower(),
        ):
            raise BridgeError(
                "Recovered file hash does not match checkpoint",
                status=500,
                code="checkpoint_result_mismatch",
            )
        # New transfers always persist this receipt before atomic move. The
        # no-receipt path remains a narrow compatibility fallback for legacy or
        # synthetic pre-existing finals; actual new move-before-registry crash
        # recovery is bound to the exact pre-move validated size+digest.
        if receipt is not None and (
            receipt[0] != info.st_size
            or not secrets.compare_digest(receipt[1], digest)
        ):
            self._reject_changed_recovery(
                job_id=job_id,
                item=item,
                final=final,
            )
        try:
            os.chmod(final, 0o600)
        except OSError:
            pass
        name = safe_filename(item.name, f"message-{item.message_id}.bin")
        mime = (
            item.mime_type
            or mimetypes.guess_type(name)[0]
            or "application/octet-stream"
        )
        record = self.files.add(
            final,
            name=name,
            mime_type=mime,
            origin_key=origin,
        )
        self._validate_recovered_record(item, record)
        if receipt is not None and (
            receipt[0] != record.size
            or not secrets.compare_digest(receipt[1], record.sha256)
        ):
            self._reject_changed_recovery(
                job_id=job_id,
                item=item,
                final=final,
                registered=record,
            )
        return record

    def _download_one(self, item: DownloadItem, *, job_id: str) -> FileRecord:
        name = safe_filename(item.name, f"message-{item.message_id}.bin")
        suffix = Path(name).suffix[:16]
        target = self.staging_dir / (
            f"{job_id}_{secrets.token_hex(12)}{suffix}.part"
        )
        if target.exists():
            raise BridgeError(
                "Unsafe staging collision",
                status=500,
                code="staging_collision",
            )
        returned: Path | None = None
        resolved: Path | None = None
        final = self._final_path(item, job_id=job_id)
        registered = False
        try:
            try:
                os.lstat(final)
            except FileNotFoundError:
                pass
            except OSError as exc:
                raise BridgeError(
                    "Private download result state is unavailable",
                    status=500,
                    code="unsafe_recovered_file",
                ) from exc
            else:
                raise BridgeError(
                    "Private download result already exists",
                    status=500,
                    code="download_result_collision",
                )
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
                raise BridgeError(
                    "Downloaded file is unavailable",
                    status=502,
                    code="media_download_failed",
                ) from exc
            if (
                stat.S_ISLNK(original_info.st_mode)
                or not stat.S_ISREG(original_info.st_mode)
                or original_info.st_nlink != 1
            ):
                raise BridgeError(
                    "Backend returned unsafe file topology",
                    status=502,
                    code="unsafe_backend_path",
                )
            resolved = returned.resolve(strict=True)
            try:
                resolved.relative_to(self.staging_dir)
            except ValueError as exc:
                raise BridgeError(
                    "Backend returned unsafe download path",
                    status=502,
                    code="unsafe_backend_path",
                ) from exc
            resolved_info = os.lstat(resolved)
            if (
                not stat.S_ISREG(resolved_info.st_mode)
                or resolved.is_symlink()
                or resolved_info.st_nlink != 1
            ):
                raise BridgeError(
                    "Backend returned unsafe file topology",
                    status=502,
                    code="unsafe_backend_path",
                )
            size = resolved_info.st_size
            if size > self.limits.max_single_bytes:
                raise BridgeError(
                    "Downloaded file exceeds size limit",
                    status=413,
                    code="file_too_large",
                )
            if item.expected_size is not None and size != item.expected_size:
                raise BridgeError(
                    "Downloaded file size mismatch",
                    status=502,
                    code="file_size_mismatch",
                )
            digest = _sha256(resolved)
            if item.expected_sha256 is not None and not secrets.compare_digest(
                digest,
                item.expected_sha256.lower(),
            ):
                raise BridgeError(
                    "Downloaded file hash mismatch",
                    status=502,
                    code="file_hash_mismatch",
                )
            # Persist only non-content validation evidence before the atomic move.
            # If the process dies after move but before registry/checkpoint, resume
            # can distinguish exact validated bytes from same-size corruption.
            self.validation_receipts.persist(
                job_id,
                item.item_id,
                size=size,
                sha256=digest,
            )
            resolved.replace(final)
            try:
                os.chmod(final, 0o600)
            except OSError:
                pass
            mime = (
                item.mime_type
                or mimetypes.guess_type(name)[0]
                or "application/octet-stream"
            )
            record = self.files.add(
                final,
                name=name,
                mime_type=mime,
                origin_key=self._origin_key(job_id, item.item_id),
            )
            verified = self.files.get(record.file_ref)
            if (
                verified is None
                or verified.size != size
                or not secrets.compare_digest(verified.sha256, digest)
            ):
                self.files.delete(record.file_ref)
                raise BridgeError(
                    "Private download result changed before registration completed",
                    status=500,
                    code="download_result_changed",
                )
            record = verified
            registered = True
            return record
        finally:
            for candidate in {
                path for path in (target, returned, resolved) if path is not None
            }:
                self._cleanup_staging_leaf(candidate)
            if not registered:
                # Normal Python exceptions clean the unregistered file. A hard
                # process loss cannot run this finally block; the deterministic
                # private path is then adopted by _recover_existing on resume.
                self._cleanup_final_leaf(final)

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

    def _accept_result(
        self,
        payload: dict[str, Any],
        item: DownloadItem,
        record: FileRecord,
    ) -> None:
        current_total = sum(
            existing.size for existing in self._complete_files(payload)
        )
        if current_total + record.size > self.limits.max_bulk_bytes:
            self.files.delete(record.file_ref)
            raise BridgeError(
                "Bulk download exceeds total size limit",
                status=413,
                code="bulk_size_limit",
            )
        payload["results"][item.item_id] = record.file_ref
        payload["failures"].pop(item.item_id, None)

    def _clear_receipt_after_durable_outcome(
        self,
        payload: dict[str, Any],
        item: DownloadItem,
    ) -> None:
        if item.item_id in payload["results"]:
            self.validation_receipts.clear(payload["job_id"], item.item_id)
            return
        failure = payload["failures"].get(item.item_id)
        if failure is not None and failure.get("retryable") is False:
            self.validation_receipts.clear(payload["job_id"], item.item_id)

    def resume(self, job_id: str) -> dict[str, Any]:
        with self._job_lock(job_id):
            payload = self.checkpoints.load(job_id)
            self._reconcile_job_staging(job_id)
            items = [DownloadItem(**raw) for raw in payload["items"]]
            if payload["status"] == "complete":
                records = self._complete_files(payload)
                for item in items:
                    if item.item_id in payload["results"]:
                        self.validation_receipts.clear(job_id, item.item_id)
                return {
                    "job_id": job_id,
                    "status": "complete",
                    "files": [record.public_metadata() for record in records],
                    "failures": [],
                    "pending": 0,
                }

            payload["status"] = "running"
            self.checkpoints.save(payload)
            for item in items:
                if item.item_id in payload["results"]:
                    continue
                try:
                    recovered = self._recover_existing(item, job_id=job_id)
                    if recovered is not None:
                        self._accept_result(payload, item, recovered)
                        self.checkpoints.save(payload)
                        self._clear_receipt_after_durable_outcome(payload, item)
                        continue
                except BridgeError as exc:
                    payload["failures"][item.item_id] = {
                        "code": exc.code,
                        "status": exc.status,
                        "retryable": self._retryable_failure(exc),
                    }
                    self.checkpoints.save(payload)
                    self._clear_receipt_after_durable_outcome(payload, item)
                    continue

                prior_failure = payload["failures"].get(item.item_id)
                if (
                    prior_failure is not None
                    and prior_failure.get("retryable") is False
                ):
                    continue
                payload["failures"].pop(item.item_id, None)
                try:
                    record = self._download_one(item, job_id=job_id)
                    self._accept_result(payload, item, record)
                except BridgeError as exc:
                    payload["failures"][item.item_id] = {
                        "code": exc.code,
                        "status": exc.status,
                        "retryable": self._retryable_failure(exc),
                    }
                self.checkpoints.save(payload)
                self._clear_receipt_after_durable_outcome(payload, item)

            pending_ids = [
                item.item_id
                for item in items
                if item.item_id not in payload["results"]
            ]
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
