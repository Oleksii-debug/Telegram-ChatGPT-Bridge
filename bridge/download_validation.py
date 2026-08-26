"""Private durable receipts binding validated download bytes across process loss."""

from __future__ import annotations

import hashlib
import os
import re
import secrets
import stat
from pathlib import Path

from .errors import BridgeError

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_RECEIPT_RE = re.compile(r"^v1 ([0-9]+) ([0-9a-f]{64})\n$")


class DownloadValidationReceipts:
    """Persist only size+digest evidence, never Telegram/private payload content."""

    def __init__(self, root: Path) -> None:
        self.root = root.resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        try:
            info = os.lstat(self.root)
        except OSError as exc:
            raise BridgeError(
                "Download validation receipt root is unavailable",
                status=503,
                code="validation_receipt_unavailable",
            ) from exc
        if (
            stat.S_ISLNK(info.st_mode)
            or not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.getuid()
        ):
            raise BridgeError(
                "Unsafe download validation receipt root",
                status=500,
                code="validation_receipt_unsafe",
            )
        try:
            os.chmod(self.root, 0o700)
        except OSError:
            pass

    @staticmethod
    def _identity(job_id: str, item_id: str) -> str:
        if not isinstance(job_id, str) or not isinstance(item_id, str):
            raise BridgeError(
                "Invalid download validation receipt identity",
                status=500,
                code="validation_receipt_unsafe",
            )
        return hashlib.sha256(f"{job_id}\x00{item_id}".encode("utf-8")).hexdigest()

    def _path(self, job_id: str, item_id: str) -> Path:
        return self.root / (self._identity(job_id, item_id) + ".receipt")

    def load(self, job_id: str, item_id: str) -> tuple[int, str] | None:
        path = self._path(job_id, item_id)
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            fd = os.open(path, flags)
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise BridgeError(
                "Download validation receipt is unavailable",
                status=503,
                code="validation_receipt_unavailable",
                details={"retryable": True},
            ) from exc
        try:
            info = os.fstat(fd)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.getuid()
                or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_size > 96
            ):
                raise BridgeError(
                    "Unsafe download validation receipt",
                    status=500,
                    code="validation_receipt_unsafe",
                )
            raw = b""
            while len(raw) <= 96:
                chunk = os.read(fd, 97 - len(raw))
                if not chunk:
                    break
                raw += chunk
            if len(raw) > 96:
                raise BridgeError(
                    "Download validation receipt is corrupt",
                    status=500,
                    code="validation_receipt_corrupt",
                )
        finally:
            os.close(fd)
        try:
            text = raw.decode("ascii")
        except UnicodeDecodeError as exc:
            raise BridgeError(
                "Download validation receipt is corrupt",
                status=500,
                code="validation_receipt_corrupt",
            ) from exc
        match = _RECEIPT_RE.fullmatch(text)
        if match is None:
            raise BridgeError(
                "Download validation receipt is corrupt",
                status=500,
                code="validation_receipt_corrupt",
            )
        size = int(match.group(1))
        if size < 0:
            raise BridgeError(
                "Download validation receipt is corrupt",
                status=500,
                code="validation_receipt_corrupt",
            )
        return size, match.group(2)

    def persist(self, job_id: str, item_id: str, *, size: int, sha256: str) -> None:
        if isinstance(size, bool) or not isinstance(size, int) or size < 0:
            raise BridgeError(
                "Invalid download validation receipt",
                status=500,
                code="validation_receipt_unsafe",
            )
        if not isinstance(sha256, str) or _SHA256_RE.fullmatch(sha256) is None:
            raise BridgeError(
                "Invalid download validation receipt",
                status=500,
                code="validation_receipt_unsafe",
            )
        final = self._path(job_id, item_id)
        existing = self.load(job_id, item_id)
        if existing is not None and existing == (size, sha256):
            return
        raw = f"v1 {size} {sha256}\n".encode("ascii")
        temp = self.root / f".{final.name}.{secrets.token_hex(8)}.tmp"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = -1
        try:
            fd = os.open(temp, flags, 0o600)
            os.fchmod(fd, 0o600)
            offset = 0
            while offset < len(raw):
                written = os.write(fd, raw[offset:])
                if written <= 0:
                    raise OSError("short validation receipt write")
                offset += written
            os.fsync(fd)
            os.close(fd)
            fd = -1
            os.replace(temp, final)
            dir_flags = os.O_RDONLY
            if hasattr(os, "O_DIRECTORY"):
                dir_flags |= os.O_DIRECTORY
            directory_fd = os.open(self.root, dir_flags)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except BridgeError:
            raise
        except OSError as exc:
            raise BridgeError(
                "Download validation receipt could not be persisted",
                status=503,
                code="validation_receipt_unavailable",
                details={"retryable": True},
            ) from exc
        finally:
            if fd >= 0:
                os.close(fd)
            try:
                temp.unlink()
            except (FileNotFoundError, OSError):
                pass

    def clear(self, job_id: str, item_id: str) -> None:
        path = self._path(job_id, item_id)
        try:
            info = os.lstat(path)
        except FileNotFoundError:
            return
        except OSError:
            return
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != 0o600
        ):
            return
        try:
            path.unlink()
        except OSError:
            pass
