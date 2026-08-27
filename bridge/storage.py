"""Private file registry and resumable download checkpoints."""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import sqlite3
import stat
import time
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterator

from .errors import BridgeError
from .validation import validate_file_ref

_JOB_ID_RE = re.compile(r"^[A-Za-z0-9_-]{16,128}$")
_ITEM_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
_CODE_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_ORIGIN_KEY_RE = re.compile(r"^dl_[0-9a-f]{64}$")
_SQLITE_TIMEOUT_SECONDS = 8.0
_SQLITE_BUSY_RETRY_SECONDS = 0.025
_SQLITE_BUSY_CODES = {
    getattr(sqlite3, "SQLITE_BUSY", 5),
    getattr(sqlite3, "SQLITE_LOCKED", 6),
}


def _sqlite_lock_contention(exc: sqlite3.OperationalError) -> bool:
    """Recognize SQLite busy/locked errors by numeric code, never message text."""

    code = getattr(exc, "sqlite_errorcode", None)
    return isinstance(code, int) and (code & 0xFF) in _SQLITE_BUSY_CODES


def _configure_sqlite_connection(connection: sqlite3.Connection) -> None:
    """Enable WAL with a bounded retry during concurrent cold bootstrap."""

    connection.execute(f"PRAGMA busy_timeout={int(_SQLITE_TIMEOUT_SECONDS * 1000)}")
    deadline = time.monotonic() + _SQLITE_TIMEOUT_SECONDS
    while True:
        try:
            row = connection.execute("PRAGMA journal_mode=WAL").fetchone()
            if not row or str(row[0]).lower() != "wal":
                raise sqlite3.OperationalError("SQLite WAL mode was not enabled")
            break
        except sqlite3.OperationalError as exc:
            if not _sqlite_lock_contention(exc) or time.monotonic() >= deadline:
                raise
            time.sleep(_SQLITE_BUSY_RETRY_SECONDS)
    connection.execute("PRAGMA synchronous=FULL")


@dataclass(frozen=True)
class FileRecord:
    file_ref: str
    path: str
    name: str
    mime_type: str
    size: int
    sha256: str
    created_at: int
    origin_key: str | None = None

    def public_metadata(self) -> dict[str, Any]:
        return {
            "file_ref": self.file_ref,
            "name": self.name,
            "mime_type": self.mime_type,
            "size": self.size,
            "sha256": self.sha256,
            "created_at": self.created_at,
        }


class FileRecordStore:
    def __init__(self, db_path: Path, root: Path) -> None:
        self.db_path = db_path.resolve()
        self.root = root.resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        for directory in {self.root, self.db_path.parent}:
            try:
                os.chmod(directory, 0o700)
            except OSError:
                pass
        with self._connect() as connection:
            # Serialize schema inspection + migration across Passenger workers.
            # Without an immediate write transaction two workers can both see
            # a legacy schema and race the same ALTER TABLE ADD COLUMN.
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS files (
                    file_ref TEXT PRIMARY KEY,
                    rel_path TEXT NOT NULL UNIQUE,
                    name TEXT NOT NULL,
                    mime_type TEXT NOT NULL,
                    size INTEGER NOT NULL,
                    sha256 TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    origin_key TEXT
                )
                """
            )
            columns = {str(row[1]) for row in connection.execute("PRAGMA table_info(files)")}
            if "origin_key" not in columns:
                connection.execute("ALTER TABLE files ADD COLUMN origin_key TEXT")
            connection.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS files_origin_key_unique ON files(origin_key) WHERE origin_key IS NOT NULL"
            )
            connection.commit()

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(str(self.db_path), timeout=_SQLITE_TIMEOUT_SECONDS)
        try:
            _configure_sqlite_connection(connection)
            yield connection
        finally:
            connection.close()

    @staticmethod
    def _validate_origin_key(origin_key: str | None) -> str | None:
        if origin_key is None:
            return None
        if not isinstance(origin_key, str) or not _ORIGIN_KEY_RE.fullmatch(origin_key):
            raise BridgeError("Invalid private file origin key", status=500, code="invalid_origin_key")
        return origin_key

    def _relative_path(self, path: Path) -> str:
        try:
            original_stat = os.lstat(path)
        except OSError as exc:
            raise BridgeError("File is unavailable", status=500, code="unsafe_file_path") from exc
        if stat.S_ISLNK(original_stat.st_mode) or not stat.S_ISREG(original_stat.st_mode) or original_stat.st_nlink != 1:
            raise BridgeError("Unsafe file topology", status=500, code="unsafe_file_topology")
        resolved = path.resolve(strict=True)
        try:
            relative = resolved.relative_to(self.root)
        except ValueError as exc:
            raise BridgeError("File is outside private storage", status=500, code="unsafe_file_path") from exc
        resolved_stat = os.lstat(resolved)
        if not stat.S_ISREG(resolved_stat.st_mode) or resolved.is_symlink() or resolved_stat.st_nlink != 1:
            raise BridgeError("Unsafe file topology", status=500, code="unsafe_file_topology")
        return relative.as_posix()

    @staticmethod
    def _hash(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    def add(
        self,
        path: Path,
        *,
        name: str,
        mime_type: str = "application/octet-stream",
        origin_key: str | None = None,
    ) -> FileRecord:
        origin = self._validate_origin_key(origin_key)
        relative = self._relative_path(path)
        size = path.stat().st_size
        sha256 = self._hash(path)
        now = int(time.time())
        file_ref = secrets.token_urlsafe(24)
        try:
            with self._connect() as connection:
                connection.execute(
                    "INSERT INTO files(file_ref,rel_path,name,mime_type,size,sha256,created_at,origin_key) VALUES (?,?,?,?,?,?,?,?)",
                    (file_ref, relative, name[:180], mime_type[:160], size, sha256, now, origin),
                )
                connection.commit()
        except sqlite3.IntegrityError as exc:
            raise BridgeError("Private file registry collision", status=409, code="file_registry_collision") from exc
        return FileRecord(file_ref, str(path.resolve()), name[:180], mime_type[:160], size, sha256, now, origin)

    def get(self, file_ref: str) -> FileRecord | None:
        try:
            safe_ref = validate_file_ref(file_ref)
        except BridgeError:
            return None
        with self._connect() as connection:
            row = connection.execute(
                "SELECT rel_path,name,mime_type,size,sha256,created_at,origin_key FROM files WHERE file_ref=?",
                (safe_ref,),
            ).fetchone()
        if not row:
            return None
        candidate = (self.root / row[0]).resolve()
        try:
            relative = candidate.relative_to(self.root)
        except ValueError:
            return None
        if relative.as_posix() != row[0]:
            return None
        try:
            candidate_stat = os.lstat(candidate)
        except OSError:
            return None
        if not stat.S_ISREG(candidate_stat.st_mode) or candidate.is_symlink() or candidate_stat.st_nlink != 1:
            return None
        if candidate_stat.st_size != int(row[3]):
            return None
        if not secrets.compare_digest(self._hash(candidate), str(row[4])):
            return None
        origin = row[6]
        if origin is not None and (not isinstance(origin, str) or not _ORIGIN_KEY_RE.fullmatch(origin)):
            return None
        return FileRecord(safe_ref, str(candidate), row[1], row[2], int(row[3]), row[4], int(row[5]), origin)

    def get_by_origin(self, origin_key: str) -> FileRecord | None:
        """Resolve a private download-origin marker without exposing it publicly."""
        try:
            origin = self._validate_origin_key(origin_key)
        except BridgeError:
            return None
        if origin is None:
            return None
        with self._connect() as connection:
            row = connection.execute("SELECT file_ref FROM files WHERE origin_key=?", (origin,)).fetchone()
        if not row:
            return None
        return self.get(str(row[0]))

    def delete(self, file_ref: str) -> bool:
        """Remove a registered private file and its registry row safely."""
        record = self.get(file_ref)
        if record is None:
            return False
        with self._connect() as connection:
            cursor = connection.execute("DELETE FROM files WHERE file_ref=?", (record.file_ref,))
            connection.commit()
        try:
            Path(record.path).unlink(missing_ok=True)
        except OSError:
            pass
        return cursor.rowcount == 1


@dataclass(frozen=True)
class DownloadItem:
    item_id: str
    chat: str
    message_id: int
    source_file_ref: str
    name: str
    mime_type: str
    expected_size: int | None = None
    expected_sha256: str | None = None

    def private_dict(self) -> dict[str, Any]:
        return asdict(self)


class CheckpointStore:
    SCHEMA = 1

    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path.resolve()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.db_path.parent, 0o700)
        except OSError:
            pass
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS download_jobs (
                    job_id TEXT PRIMARY KEY,
                    payload_json TEXT NOT NULL,
                    payload_sha256 TEXT NOT NULL,
                    updated_at INTEGER NOT NULL
                )
                """
            )
            connection.commit()

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(str(self.db_path), timeout=_SQLITE_TIMEOUT_SECONDS)
        try:
            _configure_sqlite_connection(connection)
            yield connection
        finally:
            connection.close()

    @staticmethod
    def _canonical(payload: dict[str, Any]) -> bytes:
        return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")

    @staticmethod
    def _safe_job_id(value: Any) -> str:
        if not isinstance(value, str) or not _JOB_ID_RE.fullmatch(value):
            raise BridgeError("Download checkpoint is corrupt", status=500, code="checkpoint_corrupt")
        return value

    def _validate(self, payload: dict[str, Any]) -> None:
        if set(payload) != {"schema", "job_id", "status", "items", "results", "failures"}:
            raise BridgeError("Download checkpoint is corrupt", status=500, code="checkpoint_corrupt")
        if payload["schema"] != self.SCHEMA:
            raise BridgeError("Download checkpoint schema is unsupported", status=500, code="checkpoint_schema")
        self._safe_job_id(payload["job_id"])
        if payload["status"] not in {"pending", "running", "partial", "complete", "failed"}:
            raise BridgeError("Download checkpoint is corrupt", status=500, code="checkpoint_corrupt")
        if not isinstance(payload["items"], list) or not payload["items"] or len(payload["items"]) > 500:
            raise BridgeError("Download checkpoint is corrupt", status=500, code="checkpoint_corrupt")
        if not isinstance(payload["results"], dict) or not isinstance(payload["failures"], dict):
            raise BridgeError("Download checkpoint is corrupt", status=500, code="checkpoint_corrupt")

        item_ids: set[str] = set()
        for raw in payload["items"]:
            if not isinstance(raw, dict):
                raise BridgeError("Download checkpoint is corrupt", status=500, code="checkpoint_corrupt")
            try:
                item = DownloadItem(**raw)
            except (TypeError, ValueError) as exc:
                raise BridgeError("Download checkpoint is corrupt", status=500, code="checkpoint_corrupt") from exc
            if (
                not isinstance(item.item_id, str)
                or not _ITEM_ID_RE.fullmatch(item.item_id)
                or item.item_id in item_ids
                or not isinstance(item.chat, str)
                or not item.chat
                or isinstance(item.message_id, bool)
                or not isinstance(item.message_id, int)
                or item.message_id <= 0
            ):
                raise BridgeError("Download checkpoint is corrupt", status=500, code="checkpoint_corrupt")
            try:
                validate_file_ref(item.source_file_ref)
            except BridgeError as exc:
                raise BridgeError("Download checkpoint is corrupt", status=500, code="checkpoint_corrupt") from exc
            if item.expected_size is not None and (
                isinstance(item.expected_size, bool) or not isinstance(item.expected_size, int) or item.expected_size < 0
            ):
                raise BridgeError("Download checkpoint is corrupt", status=500, code="checkpoint_corrupt")
            if item.expected_sha256 is not None and not re.fullmatch(r"[0-9a-f]{64}", item.expected_sha256):
                raise BridgeError("Download checkpoint is corrupt", status=500, code="checkpoint_corrupt")
            item_ids.add(item.item_id)

        if not set(payload["results"]).issubset(item_ids) or not set(payload["failures"]).issubset(item_ids):
            raise BridgeError("Download checkpoint is corrupt", status=500, code="checkpoint_corrupt")
        if set(payload["results"]) & set(payload["failures"]):
            raise BridgeError("Download checkpoint is corrupt", status=500, code="checkpoint_corrupt")
        for file_ref in payload["results"].values():
            try:
                validate_file_ref(file_ref)
            except BridgeError as exc:
                raise BridgeError("Download checkpoint is corrupt", status=500, code="checkpoint_corrupt") from exc
        for info in payload["failures"].values():
            if not isinstance(info, dict) or set(info) != {"code", "status", "retryable"}:
                raise BridgeError("Download checkpoint is corrupt", status=500, code="checkpoint_corrupt")
            if not isinstance(info["code"], str) or not _CODE_RE.fullmatch(info["code"]):
                raise BridgeError("Download checkpoint is corrupt", status=500, code="checkpoint_corrupt")
            if isinstance(info["status"], bool) or not isinstance(info["status"], int) or not 400 <= info["status"] <= 599:
                raise BridgeError("Download checkpoint is corrupt", status=500, code="checkpoint_corrupt")
            if not isinstance(info["retryable"], bool):
                raise BridgeError("Download checkpoint is corrupt", status=500, code="checkpoint_corrupt")
        if payload["status"] == "complete" and set(payload["results"]) != item_ids:
            raise BridgeError("Download checkpoint is corrupt", status=500, code="checkpoint_corrupt")

    def create(self, items: list[DownloadItem]) -> str:
        if not items:
            raise BridgeError("At least one download item is required", code="empty_download")
        job_id = secrets.token_urlsafe(18)
        payload = {
            "schema": self.SCHEMA,
            "job_id": job_id,
            "status": "pending",
            "items": [item.private_dict() for item in items],
            "results": {},
            "failures": {},
        }
        self.save(payload)
        return job_id

    def save(self, payload: dict[str, Any]) -> None:
        self._validate(payload)
        raw = self._canonical(payload)
        digest = hashlib.sha256(raw).hexdigest()
        now = int(time.time())
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO download_jobs(job_id,payload_json,payload_sha256,updated_at)
                VALUES (?,?,?,?)
                ON CONFLICT(job_id) DO UPDATE SET
                  payload_json=excluded.payload_json,
                  payload_sha256=excluded.payload_sha256,
                  updated_at=excluded.updated_at
                """,
                (payload["job_id"], raw.decode("utf-8"), digest, now),
            )
            connection.commit()

    def load(self, job_id: str) -> dict[str, Any]:
        if not isinstance(job_id, str) or not _JOB_ID_RE.fullmatch(job_id):
            raise BridgeError("Download job not found", status=404, code="job_not_found")
        with self._connect() as connection:
            row = connection.execute(
                "SELECT payload_json,payload_sha256 FROM download_jobs WHERE job_id=?", (job_id,)
            ).fetchone()
        if not row:
            raise BridgeError("Download job not found", status=404, code="job_not_found")
        raw = row[0].encode("utf-8")
        if not secrets.compare_digest(hashlib.sha256(raw).hexdigest(), row[1]):
            raise BridgeError("Download checkpoint integrity check failed", status=500, code="checkpoint_corrupt")
        try:
            payload = json.loads(row[0])
        except json.JSONDecodeError as exc:
            raise BridgeError("Download checkpoint is corrupt", status=500, code="checkpoint_corrupt") from exc
        if not isinstance(payload, dict):
            raise BridgeError("Download checkpoint is corrupt", status=500, code="checkpoint_corrupt")
        self._validate(payload)
        if payload["job_id"] != job_id:
            raise BridgeError("Download checkpoint identity mismatch", status=500, code="checkpoint_corrupt")
        return payload
