"""Private file registry and resumable download checkpoints."""

from __future__ import annotations

import hashlib
import json
import os
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


@dataclass(frozen=True)
class FileRecord:
    file_ref: str
    path: str
    name: str
    mime_type: str
    size: int
    sha256: str
    created_at: int

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
        with self._connect() as con:
            con.execute(
                """
                CREATE TABLE IF NOT EXISTS files (
                    file_ref TEXT PRIMARY KEY,
                    rel_path TEXT NOT NULL UNIQUE,
                    name TEXT NOT NULL,
                    mime_type TEXT NOT NULL,
                    size INTEGER NOT NULL,
                    sha256 TEXT NOT NULL,
                    created_at INTEGER NOT NULL
                )
                """
            )
            con.commit()

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        con = sqlite3.connect(str(self.db_path), timeout=8.0)
        try:
            con.execute("PRAGMA journal_mode=WAL")
            con.execute("PRAGMA synchronous=FULL")
            yield con
        finally:
            con.close()

    def _relative_path(self, path: Path) -> str:
        try:
            original_stat = os.lstat(path)
        except OSError as exc:
            raise BridgeError("File is unavailable", status=500, code="unsafe_file_path") from exc
        if stat.S_ISLNK(original_stat.st_mode) or not stat.S_ISREG(original_stat.st_mode) or original_stat.st_nlink != 1:
            raise BridgeError("Unsafe file topology", status=500, code="unsafe_file_topology")
        resolved = path.resolve(strict=True)
        try:
            rel = resolved.relative_to(self.root)
        except ValueError as exc:
            raise BridgeError("File is outside private storage", status=500, code="unsafe_file_path") from exc
        st = os.lstat(resolved)
        if not stat.S_ISREG(st.st_mode) or resolved.is_symlink() or st.st_nlink != 1:
            raise BridgeError("Unsafe file topology", status=500, code="unsafe_file_topology")
        return rel.as_posix()

    @staticmethod
    def _hash(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    def add(self, path: Path, *, name: str, mime_type: str = "application/octet-stream") -> FileRecord:
        rel = self._relative_path(path)
        size = path.stat().st_size
        sha256 = self._hash(path)
        now = int(time.time())
        # 32 URL-safe characters (~192 bits) and no relationship to server path.
        file_ref = secrets.token_urlsafe(24)
        with self._connect() as con:
            con.execute(
                "INSERT INTO files(file_ref,rel_path,name,mime_type,size,sha256,created_at) VALUES (?,?,?,?,?,?,?)",
                (file_ref, rel, name[:180], mime_type[:160], size, sha256, now),
            )
            con.commit()
        return FileRecord(file_ref, str(path.resolve()), name[:180], mime_type[:160], size, sha256, now)

    def get(self, file_ref: str) -> FileRecord | None:
        try:
            safe_ref = validate_file_ref(file_ref)
        except BridgeError:
            return None
        with self._connect() as con:
            row = con.execute(
                "SELECT rel_path,name,mime_type,size,sha256,created_at FROM files WHERE file_ref=?",
                (safe_ref,),
            ).fetchone()
        if not row:
            return None
        candidate = (self.root / row[0]).resolve()
        try:
            rel = candidate.relative_to(self.root)
        except ValueError:
            return None
        if rel.as_posix() != row[0]:
            return None
        try:
            st = os.lstat(candidate)
        except OSError:
            return None
        if not stat.S_ISREG(st.st_mode) or candidate.is_symlink() or st.st_nlink != 1:
            return None
        if st.st_size != int(row[3]):
            return None
        if not secrets.compare_digest(self._hash(candidate), str(row[4])):
            return None
        return FileRecord(safe_ref, str(candidate), row[1], row[2], int(row[3]), row[4], int(row[5]))


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
        with self._connect() as con:
            con.execute(
                """
                CREATE TABLE IF NOT EXISTS download_jobs (
                    job_id TEXT PRIMARY KEY,
                    payload_json TEXT NOT NULL,
                    payload_sha256 TEXT NOT NULL,
                    updated_at INTEGER NOT NULL
                )
                """
            )
            con.commit()

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        con = sqlite3.connect(str(self.db_path), timeout=8.0)
        try:
            con.execute("PRAGMA journal_mode=WAL")
            con.execute("PRAGMA synchronous=FULL")
            yield con
        finally:
            con.close()

    @staticmethod
    def _canonical(payload: dict[str, Any]) -> bytes:
        return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def _validate(self, payload: dict[str, Any]) -> None:
        if set(payload) != {"schema", "job_id", "status", "items", "results", "failures"}:
            raise BridgeError("Download checkpoint is corrupt", status=500, code="checkpoint_corrupt")
        if payload["schema"] != self.SCHEMA:
            raise BridgeError("Download checkpoint schema is unsupported", status=500, code="checkpoint_schema")
        if payload["status"] not in {"pending", "running", "partial", "complete", "failed"}:
            raise BridgeError("Download checkpoint is corrupt", status=500, code="checkpoint_corrupt")
        if not isinstance(payload["items"], list) or len(payload["items"]) > 500:
            raise BridgeError("Download checkpoint is corrupt", status=500, code="checkpoint_corrupt")
        if not isinstance(payload["results"], dict) or not isinstance(payload["failures"], dict):
            raise BridgeError("Download checkpoint is corrupt", status=500, code="checkpoint_corrupt")
        ids: set[str] = set()
        for raw in payload["items"]:
            if not isinstance(raw, dict):
                raise BridgeError("Download checkpoint is corrupt", status=500, code="checkpoint_corrupt")
            try:
                item = DownloadItem(**raw)
            except (TypeError, ValueError) as exc:
                raise BridgeError("Download checkpoint is corrupt", status=500, code="checkpoint_corrupt") from exc
            if item.item_id in ids or not item.item_id:
                raise BridgeError("Download checkpoint is corrupt", status=500, code="checkpoint_corrupt")
            ids.add(item.item_id)
        if not set(payload["results"]).issubset(ids) or not set(payload["failures"]).issubset(ids):
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
        with self._connect() as con:
            con.execute(
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
            con.commit()

    def load(self, job_id: str) -> dict[str, Any]:
        if not isinstance(job_id, str) or len(job_id) > 128:
            raise BridgeError("Download job not found", status=404, code="job_not_found")
        with self._connect() as con:
            row = con.execute(
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
        return payload
