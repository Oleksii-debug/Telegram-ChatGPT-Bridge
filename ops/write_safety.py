# -*- coding: utf-8 -*-
"""Persistent preview/commit/idempotency transaction model for Telegram writes.

This module is intentionally transport-agnostic. It never performs Telegram I/O by
itself. External effects are supplied as a callback so CI can prove exactly-once and
ambiguous-outcome semantics with deterministic fakes.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import sqlite3
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Iterator, Mapping, Sequence


class WriteSafetyError(RuntimeError):
    def __init__(self, code: str, *, status: int = 409):
        super().__init__(code)
        self.code = code
        self.status = status


class ReconciliationRequired(WriteSafetyError):
    def __init__(self):
        super().__init__("write_outcome_unknown_reconciliation_required", status=409)


class SafeNoSideEffectFailure(RuntimeError):
    """Callback may raise this only when it knows no external side effect occurred."""

    def __init__(self, code: str = "external_write_rejected"):
        super().__init__(code)
        self.code = code


class WriteAction(str, Enum):
    SEND = "SEND"
    REPLY = "REPLY"
    FORWARD = "FORWARD"
    SEND_FILES = "SEND_FILES"


class TransactionState(str, Enum):
    RESERVED = "RESERVED"
    CALLING = "CALLING"
    COMMITTED = "COMMITTED"
    FAILED_SAFE = "FAILED_SAFE"
    AMBIGUOUS = "AMBIGUOUS"


@dataclass(frozen=True)
class PreviewEnvelope:
    token: str
    preview_id: str
    action: WriteAction
    request_fingerprint: str
    expires_at: int
    payload: dict[str, Any]


@dataclass(frozen=True)
class CommitResult:
    state: str
    idempotent_replay: bool
    request_fingerprint: str
    result: dict[str, Any] | None


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _require_hash(value: str, code: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or any(ch not in "0123456789abcdef" for ch in value):
        raise WriteSafetyError(code, status=400)
    return value


def _positive_int(value: Any, code: str) -> int:
    if isinstance(value, bool):
        raise WriteSafetyError(code, status=400)
    try:
        number = int(value)
    except (TypeError, ValueError) as exc:
        raise WriteSafetyError(code, status=400) from exc
    if number <= 0:
        raise WriteSafetyError(code, status=400)
    return number


def _safe_id(value: Any, code: str, *, max_len: int = 128) -> str:
    if not isinstance(value, str):
        value = str(value or "")
    value = value.strip()
    if not value or len(value) > max_len or any(ord(ch) < 32 for ch in value):
        raise WriteSafetyError(code, status=400)
    return value


def normalize_write_payload(action: WriteAction | str, payload: Mapping[str, Any]) -> dict[str, Any]:
    """Validate and normalize immutable request material used by preview/commit.

    Chat names, message bodies and file names may exist in this private envelope because
    they are required for the actual write. They are never emitted by audit_metadata().
    """
    try:
        action_e = action if isinstance(action, WriteAction) else WriteAction(str(action))
    except ValueError as exc:
        raise WriteSafetyError("unsupported_write_action", status=400) from exc
    if not isinstance(payload, Mapping):
        raise WriteSafetyError("invalid_write_payload", status=400)

    if action_e in {WriteAction.SEND, WriteAction.REPLY}:
        target = _safe_id(payload.get("target"), "target_required", max_len=256)
        text = payload.get("text")
        if not isinstance(text, str) or not text.strip():
            raise WriteSafetyError("text_required", status=400)
        if len(text) > 4096:
            raise WriteSafetyError("text_too_long", status=413)
        normalized: dict[str, Any] = {"target": target, "text": text}
        if action_e is WriteAction.REPLY:
            normalized["reply_to_message_id"] = _positive_int(payload.get("reply_to_message_id"), "reply_target_required")
        elif payload.get("reply_to_message_id") not in (None, ""):
            raise WriteSafetyError("send_cannot_include_reply_target", status=400)
        return normalized

    if action_e is WriteAction.FORWARD:
        source = _safe_id(payload.get("source"), "source_required", max_len=256)
        target = _safe_id(payload.get("target"), "target_required", max_len=256)
        raw_ids = payload.get("message_ids")
        if not isinstance(raw_ids, Sequence) or isinstance(raw_ids, (str, bytes)):
            raise WriteSafetyError("invalid_message_ids", status=400)
        ids = [_positive_int(item, "invalid_message_ids") for item in raw_ids]
        if not ids or len(ids) > 100 or len(set(ids)) != len(ids):
            raise WriteSafetyError("invalid_message_ids", status=400)
        return {"source": source, "target": target, "message_ids": ids}

    target = _safe_id(payload.get("target"), "target_required", max_len=256)
    caption = payload.get("caption", "")
    if not isinstance(caption, str) or len(caption) > 4096:
        raise WriteSafetyError("caption_too_long", status=413)
    raw_files = payload.get("files")
    if not isinstance(raw_files, Sequence) or isinstance(raw_files, (str, bytes)):
        raise WriteSafetyError("files_required", status=400)
    files: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in raw_files:
        if not isinstance(item, Mapping):
            raise WriteSafetyError("invalid_file_reference", status=400)
        file_id = _safe_id(item.get("file_id"), "invalid_file_reference", max_len=128)
        digest = _require_hash(str(item.get("sha256") or ""), "file_hash_required")
        size = _positive_int(item.get("size"), "invalid_file_size")
        if size > 100 * 1024 * 1024:
            raise WriteSafetyError("file_too_large", status=413)
        dedupe = f"{file_id}:{digest}"
        if dedupe in seen:
            continue
        seen.add(dedupe)
        files.append({"file_id": file_id, "sha256": digest, "size": size})
    if not files or len(files) > 10:
        raise WriteSafetyError("invalid_file_count", status=400)
    if sum(item["size"] for item in files) > 250 * 1024 * 1024:
        raise WriteSafetyError("files_total_too_large", status=413)
    voice_note = bool(payload.get("voice_note", False))
    if voice_note and len(files) != 1:
        raise WriteSafetyError("voice_note_requires_single_file", status=400)
    result: dict[str, Any] = {"target": target, "files": files, "caption": caption, "voice_note": voice_note}
    if payload.get("reply_to_message_id") not in (None, ""):
        result["reply_to_message_id"] = _positive_int(payload.get("reply_to_message_id"), "invalid_reply_target")
    return result


def request_fingerprint(action: WriteAction | str, payload: Mapping[str, Any]) -> str:
    try:
        action_e = action if isinstance(action, WriteAction) else WriteAction(str(action))
    except ValueError as exc:
        raise WriteSafetyError("unsupported_write_action", status=400) from exc
    normalized = normalize_write_payload(action_e, payload)
    return _sha256_text(_canonical_json({"action": action_e.value, "payload": normalized}))


class PersistentWriteStore:
    SCHEMA_VERSION = 1

    def __init__(self, db_path: str | Path, *, preview_ttl_seconds: int = 300, busy_timeout_ms: int = 5000):
        if preview_ttl_seconds <= 0 or preview_ttl_seconds > 3600:
            raise ValueError("preview TTL must be 1..3600 seconds")
        if busy_timeout_ms <= 0 or busy_timeout_ms > 60000:
            raise ValueError("bounded SQLite busy timeout required")
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.preview_ttl_seconds = preview_ttl_seconds
        self.busy_timeout_ms = busy_timeout_ms
        self._thread_lock = threading.RLock()
        self._init_schema()

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        con = sqlite3.connect(str(self.db_path), timeout=self.busy_timeout_ms / 1000.0, isolation_level=None)
        try:
            con.row_factory = sqlite3.Row
            con.execute("PRAGMA foreign_keys=ON")
            con.execute("PRAGMA journal_mode=WAL")
            con.execute("PRAGMA synchronous=FULL")
            con.execute(f"PRAGMA busy_timeout={self.busy_timeout_ms}")
            yield con
        finally:
            con.close()

    def _init_schema(self) -> None:
        managed_data_tables = {"previews", "idempotency"}
        with self._connect() as con:
            con.execute("BEGIN IMMEDIATE")
            try:
                preexisting_objects = {
                    (row["name"], row["type"])
                    for row in con.execute(
                        "SELECT name, type FROM sqlite_master WHERE name IN ('meta','previews','idempotency','idx_previews_expires','idx_idempotency_state')"
                    ).fetchall()
                }
                preexisting_names = {name for name, _ in preexisting_objects}

                con.execute(
                    """
                    CREATE TABLE IF NOT EXISTS meta (
                        key TEXT PRIMARY KEY,
                        value TEXT NOT NULL
                    )
                    """
                )
                existing = con.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()
                if existing is None:
                    if preexisting_names & managed_data_tables:
                        raise RuntimeError("write-store schema metadata missing")
                    con.execute(
                        "INSERT OR IGNORE INTO meta(key,value) VALUES('schema_version',?)",
                        (str(self.SCHEMA_VERSION),),
                    )
                    existing = con.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()
                if existing is None:
                    raise RuntimeError("write-store schema version could not be initialized")
                if existing["value"] != str(self.SCHEMA_VERSION):
                    raise RuntimeError("unsupported write-store schema")

                con.execute(
                    """
                    CREATE TABLE IF NOT EXISTS previews (
                        preview_id TEXT PRIMARY KEY,
                        token_hash TEXT NOT NULL UNIQUE,
                        action TEXT NOT NULL,
                        request_fingerprint TEXT NOT NULL,
                        payload_json TEXT NOT NULL,
                        created_at INTEGER NOT NULL,
                        expires_at INTEGER NOT NULL,
                        consumed_at INTEGER
                    )
                    """
                )
                con.execute(
                    """
                    CREATE TABLE IF NOT EXISTS idempotency (
                        key_hash TEXT PRIMARY KEY,
                        request_fingerprint TEXT NOT NULL,
                        preview_id TEXT NOT NULL,
                        state TEXT NOT NULL,
                        result_json TEXT,
                        created_at INTEGER NOT NULL,
                        updated_at INTEGER NOT NULL,
                        FOREIGN KEY(preview_id) REFERENCES previews(preview_id)
                    )
                    """
                )
                con.execute("CREATE INDEX IF NOT EXISTS idx_previews_expires ON previews(expires_at)")
                con.execute("CREATE INDEX IF NOT EXISTS idx_idempotency_state ON idempotency(state)")
                con.commit()
            except Exception:
                if con.in_transaction:
                    con.rollback()
                raise

    @staticmethod
    def _token_hash(token: str) -> str:
        return _sha256_text(token)

    @staticmethod
    def _idempotency_hash(key: str) -> str:
        if not isinstance(key, str) or not (8 <= len(key) <= 200) or any(ord(ch) < 32 for ch in key):
            raise WriteSafetyError("invalid_idempotency_key", status=400)
        return _sha256_text(key)

    def create_preview(self, action: WriteAction | str, payload: Mapping[str, Any], *, now: int | None = None, ttl_seconds: int | None = None) -> PreviewEnvelope:
        try:
            action_e = action if isinstance(action, WriteAction) else WriteAction(str(action))
        except ValueError as exc:
            raise WriteSafetyError("unsupported_write_action", status=400) from exc
        normalized = normalize_write_payload(action_e, payload)
        fingerprint = request_fingerprint(action_e, normalized)
        created = int(time.time() if now is None else now)
        ttl = self.preview_ttl_seconds if ttl_seconds is None else int(ttl_seconds)
        if ttl <= 0 or ttl > 3600:
            raise WriteSafetyError("invalid_preview_ttl", status=400)
        expires = created + ttl
        token = secrets.token_urlsafe(32)
        token_hash = self._token_hash(token)
        preview_id = _sha256_text(f"{token_hash}:{fingerprint}:{created}")[:32]
        with self._connect() as con:
            con.execute(
                "INSERT INTO previews(preview_id,token_hash,action,request_fingerprint,payload_json,created_at,expires_at,consumed_at) VALUES(?,?,?,?,?,?,?,NULL)",
                (preview_id, token_hash, action_e.value, fingerprint, _canonical_json(normalized), created, expires),
            )
        return PreviewEnvelope(token, preview_id, action_e, fingerprint, expires, normalized)

    def _load_preview(self, con: sqlite3.Connection, token: str) -> sqlite3.Row | None:
        if not isinstance(token, str) or not token:
            return None
        return con.execute("SELECT * FROM previews WHERE token_hash=?", (self._token_hash(token),)).fetchone()

    def get_preview(self, token: str) -> PreviewEnvelope | None:
        with self._connect() as con:
            row = self._load_preview(con, token)
            if row is None:
                return None
            return PreviewEnvelope(
                token=token,
                preview_id=row["preview_id"],
                action=WriteAction(row["action"]),
                request_fingerprint=row["request_fingerprint"],
                expires_at=int(row["expires_at"]),
                payload=json.loads(row["payload_json"]),
            )

    def _begin_commit(
        self,
        preview_token: str,
        *,
        expected_action: WriteAction,
        idempotency_key: str,
        now: int,
    ) -> tuple[str, sqlite3.Row, dict[str, Any] | None]:
        key_hash = self._idempotency_hash(idempotency_key)
        with self._connect() as con:
            con.execute("BEGIN IMMEDIATE")
            try:
                preview = self._load_preview(con, preview_token)
                if preview is None:
                    raise WriteSafetyError("invalid_preview", status=404)
                if preview["action"] != expected_action.value:
                    raise WriteSafetyError("preview_action_mismatch", status=409)
                fingerprint = preview["request_fingerprint"]
                existing = con.execute("SELECT * FROM idempotency WHERE key_hash=?", (key_hash,)).fetchone()
                if existing is not None:
                    if existing["request_fingerprint"] != fingerprint or existing["preview_id"] != preview["preview_id"]:
                        raise WriteSafetyError("idempotency_key_conflict", status=409)
                    state = existing["state"]
                    if state == TransactionState.COMMITTED.value:
                        result = json.loads(existing["result_json"]) if existing["result_json"] else None
                        con.commit()
                        return "REPLAY", preview, result
                    if state == TransactionState.CALLING.value:
                        con.commit()
                        raise WriteSafetyError("write_in_progress", status=409)
                    if state == TransactionState.AMBIGUOUS.value:
                        con.commit()
                        raise ReconciliationRequired()
                    if state == TransactionState.RESERVED.value:
                        con.execute("UPDATE idempotency SET updated_at=? WHERE key_hash=?", (now, key_hash))
                        con.commit()
                        return "RESUME_RESERVED", preview, None
                    raise WriteSafetyError("previous_safe_failure_requires_new_preview", status=409)
                if int(preview["expires_at"]) < now:
                    raise WriteSafetyError("expired_preview", status=409)
                if preview["consumed_at"] is not None:
                    raise WriteSafetyError("used_preview", status=409)
                con.execute(
                    "INSERT INTO idempotency(key_hash,request_fingerprint,preview_id,state,result_json,created_at,updated_at) VALUES(?,?,?,?,NULL,?,?)",
                    (key_hash, fingerprint, preview["preview_id"], TransactionState.RESERVED.value, now, now),
                )
                con.execute("UPDATE previews SET consumed_at=? WHERE preview_id=?", (now, preview["preview_id"]))
                con.commit()
                return "NEW", preview, None
            except Exception:
                if con.in_transaction:
                    con.rollback()
                raise

    def _transition_to_calling(self, idempotency_key: str, fingerprint: str, *, now: int) -> dict[str, Any] | None:
        """Claim the external-call boundary or return a durable raced commit result.

        A caller reaches this method only after observing NEW/RESERVED state. If a
        concurrent writer commits before this caller acquires the transition lock, the
        durable result is a replay and must be returned without performing a second
        external effect.
        """
        key_hash = self._idempotency_hash(idempotency_key)
        with self._connect() as con:
            con.execute("BEGIN IMMEDIATE")
            row = con.execute("SELECT * FROM idempotency WHERE key_hash=?", (key_hash,)).fetchone()
            if row is None or row["request_fingerprint"] != fingerprint:
                con.rollback()
                raise WriteSafetyError("idempotency_state_missing", status=409)
            state = row["state"]
            if state == TransactionState.COMMITTED.value:
                if not row["result_json"]:
                    con.rollback()
                    raise ReconciliationRequired()
                result = json.loads(row["result_json"])
                if not isinstance(result, dict):
                    con.rollback()
                    raise ReconciliationRequired()
                con.rollback()
                return result
            if state != TransactionState.RESERVED.value:
                con.rollback()
                if state == TransactionState.CALLING.value:
                    raise WriteSafetyError("write_in_progress", status=409)
                if state == TransactionState.AMBIGUOUS.value:
                    raise ReconciliationRequired()
                raise WriteSafetyError("illegal_write_state_transition", status=409)
            con.execute(
                "UPDATE idempotency SET state=?, updated_at=? WHERE key_hash=?",
                (TransactionState.CALLING.value, now, key_hash),
            )
            con.commit()
            return None

    def _commit_result(self, idempotency_key: str, fingerprint: str, result: Mapping[str, Any], *, now: int) -> None:
        key_hash = self._idempotency_hash(idempotency_key)
        result_json = _canonical_json(dict(result))
        if len(result_json.encode("utf-8")) > 64 * 1024:
            raise WriteSafetyError("write_result_too_large", status=502)
        with self._connect() as con:
            con.execute("BEGIN IMMEDIATE")
            row = con.execute("SELECT * FROM idempotency WHERE key_hash=?", (key_hash,)).fetchone()
            if row is None or row["request_fingerprint"] != fingerprint or row["state"] != TransactionState.CALLING.value:
                con.rollback()
                raise WriteSafetyError("illegal_write_state_transition", status=409)
            con.execute(
                "UPDATE idempotency SET state=?, result_json=?, updated_at=? WHERE key_hash=?",
                (TransactionState.COMMITTED.value, result_json, now, key_hash),
            )
            con.commit()

    def _record_safe_failure(self, idempotency_key: str, fingerprint: str, *, now: int) -> None:
        key_hash = self._idempotency_hash(idempotency_key)
        with self._connect() as con:
            con.execute("BEGIN IMMEDIATE")
            row = con.execute("SELECT * FROM idempotency WHERE key_hash=?", (key_hash,)).fetchone()
            if row is None or row["request_fingerprint"] != fingerprint:
                con.rollback()
                raise WriteSafetyError("idempotency_state_missing", status=409)
            if row["state"] != TransactionState.CALLING.value:
                con.rollback()
                raise WriteSafetyError("illegal_write_state_transition", status=409)
            con.execute(
                "UPDATE idempotency SET state=?, updated_at=? WHERE key_hash=?",
                (TransactionState.FAILED_SAFE.value, now, key_hash),
            )
            con.commit()

    def _record_ambiguous(self, idempotency_key: str, fingerprint: str, *, now: int) -> None:
        key_hash = self._idempotency_hash(idempotency_key)
        with self._connect() as con:
            con.execute("BEGIN IMMEDIATE")
            row = con.execute("SELECT * FROM idempotency WHERE key_hash=?", (key_hash,)).fetchone()
            if row is None or row["request_fingerprint"] != fingerprint:
                con.rollback()
                raise WriteSafetyError("idempotency_state_missing", status=409)
            state = row["state"]
            if state == TransactionState.COMMITTED.value:
                con.rollback()
                return
            if state != TransactionState.CALLING.value:
                con.rollback()
                raise WriteSafetyError("illegal_write_state_transition", status=409)
            con.execute(
                "UPDATE idempotency SET state=?, updated_at=? WHERE key_hash=?",
                (TransactionState.AMBIGUOUS.value, now, key_hash),
            )
            con.commit()

    def _durable_committed_result(self, idempotency_key: str, fingerprint: str) -> dict[str, Any] | None:
        """Return a matching durable COMMITTED receipt without changing state."""
        key_hash = self._idempotency_hash(idempotency_key)
        with self._connect() as con:
            row = con.execute("SELECT * FROM idempotency WHERE key_hash=?", (key_hash,)).fetchone()
            if row is None or row["request_fingerprint"] != fingerprint:
                return None
            if row["state"] != TransactionState.COMMITTED.value or not row["result_json"]:
                return None
            try:
                result = json.loads(row["result_json"])
            except (TypeError, ValueError, json.JSONDecodeError):
                return None
            return result if isinstance(result, dict) else None

    def commit(
        self,
        preview_token: str,
        *,
        expected_action: WriteAction | str,
        idempotency_key: str,
        external_write: Callable[[dict[str, Any]], Mapping[str, Any]],
        now: int | None = None,
    ) -> CommitResult:
        try:
            action_e = expected_action if isinstance(expected_action, WriteAction) else WriteAction(str(expected_action))
        except ValueError as exc:
            raise WriteSafetyError("unsupported_write_action", status=400) from exc
        ts = int(time.time() if now is None else now)
        mode, preview, cached = self._begin_commit(
            preview_token,
            expected_action=action_e,
            idempotency_key=idempotency_key,
            now=ts,
        )
        fingerprint = preview["request_fingerprint"]
        if mode == "REPLAY":
            return CommitResult("COMMITTED", True, fingerprint, cached)
        payload = json.loads(preview["payload_json"])
        raced_commit = self._transition_to_calling(idempotency_key, fingerprint, now=ts)
        if raced_commit is not None:
            return CommitResult("COMMITTED", True, fingerprint, raced_commit)
        try:
            result = dict(external_write(payload))
        except SafeNoSideEffectFailure as exc:
            self._record_safe_failure(idempotency_key, fingerprint, now=ts)
            raise WriteSafetyError(exc.code, status=502) from None
        except Exception:
            self._record_ambiguous(idempotency_key, fingerprint, now=ts)
            raise ReconciliationRequired() from None
        try:
            self._commit_result(idempotency_key, fingerprint, result, now=ts)
        except Exception:
            durable_result = self._durable_committed_result(idempotency_key, fingerprint)
            if durable_result is not None:
                return CommitResult("COMMITTED", False, fingerprint, durable_result)
            try:
                self._record_ambiguous(idempotency_key, fingerprint, now=ts)
            finally:
                raise ReconciliationRequired() from None
        return CommitResult("COMMITTED", False, fingerprint, result)

    def mark_calling_transaction_ambiguous_on_recovery(self, *, now: int | None = None) -> int:
        ts = int(time.time() if now is None else now)
        with self._connect() as con:
            con.execute("BEGIN IMMEDIATE")
            cur = con.execute(
                "UPDATE idempotency SET state=?, updated_at=? WHERE state=?",
                (TransactionState.AMBIGUOUS.value, ts, TransactionState.CALLING.value),
            )
            changed = cur.rowcount
            con.commit()
            return changed

    def simulate_reserved_crash_for_test(self, preview_token: str, *, expected_action: WriteAction | str, idempotency_key: str, now: int) -> None:
        try:
            action_e = expected_action if isinstance(expected_action, WriteAction) else WriteAction(str(expected_action))
        except ValueError as exc:
            raise WriteSafetyError("unsupported_write_action", status=400) from exc
        self._begin_commit(preview_token, expected_action=action_e, idempotency_key=idempotency_key, now=now)

    def simulate_calling_crash_for_test(self, preview_token: str, *, expected_action: WriteAction | str, idempotency_key: str, now: int) -> None:
        try:
            action_e = expected_action if isinstance(expected_action, WriteAction) else WriteAction(str(expected_action))
        except ValueError as exc:
            raise WriteSafetyError("unsupported_write_action", status=400) from exc
        _, preview, _ = self._begin_commit(preview_token, expected_action=action_e, idempotency_key=idempotency_key, now=now)
        self._transition_to_calling(idempotency_key, preview["request_fingerprint"], now=now)

    def transaction_state(self, idempotency_key: str) -> str | None:
        key_hash = self._idempotency_hash(idempotency_key)
        with self._connect() as con:
            row = con.execute("SELECT state FROM idempotency WHERE key_hash=?", (key_hash,)).fetchone()
            return str(row["state"]) if row is not None else None

    def cleanup(self, *, now: int | None = None, expired_preview_grace_seconds: int = 86400) -> dict[str, int]:
        """Delete only stale uncommitted preview payloads.

        Idempotency rows, committed tombstones and ambiguous rows are deliberately never
        deleted here; that prevents cleanup/restart from re-enabling duplicate sends.
        """
        ts = int(time.time() if now is None else now)
        cutoff = ts - max(0, int(expired_preview_grace_seconds))
        with self._connect() as con:
            con.execute("BEGIN IMMEDIATE")
            cur = con.execute(
                "DELETE FROM previews WHERE expires_at < ? AND consumed_at IS NULL AND preview_id NOT IN (SELECT preview_id FROM idempotency)",
                (cutoff,),
            )
            deleted = cur.rowcount
            con.commit()
        return {"expired_uncommitted_previews_deleted": deleted, "idempotency_tombstones_deleted": 0}

    def audit_metadata(self, preview_token: str, *, idempotency_key: str | None = None) -> dict[str, Any]:
        with self._connect() as con:
            preview = self._load_preview(con, preview_token)
            if preview is None:
                raise WriteSafetyError("invalid_preview", status=404)
            payload = json.loads(preview["payload_json"])
            action = preview["action"]
            target = str(payload.get("target", ""))
            metadata: dict[str, Any] = {
                "operation_kind": action,
                "request_fingerprint": preview["request_fingerprint"],
                "target_sha256": _sha256_text(target),
                "payload_sha256": _sha256_text(preview["payload_json"]),
                "preview_id": preview["preview_id"],
                "file_count": len(payload.get("files", [])) if isinstance(payload.get("files"), list) else 0,
                "message_count": len(payload.get("message_ids", [])) if isinstance(payload.get("message_ids"), list) else (1 if action in {"SEND", "REPLY"} else 0),
                "status": "USED" if preview["consumed_at"] is not None else "PREVIEWED",
            }
            if idempotency_key is not None:
                metadata["idempotency_sha256"] = self._idempotency_hash(idempotency_key)
            return metadata
