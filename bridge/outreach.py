"""Persistent scheduling and deduplication for controlled Telegram outreach.

This module does not contact Telegram directly. It prepares one explicit
recipient/chat at a time for the existing SEND preview/commit pipeline.
"""
from __future__ import annotations

import hashlib
import sqlite3
import time
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterator
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError


class OutreachError(ValueError):
    pass


@dataclass(frozen=True)
class CampaignSpec:
    campaign_id: str
    message_text: str
    daily_limit: int
    interval_seconds: int = 0
    timezone_name: str = "UTC"
    window_start: str = "00:00"
    window_end: str = "00:00"

    @property
    def message_sha256(self) -> str:
        return hashlib.sha256(self.message_text.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class Delivery:
    campaign_id: str
    recipient: str
    message_text: str
    message_sha256: str
    dedup_key: str
    lease_until: int | None = None


def _safe_recipient(value: str) -> str:
    if not isinstance(value, str):
        raise OutreachError("recipient must be text")
    value = value.strip()
    if not value or len(value) > 256 or any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
        raise OutreachError("invalid recipient")
    return value


def _parse_hhmm(value: str) -> tuple[int, int]:
    try:
        hour_s, minute_s = value.split(":", 1)
        hour, minute = int(hour_s), int(minute_s)
    except (AttributeError, ValueError) as exc:
        raise OutreachError("time must be HH:MM") from exc
    if not 0 <= hour <= 23 or not 0 <= minute <= 59:
        raise OutreachError("time must be HH:MM")
    return hour, minute


def _timezone(name: str) -> ZoneInfo:
    try:
        return ZoneInfo(name)
    except (ZoneInfoNotFoundError, TypeError) as exc:
        raise OutreachError("unknown timezone") from exc


def _validate_spec(spec: CampaignSpec) -> CampaignSpec:
    campaign_id = spec.campaign_id.strip() if isinstance(spec.campaign_id, str) else ""
    if not campaign_id or len(campaign_id) > 128:
        raise OutreachError("invalid campaign_id")
    if not isinstance(spec.message_text, str) or not spec.message_text.strip() or len(spec.message_text) > 4096:
        raise OutreachError("invalid message_text")
    if isinstance(spec.daily_limit, bool) or not isinstance(spec.daily_limit, int) or not 1 <= spec.daily_limit <= 500:
        raise OutreachError("daily_limit must be between 1 and 500")
    if isinstance(spec.interval_seconds, bool) or not isinstance(spec.interval_seconds, int) or not 0 <= spec.interval_seconds <= 86400:
        raise OutreachError("interval_seconds must be between 0 and 86400")
    _timezone(spec.timezone_name)
    _parse_hhmm(spec.window_start)
    _parse_hhmm(spec.window_end)
    return CampaignSpec(
        campaign_id=campaign_id,
        message_text=spec.message_text,
        daily_limit=spec.daily_limit,
        interval_seconds=spec.interval_seconds,
        timezone_name=spec.timezone_name,
        window_start=spec.window_start,
        window_end=spec.window_end,
    )


def _dedup_key(recipient: str, message_sha256: str) -> str:
    return hashlib.sha256(f"{recipient}\0{message_sha256}".encode("utf-8")).hexdigest()


class OutreachStore:
    def __init__(self, db_path: Path) -> None:
        self.db_path = Path(db_path).expanduser().resolve()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as db:
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS campaigns(
                    campaign_id TEXT PRIMARY KEY,
                    message_text TEXT NOT NULL,
                    message_sha256 TEXT NOT NULL,
                    daily_limit INTEGER NOT NULL,
                    interval_seconds INTEGER NOT NULL,
                    timezone_name TEXT NOT NULL,
                    window_start TEXT NOT NULL,
                    window_end TEXT NOT NULL,
                    paused INTEGER NOT NULL DEFAULT 0,
                    created_at INTEGER NOT NULL,
                    last_sent_at INTEGER
                );
                CREATE TABLE IF NOT EXISTS recipients(
                    campaign_id TEXT NOT NULL,
                    recipient TEXT NOT NULL,
                    ordinal INTEGER NOT NULL,
                    status TEXT NOT NULL DEFAULT 'pending',
                    attempts INTEGER NOT NULL DEFAULT 0,
                    next_attempt_at INTEGER NOT NULL DEFAULT 0,
                    lease_until INTEGER,
                    last_error TEXT,
                    sent_at INTEGER,
                    PRIMARY KEY(campaign_id, recipient),
                    FOREIGN KEY(campaign_id) REFERENCES campaigns(campaign_id) ON DELETE CASCADE
                );
                CREATE INDEX IF NOT EXISTS recipients_ready_idx
                ON recipients(campaign_id,status,next_attempt_at,ordinal);
                CREATE TABLE IF NOT EXISTS send_history(
                    dedup_key TEXT PRIMARY KEY,
                    campaign_id TEXT NOT NULL,
                    recipient TEXT NOT NULL,
                    message_sha256 TEXT NOT NULL,
                    sent_at INTEGER NOT NULL
                );
                CREATE INDEX IF NOT EXISTS send_history_campaign_time_idx
                ON send_history(campaign_id,sent_at);
                """
            )
            db.commit()

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        db = sqlite3.connect(str(self.db_path), timeout=8.0)
        db.row_factory = sqlite3.Row
        try:
            db.execute("PRAGMA busy_timeout=8000")
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("PRAGMA synchronous=FULL")
            db.execute("PRAGMA foreign_keys=ON")
            yield db
        finally:
            db.close()

    def create_campaign(self, spec: CampaignSpec, recipients: list[str] | tuple[str, ...], *, created_at: int | None = None) -> dict:
        spec = _validate_spec(spec)
        if not recipients:
            raise OutreachError("at least one explicit recipient/chat is required")
        unique: list[str] = []
        seen: set[str] = set()
        for raw in recipients:
            recipient = _safe_recipient(raw)
            if recipient not in seen:
                seen.add(recipient)
                unique.append(recipient)
        now = int(time.time()) if created_at is None else int(created_at)
        with self._connect() as db:
            try:
                db.execute("BEGIN IMMEDIATE")
                db.execute(
                    """INSERT INTO campaigns(
                       campaign_id,message_text,message_sha256,daily_limit,interval_seconds,
                       timezone_name,window_start,window_end,created_at
                    ) VALUES (?,?,?,?,?,?,?,?,?)""",
                    (spec.campaign_id,spec.message_text,spec.message_sha256,spec.daily_limit,
                     spec.interval_seconds,spec.timezone_name,spec.window_start,spec.window_end,now),
                )
                db.executemany(
                    "INSERT INTO recipients(campaign_id,recipient,ordinal) VALUES (?,?,?)",
                    [(spec.campaign_id, recipient, index) for index, recipient in enumerate(unique)],
                )
                db.commit()
            except sqlite3.IntegrityError as exc:
                db.rollback()
                raise OutreachError("campaign_id already exists") from exc
        return {"campaign_id": spec.campaign_id, "recipients": len(unique), "duplicates_removed": len(recipients)-len(unique)}

    def _campaign(self, db: sqlite3.Connection, campaign_id: str) -> sqlite3.Row:
        row = db.execute("SELECT * FROM campaigns WHERE campaign_id=?", (campaign_id,)).fetchone()
        if row is None:
            raise OutreachError("campaign not found")
        return row

    @staticmethod
    def _within_window(now: int, row: sqlite3.Row) -> bool:
        local = datetime.fromtimestamp(now, tz=timezone.utc).astimezone(_timezone(str(row["timezone_name"])))
        current = (local.hour, local.minute)
        start = _parse_hhmm(str(row["window_start"]))
        end = _parse_hhmm(str(row["window_end"]))
        if start == end:
            return True
        return start <= current < end if start < end else current >= start or current < end

    @staticmethod
    def _day_bounds(now: int, timezone_name: str) -> tuple[int, int]:
        tz = _timezone(timezone_name)
        local = datetime.fromtimestamp(now, tz=timezone.utc).astimezone(tz)
        start = datetime(local.year, local.month, local.day, tzinfo=tz)
        end = start + timedelta(days=1)
        return int(start.timestamp()), int(end.timestamp())

    def _sent_today(self, db: sqlite3.Connection, row: sqlite3.Row, now: int) -> int:
        start, end = self._day_bounds(now, str(row["timezone_name"]))
        return int(db.execute(
            "SELECT COUNT(*) FROM send_history WHERE campaign_id=? AND sent_at>=? AND sent_at<?",
            (row["campaign_id"], start, end),
        ).fetchone()[0])

    @staticmethod
    def _delivery(row: sqlite3.Row, recipient: str, lease_until: int | None = None) -> Delivery:
        digest = str(row["message_sha256"])
        return Delivery(str(row["campaign_id"]), recipient, str(row["message_text"]), digest, _dedup_key(recipient, digest), lease_until)

    def preview_next(self, campaign_id: str, *, now: int | None = None) -> Delivery | None:
        current = int(time.time()) if now is None else int(now)
        with self._connect() as db:
            campaign = self._campaign(db, campaign_id)
            if bool(campaign["paused"]) or not self._within_window(current, campaign):
                return None
            if self._sent_today(db, campaign, current) >= int(campaign["daily_limit"]):
                return None
            last_sent = campaign["last_sent_at"]
            if last_sent is not None and current < int(last_sent) + int(campaign["interval_seconds"]):
                return None
            rows = db.execute(
                "SELECT recipient FROM recipients WHERE campaign_id=? AND status='pending' AND next_attempt_at<=? ORDER BY ordinal",
                (campaign_id, current),
            ).fetchall()
            for item in rows:
                delivery = self._delivery(campaign, str(item["recipient"]))
                if db.execute("SELECT 1 FROM send_history WHERE dedup_key=?", (delivery.dedup_key,)).fetchone() is None:
                    return delivery
            return None

    def claim_next(self, campaign_id: str, *, now: int | None = None, lease_seconds: int = 300) -> Delivery | None:
        if isinstance(lease_seconds, bool) or not 30 <= lease_seconds <= 3600:
            raise OutreachError("lease_seconds must be between 30 and 3600")
        current = int(time.time()) if now is None else int(now)
        lease_until = current + lease_seconds
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            campaign = self._campaign(db, campaign_id)
            db.execute(
                """UPDATE recipients SET status='pending',lease_until=NULL,last_error='lease_expired'
                   WHERE campaign_id=? AND status='inflight' AND lease_until IS NOT NULL AND lease_until<=?""",
                (campaign_id,current),
            )
            if bool(campaign["paused"]) or not self._within_window(current, campaign):
                db.commit(); return None
            if self._sent_today(db, campaign, current) >= int(campaign["daily_limit"]):
                db.commit(); return None
            last_sent = campaign["last_sent_at"]
            if last_sent is not None and current < int(last_sent) + int(campaign["interval_seconds"]):
                db.commit(); return None
            rows = db.execute(
                "SELECT recipient FROM recipients WHERE campaign_id=? AND status='pending' AND next_attempt_at<=? ORDER BY ordinal",
                (campaign_id,current),
            ).fetchall()
            for item in rows:
                recipient = str(item["recipient"])
                delivery = self._delivery(campaign, recipient, lease_until)
                if db.execute("SELECT 1 FROM send_history WHERE dedup_key=?", (delivery.dedup_key,)).fetchone():
                    db.execute(
                        "UPDATE recipients SET status='skipped_duplicate',lease_until=NULL,last_error='duplicate_message_recipient' WHERE campaign_id=? AND recipient=?",
                        (campaign_id,recipient),
                    )
                    continue
                changed = db.execute(
                    """UPDATE recipients SET status='inflight',attempts=attempts+1,lease_until=?,last_error=NULL
                       WHERE campaign_id=? AND recipient=? AND status='pending'""",
                    (lease_until,campaign_id,recipient),
                ).rowcount
                if changed == 1:
                    db.commit()
                    return delivery
            db.commit()
            return None

    def mark_sent(self, campaign_id: str, recipient: str, *, sent_at: int | None = None) -> dict:
        recipient = _safe_recipient(recipient)
        current = int(time.time()) if sent_at is None else int(sent_at)
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            campaign = self._campaign(db, campaign_id)
            row = db.execute("SELECT status FROM recipients WHERE campaign_id=? AND recipient=?", (campaign_id,recipient)).fetchone()
            if row is None or row["status"] != "inflight":
                db.rollback()
                raise OutreachError("recipient is not inflight")
            delivery = self._delivery(campaign, recipient)
            try:
                db.execute(
                    "INSERT INTO send_history(dedup_key,campaign_id,recipient,message_sha256,sent_at) VALUES (?,?,?,?,?)",
                    (delivery.dedup_key,campaign_id,recipient,delivery.message_sha256,current),
                )
            except sqlite3.IntegrityError:
                db.execute(
                    "UPDATE recipients SET status='skipped_duplicate',lease_until=NULL,last_error='duplicate_message_recipient' WHERE campaign_id=? AND recipient=?",
                    (campaign_id,recipient),
                )
                db.commit()
                return {"status":"skipped_duplicate","recipient":recipient}
            db.execute(
                "UPDATE recipients SET status='sent',lease_until=NULL,sent_at=?,last_error=NULL WHERE campaign_id=? AND recipient=?",
                (current,campaign_id,recipient),
            )
            db.execute("UPDATE campaigns SET last_sent_at=? WHERE campaign_id=?", (current,campaign_id))
            db.commit()
            return {"status":"sent","recipient":recipient,"sent_at":current}

    def mark_failed(self, campaign_id: str, recipient: str, *, error: str, retry_after_seconds: int = 0, permanent: bool = False, now: int | None = None) -> dict:
        recipient = _safe_recipient(recipient)
        if isinstance(retry_after_seconds, bool) or not 0 <= retry_after_seconds <= 86400:
            raise OutreachError("retry_after_seconds must be between 0 and 86400")
        current = int(time.time()) if now is None else int(now)
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            self._campaign(db, campaign_id)
            row = db.execute("SELECT status FROM recipients WHERE campaign_id=? AND recipient=?", (campaign_id,recipient)).fetchone()
            if row is None or row["status"] != "inflight":
                db.rollback()
                raise OutreachError("recipient is not inflight")
            status = "failed" if permanent else "pending"
            next_attempt = current if permanent else current + retry_after_seconds
            db.execute(
                "UPDATE recipients SET status=?,next_attempt_at=?,lease_until=NULL,last_error=? WHERE campaign_id=? AND recipient=?",
                (status,next_attempt,str(error)[:200],campaign_id,recipient),
            )
            db.commit()
            return {"status":status,"recipient":recipient,"next_attempt_at":next_attempt}

    def pause(self, campaign_id: str) -> None:
        self._set_paused(campaign_id, True)

    def resume(self, campaign_id: str) -> None:
        self._set_paused(campaign_id, False)

    def _set_paused(self, campaign_id: str, paused: bool) -> None:
        with self._connect() as db:
            if db.execute("UPDATE campaigns SET paused=? WHERE campaign_id=?", (1 if paused else 0,campaign_id)).rowcount != 1:
                raise OutreachError("campaign not found")
            db.commit()

    def status(self, campaign_id: str, *, now: int | None = None) -> dict:
        current = int(time.time()) if now is None else int(now)
        with self._connect() as db:
            campaign = self._campaign(db, campaign_id)
            counts = {str(row["status"]):int(row["n"]) for row in db.execute(
                "SELECT status,COUNT(*) AS n FROM recipients WHERE campaign_id=? GROUP BY status",(campaign_id,)
            )}
            return {
                "campaign_id":campaign_id,
                "paused":bool(campaign["paused"]),
                "daily_limit":int(campaign["daily_limit"]),
                "sent_today":self._sent_today(db,campaign,current),
                "interval_seconds":int(campaign["interval_seconds"]),
                "timezone_name":str(campaign["timezone_name"]),
                "window_start":str(campaign["window_start"]),
                "window_end":str(campaign["window_end"]),
                "counts":counts,
            }
