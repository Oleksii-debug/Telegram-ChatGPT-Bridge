from __future__ import annotations

import fcntl
import hashlib
import json
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path

from ops.state_retention import (
    RetentionSafetyError,
    audit_disk_policy,
    cleanup_download_checkpoints,
    cleanup_leased_archive_staging,
    cleanup_write_previews,
    create_staging_lease,
    retention_policy,
)


def _canonical(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


class Finalwave44WriteRetentionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.db = self.root / "writes.sqlite3"
        with sqlite3.connect(self.db) as con:
            con.executescript(
                """
                CREATE TABLE previews (
                    preview_id TEXT PRIMARY KEY,
                    token_hash TEXT NOT NULL UNIQUE,
                    action TEXT NOT NULL,
                    request_fingerprint TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL,
                    consumed_at INTEGER
                );
                CREATE TABLE idempotency (
                    key_hash TEXT PRIMARY KEY,
                    request_fingerprint TEXT NOT NULL,
                    preview_id TEXT NOT NULL,
                    state TEXT NOT NULL,
                    result_json TEXT,
                    created_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL,
                    FOREIGN KEY(preview_id) REFERENCES previews(preview_id)
                );
                """
            )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _preview(self, preview_id: str, *, expires: int, consumed: int | None = None) -> None:
        with sqlite3.connect(self.db) as con:
            con.execute(
                "INSERT INTO previews VALUES(?,?,?,?,?,?,?,?)",
                (
                    preview_id,
                    hashlib.sha256(preview_id.encode()).hexdigest(),
                    "SEND",
                    hashlib.sha256((preview_id + "fp").encode()).hexdigest(),
                    _canonical({"target": "synthetic", "text": "synthetic"}),
                    1,
                    expires,
                    consumed,
                ),
            )

    def _idem(self, preview_id: str, state: str) -> None:
        with sqlite3.connect(self.db) as con:
            fp = con.execute(
                "SELECT request_fingerprint FROM previews WHERE preview_id=?", (preview_id,)
            ).fetchone()[0]
            con.execute(
                "INSERT INTO idempotency VALUES(?,?,?,?,?,?,?)",
                (hashlib.sha256((preview_id + "key").encode()).hexdigest(), fp, preview_id, state, "{}" if state == "COMMITTED" else None, 2, 3),
            )

    def test_cleanup_deletes_only_expired_unreferenced_preview(self) -> None:
        self._preview("free", expires=100)
        self._preview("future", expires=980)
        for state in ("RESERVED", "CALLING", "COMMITTED", "FAILED_SAFE", "AMBIGUOUS"):
            preview_id = "p_" + state.lower()
            self._preview(preview_id, expires=100, consumed=200)
            self._idem(preview_id, state)

        result = cleanup_write_previews(self.db, now=1000, expired_grace_seconds=100)
        self.assertEqual(result.deleted, 1)
        with sqlite3.connect(self.db) as con:
            previews = {row[0] for row in con.execute("SELECT preview_id FROM previews")}
            states = {row[0] for row in con.execute("SELECT state FROM idempotency")}
            high_water = con.execute(
                "SELECT high_water FROM retention_high_water WHERE namespace='write_preview_cleanup'"
            ).fetchone()[0]
        self.assertNotIn("free", previews)
        self.assertIn("future", previews)
        self.assertEqual(states, {"RESERVED", "CALLING", "COMMITTED", "FAILED_SAFE", "AMBIGUOUS"})
        self.assertEqual(high_water, 1000)

    def test_clock_rollback_fails_closed_without_deletion(self) -> None:
        self._preview("old", expires=10)
        cleanup_write_previews(self.db, now=1000, expired_grace_seconds=2000)
        with self.assertRaisesRegex(RetentionSafetyError, "retention_clock_moved_backward"):
            cleanup_write_previews(self.db, now=999, expired_grace_seconds=0)
        with sqlite3.connect(self.db) as con:
            self.assertEqual(con.execute("SELECT COUNT(*) FROM previews WHERE preview_id='old'").fetchone()[0], 1)


class Finalwave44DownloadRetentionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        os.chmod(self.root, 0o700)
        self.db = self.root / "checkpoints.sqlite3"
        self.locks = self.root / ".download-locks"
        self.locks.mkdir(mode=0o700)
        with sqlite3.connect(self.db) as con:
            con.execute(
                "CREATE TABLE download_jobs(job_id TEXT PRIMARY KEY,payload_json TEXT NOT NULL,payload_sha256 TEXT NOT NULL,updated_at INTEGER NOT NULL)"
            )

    def tearDown(self) -> None:
        self.temp.cleanup()

    @staticmethod
    def _item(item_id: str) -> dict[str, object]:
        return {
            "item_id": item_id,
            "chat": "synthetic",
            "message_id": 1,
            "source_file_ref": "synthetic_file_ref_123456789",
            "name": "synthetic.bin",
            "mime_type": "application/octet-stream",
            "expected_size": None,
            "expected_sha256": None,
        }

    def _job(
        self,
        job_id: str,
        *,
        status: str,
        results: dict[str, str] | None = None,
        failures: dict[str, dict[str, object]] | None = None,
        updated_at: int = 100,
    ) -> None:
        payload = {
            "schema": 1,
            "job_id": job_id,
            "status": status,
            "items": [self._item("i1")],
            "results": results or {},
            "failures": failures or {},
        }
        raw = _canonical(payload)
        with sqlite3.connect(self.db) as con:
            con.execute(
                "INSERT INTO download_jobs VALUES(?,?,?,?)",
                (job_id, raw, hashlib.sha256(raw.encode()).hexdigest(), updated_at),
            )

    def test_semantic_terminality_preserves_retryable_and_nonterminal_jobs(self) -> None:
        self._job("job_complete_123456", status="complete", results={"i1": "file_ref_synthetic_123456"})
        self._job(
            "job_failed_terminal_123456",
            status="failed",
            failures={"i1": {"code": "not_found", "status": 404, "retryable": False}},
        )
        self._job(
            "job_failed_retry_123456",
            status="failed",
            failures={"i1": {"code": "temporary", "status": 503, "retryable": True}},
        )
        self._job("job_running_123456", status="running")
        self._job("job_recent_123456", status="complete", results={"i1": "file_ref_synthetic_654321"}, updated_at=950)

        result = cleanup_download_checkpoints(self.db, self.locks, now=1000, min_age_seconds=100)
        self.assertEqual(result.deleted, 2)
        self.assertGreaterEqual(result.protected, 2)
        with sqlite3.connect(self.db) as con:
            remaining = {row[0] for row in con.execute("SELECT job_id FROM download_jobs")}
            high_water = con.execute(
                "SELECT high_water FROM retention_high_water WHERE namespace='download_checkpoint_cleanup'"
            ).fetchone()[0]
        self.assertEqual(
            remaining,
            {"job_failed_retry_123456", "job_running_123456", "job_recent_123456"},
        )
        self.assertEqual(high_water, 1000)
        for removed in ("job_complete_123456", "job_failed_terminal_123456"):
            lock = self.locks / (hashlib.sha256(removed.encode()).hexdigest() + ".lock")
            self.assertFalse(lock.exists())

    def test_cleanup_racing_active_resume_skips_busy_job(self) -> None:
        job_id = "job_complete_busy_123456"
        self._job(job_id, status="complete", results={"i1": "file_ref_synthetic_123456"})
        lock_path = self.locks / (hashlib.sha256(job_id.encode()).hexdigest() + ".lock")
        fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            result = cleanup_download_checkpoints(self.db, self.locks, now=1000, min_age_seconds=100)
            self.assertEqual(result.deleted, 0)
            self.assertEqual(result.busy, 1)
            with sqlite3.connect(self.db) as con:
                self.assertEqual(con.execute("SELECT COUNT(*) FROM download_jobs WHERE job_id=?", (job_id,)).fetchone()[0], 1)
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def test_corrupt_checkpoint_is_not_deleted(self) -> None:
        self._job("job_corrupt_123456", status="complete", results={"i1": "file_ref_synthetic_123456"})
        with sqlite3.connect(self.db) as con:
            con.execute("UPDATE download_jobs SET payload_sha256='0' WHERE job_id='job_corrupt_123456'")
        result = cleanup_download_checkpoints(self.db, self.locks, now=1000, min_age_seconds=100)
        self.assertEqual(result.deleted, 0)
        self.assertEqual(result.corrupt, 1)
        with sqlite3.connect(self.db) as con:
            self.assertEqual(con.execute("SELECT COUNT(*) FROM download_jobs").fetchone()[0], 1)

    def test_download_cleanup_clock_rollback_fails_before_more_deletion(self) -> None:
        self._job("job_keep_rollback_123456", status="running")
        cleanup_download_checkpoints(self.db, self.locks, now=1000, min_age_seconds=100)
        with self.assertRaisesRegex(RetentionSafetyError, "retention_clock_moved_backward"):
            cleanup_download_checkpoints(self.db, self.locks, now=999, min_age_seconds=0)
        with sqlite3.connect(self.db) as con:
            self.assertEqual(con.execute("SELECT COUNT(*) FROM download_jobs").fetchone()[0], 1)


class Finalwave44ArchiveRetentionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.staging = self.root / "staging"
        self.staging.mkdir(mode=0o700)
        self.ledger = self.root / "retention.sqlite3"

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_unleased_archive_part_is_never_guessed_stale(self) -> None:
        legacy = self.staging / "archive_deadbeef.zip.part"
        legacy.write_bytes(b"legacy")
        result = cleanup_leased_archive_staging(self.staging, self.ledger, now=1000, min_age_seconds=10)
        self.assertEqual(result.deleted, 0)
        self.assertTrue(legacy.exists())

    def test_active_lease_blocks_cleanup_then_crash_released_lease_is_reclaimed(self) -> None:
        part = self.staging / "archive_abcdef.zip.part"
        part.write_bytes(b"synthetic")
        lease = create_staging_lease(part, now=100)
        try:
            busy = cleanup_leased_archive_staging(self.staging, self.ledger, now=1000, min_age_seconds=10)
            self.assertEqual(busy.busy, 1)
            self.assertTrue(part.exists())
            marker = lease.marker_path
            lease.close(remove_marker=False)
            lease = None
            cleaned = cleanup_leased_archive_staging(self.staging, self.ledger, now=1000, min_age_seconds=10)
            self.assertEqual(cleaned.deleted, 1)
            self.assertFalse(part.exists())
            self.assertFalse(marker.exists())
        finally:
            if lease is not None:
                lease.close(remove_marker=True)

    def test_staging_clock_rollback_fails_closed(self) -> None:
        cleanup_leased_archive_staging(self.staging, self.ledger, now=1000, min_age_seconds=10)
        with self.assertRaisesRegex(RetentionSafetyError, "retention_clock_moved_backward"):
            cleanup_leased_archive_staging(self.staging, self.ledger, now=999, min_age_seconds=10)


class Finalwave44ProtectedKnowledgeTests(unittest.TestCase):
    def test_policy_explicitly_protects_authoritative_security_knowledge(self) -> None:
        policy = retention_policy()
        for key in (
            "write_idempotency",
            "write_committed_tombstone",
            "write_ambiguous_tombstone",
            "rate_limit_high_water",
            "retention_high_water",
            "audit_history",
        ):
            self.assertEqual(policy[key], "AUTHORITATIVE_PROTECTED")

    def test_audit_disk_is_inventory_only_not_auto_delete(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "audit.jsonl"
            path.write_text("synthetic\n", encoding="ascii")
            info = audit_disk_policy(path)
            self.assertEqual(info["classification"], "AUTHORITATIVE_PROTECTED")
            self.assertFalse(info["automatic_delete"])
            self.assertEqual(info["bytes"], len(b"synthetic\n"))
            self.assertTrue(path.exists())


if __name__ == "__main__":
    unittest.main()
