from __future__ import annotations

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
)


def _canonical(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _download_schema(path: Path) -> None:
    with sqlite3.connect(path) as con:
        con.execute(
            "CREATE TABLE download_jobs("
            "job_id TEXT PRIMARY KEY,payload_json TEXT NOT NULL,"
            "payload_sha256 TEXT NOT NULL,updated_at INTEGER NOT NULL)"
        )


def _insert_job(path: Path, job_id: str, *, status: str, retryable: bool | None = None) -> None:
    item = {
        "item_id": "i1",
        "chat": "synthetic",
        "message_id": 1,
        "source_file_ref": "synthetic",
        "name": "synthetic.bin",
        "mime_type": "application/octet-stream",
        "expected_size": None,
        "expected_sha256": None,
    }
    results: dict[str, str] = {}
    failures: dict[str, object] = {}
    if status == "complete":
        results["i1"] = "synthetic_file_ref"
    elif retryable is not None:
        failures["i1"] = {"code": "synthetic", "status": 503 if retryable else 400, "retryable": retryable}
    payload = {
        "schema": 1,
        "job_id": job_id,
        "status": status,
        "items": [item],
        "results": results,
        "failures": failures,
    }
    raw = _canonical(payload)
    with sqlite3.connect(path) as con:
        con.execute(
            "INSERT INTO download_jobs VALUES(?,?,?,?)",
            (job_id, raw, hashlib.sha256(raw.encode()).hexdigest(), 10),
        )


class Finalwave44RetentionTopologyTests(unittest.TestCase):
    def test_sqlite_symlink_is_rejected_before_cleanup(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            real = root / "real.sqlite3"
            with sqlite3.connect(real) as con:
                con.executescript(
                    "CREATE TABLE previews(preview_id TEXT,expires_at INTEGER,consumed_at INTEGER);"
                    "CREATE TABLE idempotency(preview_id TEXT);"
                )
            link = root / "writes.sqlite3"
            try:
                link.symlink_to(real)
            except (OSError, NotImplementedError):
                self.skipTest("symlink unavailable")
            with self.assertRaisesRegex(RetentionSafetyError, "unsafe_retention_database"):
                cleanup_write_previews(link, now=100, expired_grace_seconds=0)

    def test_broken_audit_symlink_is_not_misclassified_as_missing(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            link = Path(td) / "audit.jsonl"
            try:
                link.symlink_to(Path(td) / "missing-target")
            except (OSError, NotImplementedError):
                self.skipTest("symlink unavailable")
            with self.assertRaisesRegex(RetentionSafetyError, "unsafe_audit_topology"):
                audit_disk_policy(link)

    def test_nonterminal_checkpoint_scan_does_not_create_lock_garbage(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            os.chmod(root, 0o700)
            db = root / "checkpoints.sqlite3"
            locks = root / ".download-locks"
            locks.mkdir(mode=0o700)
            _download_schema(db)
            job_id = "pending_job_synthetic_123456"
            _insert_job(db, job_id, status="running")
            result = cleanup_download_checkpoints(db, locks, now=1000, min_age_seconds=100)
            self.assertEqual(result.deleted, 0)
            self.assertEqual(result.protected, 1)
            lock_path = locks / (hashlib.sha256(job_id.encode()).hexdigest() + ".lock")
            self.assertFalse(lock_path.exists())

    def test_retryable_failure_is_protected_without_creating_lock(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            os.chmod(root, 0o700)
            db = root / "checkpoints.sqlite3"
            locks = root / ".download-locks"
            locks.mkdir(mode=0o700)
            _download_schema(db)
            job_id = "retry_job_synthetic_123456"
            _insert_job(db, job_id, status="failed", retryable=True)
            result = cleanup_download_checkpoints(db, locks, now=1000, min_age_seconds=100)
            self.assertEqual(result.deleted, 0)
            self.assertEqual(result.protected, 1)
            self.assertFalse((locks / (hashlib.sha256(job_id.encode()).hexdigest() + ".lock")).exists())

    def test_mismatched_lease_marker_cannot_delete_other_part(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            os.chmod(root, 0o700)
            staging = root / "staging"
            staging.mkdir(mode=0o700)
            victim = staging / "archive_victim.zip.part"
            victim.write_bytes(b"do-not-delete")
            marker = staging / "archive_attacker.zip.part.lease"
            marker.write_text(
                _canonical({"schema": 1, "part": victim.name, "created_at": 1}),
                encoding="ascii",
            )
            os.chmod(marker, 0o600)
            result = cleanup_leased_archive_staging(
                staging,
                root / "ledger.sqlite3",
                now=1000,
                min_age_seconds=10,
            )
            self.assertEqual(result.deleted, 0)
            self.assertEqual(result.corrupt, 1)
            self.assertTrue(victim.exists())
            self.assertTrue(marker.exists())

    def test_hardlinked_staging_part_is_not_deleted(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            os.chmod(root, 0o700)
            staging = root / "staging"
            staging.mkdir(mode=0o700)
            part = staging / "archive_hardlink.zip.part"
            part.write_bytes(b"synthetic")
            alias = staging / "alias.bin"
            try:
                os.link(part, alias)
            except OSError:
                self.skipTest("hardlinks unavailable")
            marker = staging / (part.name + ".lease")
            marker.write_text(_canonical({"schema": 1, "part": part.name, "created_at": 1}), encoding="ascii")
            os.chmod(marker, 0o600)
            result = cleanup_leased_archive_staging(
                staging,
                root / "ledger.sqlite3",
                now=1000,
                min_age_seconds=10,
            )
            self.assertEqual(result.deleted, 0)
            self.assertEqual(result.corrupt, 1)
            self.assertTrue(part.exists())
            self.assertTrue(alias.exists())


if __name__ == "__main__":
    unittest.main()
