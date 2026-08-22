# -*- coding: utf-8 -*-
"""Audit round 10: private control evidence and lock invariants."""
from __future__ import annotations

import json
import os
import stat
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from ops import deploy_release, release_guard


class ControlEvidenceTests(unittest.TestCase):
    def approval(self):
        now = datetime.now(timezone.utc)
        return {
            "approved": True,
            "approved_sha": "1" * 40,
            "repository": "synthetic/round10",
            "approved_ref": "main",
            "release_manifest_sha256": "2" * 64,
            "ci_run_id": "round10",
            "audit_id": "audit-round10",
            "approval_id": "approval-round10",
            "nonce": "ephemeral-value-not-for-evidence",
            "issued_at": now.isoformat(),
            "expires_at": (now + timedelta(hours=1)).isoformat(),
            "data_schema_change": False,
        }

    def journal(self):
        prepared_meta = {"payload_manifest_sha256": "3" * 64}
        return deploy_release._new_transaction_journal(
            "synthetic/round10", "main", "1" * 40, "4" * 40,
            "2" * 64, prepared_meta, ["var"], self.approval()
        )

    def test_journal_contains_digest_not_nonce_or_secret_payload(self):
        journal = self.journal()
        encoded = json.dumps(journal, sort_keys=True)
        self.assertNotIn("nonce", journal)
        self.assertNotIn("ephemeral-value-not-for-evidence", encoded)
        self.assertEqual(64, len(journal["approval_marker_sha256"]))
        self.assertEqual("process-loss-same-host-v1", journal["durability_contract"])

    def test_journal_timestamps_are_timezone_aware(self):
        journal = self.journal()
        for key in ("created_at", "updated_at"):
            parsed = datetime.fromisoformat(journal[key].replace("Z", "+00:00"))
            self.assertIsNotNone(parsed.tzinfo)

    def test_immutable_transaction_provenance_cannot_change(self):
        with tempfile.TemporaryDirectory() as td:
            control = Path(td) / "control"
            control.mkdir()
            control.chmod(0o700)
            journal = deploy_release._write_transaction_journal(control, self.journal())
            with self.assertRaises(release_guard.SafetyError):
                deploy_release._transition_transaction(
                    control, journal, "MATERIALIZED", sha="5" * 40
                )

    def test_consumed_marker_omits_nonce_and_has_private_mode(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "control"
            root.mkdir()
            root.chmod(0o700)
            consumed = root / "consumed"
            marker = release_guard.consume_external_approval(self.approval(), consumed)
            payload = json.loads(marker.read_text(encoding="utf-8"))
            self.assertEqual({"approval_id", "consumed_at"}, set(payload))
            self.assertNotIn("nonce", payload)
            self.assertEqual(0, stat.S_IMODE(marker.stat().st_mode) & 0o077)


@unittest.skipUnless(os.name == "posix", "deployment lock is POSIX-specific")
class LockInvariantTests(unittest.TestCase):
    def test_lock_can_acquire_release_100_times_without_stale_state(self):
        with tempfile.TemporaryDirectory() as td:
            control = Path(td) / "control"
            control.mkdir()
            control.chmod(0o700)
            for _ in range(100):
                with deploy_release._deployment_lock(control) as path:
                    self.assertEqual(control / deploy_release.TRANSACTION_LOCK, path)
            lock = control / deploy_release.TRANSACTION_LOCK
            self.assertTrue(lock.is_file())
            self.assertEqual(0, stat.S_IMODE(lock.stat().st_mode) & 0o077)

    def test_symlink_lock_path_fails_closed(self):
        with tempfile.TemporaryDirectory() as td:
            control = Path(td) / "control"
            control.mkdir()
            control.chmod(0o700)
            target = control / "target"
            target.write_text("", encoding="utf-8")
            target.chmod(0o600)
            (control / deploy_release.TRANSACTION_LOCK).symlink_to(target)
            with self.assertRaises(release_guard.SafetyError):
                with deploy_release._deployment_lock(control):
                    pass

    def test_lock_file_contains_no_runtime_or_approval_metadata(self):
        with tempfile.TemporaryDirectory() as td:
            control = Path(td) / "control"
            control.mkdir()
            control.chmod(0o700)
            with deploy_release._deployment_lock(control):
                pass
            self.assertEqual("", (control / deploy_release.TRANSACTION_LOCK).read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
