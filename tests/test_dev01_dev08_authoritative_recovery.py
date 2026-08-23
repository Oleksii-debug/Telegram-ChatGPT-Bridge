# -*- coding: utf-8 -*-
"""Canonical A01-11 tests for authoritative DEV08 recovery semantics."""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from ops import deploy_release
from ops.release_guard import SafetyError


class BackedUpCandidateLayout:
    def __init__(self, root: Path):
        self.root = root
        self.releases = root / "releases"
        self.releases.mkdir()
        self.old_sha = "7" * 40
        self.new_sha = "8" * 40
        self.old = self.releases / self.old_sha
        self.final = self.releases / self.new_sha
        self.old.mkdir()
        self.final.mkdir()

        self.state = root / "state"
        (self.state / "var").mkdir(parents=True)
        self.active = root / "active"
        self.active.symlink_to(self.final)

        self.control = root / "control"
        self.control.mkdir()
        self.control.chmod(0o700)
        self.consumed = self.control / "consumed"
        self.consumed.mkdir()
        self.consumed.chmod(0o700)
        self.status = self.control / "status.json"

        for name in ("restart", "identity", "unauth", "auth", "resume"):
            hook = self.control / name
            hook.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            hook.chmod(0o700)

        self.approval = {"approval_id": "approval-a01-11", "nonce": "nonce-a01-11"}
        now = deploy_release.utc_now_iso()
        runtime_entries = ["var"]
        runtime_digest = deploy_release._runtime_manifest_digest(runtime_entries)
        marker_digest = deploy_release._approval_marker_digest(self.approval)
        release_manifest = "a" * 64
        self.journal = {
            "schema_version": deploy_release.JOURNAL_SCHEMA_VERSION,
            "durability_contract": deploy_release.DURABILITY_CONTRACT,
            "transaction_id": deploy_release._transaction_id(
                "synthetic/a01-11",
                "main",
                self.new_sha,
                self.old_sha,
                release_manifest,
                runtime_digest,
                marker_digest,
            ),
            "repository": "synthetic/a01-11",
            "approved_ref": "main",
            "sha": self.new_sha,
            "previous_sha": self.old_sha,
            "release_manifest_sha256": release_manifest,
            "prepared_payload_sha256": "b" * 64,
            "runtime_manifest_sha256": runtime_digest,
            "runtime_entries": runtime_entries,
            "approval_id": self.approval["approval_id"],
            "approval_marker_sha256": marker_digest,
            "state": "BACKED_UP",
            "created_at": now,
            "updated_at": now,
        }
        deploy_release._write_transaction_journal(self.control, self.journal)
        marker = self.consumed / (marker_digest + ".consumed.json")
        marker.write_text(
            json.dumps({"approval_id": self.approval["approval_id"], "consumed_at": now}),
            encoding="utf-8",
        )
        marker.chmod(0o600)
        self.marker = marker

    def kwargs(self) -> dict:
        c = self.control
        return {
            "control_root": c,
            "releases_root": self.releases,
            "persistent_state_root": self.state,
            "runtime_entries": ["var"],
            "active_link": self.active,
            "approval_consumption_root": self.consumed,
            "restart_hook": c / "restart",
            "identity_hook": c / "identity",
            "unauth_hook": c / "unauth",
            "auth_hook": c / "auth",
            "resume_hook": c / "resume",
            "status_file": self.status,
        }

    def durable_journal(self) -> dict:
        return json.loads(
            (self.control / deploy_release.TRANSACTION_JOURNAL).read_text(encoding="utf-8")
        )


class AuthoritativeBackedUpCandidateRecoveryTests(unittest.TestCase):
    def test_backed_up_active_candidate_promotes_to_switched_and_reuses_normal_recovery(self):
        with tempfile.TemporaryDirectory() as td:
            layout = BackedUpCandidateLayout(Path(td))
            with mock.patch.object(
                deploy_release, "_verify_journal_candidate", return_value={}
            ) as verify, mock.patch.object(
                deploy_release,
                "classify_deployment_recovery",
                wraps=deploy_release.classify_deployment_recovery,
            ) as classify:
                result = deploy_release._reconcile_incomplete_transaction(**layout.kwargs())

            self.assertEqual("DEPLOYED", result["state"])
            self.assertEqual("resumed_after_switch", result["recovery_mode"])
            self.assertEqual(
                "atomic_switch_observed_before_switched_journal",
                result["recovery_reason_code"],
            )
            self.assertEqual(layout.final.resolve(), layout.active.resolve())
            self.assertEqual("DEPLOYED", layout.durable_journal()["state"])
            self.assertGreaterEqual(verify.call_count, 2)
            self.assertEqual("BACKED_UP", classify.call_args.kwargs["journal_state"])
            self.assertEqual("candidate", classify.call_args.kwargs["active_role"])
            self.assertTrue(classify.call_args.kwargs["approval_marker_valid"])
            self.assertTrue(classify.call_args.kwargs["candidate_verified"])

    def test_candidate_reverification_failure_records_observed_switch_then_rolls_back(self):
        with tempfile.TemporaryDirectory() as td:
            layout = BackedUpCandidateLayout(Path(td))
            with mock.patch.object(
                deploy_release,
                "_verify_journal_candidate",
                side_effect=SafetyError("synthetic candidate mismatch"),
            ):
                result = deploy_release._reconcile_incomplete_transaction(**layout.kwargs())

            self.assertEqual("ROLLED_BACK", result["state"])
            self.assertEqual("candidate_reverification_failed", result["recovery_mode"])
            self.assertEqual(
                "candidate_reverification_failed",
                result["recovery_reason_code"],
            )
            self.assertEqual(layout.old.resolve(), layout.active.resolve())
            self.assertEqual("ROLLED_BACK", layout.durable_journal()["state"])
            qroot = layout.releases / ".quarantine"
            self.assertTrue(qroot.is_dir() and any(qroot.iterdir()))

    def test_missing_committed_marker_remains_fail_closed_ambiguous(self):
        with tempfile.TemporaryDirectory() as td:
            layout = BackedUpCandidateLayout(Path(td))
            layout.marker.unlink()
            with self.assertRaises(SafetyError):
                deploy_release._reconcile_incomplete_transaction(**layout.kwargs())

            journal = layout.durable_journal()
            self.assertEqual("CRITICAL_TRANSACTION_AMBIGUOUS", journal["state"])
            self.assertEqual("committed_marker_missing", journal["reason_code"])
            self.assertEqual(layout.final.resolve(), layout.active.resolve())


if __name__ == "__main__":
    unittest.main()
