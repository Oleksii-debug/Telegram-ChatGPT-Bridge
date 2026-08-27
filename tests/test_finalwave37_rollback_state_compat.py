# -*- coding: utf-8 -*-
from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

from bridge.audit import AuditLog
from bridge.runtime import RuntimeBootstrapError, _SQLiteFixedWindowStore
from bridge.storage import CheckpointStore, DownloadItem, FileRecordStore
from ops import deploy_release, release_guard
from ops.finalwave37_rollback_state_compat import (
    CANDIDATE_ANCHOR_SHA,
    PREDECESSOR_EVIDENCE_SHA,
    RollbackStateContractError,
    assess_exact_sha_rollback_plan,
    classify_restore_request,
    matrix_by_domain,
)
from ops.write_safety import PersistentWriteStore, ReconciliationRequired, WriteAction
from tests.test_audit_round9 import Round9Layout


WRITE_TERMINAL_ADAPT_SHA = "e3e956d555ad12cceae1b7311a6a988c020db58b"
WRITE_SCHEMA_BOOTSTRAP_ADAPT_SHA = "b4db4749fb0e36a967acd2a7740d463e8104c00f"
CURRENT_DYNAMIC_CANDIDATE_SHA = "3e7763e99550373e830924e72d58388c23a7caa1"

LEGACY_FILES_SCHEMA = """
CREATE TABLE files (
    file_ref TEXT PRIMARY KEY,
    rel_path TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    mime_type TEXT NOT NULL,
    size INTEGER NOT NULL,
    sha256 TEXT NOT NULL,
    created_at INTEGER NOT NULL
)
"""


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _git_show(sha: str, path: str) -> str:
    root = _repo_root()
    if not (root / ".git").exists():
        raise unittest.SkipTest("full Git history required for exact predecessor evidence")
    try:
        return subprocess.check_output(
            ["git", "show", f"{sha}:{path}"],
            cwd=root,
            text=True,
            stderr=subprocess.DEVNULL,
        )
    except subprocess.CalledProcessError as exc:
        raise unittest.SkipTest("exact predecessor object unavailable in checkout") from exc


def _git_blob(sha: str, path: str) -> str:
    root = _repo_root()
    if not (root / ".git").exists():
        raise unittest.SkipTest("full Git history required for exact predecessor evidence")
    try:
        return subprocess.check_output(
            ["git", "rev-parse", f"{sha}:{path}"], cwd=root, text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except subprocess.CalledProcessError as exc:
        raise unittest.SkipTest("exact predecessor object unavailable in checkout") from exc


def _load_predecessor_storage():
    source = _git_show(PREDECESSOR_EVIDENCE_SHA, "bridge/storage.py")
    name = "bridge._finalwave37_predecessor_storage"
    module = types.ModuleType(name)
    module.__package__ = "bridge"
    sys.modules[name] = module
    exec(compile(source, "predecessor_bridge_storage.py", "exec"), module.__dict__)
    return name, module


def _load_predecessor_audit():
    source = _git_show(PREDECESSOR_EVIDENCE_SHA, "bridge/audit.py")
    name = "bridge._finalwave37_predecessor_audit"
    module = types.ModuleType(name)
    module.__package__ = "bridge"
    sys.modules[name] = module
    exec(compile(source, "predecessor_bridge_audit.py", "exec"), module.__dict__)
    return name, module, source


def _create_legacy_files_db(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(str(path)) as connection:
        connection.execute(LEGACY_FILES_SCHEMA)
        connection.commit()


class RollbackMatrixContractTests(unittest.TestCase):
    def test_matrix_covers_exact_required_domains_and_preserves_state(self):
        matrix = matrix_by_domain()
        self.assertEqual(
            {"files", "downloads", "writes", "rate", "reliability", "session", "audit"},
            set(matrix),
        )
        self.assertTrue(all(area.rollback_action == "PRESERVE_CURRENT" for area in matrix.values()))
        self.assertIn("duplicate Telegram effects", matrix["writes"].loss_risk)
        self.assertIn("high-water", matrix["rate"].loss_risk)
        self.assertIn("never copied", matrix["session"].predecessor_basis)

    def test_broad_and_critical_state_restore_fail_closed(self):
        self.assertEqual(
            "BLOCKED_UNSAFE_BROAD_STATE_RESTORE",
            classify_restore_request(["state/"]).action,
        )
        for domain in ("writes", "rate", "reliability", "session", "audit"):
            with self.subTest(domain=domain):
                self.assertEqual(
                    "BLOCKED_UNSAFE_CRITICAL_STATE_RESTORE",
                    classify_restore_request([domain]).action,
                )
        self.assertEqual(
            "TARGETED_RESTORE_REQUIRES_SEPARATE_AUDIT",
            classify_restore_request(["files"]).action,
        )

    def _decision(self, **overrides):
        values = dict(
            candidate_sha=CANDIDATE_ANCHOR_SHA,
            approved_candidate_sha=CANDIDATE_ANCHOR_SHA,
            rollback_target_sha=PREDECESSOR_EVIDENCE_SHA,
            observed_live_previous_sha=PREDECESSOR_EVIDENCE_SHA,
            compatibility_reference_sha=PREDECESSOR_EVIDENCE_SHA,
            target_specific_compatibility_proven=True,
            schema_change_declared=True,
            forced_smoke_passed=True,
            rollback_target_security_regression_cleared=True,
            independent_auditor_gate=False,
        )
        values.update(overrides)
        return assess_exact_sha_rollback_plan(**values)

    def test_plan_requires_live_last_known_good_identity(self):
        decision = self._decision(observed_live_previous_sha=None)
        self.assertEqual("BLOCKED_LKG_IDENTITY_REQUIRED", decision.action)
        self.assertFalse(decision.production_authorized)

    def test_plan_rejects_target_not_matching_observed_live_previous(self):
        decision = self._decision(observed_live_previous_sha="f" * 40)
        self.assertEqual("BLOCKED_LKG_IDENTITY_MISMATCH", decision.action)

    def test_candidate_schema_change_must_be_declared(self):
        decision = self._decision(schema_change_declared=False)
        self.assertEqual("BLOCKED_SCHEMA_DECLARATION_REQUIRED", decision.action)

    def test_actual_target_needs_target_specific_compatibility(self):
        live = "f" * 40
        decision = self._decision(
            rollback_target_sha=live,
            observed_live_previous_sha=live,
            compatibility_reference_sha=PREDECESSOR_EVIDENCE_SHA,
            target_specific_compatibility_proven=False,
        )
        self.assertEqual("BLOCKED_TARGET_SPECIFIC_COMPATIBILITY_REQUIRED", decision.action)

    def test_forced_smoke_is_mandatory(self):
        decision = self._decision(forced_smoke_passed=False)
        self.assertEqual("BLOCKED_FORCED_SMOKE_REQUIRED", decision.action)

    def test_evidence_predecessor_is_blocked_until_audit_security_regression_is_cleared(self):
        decision = self._decision(rollback_target_security_regression_cleared=False)
        self.assertEqual("BLOCKED_ROLLBACK_TARGET_SECURITY_REGRESSION", decision.action)

    def test_any_actual_target_is_blocked_until_security_regression_is_cleared(self):
        live = "f" * 40
        decision = self._decision(
            rollback_target_sha=live,
            observed_live_previous_sha=live,
            compatibility_reference_sha=live,
            target_specific_compatibility_proven=True,
            rollback_target_security_regression_cleared=False,
        )
        self.assertEqual("BLOCKED_ROLLBACK_TARGET_SECURITY_REGRESSION", decision.action)

    def test_current_candidate_binding_is_dynamic_not_module_anchor(self):
        self.assertNotEqual(CANDIDATE_ANCHOR_SHA, CURRENT_DYNAMIC_CANDIDATE_SHA)
        decision = self._decision(
            candidate_sha=CURRENT_DYNAMIC_CANDIDATE_SHA,
            approved_candidate_sha=CURRENT_DYNAMIC_CANDIDATE_SHA,
        )
        self.assertEqual("AUDITOR_GATE_REQUIRED", decision.action)

    def test_wrong_but_well_formed_candidate_sha_is_rejected(self):
        decision = self._decision(
            candidate_sha="f" * 40,
            approved_candidate_sha=CURRENT_DYNAMIC_CANDIDATE_SHA,
        )
        self.assertEqual("BLOCKED_CANDIDATE_IDENTITY_MISMATCH", decision.action)

    def test_malformed_approved_candidate_sha_is_rejected(self):
        with self.assertRaises(RollbackStateContractError):
            self._decision(approved_candidate_sha="not-a-sha")

    def test_complete_nonlive_contract_still_requires_auditor_and_live_evidence(self):
        decision = self._decision(independent_auditor_gate=False)
        self.assertEqual("AUDITOR_GATE_REQUIRED", decision.action)
        self.assertFalse(decision.production_authorized)
        gated = self._decision(independent_auditor_gate=True)
        self.assertEqual("LIVE_ROLLBACK_EVIDENCE_REQUIRED", gated.action)
        self.assertFalse(gated.production_authorized)

    def test_truthy_non_boolean_evidence_is_rejected(self):
        with self.assertRaises(RollbackStateContractError):
            self._decision(forced_smoke_passed=1)


class ExactPredecessorCompatibilityTests(unittest.TestCase):
    def test_write_source_hardening_is_exactly_bound_and_rollback_preserves_state(self):
        self.assertEqual(
            _git_blob(PREDECESSOR_EVIDENCE_SHA, "ops/write_safety.py"),
            _git_blob(CANDIDATE_ANCHOR_SHA, "ops/write_safety.py"),
        )
        self.assertNotEqual(
            _git_blob(CANDIDATE_ANCHOR_SHA, "ops/write_safety.py"),
            _git_blob("HEAD", "ops/write_safety.py"),
        )
        self.assertNotEqual(
            _git_blob(WRITE_TERMINAL_ADAPT_SHA, "ops/write_safety.py"),
            _git_blob("HEAD", "ops/write_safety.py"),
        )
        self.assertEqual(
            _git_blob(WRITE_SCHEMA_BOOTSTRAP_ADAPT_SHA, "ops/write_safety.py"),
            _git_blob("HEAD", "ops/write_safety.py"),
        )
        for path in ("bridge/runtime.py", "ops/telegram_session_lock.py"):
            with self.subTest(path=path):
                self.assertNotEqual(
                    _git_blob(PREDECESSOR_EVIDENCE_SHA, path),
                    _git_blob("HEAD", path),
                )
        # Source hardening is not itself a compatibility PASS. The rollback
        # contract still requires exact live-LKG identity, target-specific
        # compatibility, forced smoke, and an independently cleared target gate.

    def test_predecessor_file_store_can_open_and_write_candidate_migrated_schema(self):
        name, predecessor = _load_predecessor_storage()
        self.addCleanup(sys.modules.pop, name, None)
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            db = root / "state" / "files.sqlite3"
            files = root / "files"
            _create_legacy_files_db(db)
            FileRecordStore(db, files)
            with sqlite3.connect(str(db)) as connection:
                columns = tuple(str(row[1]) for row in connection.execute("PRAGMA table_info(files)"))
            self.assertIn("origin_key", columns)

            old_store = predecessor.FileRecordStore(db, files)
            payload = files / "compatibility.txt"
            payload.write_text("synthetic", encoding="utf-8")
            record = old_store.add(payload, name="compatibility.txt", mime_type="text/plain")
            loaded = old_store.get(record.file_ref)
            self.assertIsNotNone(loaded)
            self.assertEqual(record.sha256, loaded.sha256)

    def test_predecessor_checkpoint_store_loads_and_saves_candidate_checkpoint(self):
        name, predecessor = _load_predecessor_storage()
        self.addCleanup(sys.modules.pop, name, None)
        with tempfile.TemporaryDirectory() as td:
            db = Path(td) / "state" / "downloads.sqlite3"
            current = CheckpointStore(db)
            item = DownloadItem(
                item_id="item-1",
                chat="synthetic-chat",
                message_id=1,
                source_file_ref="A" * 24,
                name="synthetic.txt",
                mime_type="text/plain",
            )
            job_id = current.create([item])
            old = predecessor.CheckpointStore(db)
            payload = old.load(job_id)
            self.assertEqual(1, payload["schema"])
            old.save(payload)
            self.assertEqual(payload, current.load(job_id))

    def test_audit_stream_format_is_append_compatible_but_predecessor_writer_is_security_weaker(self):
        name, predecessor, old_source = _load_predecessor_audit()
        self.addCleanup(sys.modules.pop, name, None)
        current_source = (_repo_root() / "bridge" / "audit.py").read_text(encoding="utf-8")
        self.assertNotIn("O_NOFOLLOW", old_source)
        self.assertIn("O_NOFOLLOW", current_source)

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            root.chmod(0o700)
            path = root / "audit.jsonl"
            AuditLog(path).write("read", status=200, count=1)
            predecessor.AuditLog(path).write("read", status=200, count=2)
            rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
            self.assertEqual([1, 2], [row["count"] for row in rows])
            self.assertEqual(0o600, os.stat(path).st_mode & 0o777)


class PreserveOnlyStateOracles(unittest.TestCase):
    def test_ambiguous_write_knowledge_survives_reopen_and_prevents_retry(self):
        with tempfile.TemporaryDirectory() as td:
            db = Path(td) / "writes.sqlite3"
            store = PersistentWriteStore(db)
            preview = store.create_preview(
                WriteAction.SEND,
                {"target": "synthetic-target", "text": "synthetic body"},
                now=100,
            )
            calls = []

            def uncertain(_payload):
                calls.append("called")
                raise RuntimeError("synthetic uncertain external outcome")

            with self.assertRaises(ReconciliationRequired):
                store.commit(
                    preview.token,
                    expected_action=WriteAction.SEND,
                    idempotency_key="idem-finalwave37",
                    external_write=uncertain,
                    now=101,
                )
            self.assertEqual(["called"], calls)
            self.assertEqual("AMBIGUOUS", store.transaction_state("idem-finalwave37"))

            reopened = PersistentWriteStore(db)
            retry_calls = []
            with self.assertRaises(ReconciliationRequired):
                reopened.commit(
                    preview.token,
                    expected_action=WriteAction.SEND,
                    idempotency_key="idem-finalwave37",
                    external_write=lambda _payload: retry_calls.append("unsafe") or {},
                    now=102,
                )
            self.assertEqual([], retry_calls)
            self.assertEqual("AMBIGUOUS", reopened.transaction_state("idem-finalwave37"))

    @unittest.skipIf(os.name != "posix", "runtime private SQLite contract is POSIX")
    def test_preserved_rate_high_water_rejects_clock_regression(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            root.chmod(0o700)
            db = root / "rate_limit.sqlite3"
            now = [100]
            store = _SQLiteFixedWindowStore(db, clock=lambda: now[0])
            allowed, remaining, retry = store.take(
                namespace="read", actor="synthetic", operation="read-api", limit=5, window_seconds=60
            )
            self.assertTrue(allowed)
            self.assertEqual(4, remaining)
            self.assertEqual(0, retry)
            with sqlite3.connect(str(db)) as connection:
                self.assertEqual(100, connection.execute(
                    "SELECT high_water FROM fixed_window_clock WHERE singleton=1"
                ).fetchone()[0])
            now[0] = 99
            with self.assertRaises(RuntimeBootstrapError) as caught:
                store.take(
                    namespace="read", actor="synthetic", operation="read-api", limit=5, window_seconds=60
                )
            self.assertEqual("rate_limit_clock_moved_backward", caught.exception.code)

    def test_forced_failed_smoke_rolls_code_back_without_rewinding_shared_state(self):
        with tempfile.TemporaryDirectory() as td:
            layout = Round9Layout(Path(td))
            state_file = layout.state / "var/db"
            observed_identities: list[str] = []

            def hook(_path: Path, name: str, *, timeout: int = 60, args=None) -> None:
                if name == "authenticated smoke":
                    state_file.write_text("candidate-mutated", encoding="utf-8")
                    raise release_guard.SafetyError("synthetic forced-smoke failure")

            def identity(_hook: Path, expected_sha: str) -> None:
                observed_identities.append(expected_sha)

            with mock.patch.object(
                deploy_release, "verify_approved_ref_policy", return_value=layout.new_sha
            ), mock.patch.object(
                deploy_release, "verify_running_release", side_effect=identity
            ), mock.patch.object(
                deploy_release, "run_private_hook", side_effect=hook
            ):
                rc = deploy_release.execute_prepared_release(**layout.kwargs())

            self.assertEqual(20, rc)
            self.assertEqual(layout.old.resolve(), layout.active.resolve())
            self.assertEqual("ROLLED_BACK", layout.journal()["state"])
            self.assertEqual("candidate-mutated", state_file.read_text(encoding="utf-8"))
            self.assertEqual(layout.old_sha, observed_identities[-1])
            self.assertTrue(list((layout.root / "backups/state").glob("*.tar.gz")))


if __name__ == "__main__":
    unittest.main()
