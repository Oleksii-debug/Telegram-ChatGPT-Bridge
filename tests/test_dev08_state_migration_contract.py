# -*- coding: utf-8 -*-
from __future__ import annotations

import json
import multiprocessing
import os
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
import types
import unittest
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from bridge.app import BridgeApplication, ReadAppConfig
from bridge.storage import FileRecordStore
from ops import deploy_release, release_guard
from ops.dev08_state_migration_contract import (
    StateMigrationContractError,
    assess_audited_plan_boundary,
    assess_state_migration,
    inventory_by_name,
)
from tests.test_audit_round9 import Round9Layout


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
PREDECESSOR_SHA = "00684e834a523f55ea3b61c1a12cb9dc54cfd947"


def create_legacy_files_db(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(str(path)) as connection:
        connection.execute(LEGACY_FILES_SCHEMA)
        connection.commit()


def files_schema(path: Path) -> tuple[tuple[str, ...], tuple[str, ...]]:
    with sqlite3.connect(str(path)) as connection:
        columns = tuple(str(row[1]) for row in connection.execute("PRAGMA table_info(files)"))
        indexes = tuple(sorted(str(row[1]) for row in connection.execute("PRAGMA index_list(files)")))
    return columns, indexes


def _migration_worker(db: str, files_root: str, start_event, result_queue) -> None:
    try:
        if not start_event.wait(10):
            result_queue.put("start-timeout")
            return
        FileRecordStore(Path(db), Path(files_root))
        result_queue.put("ok")
    except BaseException as exc:  # synthetic type-only evidence
        result_queue.put(type(exc).__name__)


class CanonicalApprovalSchemaContractTests(unittest.TestCase):
    def _write_approval(self, root: Path, *, data_schema_change: bool) -> tuple[Path, dict]:
        sha = "a" * 40
        manifest = "b" * 64
        now = datetime.now(timezone.utc)
        payload = {
            "approved": True,
            "approved_sha": sha,
            "repository": "synthetic/dev08-r4",
            "approved_ref": "main",
            "release_manifest_sha256": manifest,
            "ci_run_id": "dev08-r4",
            "audit_id": "audit-dev08-r4",
            "approval_id": "approval-dev08-r4",
            "nonce": "nonce-dev08-r4",
            "issued_at": now.isoformat(),
            "expires_at": (now + timedelta(hours=1)).isoformat(),
            "data_schema_change": data_schema_change,
        }
        path = root / "approval.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        path.chmod(0o600)
        expected = {
            "expected_sha": sha,
            "expected_repository": payload["repository"],
            "expected_ref": payload["approved_ref"],
            "expected_manifest_sha256": manifest,
            "expected_ci_run_id": payload["ci_run_id"],
            "expected_audit_id": payload["audit_id"],
            "now": now,
        }
        return path, expected

    def test_canonical_approval_accepts_only_no_schema_change(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            path, expected = self._write_approval(root, data_schema_change=False)
            approval = release_guard.load_external_approval(path, **expected)
            self.assertIs(approval["data_schema_change"], False)

    def test_canonical_approval_rejects_declared_schema_change(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            path, expected = self._write_approval(root, data_schema_change=True)
            with self.assertRaises(release_guard.SafetyError):
                release_guard.load_external_approval(path, **expected)


class PersistentStateInventoryTests(unittest.TestCase):
    def test_inventory_separates_all_current_persistent_state_classes(self):
        inventory = inventory_by_name()
        self.assertEqual(
            {
                "file_registry",
                "download_checkpoints",
                "write_idempotency",
                "rate_limit",
                "private_files",
                "download_staging",
                "archive_staging",
                "telegram_session_and_private_config",
                "audit_evidence",
            },
            set(inventory),
        )
        self.assertEqual("state/files.sqlite3", inventory["file_registry"].location)
        self.assertEqual("state/downloads.sqlite3", inventory["download_checkpoints"].location)
        self.assertEqual("state/writes.sqlite3", inventory["write_idempotency"].location)
        self.assertEqual("state/rate_limit.sqlite3", inventory["rate_limit"].location)

    def test_inventory_forbids_blind_restore_of_critical_state(self):
        inventory = inventory_by_name()
        self.assertIn("never blind-restore", inventory["write_idempotency"].rollback_rule)
        self.assertIn("preserve exactly", inventory["telegram_session_and_private_config"].rollback_rule)
        self.assertIn("never roll back", inventory["audit_evidence"].rollback_rule)


class IntegratedRuntimeMigrationTests(unittest.TestCase):
    def test_current_file_store_changes_legacy_persistent_schema(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            db = root / "state" / "files.sqlite3"
            files = root / "files"
            create_legacy_files_db(db)
            before_columns, before_indexes = files_schema(db)
            self.assertNotIn("origin_key", before_columns)
            self.assertNotIn("files_origin_key_unique", before_indexes)

            FileRecordStore(db, files)

            after_columns, after_indexes = files_schema(db)
            self.assertEqual(before_columns + ("origin_key",), after_columns)
            self.assertIn("files_origin_key_unique", after_indexes)

    def test_bridge_application_startup_runs_the_persistent_schema_migration(self):
        with tempfile.TemporaryDirectory() as td:
            private = Path(td) / "private"
            db = private / "state" / "files.sqlite3"
            create_legacy_files_db(db)
            before = files_schema(db)

            app = BridgeApplication(config=ReadAppConfig(private_root=private))
            self.assertIsNotNone(app.files)

            after = files_schema(db)
            self.assertNotEqual(before, after)
            self.assertIn("origin_key", after[0])
            self.assertIn("files_origin_key_unique", after[1])

    def test_no_schema_change_approval_can_be_valid_while_startup_still_migrates(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            approval_path = root / "control" / "approval.json"
            approval_path.parent.mkdir()
            approval_path.parent.chmod(0o700)
            now = datetime.now(timezone.utc)
            payload = {
                "approved": True,
                "approved_sha": "a" * 40,
                "repository": "synthetic/dev08-r4",
                "approved_ref": "main",
                "release_manifest_sha256": "b" * 64,
                "ci_run_id": "dev08-r4",
                "audit_id": "audit-dev08-r4",
                "approval_id": "approval-dev08-r4-false",
                "nonce": "nonce-dev08-r4-false",
                "issued_at": now.isoformat(),
                "expires_at": (now + timedelta(hours=1)).isoformat(),
                "data_schema_change": False,
            }
            approval_path.write_text(json.dumps(payload), encoding="utf-8")
            approval_path.chmod(0o600)
            accepted = release_guard.load_external_approval(
                approval_path,
                expected_sha=payload["approved_sha"],
                expected_repository=payload["repository"],
                expected_ref=payload["approved_ref"],
                expected_manifest_sha256=payload["release_manifest_sha256"],
                expected_ci_run_id=payload["ci_run_id"],
                expected_audit_id=payload["audit_id"],
                now=now,
            )
            self.assertIs(accepted["data_schema_change"], False)

            private = root / "private"
            db = private / "state" / "files.sqlite3"
            create_legacy_files_db(db)
            before = files_schema(db)
            BridgeApplication(config=ReadAppConfig(private_root=private))
            after = files_schema(db)
            self.assertNotEqual(before, after)

            decision = assess_state_migration(
                runtime_schema_changed=True,
                approval_allows_schema_change=bool(accepted["data_schema_change"]),
                rollback_restores_persistent_state=False,
                backward_compatibility_proven=False,
            )
            self.assertEqual("BLOCKED_MIGRATION_PLAN_REQUIRED", decision.action)
            self.assertFalse(decision.production_authorized)

    def test_interrupted_schema_migration_rolls_back_and_retry_succeeds(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            db = root / "state" / "files.sqlite3"
            files = root / "files"
            create_legacy_files_db(db)
            legacy = files_schema(db)

            @contextmanager
            def interrupted_connect(_self):
                connection = sqlite3.connect(str(db), timeout=8.0)
                connection.execute("PRAGMA journal_mode=WAL")
                connection.execute("PRAGMA synchronous=FULL")

                class Proxy:
                    def execute(self, statement, *args):
                        normalized = " ".join(str(statement).split()).upper()
                        if normalized.startswith("CREATE UNIQUE INDEX"):
                            raise sqlite3.OperationalError("synthetic migration interruption")
                        return connection.execute(statement, *args)

                    def commit(self):
                        return connection.commit()

                try:
                    yield Proxy()
                finally:
                    connection.close()

            with mock.patch.object(FileRecordStore, "_connect", interrupted_connect):
                with self.assertRaises(sqlite3.OperationalError):
                    FileRecordStore(db, files)

            self.assertEqual(legacy, files_schema(db))
            FileRecordStore(db, files)
            columns, indexes = files_schema(db)
            self.assertIn("origin_key", columns)
            self.assertIn("files_origin_key_unique", indexes)

    @unittest.skipIf(os.name != "posix", "concurrent migration contract is POSIX CI evidence")
    def test_concurrent_process_startup_serializes_the_same_migration(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            db = root / "state" / "files.sqlite3"
            files = root / "files"
            create_legacy_files_db(db)

            ctx = multiprocessing.get_context("fork")
            start = ctx.Event()
            results = ctx.Queue()
            workers = [
                ctx.Process(target=_migration_worker, args=(str(db), str(files), start, results))
                for _ in range(2)
            ]
            for process in workers:
                process.start()
            start.set()
            observed = [results.get(timeout=20) for _ in workers]
            for process in workers:
                process.join(20)
                self.assertEqual(0, process.exitcode)

            self.assertEqual(["ok", "ok"], sorted(observed))
            columns, indexes = files_schema(db)
            self.assertEqual(1, columns.count("origin_key"))
            self.assertIn("files_origin_key_unique", indexes)

    def test_predecessor_file_store_can_open_and_write_current_migrated_schema(self):
        root = Path(__file__).resolve().parents[1]
        if not (root / ".git").exists():
            self.skipTest("full Git history required for exact predecessor compatibility evidence")
        source = subprocess.check_output(
            ["git", "show", f"{PREDECESSOR_SHA}:bridge/storage.py"],
            cwd=root,
            text=True,
            stderr=subprocess.DEVNULL,
        )
        module = types.ModuleType("bridge._dev08_predecessor_storage")
        module.__package__ = "bridge"
        sys.modules[module.__name__] = module
        self.addCleanup(sys.modules.pop, module.__name__, None)
        exec(compile(source, "predecessor_bridge_storage.py", "exec"), module.__dict__)
        old_store_type = module.FileRecordStore

        with tempfile.TemporaryDirectory() as td:
            private = Path(td)
            db = private / "state" / "files.sqlite3"
            files = private / "files"
            create_legacy_files_db(db)
            FileRecordStore(db, files)
            self.assertIn("origin_key", files_schema(db)[0])

            old_store = old_store_type(db, files)
            payload = files / "compatibility.txt"
            payload.write_text("synthetic", encoding="utf-8")
            record = old_store.add(payload, name="compatibility.txt", mime_type="text/plain")
            loaded = old_store.get(record.file_ref)
            self.assertIsNotNone(loaded)
            self.assertEqual(record.sha256, loaded.sha256)

    def test_current_origin_key_migration_is_backward_compatible_but_still_needs_plan(self):
        decision = assess_audited_plan_boundary(
            runtime_schema_changed=True,
            approval_declares_schema_change=True,
            exact_sha_plan_bound=True,
            backward_compatibility_proven=True,
            targeted_restore_defined=False,
            sqlite_snapshot_consistency_proven=False,
            blind_private_tree_restore_requested=False,
        )
        self.assertEqual("AUDITOR_GATE_REQUIRED", decision.action)
        self.assertFalse(decision.production_authorized)


class SQLiteBackupBoundaryTests(unittest.TestCase):
    def test_quiescent_backup_captures_db_wal_shm_as_one_recoverable_set(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            state = root / "persistent"
            state.mkdir()
            db = state / "synthetic.sqlite3"
            writer = sqlite3.connect(str(db))
            reader = None
            try:
                self.assertEqual("wal", writer.execute("PRAGMA journal_mode=WAL").fetchone()[0].lower())
                writer.execute("PRAGMA wal_autocheckpoint=0")
                writer.execute("CREATE TABLE sample(value TEXT NOT NULL)")
                writer.commit()

                reader = sqlite3.connect(str(db))
                reader.execute("PRAGMA journal_mode=WAL")
                reader.execute("BEGIN")
                reader.execute("SELECT count(*) FROM sample").fetchone()

                writer.execute("INSERT INTO sample(value) VALUES('committed-in-wal')")
                writer.commit()
                wal = Path(str(db) + "-wal")
                shm = Path(str(db) + "-shm")
                self.assertTrue(wal.exists())
                self.assertTrue(shm.exists())
                self.assertGreater(wal.stat().st_size, 0)

                backup = deploy_release.backup_persistent_state(
                    state,
                    root / "backups",
                    "c" * 40,
                )
                with tarfile.open(backup, "r:gz") as archive:
                    names = set(archive.getnames())
                    self.assertIn("persistent_state/synthetic.sqlite3", names)
                    self.assertIn("persistent_state/synthetic.sqlite3-wal", names)
                    self.assertIn("persistent_state/synthetic.sqlite3-shm", names)
                    restore_root = root / "restore"
                    archive.extractall(restore_root)

                restored = restore_root / "persistent_state" / "synthetic.sqlite3"
                with sqlite3.connect(str(restored)) as connection:
                    count = connection.execute("SELECT count(*) FROM sample").fetchone()[0]
                self.assertEqual(1, count)
            finally:
                if reader is not None:
                    reader.rollback()
                    reader.close()
                writer.close()

    def test_targeted_restore_requires_snapshot_consistency_evidence(self):
        decision = assess_audited_plan_boundary(
            runtime_schema_changed=True,
            approval_declares_schema_change=True,
            exact_sha_plan_bound=True,
            backward_compatibility_proven=False,
            targeted_restore_defined=True,
            sqlite_snapshot_consistency_proven=False,
            blind_private_tree_restore_requested=False,
        )
        self.assertEqual("BLOCKED_SQLITE_SNAPSHOT_CONTRACT_REQUIRED", decision.action)
        self.assertFalse(decision.production_authorized)


class RollbackPersistentStateTests(unittest.TestCase):
    def test_code_rollback_does_not_restore_candidate_mutated_persistent_state(self):
        with tempfile.TemporaryDirectory() as td:
            layout = Round9Layout(Path(td))
            state_file = layout.state / "var/db"
            self.assertEqual("state", state_file.read_text(encoding="utf-8"))

            def fault_hook(path: Path, name: str, *, timeout: int = 60, args=None) -> None:
                if name == "authenticated smoke":
                    self.assertNotEqual(layout.old.resolve(), layout.active.resolve())
                    state_file.write_text("candidate-mutated", encoding="utf-8")
                    raise release_guard.SafetyError("synthetic post-startup state mutation")
                return None

            with mock.patch.object(
                deploy_release, "verify_approved_ref_policy", return_value=layout.new_sha
            ), mock.patch.object(
                deploy_release, "verify_running_release", return_value=None
            ), mock.patch.object(
                deploy_release, "run_private_hook", side_effect=fault_hook
            ):
                rc = deploy_release.execute_prepared_release(**layout.kwargs())

            self.assertEqual(20, rc)
            self.assertEqual(layout.old.resolve(), layout.active.resolve())
            self.assertEqual("ROLLED_BACK", layout.journal()["state"])
            self.assertEqual("candidate-mutated", state_file.read_text(encoding="utf-8"))
            state_backups = list((layout.root / "backups/state").glob("*.tar.gz"))
            self.assertTrue(state_backups, "pre-deploy persistent-state backup should exist")

    def test_failed_candidate_smoke_reverifies_previous_release_identity_before_healthy_rollback(self):
        with tempfile.TemporaryDirectory() as td:
            layout = Round9Layout(Path(td))
            identities: list[str] = []

            def fault_hook(path: Path, name: str, *, timeout: int = 60, args=None) -> None:
                if name == "authenticated smoke":
                    raise release_guard.SafetyError("synthetic candidate smoke failure")
                return None

            def verify_identity(_hook: Path, expected_sha: str) -> None:
                identities.append(expected_sha)

            with mock.patch.object(
                deploy_release, "verify_approved_ref_policy", return_value=layout.new_sha
            ), mock.patch.object(
                deploy_release, "verify_running_release", side_effect=verify_identity
            ), mock.patch.object(
                deploy_release, "run_private_hook", side_effect=fault_hook
            ):
                rc = deploy_release.execute_prepared_release(**layout.kwargs())

            self.assertEqual(20, rc)
            self.assertGreaterEqual(len(identities), 2)
            self.assertEqual(layout.new_sha, identities[0])
            self.assertEqual(layout.old_sha, identities[-1])
            self.assertEqual(layout.old.resolve(), layout.active.resolve())
            self.assertEqual("ROLLED_BACK", layout.journal()["state"])

    def test_schema_migration_needs_rollback_compatibility_when_state_is_not_restored(self):
        decision = assess_state_migration(
            runtime_schema_changed=True,
            approval_allows_schema_change=True,
            rollback_restores_persistent_state=False,
            backward_compatibility_proven=False,
        )
        self.assertEqual("BLOCKED_ROLLBACK_COMPATIBILITY_REQUIRED", decision.action)
        self.assertFalse(decision.production_authorized)


class AuditedMigrationPlanContractTests(unittest.TestCase):
    def test_runtime_change_cannot_be_described_as_no_schema_change(self):
        decision = assess_audited_plan_boundary(
            runtime_schema_changed=True,
            approval_declares_schema_change=False,
            exact_sha_plan_bound=True,
            backward_compatibility_proven=True,
            targeted_restore_defined=False,
            sqlite_snapshot_consistency_proven=True,
            blind_private_tree_restore_requested=False,
        )
        self.assertEqual("BLOCKED_APPROVAL_STATE_MISMATCH", decision.action)

    def test_declared_change_without_exact_sha_plan_fails_closed(self):
        decision = assess_audited_plan_boundary(
            runtime_schema_changed=True,
            approval_declares_schema_change=True,
            exact_sha_plan_bound=False,
            backward_compatibility_proven=True,
            targeted_restore_defined=False,
            sqlite_snapshot_consistency_proven=True,
            blind_private_tree_restore_requested=False,
        )
        self.assertEqual("BLOCKED_MIGRATION_PLAN_REQUIRED", decision.action)

    def test_blind_private_tree_restore_is_always_rejected(self):
        decision = assess_audited_plan_boundary(
            runtime_schema_changed=True,
            approval_declares_schema_change=True,
            exact_sha_plan_bound=True,
            backward_compatibility_proven=False,
            targeted_restore_defined=True,
            sqlite_snapshot_consistency_proven=True,
            blind_private_tree_restore_requested=True,
        )
        self.assertEqual("BLOCKED_UNSAFE_PRIVATE_TREE_RESTORE", decision.action)

    def test_complete_plan_contract_still_requires_independent_auditor_gate(self):
        decision = assess_audited_plan_boundary(
            runtime_schema_changed=True,
            approval_declares_schema_change=True,
            exact_sha_plan_bound=True,
            backward_compatibility_proven=True,
            targeted_restore_defined=False,
            sqlite_snapshot_consistency_proven=False,
            blind_private_tree_restore_requested=False,
        )
        self.assertEqual("AUDITOR_GATE_REQUIRED", decision.action)
        self.assertFalse(decision.production_authorized)

    def test_truthy_non_booleans_fail_closed(self):
        with self.assertRaises(StateMigrationContractError):
            assess_audited_plan_boundary(
                runtime_schema_changed=1,  # type: ignore[arg-type]
                approval_declares_schema_change=False,
                exact_sha_plan_bound=False,
                backward_compatibility_proven=False,
                targeted_restore_defined=False,
                sqlite_snapshot_consistency_proven=False,
                blind_private_tree_restore_requested=False,
            )


class StateMigrationClassifierTests(unittest.TestCase):
    def test_no_schema_change_is_clear_but_never_authorizes_production(self):
        decision = assess_state_migration(
            runtime_schema_changed=False,
            approval_allows_schema_change=False,
            rollback_restores_persistent_state=False,
            backward_compatibility_proven=False,
        )
        self.assertEqual("NO_SCHEMA_MIGRATION", decision.action)
        self.assertFalse(decision.production_authorized)

    def test_backward_compatibility_still_requires_audited_migration_path(self):
        decision = assess_state_migration(
            runtime_schema_changed=True,
            approval_allows_schema_change=True,
            rollback_restores_persistent_state=False,
            backward_compatibility_proven=True,
        )
        self.assertEqual("AUDITED_MIGRATION_PATH_REQUIRED", decision.action)
        self.assertFalse(decision.production_authorized)

    def test_state_restore_still_requires_audited_migration_path(self):
        decision = assess_state_migration(
            runtime_schema_changed=True,
            approval_allows_schema_change=True,
            rollback_restores_persistent_state=True,
            backward_compatibility_proven=False,
        )
        self.assertEqual("AUDITED_MIGRATION_PATH_REQUIRED", decision.action)
        self.assertFalse(decision.production_authorized)

    def test_truthy_non_booleans_fail_closed(self):
        with self.assertRaises(StateMigrationContractError):
            assess_state_migration(
                runtime_schema_changed=1,  # type: ignore[arg-type]
                approval_allows_schema_change=False,
                rollback_restores_persistent_state=False,
                backward_compatibility_proven=False,
            )


if __name__ == "__main__":
    unittest.main()
