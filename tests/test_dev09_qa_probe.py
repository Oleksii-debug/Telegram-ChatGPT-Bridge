from __future__ import annotations

import json
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from bridge.app import BridgeApplication, ReadAppConfig
from bridge.backend import TelethonReadBackend, TelethonReadConfig
from bridge.downloads import DownloadManager
from bridge.errors import BridgeError
from bridge.storage import CheckpointStore, DownloadItem, FileRecordStore
from bridge.validation import DateRange
from ops.dev09_qa_probe import (
    EXPECTED_PARENT_SHA,
    MANIFEST,
    _load_manifest,
    candidate_truth_snapshot,
    canonical_provenance_probe,
    exported_test_suite_probe,
    validate_workflow_parent,
)

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY_GIT_AVAILABLE = (ROOT / ".git").exists()
SKIP_EXPENSIVE = os.environ.get("DEV09_SKIP_EXPENSIVE") == "1"
requires_repository_git = unittest.skipUnless(
    REPOSITORY_GIT_AVAILABLE,
    "DEV09 exact-parent probe requires repository Git metadata and is skipped inside PREPARE payload",
)
requires_expensive_repository_probe = unittest.skipIf(
    (not REPOSITORY_GIT_AVAILABLE) or SKIP_EXPENSIVE,
    "DEV09 nested exact-parent probe skipped in aggregate regression",
)


class _CountingDownloadBackend:
    def __init__(self) -> None:
        self.calls = 0

    def download_media(self, **kwargs):  # type: ignore[no-untyped-def]
        self.calls += 1
        target = Path(kwargs["destination"])
        target.write_bytes(b"abc")
        return {"path": str(target)}


class _FailOnSaveCheckpointStore(CheckpointStore):
    def __init__(self, db_path: Path) -> None:
        self.save_calls = 0
        self.fail_at: int | None = None
        super().__init__(db_path)

    def save(self, payload):  # type: ignore[no-untyped-def]
        self.save_calls += 1
        if self.fail_at is not None and self.save_calls == self.fail_at:
            raise RuntimeError("fault_injected_checkpoint_save")
        return super().save(payload)


class _CaptureSearchBackend:
    def __init__(self) -> None:
        self.kwargs = None

    def search(self, **kwargs):  # type: ignore[no-untyped-def]
        self.kwargs = dict(kwargs)
        return SimpleNamespace(items=(), next_cursor=None, scanned=0)


class _StrictGlobalTelethonClient:
    """Minimal fake matching Telethon's global-search precondition.

    entity=None requires a non-empty search/filter/from_user. Current canonical
    sender-only search supplies none of those server-side constraints.
    """

    async def connect(self) -> None:
        return None

    async def is_user_authorized(self) -> bool:
        return True

    async def disconnect(self) -> None:
        return None

    def iter_messages(self, entity, limit: int, *, search: str = "", from_user=None):  # type: ignore[no-untyped-def]
        del limit
        if entity is None and not search and from_user is None:
            raise ValueError("global search requires search/filter/from_user")
        return []


class Dev09ExactParentTests(unittest.TestCase):
    def test_manifest_is_exact_parent_qa_only_and_non_authorizing(self):
        payload = _load_manifest()
        self.assertEqual(payload["parent_sha"], EXPECTED_PARENT_SHA)
        self.assertFalse(payload["production_logic_modified"])
        self.assertFalse(payload["deployment_authorized"])
        self.assertFalse(payload["live_write_authorized"])
        self.assertFalse(payload["product_pass"])
        self.assertEqual(
            payload["qa_paths"],
            sorted([
                ".github/workflows/dev09-e2e-qa.yml",
                "docs/DEV09_SWARM_QA.md",
                "integration/dev09_qa_v1.json",
                "ops/dev09_qa_probe.py",
                "tests/test_dev09_qa_probe.py",
            ]),
        )

    def test_workflow_parent_gate_fails_when_canonical_moves(self):
        validate_workflow_parent(EXPECTED_PARENT_SHA)
        with self.assertRaisesRegex(ValueError, "DEV09_QA_PARENT_MOVED"):
            validate_workflow_parent("0" * 40)

    @requires_repository_git
    def test_live_pr_base_matches_exact_restack_when_workflow_supplies_it(self):
        observed = os.environ.get("DEV09_EXPECTED_BASE_SHA")
        if observed is not None:
            self.assertEqual(observed, EXPECTED_PARENT_SHA)


class Dev09CurrentCanonicalTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.provenance = None
        cls.suite = None
        if REPOSITORY_GIT_AVAILABLE and not SKIP_EXPENSIVE:
            cls.provenance = canonical_provenance_probe()
            cls.suite = exported_test_suite_probe()

    @requires_expensive_repository_probe
    def test_exact_parent_provenance_is_clear_after_peer_sync_accounting(self):
        result = self.provenance
        self.assertIsNotNone(result)
        self.assertEqual(result["parent_sha"], EXPECTED_PARENT_SHA)
        self.assertEqual(result["classification"], "CLEAR")
        self.assertEqual(result["reason"], "NONE")
        self.assertEqual(result["return_code"], 0)
        self.assertFalse(result["private_values_recorded"])
        self.assertFalse(result["production_mutated"])
        self.assertFalse(result["deployment_authorized"])
        self.assertFalse(result["product_pass"])

    @requires_expensive_repository_probe
    def test_exact_exported_functional_suite_remains_clear(self):
        result = self.suite
        self.assertIsNotNone(result)
        self.assertEqual(result["parent_sha"], EXPECTED_PARENT_SHA)
        self.assertEqual(result["classification"], "CLEAR")
        self.assertEqual(result["reason"], "NONE")
        self.assertEqual(result["return_code"], 0)
        self.assertEqual(result["failure_test_count"], 0)
        self.assertEqual(result["failure_test_ids"], [])
        self.assertFalse(result["git_metadata_present"])
        self.assertFalse(result["private_values_recorded"])
        self.assertFalse(result["production_mutated"])
        self.assertFalse(result["deployment_authorized"])
        self.assertFalse(result["product_pass"])

    @requires_expensive_repository_probe
    def test_public_probe_shapes_are_bounded(self):
        suite = self.suite
        provenance = self.provenance
        self.assertIsNotNone(suite)
        self.assertIsNotNone(provenance)
        lowered = json.dumps({"suite": suite, "provenance": provenance}, sort_keys=True).casefold()
        for forbidden in ("stdout", "stderr", "traceback", "exception", "message_body", "file_content"):
            self.assertNotIn(forbidden, lowered)

    def test_probes_are_repository_only_inside_prepare_payload(self):
        if not REPOSITORY_GIT_AVAILABLE:
            self.assertEqual(exported_test_suite_probe()["classification"], "QA_PROBE_UNAVAILABLE")
            self.assertEqual(canonical_provenance_probe()["classification"], "QA_PROBE_UNAVAILABLE")
        self.assertTrue(MANIFEST.is_file())


@unittest.skipUnless(os.name == "posix", "download durability fault oracle is POSIX/HOSTiQ oriented")
class Dev09DownloadDurabilityClosureTests(unittest.TestCase):
    def test_checkpoint_save_crash_recovers_registered_result_without_redownload(self):
        with tempfile.TemporaryDirectory(prefix="dev09-download-crash-") as td:
            root = Path(td)
            files = FileRecordStore(root / "state" / "files.sqlite3", root / "files")
            checkpoints = _FailOnSaveCheckpointStore(root / "state" / "downloads.sqlite3")
            backend = _CountingDownloadBackend()
            manager = DownloadManager(
                backend=backend,
                files=files,
                checkpoints=checkpoints,
                staging_dir=root / "tmp" / "downloads",
            )
            item = DownloadItem(
                "item1",
                "1",
                1,
                "tg_1_0123456789abcdefabcd",
                "a.txt",
                "text/plain",
                3,
                None,
            )
            job_id = checkpoints.create([item])
            checkpoints.fail_at = 3

            with self.assertRaisesRegex(RuntimeError, "fault_injected_checkpoint_save"):
                manager.resume(job_id)
            self.assertEqual(backend.calls, 1)

            durable_checkpoint = CheckpointStore(checkpoints.db_path).load(job_id)
            self.assertEqual(durable_checkpoint["results"], {})
            with sqlite3.connect(str(files.db_path)) as connection:
                first_rows = [str(row[0]) for row in connection.execute("SELECT file_ref FROM files").fetchall()]
            self.assertEqual(len(first_rows), 1)

            restarted = DownloadManager(
                backend=backend,
                files=files,
                checkpoints=CheckpointStore(checkpoints.db_path),
                staging_dir=root / "tmp-restarted" / "downloads",
            )
            result = restarted.resume(job_id)
            self.assertEqual(result["status"], "complete")
            self.assertEqual(backend.calls, 1)
            self.assertEqual(len(result["files"]), 1)
            self.assertEqual(str(result["files"][0]["file_ref"]), first_rows[0])

            with sqlite3.connect(str(files.db_path)) as connection:
                final_rows = [str(row[0]) for row in connection.execute("SELECT file_ref FROM files").fetchall()]
            self.assertEqual(final_rows, first_rows)


class Dev09GlobalSenderSearchFindingTests(unittest.TestCase):
    """Executable oracle for the open global sender-only D3/D4 gap.

    This intentionally records the current-parent defect. When DEV03/DEV01
    integrates a real from_user/global-search design, DEV09 must flip this from
    reproducer to closure oracle on the new exact parent.
    """

    def test_api_contract_accepts_sender_only_search_without_chat_or_text(self):
        backend = _CaptureSearchBackend()
        app = BridgeApplication(
            config=ReadAppConfig(auth_secret="synthetic-dev09-token"),
            backend=backend,  # type: ignore[arg-type]
        )
        payload = app._handle_post("search.read", {"sender": "reader"})
        self.assertEqual(payload["items"], [])
        self.assertIsNotNone(backend.kwargs)
        self.assertIsNone(backend.kwargs["chat"])
        self.assertEqual(backend.kwargs["sender"], "reader")
        self.assertEqual(backend.kwargs["text"], "")

    def test_current_backend_sender_only_global_search_lacks_server_constraint(self):
        backend = TelethonReadBackend(
            client_factory=_StrictGlobalTelethonClient,
            config=TelethonReadConfig(request_timeout_seconds=2, search_scan_limit=100),
        )
        with self.assertRaises(BridgeError) as captured:
            backend.search(
                chat=None,
                sender="reader",
                text="",
                dates=DateRange(None, None),
                limit=10,
                cursor=None,
                scan_limit=10,
            )
        self.assertEqual(captured.exception.code, "telegram_rpc_error")
        self.assertEqual(captured.exception.status, 502)


class Dev09AcceptanceTruthTests(unittest.TestCase):
    def test_all_67_and_current_19_route_inventory_remain_conservative(self):
        snapshot = candidate_truth_snapshot()
        self.assertEqual(snapshot["criterion_count"], 67)
        self.assertEqual(
            snapshot["coverage_counts"],
            {
                "LIVE_EXTERNAL_REQUIRED": 17,
                "REAL_SOURCE_REQUIRED": 13,
                "SYNTHETIC_EXECUTABLE": 37,
            },
        )
        self.assertEqual(snapshot["product_pass_count"], 0)
        self.assertEqual(snapshot["route_count"], 19)
        self.assertEqual(snapshot["action_operation_count"], 17)
        self.assertEqual(snapshot["private_surface_count"], 0)
        self.assertFalse(snapshot["product_pass"])
        self.assertFalse(snapshot["deployment_authorized"])

    def test_k5_remains_live_external_and_requires_independent_write_approval(self):
        snapshot = candidate_truth_snapshot()
        self.assertEqual(snapshot["k5_evidence_class"], "LIVE_EXTERNAL_REQUIRED")
        self.assertTrue(snapshot["k5_explicit_write_approval_required"])


if __name__ == "__main__":
    unittest.main()
