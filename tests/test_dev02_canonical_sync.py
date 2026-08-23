# -*- coding: utf-8 -*-
from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from ops.dev02_canonical_sync import (
    CRITICAL_RUNTIME_PATHS,
    CanonicalSyncError,
    validate_sync_summary,
    verify_candidate_runtime_sync,
)


class Dev02CanonicalSyncTests(unittest.TestCase):
    def git(self, root: Path, *args: str) -> str:
        env = os.environ.copy()
        env.update({
            "GIT_AUTHOR_NAME": "test",
            "GIT_AUTHOR_EMAIL": "test@example.invalid",
            "GIT_COMMITTER_NAME": "test",
            "GIT_COMMITTER_EMAIL": "test@example.invalid",
        })
        cp = subprocess.run(
            ["git", *args],
            cwd=root,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True,
        )
        return cp.stdout.strip()

    def write(self, root: Path, rel: str, text: str) -> None:
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    def commit(self, root: Path, message: str) -> str:
        self.git(root, "add", "-A")
        self.git(root, "commit", "-m", message)
        return self.git(root, "rev-parse", "HEAD")

    def make_protocol_repo(self, td: str) -> tuple[Path, str]:
        root = Path(td)
        self.git(root, "init")
        for path in CRITICAL_RUNTIME_PATHS:
            self.write(root, path, f"reviewed:{path}\n")
        self.write(root, "ops/server_manifest.py", "def collect_server_manifest():\n    return 'reviewed'\n")
        self.write(root, "integration/release_to_live_v1.json", json.dumps({
            "schema_version": 1,
            "paths": [],
            "dev_b_round2_sync": {"sha": "0" * 40},
        }))
        protocol = self.commit(root, "protocol")
        return root, protocol

    def write_current_ledger(self, root: Path, protocol: str, *, current=True, paths=True) -> None:
        self.write(root, "integration/release_to_live_v1.json", json.dumps({
            "schema_version": 2,
            "paths": list(CRITICAL_RUNTIME_PATHS) if paths else list(CRITICAL_RUNTIME_PATHS[:-1]),
            "dev02_runtime_sync": {"sha": protocol if current else "1" * 40},
            "deployment_authorized": False,
        }, sort_keys=True))

    def test_exact_descendant_bytes_and_current_ledger_are_ready_only_for_revalidation(self):
        with tempfile.TemporaryDirectory() as td:
            root, protocol = self.make_protocol_repo(td)
            self.write_current_ledger(root, protocol)
            candidate = self.commit(root, "canonical")
            result = verify_candidate_runtime_sync(root, candidate, protocol_sha=protocol)
            self.assertEqual("READY_FOR_CANONICAL_REVALIDATION", result["status"])
            self.assertEqual("PASS", result["protocol_ancestry"])
            self.assertEqual("PASS", result["critical_blob_identity"])
            self.assertEqual("PASS", result["ledger_binding"])
            self.assertEqual("PASS", result["ledger_path_accounting"])
            self.assertFalse(result["promotion_authorized"])
            self.assertEqual(result, validate_sync_summary(result))

    def test_stale_sha_and_missing_path_accounting_are_distinguished_from_runtime_drift(self):
        with tempfile.TemporaryDirectory() as td:
            root, protocol = self.make_protocol_repo(td)
            self.write_current_ledger(root, protocol, current=False, paths=False)
            candidate = self.commit(root, "stale-ledger")
            result = verify_candidate_runtime_sync(root, candidate, protocol_sha=protocol)
            self.assertEqual("BLOCKED_LEDGER_STALE", result["status"])
            self.assertEqual("PASS", result["critical_blob_identity"])
            self.assertEqual("STALE", result["ledger_binding"])
            self.assertEqual("STALE", result["ledger_path_accounting"])

    def test_post_protocol_critical_file_mutation_blocks_runtime_sync(self):
        with tempfile.TemporaryDirectory() as td:
            root, protocol = self.make_protocol_repo(td)
            self.write_current_ledger(root, protocol)
            self.write(root, CRITICAL_RUNTIME_PATHS[0], "mutated\n")
            candidate = self.commit(root, "drift")
            result = verify_candidate_runtime_sync(root, candidate, protocol_sha=protocol)
            self.assertEqual("BLOCKED_RUNTIME_DRIFT", result["status"])
            self.assertEqual("FAIL", result["critical_blob_identity"])
            self.assertEqual("NOT_CHECKED", result["ledger_binding"])

    def test_deleted_critical_runtime_file_blocks_without_git_error_detail(self):
        with tempfile.TemporaryDirectory() as td:
            root, protocol = self.make_protocol_repo(td)
            self.write_current_ledger(root, protocol)
            (root / CRITICAL_RUNTIME_PATHS[1]).unlink()
            candidate = self.commit(root, "delete-runtime")
            result = verify_candidate_runtime_sync(root, candidate, protocol_sha=protocol)
            self.assertEqual("BLOCKED_RUNTIME_DRIFT", result["status"])
            self.assertNotIn(str(root), repr(result))

    def test_non_descendant_candidate_fails_ancestry_before_blob_or_ledger_claim(self):
        with tempfile.TemporaryDirectory() as td:
            root, protocol = self.make_protocol_repo(td)
            self.git(root, "checkout", "--orphan", "other")
            for child in list(root.iterdir()):
                if child.name == ".git":
                    continue
                if child.is_dir():
                    import shutil
                    shutil.rmtree(child)
                else:
                    child.unlink()
            self.write(root, "README.md", "other\n")
            candidate = self.commit(root, "unrelated")
            result = verify_candidate_runtime_sync(root, candidate, protocol_sha=protocol)
            self.assertEqual("BLOCKED_PROTOCOL_ANCESTRY", result["status"])
            self.assertEqual("NOT_CHECKED", result["critical_blob_identity"])

    def test_short_or_non_sha_candidate_fails_before_git_identity_claim(self):
        with tempfile.TemporaryDirectory() as td:
            root, protocol = self.make_protocol_repo(td)
            for bad in ("HEAD", protocol[:12], "g" * 40, ""):
                with self.subTest(bad=bad), self.assertRaises(CanonicalSyncError):
                    verify_candidate_runtime_sync(root, bad, protocol_sha=protocol)

    def test_malformed_ledger_fails_closed_without_copying_content(self):
        with tempfile.TemporaryDirectory() as td:
            root, protocol = self.make_protocol_repo(td)
            self.write(root, "integration/release_to_live_v1.json", "{not-json")
            candidate = self.commit(root, "bad-ledger")
            with self.assertRaisesRegex(CanonicalSyncError, "ledger invalid"):
                verify_candidate_runtime_sync(root, candidate, protocol_sha=protocol)

    def test_server_manifest_adaptation_is_allowed_because_not_in_byte_exact_protocol_set(self):
        with tempfile.TemporaryDirectory() as td:
            root, protocol = self.make_protocol_repo(td)
            self.write_current_ledger(root, protocol)
            self.write(root, "ops/server_manifest.py", "def collect_server_manifest():\n    return 'canonical-adaptation'\n")
            candidate = self.commit(root, "allowed-adaptation")
            result = verify_candidate_runtime_sync(root, candidate, protocol_sha=protocol)
            self.assertEqual("READY_FOR_CANONICAL_REVALIDATION", result["status"])

    def test_summary_cannot_be_mutated_into_promotion_authorization(self):
        with tempfile.TemporaryDirectory() as td:
            root, protocol = self.make_protocol_repo(td)
            self.write_current_ledger(root, protocol)
            candidate = self.commit(root, "canonical")
            result = verify_candidate_runtime_sync(root, candidate, protocol_sha=protocol)
            result["promotion_authorized"] = True
            with self.assertRaises(CanonicalSyncError):
                validate_sync_summary(result)


if __name__ == "__main__":
    unittest.main()
