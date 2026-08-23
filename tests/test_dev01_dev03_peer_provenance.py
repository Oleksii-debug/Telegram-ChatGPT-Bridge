from __future__ import annotations

import json
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "integration" / "provenance_v1.json"
SOURCE_SHA = "5c5bd6cea20ac8d977374f1068cb8aec72df1047"
MERGE_COMMIT = "c0a2b443e811eee8460af6c688f30ad3bbdf5f4d"
FIRST_PARENT = "2ed817a5e6f9e765757aae1fd91dbe7b30a9190b"
EXACT_PATHS = {
    "bridge/backend.py",
    "bridge/models.py",
    "bridge/validation.py",
    "docs/DEV03_SWARM_READ_HARDENING.md",
    "tests/test_dev03_history_offset.py",
    "tests/test_dev03_swarm_read.py",
}
EXCLUDED_WORKFLOW = ".github/workflows/dev03-read.yml"

REPOSITORY_GIT_AVAILABLE = (ROOT / ".git").exists()
requires_repository_git = unittest.skipUnless(
    REPOSITORY_GIT_AVAILABLE,
    "repository-level peer provenance requires Git metadata; outer canonical CI verifies it before PREPARE",
)


def _git(*args: str) -> str:
    completed = subprocess.run(
        ["git", *args],
        cwd=ROOT,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        encoding="utf-8",
    )
    return completed.stdout.strip()


def _blob(ref: str, path: str) -> str:
    value = _git("rev-parse", f"{ref}:{path}")
    if len(value) != 40 or any(ch not in "0123456789abcdef" for ch in value):
        raise AssertionError(f"invalid blob identity: {path}")
    return value


class Dev01Dev03PeerProvenanceTests(unittest.TestCase):
    def test_manifest_records_exact_non_authorizing_dev03_sync(self):
        payload = json.loads(MANIFEST.read_text(encoding="utf-8"))
        sync = payload["swarm_integrations"]["DEV03_READ_HARDENING"]
        self.assertEqual(36, sync["pr"])
        self.assertEqual(SOURCE_SHA, sync["source_sha"])
        self.assertEqual(MERGE_COMMIT, sync["merge_commit"])
        self.assertEqual(FIRST_PARENT, sync["first_parent"])
        self.assertEqual(EXACT_PATHS, set(sync["exact_blob_paths"]))
        self.assertEqual([EXCLUDED_WORKFLOW], sync["excluded_specialist_paths"])
        self.assertEqual(["A01-08", "A01-09"], sync["auditor_findings"])
        self.assertEqual(32642004555, sync["source_ci_run_id"])
        self.assertEqual(97200427195, sync["source_ci_job_id"])
        self.assertFalse(sync["production_mutated"])
        self.assertFalse(sync["deployment_authorized"])

    @requires_repository_git
    def test_semantic_merge_parent_order_and_exact_blobs(self):
        self.assertEqual(
            [FIRST_PARENT, SOURCE_SHA],
            _git("show", "-s", "--format=%P", MERGE_COMMIT).split(),
        )
        subprocess.run(
            ["git", "merge-base", "--is-ancestor", MERGE_COMMIT, "HEAD"],
            cwd=ROOT,
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        for path in sorted(EXACT_PATHS):
            with self.subTest(path=path):
                self.assertEqual(_blob("HEAD", path), _blob(SOURCE_SHA, path))

    @requires_repository_git
    def test_specialist_workflow_is_not_imported(self):
        completed = subprocess.run(
            ["git", "cat-file", "-e", f"HEAD:{EXCLUDED_WORKFLOW}"],
            cwd=ROOT,
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        self.assertNotEqual(0, completed.returncode)

    def test_a01_08_and_a01_09_oracles_are_present(self):
        backend = (ROOT / "bridge" / "backend.py").read_text(encoding="utf-8")
        history_tests = (ROOT / "tests" / "test_dev03_history_offset.py").read_text(encoding="utf-8")
        read_tests = (ROOT / "tests" / "test_dev03_swarm_read.py").read_text(encoding="utf-8")
        self.assertIn("offset_id", backend)
        self.assertIn("offset_id", history_tests)
        self.assertIn("display_name", backend)
        self.assertIn("get_sender", read_tests)


if __name__ == "__main__":
    unittest.main()
