from __future__ import annotations

import json
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "integration" / "provenance_v1.json"
SOURCE_SHA = "c10ca6aa40755a88c98e2c200001bc05ca0bcf98"
MERGE_COMMIT = "301817d7e2c1a2fa55435d11ce5c6edc0cef5d71"
FIRST_PARENT = "2d98d036a3dc13545a9661005d6e290f12bcfe22"
EXACT_PATHS = {
    "bridge/app.py",
    "bridge/archive.py",
    "bridge/downloads.py",
    "bridge/file_access.py",
    "bridge/filenames.py",
    "bridge/storage.py",
    "docs/DEV04_MEDIA_STORAGE.md",
    "tests/test_dev04_media_storage.py",
    "tests/test_dev04_migration_concurrency.py",
    "tests/test_dev04_private_serving.py",
}
# Historical canonical adaptations already recorded by the DEV04 ledger.
CANONICAL_ADAPTATIONS = {
    "bridge/app.py": "751a9cbf281f3421dcfae3787dbbae1b910bb80b",
    "bridge/file_access.py": "6963e8c046efbf42e18ebfd31e9fbd54343bfb8d",
    "bridge/storage.py": "6963e8c046efbf42e18ebfd31e9fbd54343bfb8d",
    "tests/test_dev04_migration_concurrency.py": "6963e8c046efbf42e18ebfd31e9fbd54343bfb8d",
    "tests/test_dev04_private_serving.py": "6963e8c046efbf42e18ebfd31e9fbd54343bfb8d",
}
# FINAL10 B5 accepted the historical DEV04 integration and requested only the
# two launch-relevant PR #50 media residuals. These three exact blobs were
# assembled together at this one canonical commit. Keep them separate from the
# historical ledger so the old non-authorizing record remains immutable.
FINAL10_MEDIA_ADAPTATIONS = {
    "bridge/archive.py": "6878a21ebe46a3cdb1e84ef600587ec5cc99c90e",
    "bridge/downloads.py": "6878a21ebe46a3cdb1e84ef600587ec5cc99c90e",
    "tests/test_dev04_media_storage.py": "6878a21ebe46a3cdb1e84ef600587ec5cc99c90e",
}
EXCLUDED_WORKFLOW = ".github/workflows/dev04-media-storage-qa.yml"

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


class Dev01Dev04PeerProvenanceTests(unittest.TestCase):
    def test_manifest_records_exact_non_authorizing_dev04_sync(self):
        payload = json.loads(MANIFEST.read_text(encoding="utf-8"))
        sync = payload["swarm_integrations"]["DEV04_MEDIA_STORAGE"]
        self.assertEqual(sync["pr"], 37)
        self.assertEqual(sync["source_sha"], SOURCE_SHA)
        self.assertEqual(sync["merge_commit"], MERGE_COMMIT)
        self.assertEqual(sync["first_parent"], FIRST_PARENT)
        self.assertEqual(set(sync["exact_blob_paths"]), EXACT_PATHS)
        self.assertEqual(sync["canonical_adaptations"], CANONICAL_ADAPTATIONS)
        self.assertEqual(sync["excluded_specialist_paths"], [EXCLUDED_WORKFLOW])
        self.assertEqual(sync["auditor_finding"], "A01-06")
        self.assertEqual(sync["source_ci_run_id"], 32641698071)
        self.assertEqual(sync["source_ci_job_id"], 97199658228)
        self.assertFalse(sync["production_mutated"])
        self.assertFalse(sync["deployment_authorized"])

    @requires_repository_git
    def test_semantic_merge_parent_order_is_exact(self):
        self.assertEqual(_git("show", "-s", "--format=%P", MERGE_COMMIT).split(), [FIRST_PARENT, SOURCE_SHA])
        subprocess.run(
            ["git", "merge-base", "--is-ancestor", MERGE_COMMIT, "HEAD"],
            cwd=ROOT,
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    @requires_repository_git
    def test_all_accepted_paths_are_byte_exact_or_exactly_accounted_canonical_adaptations(self):
        adaptations = {**CANONICAL_ADAPTATIONS, **FINAL10_MEDIA_ADAPTATIONS}
        self.assertTrue(set(adaptations).issubset(EXACT_PATHS))
        for path, commit in sorted(adaptations.items()):
            with self.subTest(path=path, adaptation_commit=commit):
                subprocess.run(
                    ["git", "merge-base", "--is-ancestor", commit, "HEAD"],
                    cwd=ROOT,
                    check=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                self.assertEqual(_blob("HEAD", path), _blob(commit, path))
                self.assertNotEqual(_blob("HEAD", path), _blob(SOURCE_SHA, path))

        for path in sorted(EXACT_PATHS - set(adaptations)):
            with self.subTest(path=path):
                self.assertEqual(_blob("HEAD", path), _blob(SOURCE_SHA, path))

    @requires_repository_git
    def test_final10_media_adaptations_are_one_exact_reviewed_slice(self):
        self.assertEqual(set(FINAL10_MEDIA_ADAPTATIONS.values()), {"6878a21ebe46a3cdb1e84ef600587ec5cc99c90e"})
        for path in sorted(FINAL10_MEDIA_ADAPTATIONS):
            with self.subTest(path=path):
                self.assertEqual(_blob("HEAD", path), _blob("29a9d3bf30ac75999b86b51d694e6885b54b519a", path))

    @requires_repository_git
    def test_specialist_workflow_is_not_imported(self):
        completed = subprocess.run(
            ["git", "cat-file", "-e", f"HEAD:{EXCLUDED_WORKFLOW}"],
            cwd=ROOT,
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        self.assertNotEqual(completed.returncode, 0)

    def test_a01_06_crash_recovery_oracles_are_in_exact_source_set(self):
        source = (ROOT / "tests" / "test_dev04_media_storage.py").read_text(encoding="utf-8")
        self.assertIn("test_registered_result_is_recovered_after_checkpoint_save_gap", source)
        self.assertIn("test_moved_unregistered_result_is_adopted_after_crash_gap", source)
        self.assertIn("self.assertEqual(self.backend.calls, 0)", source)


if __name__ == "__main__":
    unittest.main()
