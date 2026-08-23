from __future__ import annotations

import json
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "integration" / "provenance_v1.json"
SOURCE_SHA = "2916828628a091a9edd8c4992d9db8834ac1ff68"
MERGE_COMMIT = "5e35599cca1162bad9501044dfb6a79fa358e182"
FIRST_PARENT = "4ebfceb153e94840fa046af88cee1131e0705657"
AUTHORITATIVE_PARENT = "2480d74b623283eeebfdb74c711cbc229d89cd14"
EXACT_PATHS = {
    "docs/DEV08_DEPLOYMENT_RECOVERY_R3.md",
    "ops/dev08_deploy_recovery.py",
}
AUTHORITATIVE_RUNTIME_PATHS = {
    "ops/deploy_release.py",
    "tests/test_dev01_dev08_authoritative_recovery.py",
}
EXCLUDED_PATHS = {
    "tests/test_dev08_deploy_recovery.py",
    "tools/verify_dev08_r3_provenance.py",
}

REPOSITORY_GIT_AVAILABLE = (ROOT / ".git").exists()
requires_repository_git = unittest.skipUnless(
    REPOSITORY_GIT_AVAILABLE,
    "repository-level peer provenance requires Git metadata; outer canonical CI verifies it before PREPARE",
)


def _git(*args: str) -> str:
    completed = subprocess.run(
        ["git", *args], cwd=ROOT, check=True,
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        text=True, encoding="utf-8",
    )
    return completed.stdout.strip()


def _blob(ref: str, path: str) -> str:
    value = _git("rev-parse", f"{ref}:{path}")
    if len(value) != 40 or any(ch not in "0123456789abcdef" for ch in value):
        raise AssertionError(f"invalid blob identity: {path}")
    return value


class Dev01Dev08PeerProvenanceTests(unittest.TestCase):
    def test_manifest_records_exact_oracle_and_authoritative_runtime_sync(self):
        payload = json.loads(MANIFEST.read_text(encoding="utf-8"))
        sync = payload["swarm_integrations"]["DEV08_DEPLOYMENT_RECOVERY_ORACLE"]
        self.assertEqual(48, sync["pr"])
        self.assertEqual(SOURCE_SHA, sync["source_sha"])
        self.assertEqual(MERGE_COMMIT, sync["merge_commit"])
        self.assertEqual(FIRST_PARENT, sync["first_parent"])
        self.assertEqual(EXACT_PATHS, set(sync["exact_blob_paths"]))
        self.assertEqual(EXCLUDED_PATHS, set(sync["excluded_specialist_paths"]))
        self.assertEqual(32646112339, sync["source_validation_run_id"])
        self.assertEqual(97210515630, sync["source_validation_job_id"])
        self.assertEqual("A01-11", sync["auditor_finding"])
        self.assertEqual(AUTHORITATIVE_PARENT, sync["authoritative_runtime_parent_sha"])
        self.assertEqual(AUTHORITATIVE_RUNTIME_PATHS, set(sync["authoritative_runtime_paths"]))
        self.assertTrue(sync["production_runtime_modified"])
        self.assertFalse(sync["production_mutated"])
        self.assertFalse(sync["deployment_authorized"])

    @requires_repository_git
    def test_semantic_merge_parent_order_and_exact_oracle_blobs(self):
        self.assertEqual(
            [FIRST_PARENT, SOURCE_SHA],
            _git("show", "-s", "--format=%P", MERGE_COMMIT).split(),
        )
        subprocess.run(
            ["git", "merge-base", "--is-ancestor", MERGE_COMMIT, "HEAD"],
            cwd=ROOT, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        for path in sorted(EXACT_PATHS):
            with self.subTest(path=path):
                self.assertEqual(_blob("HEAD", path), _blob(SOURCE_SHA, path))

    @requires_repository_git
    def test_specialist_test_and_provenance_tool_are_not_blindly_imported(self):
        for path in sorted(EXCLUDED_PATHS):
            with self.subTest(path=path):
                source = subprocess.run(
                    ["git", "cat-file", "-e", f"{SOURCE_SHA}:{path}"],
                    cwd=ROOT, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                )
                head = subprocess.run(
                    ["git", "cat-file", "-e", f"HEAD:{path}"],
                    cwd=ROOT, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                )
                self.assertEqual(0, source.returncode)
                self.assertNotEqual(0, head.returncode)

    def test_classifier_keeps_recovery_non_authorizing_and_narrow(self):
        from ops.dev08_deploy_recovery import classify_deployment_recovery

        good = classify_deployment_recovery(
            journal_state="BACKED_UP",
            active_role="candidate",
            approval_marker_valid=True,
            runtime_manifest_matches=True,
            candidate_verified=True,
            previous_release_available=True,
        )
        self.assertEqual("RECOVER_AS_SWITCHED", good.action)
        self.assertEqual("SWITCHED", good.journal_transition)
        self.assertEqual(
            "AMBIGUOUS",
            classify_deployment_recovery(
                journal_state="BACKED_UP",
                active_role="candidate",
                approval_marker_valid=False,
                runtime_manifest_matches=True,
                candidate_verified=True,
                previous_release_available=True,
            ).action,
        )


if __name__ == "__main__":
    unittest.main()
