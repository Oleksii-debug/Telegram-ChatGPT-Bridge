from __future__ import annotations

import json
import unittest
from pathlib import Path

from tools.verify_integration_provenance import (
    MANIFEST,
    RELEASE_OVERRIDE,
    ROOT,
    TERMINAL_DEV_B_EXACT,
    TERMINAL_DEV_B_FIRST_PARENT,
    TERMINAL_DEV_B_MERGE,
    TERMINAL_DEV_B_RETAINED,
    TERMINAL_DEV_B_SHA,
    ProvenanceError,
    _blob,
    _path_exists,
    _reject_unexpected_paths,
    _verify_overlap_matrix,
    verify_repository,
)


REPOSITORY_GIT_AVAILABLE = (ROOT / ".git").exists()
requires_repository_git = unittest.skipUnless(
    REPOSITORY_GIT_AVAILABLE,
    "repository-level provenance requires Git metadata; outer canonical CI verifies it before PREPARE",
)


class DevAProvenanceTests(unittest.TestCase):
    @requires_repository_git
    def test_exact_candidate_provenance_is_machine_verifiable(self):
        result = verify_repository()
        self.assertEqual(result["schema_version"], 2)
        self.assertEqual(result["base"], "26a2df12c350f670a703b236edc3648f339b64a9")
        self.assertEqual(result["verified_predecessor_count"], 8)
        self.assertEqual(result["semantic_merge_count"], 8)
        self.assertEqual(result["dev4_override_count"], 1)
        self.assertEqual(result["dev_b_imported_path_count"], 16)
        self.assertEqual(result["dev_b_adapted_path_count"], 4)
        self.assertEqual(result["dev_b_superseded_path_count"], 2)
        self.assertEqual(result["dev_b_round2_sync_path_count"], 9)
        self.assertEqual(result["dev_b_round2_adapted_path_count"], 3)
        self.assertEqual(result["dev_b_terminal_exact_path_count"], 24)
        self.assertEqual(result["dev_b_terminal_retained_path_count"], 6)
        self.assertEqual(result["dev_c_exact_path_count"], 2)
        self.assertEqual(result["dev_c_adapted_path_count"], 2)
        self.assertEqual(result["release_to_live_path_count"], 46)
        self.assertEqual(result["pr2_pr3_overlap_count"], 7)
        self.assertEqual(result["pr2_pr5_overlap_count"], 3)
        self.assertEqual(result["rejected_dev5_overlap_count"], 7)
        self.assertFalse(result["private_values_recorded"])
        self.assertGreaterEqual(result["changed_path_count"], 100)

    @requires_repository_git
    def test_cross_pr_overlap_matrix_is_recomputed_not_trusted_as_prose(self):
        payload = json.loads(MANIFEST.read_text(encoding="utf-8"))
        observed = _verify_overlap_matrix(payload)
        self.assertEqual(observed["PR2_PR3"], 7)
        self.assertEqual(observed["PR2_PR5"], 3)
        self.assertEqual(sum(observed.values()), 10)

    @requires_repository_git
    def test_rejected_dev5_overlaps_are_identical_to_dev1_authority(self):
        payload = json.loads(MANIFEST.read_text(encoding="utf-8"))
        base = payload["base"]["sha"]
        rejected = payload["predecessors"]["DEV5"]["rejected_overlaps_preserve_base"]
        self.assertEqual(len(rejected), 7)
        for path in rejected:
            with self.subTest(path=path):
                self.assertEqual(_blob("HEAD", path), _blob(base, path))

    def test_ported_dev5_paths_are_disjoint_from_rejected_production_overlaps(self):
        payload = json.loads(MANIFEST.read_text(encoding="utf-8"))
        dev5 = payload["predecessors"]["DEV5"]
        self.assertTrue(set(dev5["ported_paths"]).isdisjoint(dev5["rejected_overlaps_preserve_base"]))

    @requires_repository_git
    def test_dev4_write_safety_override_is_narrow_and_explicit(self):
        payload = json.loads(MANIFEST.read_text(encoding="utf-8"))
        self.assertEqual(set(payload["predecessors"]["DEV4"]["dev_a_overrides"]), {"ops/write_safety.py"})
        self.assertNotEqual(
            _blob("HEAD", "ops/write_safety.py"),
            _blob(payload["predecessors"]["DEV4"]["sha"], "ops/write_safety.py"),
        )

    @requires_repository_git
    def test_dev_b_nonadapted_historical_imports_are_owned_by_exact_layers(self):
        release = json.loads(RELEASE_OVERRIDE.read_text(encoding="utf-8"))
        dev_b = release["dev_b"]
        adapted = set(dev_b["adapted_paths"])
        round2 = set(release["dev_b_round2_sync"]["exact_blob_paths"])
        terminal = set(release["dev_b_terminal_sync"]["exact_blob_paths"])
        retained = set(release["dev_b_terminal_sync"]["retained_dev_a_adaptations"])
        for path in dev_b["imported_paths"]:
            if path in adapted or path in round2 or path in terminal or path in retained:
                continue
            with self.subTest(path=path):
                self.assertEqual(_blob("HEAD", path), _blob(dev_b["sha"], path))

    @requires_repository_git
    def test_dev_b_round2_sync_remains_historical_and_suppression_absent(self):
        release = json.loads(RELEASE_OVERRIDE.read_text(encoding="utf-8"))
        sync = release["dev_b_round2_sync"]
        terminal = set(release["dev_b_terminal_sync"]["exact_blob_paths"])
        self.assertEqual(sync["sha"], "6f943ee15f053acc5b4f15167c16d431023a35d1")
        self.assertEqual(sync["merge_commit"], "919d7d409564d7c21e46009e1d76cfa5d1fd602d")
        self.assertFalse(sync["strict_history_suppression_imported"])
        self.assertEqual(len(sync["exact_blob_paths"]), 9)
        for path in set(sync["exact_blob_paths"]) - terminal:
            with self.subTest(path=path):
                self.assertEqual(_blob("HEAD", path), _blob(sync["sha"], path))
        self.assertEqual(
            set(sync["retained_dev_a_adaptations"]),
            {"ops/server_manifest.py", "tests/test_devb_round2_release.py", "tests/test_server_manifest.py"},
        )
        self.assertFalse(_path_exists("HEAD", "tools/strict_history_secret_scan.py"))
        self.assertFalse(_path_exists("HEAD", "tests/test_strict_history_secret_scan.py"))

    @requires_repository_git
    def test_dev_b_terminal_sync_is_exact_with_explicit_canonical_retained_set(self):
        release = json.loads(RELEASE_OVERRIDE.read_text(encoding="utf-8"))
        sync = release["dev_b_terminal_sync"]
        self.assertEqual(sync["sha"], TERMINAL_DEV_B_SHA)
        self.assertEqual(sync["merge_commit"], TERMINAL_DEV_B_MERGE)
        self.assertEqual(sync["first_parent"], TERMINAL_DEV_B_FIRST_PARENT)
        self.assertEqual(set(sync["exact_blob_paths"]), TERMINAL_DEV_B_EXACT)
        self.assertEqual(set(sync["retained_dev_a_adaptations"]), TERMINAL_DEV_B_RETAINED)
        self.assertFalse(sync["strict_history_suppression_imported"])
        self.assertFalse(sync["production_mutated"])
        for path in sync["exact_blob_paths"]:
            with self.subTest(path=path):
                self.assertEqual(_blob("HEAD", path), _blob(sync["sha"], path))
        for path in sync["retained_dev_a_adaptations"]:
            with self.subTest(path=path):
                self.assertNotEqual(_blob("HEAD", path), _blob(sync["sha"], path))

    @requires_repository_git
    def test_dev_c_qa_sync_is_exact_except_declared_adaptations(self):
        release = json.loads(RELEASE_OVERRIDE.read_text(encoding="utf-8"))
        sync = release["dev_c_qa_sync"]
        self.assertEqual(sync["sha"], "5758bfdcd9ecee4011fc3caaa3c68eb46ee2af19")
        self.assertEqual(sync["merge_commit"], "df318aa089f754b7a14f624b7c27cca59758cbe8")
        self.assertEqual(sync["first_parent"], "94c6ab7e3afabd769a63b44b222bfc0bbf067f67")
        self.assertFalse(sync["production_logic_modified"])
        self.assertEqual(
            set(sync["exact_blob_paths"]),
            {"docs/DEV_C_RELEASE_TO_LIVE_QA.md", "ops/devc_release_qa.py"},
        )
        self.assertEqual(
            set(sync["adapted_paths"]),
            {"tests/test_devc_release_e2e.py", "tests/test_devc_release_qa.py"},
        )
        for path in sync["exact_blob_paths"]:
            with self.subTest(path=path):
                self.assertEqual(_blob("HEAD", path), _blob(sync["sha"], path))
        for path in sync["adapted_paths"]:
            with self.subTest(path=path):
                self.assertNotEqual(_blob("HEAD", path), _blob(sync["sha"], path))

    def test_dev_b_supersession_is_narrow_and_explicit(self):
        release = json.loads(RELEASE_OVERRIDE.read_text(encoding="utf-8"))
        self.assertEqual(
            set(release["dev_b"]["supersedes_predecessor_paths"]),
            {"ops/hostiq_lifecycle.py", "tests/test_dev2_lifecycle.py"},
        )
        self.assertEqual(
            set(release["dev_b_terminal_sync"]["retained_dev_a_adaptations"]),
            TERMINAL_DEV_B_RETAINED,
        )

    def test_unexpected_candidate_path_is_rejected(self):
        with self.assertRaises(ProvenanceError):
            _reject_unexpected_paths({"bridge/app.py", "private/session.bin"}, {"bridge/app.py"})

    def test_manifests_contain_no_secret_value_fields_or_private_content(self):
        text = MANIFEST.read_text(encoding="utf-8") + RELEASE_OVERRIDE.read_text(encoding="utf-8")
        lowered = text.casefold()
        for forbidden in (
            "tg_api_hash",
            "tg_session_string",
            "bridge_token",
            "login_code",
            "2fa_password",
            "hostiq_cpanel_password",
            "ssh_private_key",
            "private telegram message",
        ):
            self.assertNotIn(forbidden, lowered)

    @requires_repository_git
    def test_invalid_git_path_fails_closed(self):
        with self.assertRaises(ProvenanceError):
            _blob("HEAD", "definitely/not/a/candidate/path")

    def test_provenance_files_live_inside_repository(self):
        self.assertEqual(ROOT, Path(__file__).resolve().parents[1])
        self.assertTrue(MANIFEST.is_file())
        self.assertTrue(RELEASE_OVERRIDE.is_file())


if __name__ == "__main__":
    unittest.main()
