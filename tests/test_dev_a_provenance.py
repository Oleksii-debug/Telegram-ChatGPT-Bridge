from __future__ import annotations

import json
import unittest
from pathlib import Path

from tools.verify_integration_provenance import (
    MANIFEST,
    RELEASE_OVERRIDE,
    ProvenanceError,
    ROOT,
    _blob,
    _reject_unexpected_paths,
    _verify_overlap_matrix,
    verify_repository,
)


class DevAProvenanceTests(unittest.TestCase):
    def test_exact_candidate_provenance_is_machine_verifiable(self):
        result = verify_repository()
        self.assertEqual(result["schema_version"], 2)
        self.assertEqual(result["base"], "26a2df12c350f670a703b236edc3648f339b64a9")
        self.assertEqual(result["verified_predecessor_count"], 5)
        self.assertEqual(result["semantic_merge_count"], 5)
        self.assertEqual(result["dev_b_imported_path_count"], 16)
        self.assertEqual(result["dev_b_adapted_path_count"], 4)
        self.assertEqual(result["dev_b_superseded_path_count"], 2)
        self.assertEqual(result["release_to_live_path_count"], 26)
        self.assertEqual(result["pr2_pr3_overlap_count"], 7)
        self.assertEqual(result["pr2_pr5_overlap_count"], 3)
        self.assertEqual(result["rejected_dev5_overlap_count"], 7)
        self.assertFalse(result["private_values_recorded"])
        self.assertGreaterEqual(result["changed_path_count"], 70)

    def test_cross_pr_overlap_matrix_is_recomputed_not_trusted_as_prose(self):
        payload = json.loads(MANIFEST.read_text(encoding="utf-8"))
        observed = _verify_overlap_matrix(payload)
        self.assertEqual(observed["PR2_PR3"], 7)
        self.assertEqual(observed["PR2_PR5"], 3)
        self.assertEqual(sum(observed.values()), 10)

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

    def test_dev_b_nonadapted_imports_remain_byte_identical(self):
        release = json.loads(RELEASE_OVERRIDE.read_text(encoding="utf-8"))
        dev_b = release["dev_b"]
        adapted = set(dev_b["adapted_paths"])
        for path in dev_b["imported_paths"]:
            if path in adapted:
                continue
            with self.subTest(path=path):
                self.assertEqual(_blob("HEAD", path), _blob(dev_b["sha"], path))

    def test_dev_b_supersession_is_narrow_and_explicit(self):
        release = json.loads(RELEASE_OVERRIDE.read_text(encoding="utf-8"))
        self.assertEqual(
            set(release["dev_b"]["supersedes_predecessor_paths"]),
            {"ops/hostiq_lifecycle.py", "tests/test_dev2_lifecycle.py"},
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

    def test_invalid_git_path_fails_closed(self):
        with self.assertRaises(ProvenanceError):
            _blob("HEAD", "definitely/not/a/candidate/path")

    def test_provenance_files_live_inside_repository(self):
        self.assertEqual(ROOT, Path(__file__).resolve().parents[1])
        self.assertTrue(MANIFEST.is_file())
        self.assertTrue(RELEASE_OVERRIDE.is_file())


if __name__ == "__main__":
    unittest.main()
