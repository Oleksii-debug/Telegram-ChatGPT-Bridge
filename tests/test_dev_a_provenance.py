from __future__ import annotations

import json
import unittest
from pathlib import Path

from tools.verify_integration_provenance import (
    CANONICAL_MANIFEST,
    MANIFEST,
    RELEASE_OVERRIDE,
    ROOT,
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
        self.assertEqual(result["canonical_assembly_sha"], "7e25e43cf7e8423094271fce6807e247e14b13a0")
        self.assertEqual(result["canonical_launch_source_count"], 3)
        self.assertGreaterEqual(result["canonical_launch_path_count"], 20)
        self.assertEqual(result["canonical_w09_override_count"], 4)
        self.assertFalse(result["private_values_recorded"])

    @requires_repository_git
    def test_canonical_exact_sources_match_their_reviewed_blobs(self):
        payload = json.loads(CANONICAL_MANIFEST.read_text(encoding="utf-8"))
        for source in payload["sources"].values():
            for path in source["exact_paths"]:
                with self.subTest(path=path):
                    self.assertEqual(_blob("HEAD", path), _blob(source["sha"], path))

    @requires_repository_git
    def test_runtime_composition_is_frozen_at_assembly_commit(self):
        payload = json.loads(CANONICAL_MANIFEST.read_text(encoding="utf-8"))
        path = payload["runtime_composition"]["path"]
        self.assertEqual(_blob("HEAD", path), _blob(payload["assembly_sha"], path))
        self.assertEqual(
            payload["runtime_composition"]["installer_paths"],
            ["bridge/dialog_pagination.py", "bridge/typed_dialog_identity.py"],
        )

    @requires_repository_git
    def test_only_explicit_w09_overrides_supersede_old_dev5_rejections(self):
        historical = json.loads(MANIFEST.read_text(encoding="utf-8"))
        canonical = json.loads(CANONICAL_MANIFEST.read_text(encoding="utf-8"))
        base = historical["base"]["sha"]
        overrides = set(canonical["w09_base_authority_overrides"])
        rejected = set(historical["predecessors"]["DEV5"]["rejected_overlaps_preserve_base"])
        self.assertTrue(overrides <= rejected)
        for path in rejected - overrides:
            with self.subTest(path=path):
                self.assertEqual(_blob("HEAD", path), _blob(base, path))
        for path in overrides:
            with self.subTest(path=path):
                self.assertNotEqual(_blob("HEAD", path), _blob(base, path))

    @requires_repository_git
    def test_cross_pr_overlap_matrix_is_still_recomputed(self):
        payload = json.loads(MANIFEST.read_text(encoding="utf-8"))
        observed = _verify_overlap_matrix(payload)
        self.assertEqual(observed["PR2_PR3"], 7)
        self.assertEqual(observed["PR2_PR5"], 3)

    def test_unexpected_candidate_path_is_rejected(self):
        with self.assertRaises(ProvenanceError):
            _reject_unexpected_paths({"bridge/app.py", "private/session.bin"}, {"bridge/app.py"})

    @requires_repository_git
    def test_invalid_git_path_fails_closed(self):
        with self.assertRaises(ProvenanceError):
            _blob("HEAD", "definitely/not/a/candidate/path")

    def test_manifests_contain_no_private_values(self):
        text = (
            MANIFEST.read_text(encoding="utf-8")
            + RELEASE_OVERRIDE.read_text(encoding="utf-8")
            + CANONICAL_MANIFEST.read_text(encoding="utf-8")
        ).casefold()
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
            self.assertNotIn(forbidden, text)

    def test_provenance_files_live_inside_repository(self):
        self.assertEqual(ROOT, Path(__file__).resolve().parents[1])
        self.assertTrue(MANIFEST.is_file())
        self.assertTrue(RELEASE_OVERRIDE.is_file())
        self.assertTrue(CANONICAL_MANIFEST.is_file())
        self.assertFalse(_path_exists("HEAD", "tools/strict_history_secret_scan.py"))


if __name__ == "__main__":
    unittest.main()
