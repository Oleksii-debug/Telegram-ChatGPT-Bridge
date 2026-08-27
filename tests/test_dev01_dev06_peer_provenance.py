# -*- coding: utf-8 -*-
"""DEV01 proof that the selected DEV06 source-contract slice was semantically integrated."""
from __future__ import annotations

import json
import unittest

from tools.verify_integration_provenance import RELEASE_OVERRIDE, ROOT, _assert_ancestor, _blob, _parents, _path_exists

SOURCE_SHA = "bebf365af414e10f0f0a58f44a37c86134e44c5d"
MERGE_SHA = "ed4820d2297a65870abb6c2cc2f3a5e63a569302"
FIRST_PARENT = "00684e834a523f55ea3b61c1a12cb9dc54cfd947"
EXACT_PATHS = {
    "docs/DEV06_API_CONTRACTS.md",
    "ops/dev06_api_contracts.py",
    "ops/dev06_runtime_conformance.py",
    "tests/test_dev06_api_contracts.py",
    "tests/test_dev06_runtime_conformance.py",
    "tools/build_dev06_action_openapi.py",
}
EXCLUDED_PATHS = {".github/workflows/dev06-api-contracts.yml"}

REPOSITORY_GIT_AVAILABLE = (ROOT / ".git").exists()
requires_repository_git = unittest.skipUnless(
    REPOSITORY_GIT_AVAILABLE,
    "DEV06 peer provenance requires Git metadata; outer canonical CI verifies it before PREPARE",
)


class Dev01Dev06PeerProvenanceTests(unittest.TestCase):
    def section(self) -> dict:
        payload = json.loads(RELEASE_OVERRIDE.read_text(encoding="utf-8"))
        section = payload.get("dev06_contract_sync")
        self.assertIsInstance(section, dict)
        return section

    def test_ledger_section_is_exact_non_authorizing_and_workflow_excluded(self):
        section = self.section()
        self.assertEqual(45, section.get("pr"))
        self.assertEqual(SOURCE_SHA, section.get("sha"))
        self.assertEqual(MERGE_SHA, section.get("merge_commit"))
        self.assertEqual(FIRST_PARENT, section.get("first_parent"))
        self.assertEqual(EXACT_PATHS, set(section.get("exact_blob_paths", ())))
        self.assertEqual(EXCLUDED_PATHS, set(section.get("excluded_specialist_paths", ())))
        self.assertFalse(section.get("production_runtime_modified"))
        self.assertFalse(section.get("production_mutated"))
        self.assertFalse(section.get("deployment_authorized"))

    @requires_repository_git
    def test_semantic_merge_parent_order_and_selected_source_blobs_are_exact(self):
        self.assertEqual((FIRST_PARENT, SOURCE_SHA), _parents(MERGE_SHA))
        _assert_ancestor(MERGE_SHA, "HEAD")
        for path in EXACT_PATHS:
            with self.subTest(path=path):
                self.assertEqual(_blob("HEAD", path), _blob(SOURCE_SHA, path))
        for path in EXCLUDED_PATHS:
            with self.subTest(path=path):
                self.assertTrue(_path_exists(SOURCE_SHA, path))
                self.assertFalse(_path_exists("HEAD", path))


if __name__ == "__main__":
    unittest.main()
