# -*- coding: utf-8 -*-
"""DEV01 proof that the DEV02 canonical revalidation slice was semantically integrated."""
from __future__ import annotations

import json
import unittest

from tools.verify_integration_provenance import RELEASE_OVERRIDE, ROOT, _assert_ancestor, _blob, _parents

SOURCE_SHA = "d821de179c2d06e2a9bb83565f7a637a2dbec290"
MERGE_SHA = "a4fea8431b999e1bab7d95168ce0fc4d2a20305d"
FIRST_PARENT = "999709f0ab2daee08fdb5c793419d1c45967238d"
EXACT_PATHS = {
    "docs/DEV02_CANONICAL_RUNTIME_SYNC.md",
    "ops/dev02_canonical_sync.py",
    "tests/test_dev02_canonical_sync.py",
    "tools/verify_dev02_canonical_sync.py",
}
ADAPTED_PATHS = {"tests/test_devb_compile.py"}

REPOSITORY_GIT_AVAILABLE = (ROOT / ".git").exists()
requires_repository_git = unittest.skipUnless(
    REPOSITORY_GIT_AVAILABLE,
    "DEV02 peer provenance requires Git metadata; outer canonical CI verifies it before PREPARE",
)


class Dev01Dev02PeerProvenanceTests(unittest.TestCase):
    def section(self) -> dict:
        payload = json.loads(RELEASE_OVERRIDE.read_text(encoding="utf-8"))
        section = payload.get("dev02_canonical_revalidation_sync")
        self.assertIsInstance(section, dict)
        return section

    def test_ledger_section_is_exact_and_non_authorizing(self):
        section = self.section()
        self.assertEqual(11, section.get("pr"))
        self.assertEqual(SOURCE_SHA, section.get("sha"))
        self.assertEqual(MERGE_SHA, section.get("merge_commit"))
        self.assertEqual(FIRST_PARENT, section.get("first_parent"))
        self.assertEqual(EXACT_PATHS, set(section.get("exact_blob_paths", ())))
        self.assertEqual(ADAPTED_PATHS, set(section.get("adapted_paths", ())))
        self.assertFalse(section.get("production_mutated"))
        self.assertFalse(section.get("promotion_authorized"))

    @requires_repository_git
    def test_semantic_merge_parent_order_and_source_blobs_are_exact(self):
        self.assertEqual((FIRST_PARENT, SOURCE_SHA), _parents(MERGE_SHA))
        _assert_ancestor(MERGE_SHA, "HEAD")
        for path in EXACT_PATHS:
            with self.subTest(path=path):
                self.assertEqual(_blob("HEAD", path), _blob(SOURCE_SHA, path))
        for path in ADAPTED_PATHS:
            with self.subTest(path=path):
                self.assertNotEqual(_blob("HEAD", path), _blob(SOURCE_SHA, path))


if __name__ == "__main__":
    unittest.main()
