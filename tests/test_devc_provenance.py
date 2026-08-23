# -*- coding: utf-8 -*-
from __future__ import annotations

import json
import unittest
from pathlib import Path

from tools.verify_dev_c_release_qa import (
    ALLOWED_PATHS,
    DevCProvenanceError,
    MANIFEST,
    ROOT,
    _load_manifest,
    _safe_paths,
    verify_repository,
)


class DevCReleaseQaProvenanceTests(unittest.TestCase):
    def test_manifest_is_exact_non_authorizing_overlay(self):
        payload = _load_manifest()
        self.assertEqual("DEV_C", payload["role"])
        self.assertEqual("RELEASE_TO_LIVE_ROUND_2", payload["round"])
        self.assertEqual(set(payload["paths"]), set(ALLOWED_PATHS))
        self.assertFalse(payload["production_logic_changed"])
        self.assertFalse(payload["private_values_recorded"])
        self.assertFalse(payload["deployment_authorized"])

    def test_path_allowlist_cannot_expand_by_manifest_only(self):
        payload = json.loads(MANIFEST.read_text(encoding="utf-8"))
        expanded = sorted(set(payload["paths"]) | {"bridge/app.py"})
        with self.assertRaises(DevCProvenanceError):
            _safe_paths(expanded)

    def test_no_wildcard_or_prefix_authority_exists(self):
        for path in ALLOWED_PATHS:
            self.assertNotIn("*", path)
            self.assertNotIn("?", path)
            self.assertNotIn("..", Path(path).parts)
        self.assertNotIn("bridge/app.py", ALLOWED_PATHS)
        self.assertNotIn("ops/deploy_release.py", ALLOWED_PATHS)
        self.assertNotIn("passenger_wsgi.py", ALLOWED_PATHS)

    @unittest.skipUnless((ROOT / ".git").exists(), "CHECKOUT_ONLY_DEV_C_PROVENANCE")
    def test_live_checkout_delta_matches_exact_parent(self):
        result = verify_repository()
        self.assertEqual("DEV_C", result["role"])
        self.assertEqual(len(ALLOWED_PATHS), result["dev_c_path_count"])
        self.assertFalse(result["production_logic_changed"])
        self.assertFalse(result["private_values_recorded"])
        self.assertFalse(result["deployment_authorized"])


if __name__ == "__main__":
    unittest.main()
