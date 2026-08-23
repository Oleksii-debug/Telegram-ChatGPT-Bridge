from __future__ import annotations

import json
import os
import unittest
from pathlib import Path

from ops.dev09_qa_probe import (
    EXPECTED_PARENT_SHA,
    MANIFEST,
    _load_manifest,
    candidate_truth_snapshot,
    canonical_provenance_probe,
    exported_test_suite_probe,
    validate_workflow_parent,
)

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY_GIT_AVAILABLE = (ROOT / ".git").exists()
SKIP_EXPENSIVE = os.environ.get("DEV09_SKIP_EXPENSIVE") == "1"
requires_repository_git = unittest.skipUnless(
    REPOSITORY_GIT_AVAILABLE,
    "DEV09 exact-parent probe requires repository Git metadata and is skipped inside PREPARE payload",
)
requires_expensive_repository_probe = unittest.skipIf(
    (not REPOSITORY_GIT_AVAILABLE) or SKIP_EXPENSIVE,
    "DEV09 nested exact-parent probe skipped in aggregate regression",
)


class Dev09ExactParentTests(unittest.TestCase):
    def test_manifest_is_exact_parent_qa_only_and_non_authorizing(self):
        payload = _load_manifest()
        self.assertEqual(payload["parent_sha"], EXPECTED_PARENT_SHA)
        self.assertFalse(payload["production_logic_modified"])
        self.assertFalse(payload["deployment_authorized"])
        self.assertFalse(payload["live_write_authorized"])
        self.assertFalse(payload["product_pass"])
        self.assertEqual(
            payload["qa_paths"],
            sorted([
                ".github/workflows/dev09-e2e-qa.yml",
                "docs/DEV09_SWARM_QA.md",
                "integration/dev09_qa_v1.json",
                "ops/dev09_qa_probe.py",
                "tests/test_dev09_qa_probe.py",
            ]),
        )

    def test_workflow_parent_gate_fails_when_canonical_moves(self):
        validate_workflow_parent(EXPECTED_PARENT_SHA)
        with self.assertRaisesRegex(ValueError, "DEV09_QA_PARENT_MOVED"):
            validate_workflow_parent("0" * 40)

    @requires_repository_git
    def test_live_pr_base_matches_exact_restack_when_workflow_supplies_it(self):
        observed = os.environ.get("DEV09_EXPECTED_BASE_SHA")
        if observed is not None:
            self.assertEqual(observed, EXPECTED_PARENT_SHA)


class Dev09CurrentCanonicalTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.provenance = None
        cls.suite = None
        if REPOSITORY_GIT_AVAILABLE and not SKIP_EXPENSIVE:
            cls.provenance = canonical_provenance_probe()
            cls.suite = exported_test_suite_probe()

    @requires_expensive_repository_probe
    def test_exact_parent_provenance_fails_closed_on_new_unaccounted_peer_sync(self):
        result = self.provenance
        self.assertIsNotNone(result)
        self.assertEqual(result["parent_sha"], EXPECTED_PARENT_SHA)
        self.assertEqual(result["classification"], "BLOCKED_CANONICAL_PROVENANCE")
        self.assertEqual(result["reason"], "PROVENANCE_FAILURE")
        self.assertNotEqual(result["return_code"], 0)
        self.assertFalse(result["private_values_recorded"])
        self.assertFalse(result["production_mutated"])
        self.assertFalse(result["deployment_authorized"])
        self.assertFalse(result["product_pass"])

    @requires_expensive_repository_probe
    def test_exact_exported_functional_suite_remains_clear(self):
        result = self.suite
        self.assertIsNotNone(result)
        self.assertEqual(result["parent_sha"], EXPECTED_PARENT_SHA)
        self.assertEqual(result["classification"], "CLEAR")
        self.assertEqual(result["reason"], "NONE")
        self.assertEqual(result["return_code"], 0)
        self.assertEqual(result["failure_test_count"], 0)
        self.assertEqual(result["failure_test_ids"], [])
        self.assertFalse(result["git_metadata_present"])
        self.assertFalse(result["private_values_recorded"])
        self.assertFalse(result["production_mutated"])
        self.assertFalse(result["deployment_authorized"])
        self.assertFalse(result["product_pass"])

    @requires_expensive_repository_probe
    def test_public_probe_shapes_are_bounded(self):
        suite = self.suite
        provenance = self.provenance
        self.assertIsNotNone(suite)
        self.assertIsNotNone(provenance)
        lowered = json.dumps({"suite": suite, "provenance": provenance}, sort_keys=True).casefold()
        for forbidden in ("stdout", "stderr", "traceback", "exception", "message_body", "file_content"):
            self.assertNotIn(forbidden, lowered)

    def test_probes_are_repository_only_inside_prepare_payload(self):
        if not REPOSITORY_GIT_AVAILABLE:
            self.assertEqual(exported_test_suite_probe()["classification"], "QA_PROBE_UNAVAILABLE")
            self.assertEqual(canonical_provenance_probe()["classification"], "QA_PROBE_UNAVAILABLE")
        self.assertTrue(MANIFEST.is_file())


class Dev09AcceptanceTruthTests(unittest.TestCase):
    def test_all_67_and_current_19_route_inventory_remain_conservative(self):
        snapshot = candidate_truth_snapshot()
        self.assertEqual(snapshot["criterion_count"], 67)
        self.assertEqual(
            snapshot["coverage_counts"],
            {
                "LIVE_EXTERNAL_REQUIRED": 17,
                "REAL_SOURCE_REQUIRED": 13,
                "SYNTHETIC_EXECUTABLE": 37,
            },
        )
        self.assertEqual(snapshot["product_pass_count"], 0)
        self.assertEqual(snapshot["route_count"], 19)
        self.assertEqual(snapshot["action_operation_count"], 17)
        self.assertEqual(snapshot["private_surface_count"], 0)
        self.assertFalse(snapshot["product_pass"])
        self.assertFalse(snapshot["deployment_authorized"])

    def test_k5_remains_live_external_and_requires_independent_write_approval(self):
        snapshot = candidate_truth_snapshot()
        self.assertEqual(snapshot["k5_evidence_class"], "LIVE_EXTERNAL_REQUIRED")
        self.assertTrue(snapshot["k5_explicit_write_approval_required"])


if __name__ == "__main__":
    unittest.main()
