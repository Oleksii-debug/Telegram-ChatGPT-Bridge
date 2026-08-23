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
EXPECTED_CROSS_LANE_FAILURES = [
    "test_devb_round2_release.DevBRound2ReleaseContractsTests.test_passenger_binding_rejects_runtime_from_different_wsgi",
    "test_devb_round2_release.DevBRound2ReleaseContractsTests.test_preflight_manifest_and_passenger_binding_share_exact_wsgi_identity",
    "test_devc_release_qa.PreparedAndCrossLaneTruthTests.test_v2_exact_binding_is_accepted_but_never_self_authorizes_promotion",
]
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
        for path in payload["qa_paths"]:
            self.assertFalse(path.startswith("bridge/"), path)
            self.assertNotEqual(path, "passenger_wsgi.py")
            self.assertFalse(path.startswith("requirements"), path)

    def test_workflow_parent_gate_fails_when_canonical_moves(self):
        validate_workflow_parent(EXPECTED_PARENT_SHA)
        with self.assertRaisesRegex(ValueError, "DEV09_QA_PARENT_MOVED"):
            validate_workflow_parent("0" * 40)

    @requires_repository_git
    def test_live_pr_base_matches_exact_restack_when_workflow_supplies_it(self):
        observed = os.environ.get("DEV09_EXPECTED_BASE_SHA")
        if observed is not None:
            self.assertEqual(observed, EXPECTED_PARENT_SHA)


class Dev09CanonicalProvenanceTests(unittest.TestCase):
    @requires_expensive_repository_probe
    def test_exact_parent_provenance_is_clear_after_terminal_dev2_accounting(self):
        result = canonical_provenance_probe()
        self.assertEqual(result["parent_sha"], EXPECTED_PARENT_SHA)
        self.assertEqual(result["classification"], "CLEAR")
        self.assertEqual(result["reason"], "NONE")
        self.assertEqual(result["return_code"], 0)
        self.assertFalse(result["private_values_recorded"])
        self.assertFalse(result["production_mutated"])
        self.assertFalse(result["deployment_authorized"])
        self.assertFalse(result["product_pass"])

    def test_provenance_probe_public_shape_is_bounded_inside_prepare_payload(self):
        if not REPOSITORY_GIT_AVAILABLE:
            result = canonical_provenance_probe()
            self.assertEqual(result["classification"], "QA_PROBE_UNAVAILABLE")
            self.assertEqual(result["reason"], "REPOSITORY_GIT_UNAVAILABLE")
        else:
            self.skipTest("exact repository result covered by repository-only test")


class Dev09ExportedSuiteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result = None
        if REPOSITORY_GIT_AVAILABLE and not SKIP_EXPENSIVE:
            cls.result = exported_test_suite_probe()

    @requires_expensive_repository_probe
    def test_exact_exported_canonical_suite_has_exact_three_current_cross_lane_failures(self):
        result = self.result
        self.assertIsNotNone(result)
        self.assertEqual(result["parent_sha"], EXPECTED_PARENT_SHA)
        self.assertEqual(result["classification"], "BLOCKED_INTERNAL_QA")
        self.assertEqual(result["reason"], "EXPORTED_CANONICAL_TEST_FAILURE")
        self.assertNotEqual(result["return_code"], 0)
        self.assertEqual(result["failure_test_count"], 3)
        self.assertEqual(result["failure_test_ids"], EXPECTED_CROSS_LANE_FAILURES)
        self.assertFalse(result["git_metadata_present"])
        self.assertFalse(result["private_values_recorded"])
        self.assertFalse(result["production_mutated"])
        self.assertFalse(result["deployment_authorized"])
        self.assertFalse(result["product_pass"])

    @requires_expensive_repository_probe
    def test_exported_suite_public_shape_has_no_raw_process_output(self):
        result = self.result
        self.assertIsNotNone(result)
        self.assertEqual(
            set(result),
            {
                "parent_sha", "classification", "reason", "return_code",
                "failure_test_count", "failure_test_ids", "git_metadata_present",
                "private_values_recorded", "production_mutated",
                "deployment_authorized", "product_pass",
            },
        )
        lowered = json.dumps(result, sort_keys=True).casefold()
        for forbidden in ("stdout", "stderr", "traceback", "exception", "message_body", "file_content"):
            self.assertNotIn(forbidden, lowered)

    def test_probe_is_repository_only_inside_prepare_payload(self):
        if not REPOSITORY_GIT_AVAILABLE:
            result = exported_test_suite_probe()
            self.assertEqual(result["classification"], "QA_PROBE_UNAVAILABLE")
            self.assertEqual(result["reason"], "REPOSITORY_GIT_UNAVAILABLE")
            self.assertFalse(result["git_metadata_present"])
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
