from __future__ import annotations

import json
import unittest

from ops.acceptance_harness import CRITERIA
from ops.candidate_contracts import (
    candidate_acceptance_coverage,
    integrated_api_inventory,
    validate_candidate_acceptance_coverage,
    validate_integrated_api_inventory,
)
from ops.openapi_registry import OPERATIONS, OperationClass


class CandidateAcceptanceCoverageTests(unittest.TestCase):
    def test_all_67_are_accounted_exactly_once_with_conservative_counts(self):
        rows = candidate_acceptance_coverage()
        self.assertEqual(67, len(rows))
        self.assertEqual(set(CRITERIA), {row["criterion"] for row in rows})
        self.assertEqual(
            {
                "LIVE_EXTERNAL_REQUIRED": 17,
                "REAL_SOURCE_REQUIRED": 13,
                "SYNTHETIC_EXECUTABLE": 37,
            },
            validate_candidate_acceptance_coverage(rows),
        )
        self.assertTrue(all(row["product_pass"] is False for row in rows))

    def test_deployed_action_and_human_nvda_criteria_are_never_source_promoted(self):
        by_id = {row["criterion"]: row for row in candidate_acceptance_coverage()}
        for criterion in ("H1", "I1", "I4", "I6", "K1", "K2", "K3", "K4", "K5"):
            self.assertEqual("LIVE_EXTERNAL_REQUIRED", by_id[criterion]["evidence_class"])
        for criterion in ("I1", "I4", "I6"):
            self.assertTrue(by_id[criterion]["human_verification_required"])
        self.assertTrue(by_id["K5"]["explicit_write_approval_required"])
        self.assertFalse(by_id["K4"]["explicit_write_approval_required"])

    def test_mutated_coverage_cannot_overclaim_product_pass(self):
        rows = [dict(row) for row in candidate_acceptance_coverage()]
        rows[0]["product_pass"] = True
        with self.assertRaises(ValueError):
            validate_candidate_acceptance_coverage(rows)


class CandidateApiInventoryTests(unittest.TestCase):
    def test_inventory_matches_action_registry_plus_two_intentional_non_action_routes(self):
        rows = integrated_api_inventory()
        validate_integrated_api_inventory(rows)
        action_keys = {(spec.method.upper(), spec.path) for spec in OPERATIONS}
        observed = {(row["method"], row["path"]) for row in rows}
        self.assertEqual(
            action_keys | {("GET", "/health"), ("GET", "/api/v1/files/{file_ref}")},
            observed,
        )
        action_rows = [row for row in rows if row["action_operation_id"] is not None]
        self.assertEqual(len(OPERATIONS), len(action_rows))
        self.assertTrue(all(row["auth_policy"] == "BEARER" for row in action_rows))

    def test_write_preview_commit_inventory_preserves_safety_classes(self):
        by_action_id = {row["action_operation_id"]: row for row in integrated_api_inventory() if row["action_operation_id"]}
        for spec in OPERATIONS:
            row = by_action_id[spec.operation_id]
            if spec.operation_class is OperationClass.WRITE_PREVIEW:
                self.assertEqual("PROTECTED_WRITE_PREVIEW", row["safety_class"])
                self.assertEqual("WRITE_OPERATION_SCOPED", row["rate_class"])
                self.assertIn("H4", row["acceptance_criteria"])
            elif spec.operation_class is OperationClass.WRITE_COMMIT:
                self.assertEqual("PROTECTED_WRITE_COMMIT", row["safety_class"])
                self.assertEqual("WRITE_OPERATION_SCOPED", row["rate_class"])
                self.assertIn("F5", row["acceptance_criteria"])

    def test_non_action_routes_have_explicit_narrow_policies(self):
        by_path = {row["path"]: row for row in integrated_api_inventory()}
        health = by_path["/health"]
        self.assertEqual("PUBLIC", health["auth_policy"])
        self.assertEqual("NONE", health["rate_class"])
        private_file = by_path["/api/v1/files/{file_ref}"]
        self.assertEqual("BEARER_OR_SIGNED", private_file["auth_policy"])
        self.assertEqual("PRIVATE_FILE_READ", private_file["rate_class"])
        self.assertIsNone(private_file["action_operation_id"])

    def test_inventory_contains_no_private_setup_or_secret_like_surface(self):
        serialized = json.dumps(integrated_api_inventory(), ensure_ascii=False).casefold()
        for forbidden in ("setup-", "login-code", "session-string", "tg_api_hash", "bridge_token"):
            self.assertNotIn(forbidden, serialized)


if __name__ == "__main__":
    unittest.main()
