# -*- coding: utf-8 -*-
import unittest
from collections import Counter

from ops import devb_run_matrix


class DevBRunMatrixTests(unittest.TestCase):
    def test_user_requested_minimum_and_lane_accounting_are_exact(self):
        rows = devb_run_matrix.RUN_MATRIX
        summary = devb_run_matrix.validate_run_matrix(rows)
        self.assertEqual(200, len(rows))
        self.assertEqual(200, summary["check_count"])
        self.assertEqual({"DEV_B": 100, "DEV_A": 50, "DEV_C": 50}, summary["lane_counts"])
        self.assertEqual(len(rows), len({row.check_id for row in rows}))

    def test_all_outcomes_are_conservative_and_non_authorizing(self):
        summary = devb_run_matrix.RUN_SUMMARY
        self.assertFalse(summary["promotion_authorized"])
        self.assertFalse(summary["product_pass"])
        self.assertTrue(set(summary["outcome_counts"]).issubset(devb_run_matrix.OUTCOMES))
        self.assertGreater(summary["outcome_counts"].get("FINDING_OPEN", 0), 0)
        self.assertGreater(summary["outcome_counts"].get("BLOCKED_EXTERNAL", 0), 0)
        self.assertGreater(summary["outcome_counts"].get("IN_PROGRESS", 0), 0)

    def test_required_cross_lane_findings_are_explicit(self):
        controls = {(row.lane, row.control): row.outcome for row in devb_run_matrix.RUN_MATRIX}
        self.assertEqual("FINDING_OPEN", controls[("DEV_A", "devb-exact-path-drift")])
        self.assertEqual("FINDING_OPEN", controls[("DEV_A", "request-path-hook-present")])
        self.assertEqual("FINDING_OPEN", controls[("DEV_C", "base-equals-current-deva")])
        self.assertEqual("FINDING_OPEN", controls[("DEV_C", "exact-head-ci-present")])
        self.assertEqual("BLOCKED_EXTERNAL", controls[("DEV_C", "human-nvda-i1")])
        self.assertEqual("BLOCKED_EXTERNAL", controls[("DEV_B", "fresh-hostiq-manifest")]) if controls[("DEV_B", "fresh-hostiq-manifest")] == "BLOCKED_EXTERNAL" else self.assertEqual("IN_PROGRESS", controls[("DEV_B", "fresh-hostiq-manifest")])

    def test_no_control_claims_product_or_deployment_pass(self):
        for row in devb_run_matrix.RUN_MATRIX:
            rendered = f"{row.check_id} {row.control} {row.outcome} {row.evidence_code}".casefold()
            self.assertNotIn("product_pass", rendered)
            self.assertNotIn("deployment_authorized", rendered)
            self.assertNotIn("production_pass", rendered)

    def test_each_lane_has_ten_named_categories(self):
        by_lane = {}
        for row in devb_run_matrix.RUN_MATRIX:
            by_lane.setdefault(row.lane, set()).add(row.category)
        self.assertEqual(10, len(by_lane["DEV_B"]))
        self.assertEqual(10, len(by_lane["DEV_A"]))
        self.assertEqual(10, len(by_lane["DEV_C"]))
        self.assertEqual({"DEV_B": 100, "DEV_A": 50, "DEV_C": 50}, dict(Counter(row.lane for row in devb_run_matrix.RUN_MATRIX)))


if __name__ == "__main__":
    unittest.main()
