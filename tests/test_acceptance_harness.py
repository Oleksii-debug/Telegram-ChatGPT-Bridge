# -*- coding: utf-8 -*-
"""Acceptance harness contract tests. Synthetic harness readiness is never product PASS."""
from __future__ import annotations

import json
import unittest

from ops import acceptance_harness as ah


class AcceptanceMatrixTests(unittest.TestCase):
    def test_exact_a_to_k_matrix_shape(self):
        ah.validate_matrix()
        ids = [item["criterion"] for item in ah.ACCEPTANCE_MATRIX]
        self.assertEqual(67, len(ids))
        self.assertEqual(67, len(set(ids)))
        self.assertEqual(set("ABCDEFGHIJK"), {item[0] for item in ids})

    def test_planning_matrix_does_not_claim_product_pass(self):
        self.assertNotIn("PASS", {item["plan_status"] for item in ah.ACCEPTANCE_MATRIX})
        self.assertEqual("IMPLEMENTED_TEST", ah.CRITERIA["B4"]["plan_status"])
        self.assertEqual("IMPLEMENTED_TEST", ah.CRITERIA["J5"]["plan_status"])
        self.assertEqual("EXTERNALLY_BLOCKED", ah.CRITERIA["J1"]["plan_status"])
        self.assertEqual("READY_FOR_REAL_SOURCE", ah.CRITERIA["A1"]["plan_status"])

    def test_result_requires_exact_sha_environment_and_evidence_reference(self):
        payload = ah.build_result(
            criterion="B4",
            code_sha="a" * 40,
            environment_class="github-ci",
            result="PASS",
            evidence_ref="ci:RecoveryGuard#43",
            facts={"scan": "current-and-history", "count": 2},
        )
        encoded = ah.serialize_result(payload)
        roundtrip = json.loads(encoded)
        self.assertEqual("B4", roundtrip["criterion"])
        self.assertEqual("a" * 40, roundtrip["code_sha"])
        with self.assertRaises(ValueError):
            ah.build_result(
                criterion="B4",
                code_sha="short",
                environment_class="github-ci",
                result="PASS",
                evidence_ref="ci:bad",
            )

    def test_privacy_unsafe_evidence_fields_are_rejected(self):
        forbidden = (
            "token", "session_string", "api_hash", "password", "nonce",
            "setup_route", "message_body", "file_content", "cookies", "private_key",
        )
        for key in forbidden:
            with self.subTest(key=key):
                with self.assertRaises(ValueError):
                    ah.build_result(
                        criterion="B4",
                        code_sha="b" * 40,
                        environment_class="synthetic",
                        result="BLOCKED",
                        evidence_ref="test:privacy",
                        facts={key: "do-not-serialize"},
                    )

    def test_unbounded_and_private_key_material_is_rejected(self):
        with self.assertRaises(ValueError):
            ah.build_result(
                criterion="B4",
                code_sha="c" * 40,
                environment_class="synthetic",
                result="FAIL",
                evidence_ref="test:oversize",
                facts={"detail": "x" * 1001},
            )
        with self.assertRaises(ValueError):
            ah.build_result(
                criterion="B4",
                code_sha="d" * 40,
                environment_class="synthetic",
                result="FAIL",
                evidence_ref="test:key",
                facts={"detail": "-----BEGIN TEST PRIVATE KEY-----"},
            )


class TelegramAuthorizationGateTests(unittest.TestCase):
    def test_current_gate_is_not_yet_required(self):
        flag = "USER_TELEGRAM_AUTH_NOT_YET_REQUIRED"
        self.assertEqual("USER_TELEGRAM_AUTH_NOT_YET_REQUIRED", flag)


if __name__ == "__main__":
    unittest.main()
