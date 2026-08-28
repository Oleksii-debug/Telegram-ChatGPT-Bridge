# -*- coding: utf-8 -*-
from __future__ import annotations

import copy
import json
import os
import tempfile
import unittest
from pathlib import Path

from ops.dev06_deployed_action_evidence import (
    MAX_SCHEMA_BYTES,
    PRODUCTION_BASE_URL,
    DeployedActionEvidenceError,
    canonical_json_bytes,
    compare_deployed_action_schema,
    load_observed_schema,
    schema_sha256,
    validate_evidence_summary,
)
from ops.dev06_runtime_conformance import build_compatible_chatgpt_action_openapi


CANDIDATE_SHA = "1" * 40


def operation(document, operation_id):
    for item in document["paths"].values():
        for candidate in item.values():
            if isinstance(candidate, dict) and candidate.get("operationId") == operation_id:
                return candidate
    raise AssertionError(operation_id)


class DeployedActionEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.expected = build_compatible_chatgpt_action_openapi(PRODUCTION_BASE_URL)

    def compare(self, document=None, *, source="SOURCE_MOCK"):
        return compare_deployed_action_schema(
            CANDIDATE_SHA,
            self.expected if document is None else document,
            source_classification=source,
        )

    def test_exact_generated_schema_matches_but_never_self_authorizes_h1(self):
        result = self.compare()
        self.assertTrue(result["schema_match"])
        self.assertEqual(result["expected_operation_count"], 17)
        self.assertEqual(result["observed_operation_count"], 17)
        self.assertEqual(result["operation_drift_count"], 0)
        self.assertEqual(result["mismatch_codes"], [])
        self.assertFalse(result["product_h1_pass"])
        self.assertFalse(result["deployment_authorized"])
        self.assertFalse(result["production_mutated"])
        self.assertFalse(result["private_values_recorded"])
        self.assertEqual(len(result["expected_schema_sha256"]), 64)
        self.assertLess(result["expected_schema_bytes"], MAX_SCHEMA_BYTES)
        validate_evidence_summary(result)

    def test_deployed_capture_label_is_not_proof_or_authority(self):
        result = self.compare(source="DEPLOYED_CAPTURE")
        self.assertTrue(result["schema_match"])
        self.assertEqual(result["source_classification"], "DEPLOYED_CAPTURE")
        self.assertFalse(result["product_h1_pass"])
        self.assertFalse(result["deployment_authorized"])

    def test_root_bearer_removal_is_detected(self):
        bad = copy.deepcopy(self.expected)
        bad["security"] = []
        result = self.compare(bad)
        self.assertFalse(result["schema_match"])
        self.assertIn("ROOT_SECURITY_DRIFT", result["mismatch_codes"])
        self.assertIn("OBSERVED_SCHEMA_VALIDATION_FAILED", result["mismatch_codes"])

    def test_server_origin_drift_is_detected(self):
        bad = copy.deepcopy(self.expected)
        bad["servers"] = [{"url": "https://example.invalid"}]
        result = self.compare(bad)
        self.assertFalse(result["schema_match"])
        self.assertIn("SERVER_ORIGIN_DRIFT", result["mismatch_codes"])

    def test_private_extra_path_is_detected_without_echoing_path(self):
        bad = copy.deepcopy(self.expected)
        bad["paths"]["/api/v1/setup/private"] = {
            "post": copy.deepcopy(operation(bad, "listTelegramDialogs"))
        }
        result = self.compare(bad)
        rendered = json.dumps(result, sort_keys=True)
        self.assertFalse(result["schema_match"])
        self.assertIn("PATH_SET_DRIFT", result["mismatch_codes"])
        self.assertIn("OBSERVED_SCHEMA_VALIDATION_FAILED", result["mismatch_codes"])
        self.assertNotIn("/api/v1/setup/private", rendered)

    def test_missing_operation_changes_path_and_operation_counts(self):
        bad = copy.deepcopy(self.expected)
        del bad["paths"]["/api/v1/dialogs/list"]
        result = self.compare(bad)
        self.assertFalse(result["schema_match"])
        self.assertIn("PATH_SET_DRIFT", result["mismatch_codes"])
        self.assertIn("OPERATION_COUNT_DRIFT", result["mismatch_codes"])
        self.assertGreater(result["operation_drift_count"], 0)

    def test_consequential_semantics_drift_is_detected(self):
        bad = copy.deepcopy(self.expected)
        operation(bad, "commitTelegramSend")["x-openai-isConsequential"] = False
        result = self.compare(bad)
        self.assertFalse(result["schema_match"])
        self.assertIn("OPERATION_CONTRACT_DRIFT", result["mismatch_codes"])
        self.assertIn("OBSERVED_SCHEMA_VALIDATION_FAILED", result["mismatch_codes"])

    def test_request_schema_drift_is_detected(self):
        bad = copy.deepcopy(self.expected)
        body = operation(bad, "searchTelegramMessages")["requestBody"]["content"]["application/json"]["schema"]
        body["additionalProperties"] = True
        result = self.compare(bad)
        self.assertFalse(result["schema_match"])
        self.assertIn("OPERATION_CONTRACT_DRIFT", result["mismatch_codes"])
        self.assertIn("OBSERVED_SCHEMA_VALIDATION_FAILED", result["mismatch_codes"])

    def test_response_retry_after_drift_is_detected(self):
        bad = copy.deepcopy(self.expected)
        del operation(bad, "searchTelegramMessages")["responses"]["429"]["headers"]["Retry-After"]
        result = self.compare(bad)
        self.assertFalse(result["schema_match"])
        self.assertIn("OPERATION_CONTRACT_DRIFT", result["mismatch_codes"])
        self.assertIn("OBSERVED_SCHEMA_VALIDATION_FAILED", result["mismatch_codes"])

    def test_canonical_serialization_and_hash_are_deterministic(self):
        first = canonical_json_bytes(self.expected)
        reordered = json.loads(first.decode("utf-8"))
        self.assertEqual(first, canonical_json_bytes(reordered))
        self.assertEqual(schema_sha256(self.expected), schema_sha256(reordered))

    def test_invalid_candidate_sha_and_source_classification_fail_closed(self):
        with self.assertRaisesRegex(DeployedActionEvidenceError, "CANDIDATE_SHA_INVALID"):
            compare_deployed_action_schema("short", self.expected)
        with self.assertRaisesRegex(DeployedActionEvidenceError, "SOURCE_CLASSIFICATION_INVALID"):
            compare_deployed_action_schema(CANDIDATE_SHA, self.expected, source_classification="trusted")

    def test_oversized_schema_is_rejected_as_ingestion_safety_not_platform_claim(self):
        bad = copy.deepcopy(self.expected)
        bad["info"]["description"] = "x" * MAX_SCHEMA_BYTES
        with self.assertRaisesRegex(DeployedActionEvidenceError, "SCHEMA_DOCUMENT_SIZE_INVALID"):
            self.compare(bad)

    def test_summary_mutation_cannot_claim_h1_or_deployment(self):
        result = self.compare()
        for key in ("product_h1_pass", "deployment_authorized", "production_mutated", "private_values_recorded"):
            bad = copy.deepcopy(result)
            bad[key] = True
            with self.assertRaisesRegex(DeployedActionEvidenceError, "EVIDENCE_MUST_NOT_SELF_AUTHORIZE"):
                validate_evidence_summary(bad)

    def test_bounded_file_loader_accepts_regular_json_and_rejects_invalid_json(self):
        with tempfile.TemporaryDirectory() as td:
            good = Path(td) / "observed.json"
            good.write_bytes(canonical_json_bytes(self.expected))
            loaded = load_observed_schema(good)
            self.assertEqual(schema_sha256(loaded), schema_sha256(self.expected))
            bad = Path(td) / "bad.json"
            bad.write_text("not-json", encoding="utf-8")
            with self.assertRaisesRegex(DeployedActionEvidenceError, "OBSERVED_SCHEMA_JSON_INVALID"):
                load_observed_schema(bad)

    @unittest.skipUnless(hasattr(os, "symlink"), "symlink unavailable")
    def test_observed_schema_symlink_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            real = Path(td) / "real.json"
            real.write_bytes(canonical_json_bytes(self.expected))
            link = Path(td) / "link.json"
            try:
                os.symlink(real, link)
            except OSError:
                self.skipTest("symlink creation unavailable")
            with self.assertRaisesRegex(DeployedActionEvidenceError, "OBSERVED_SCHEMA_FILE_UNSAFE"):
                load_observed_schema(link)


if __name__ == "__main__":
    unittest.main()
