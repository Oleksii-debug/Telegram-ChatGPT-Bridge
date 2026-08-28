# -*- coding: utf-8 -*-
from __future__ import annotations

import copy
import json
import os
import tempfile
import unittest
from pathlib import Path

from ops.dev06_action_e2e_evidence import (
    ActionE2EEvidenceError,
    build_read_capture,
    load_h1_summary,
    load_h2_capture,
    summarize_h2_candidate,
    validate_h2_summary,
)
from ops.dev06_deployed_action_evidence import (
    PRODUCTION_BASE_URL,
    compare_deployed_action_schema,
)
from ops.dev06_runtime_conformance import build_compatible_chatgpt_action_openapi


CANDIDATE_SHA = "2" * 40


def safe_dialog_response():
    return {
        "ok": True,
        "request_id": "0123456789abcdef",
        "data": {"items": [], "next_cursor": None, "scanned": 0},
    }


class ActionE2EEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.document = build_compatible_chatgpt_action_openapi(PRODUCTION_BASE_URL)
        self.h1_deployed = compare_deployed_action_schema(
            CANDIDATE_SHA,
            self.document,
            source_classification="DEPLOYED_CAPTURE",
        )

    def capture(self, **kwargs):
        values = {
            "candidate_sha": CANDIDATE_SHA,
            "operation_id": "listTelegramDialogs",
            "status": 200,
            "headers": {"Content-Type": "application/json; charset=utf-8"},
            "payload": safe_dialog_response(),
            "source_classification": "SOURCE_MOCK",
            "bearer_configured_privately": False,
            "chatgpt_action_observed": False,
        }
        values.update(kwargs)
        return build_read_capture(**values)

    def test_private_response_is_validated_but_never_copied_to_capture(self):
        payload = safe_dialog_response()
        payload["data"]["items"] = [{
            "id": "private-id",
            "kind": "user",
            "title": "Private Title",
            "username": None,
            "unread_count": 0,
            "pinned": False,
            "last_message_at": None,
        }]
        capture = self.capture(payload=payload)
        rendered = json.dumps(capture, sort_keys=True)
        self.assertTrue(capture["response_schema_valid"])
        self.assertNotIn("Private Title", rendered)
        self.assertNotIn("private-id", rendered)
        self.assertNotIn("items", rendered)
        self.assertFalse(capture["private_values_recorded"])

    def test_response_schema_drift_is_bounded_to_boolean_and_count(self):
        bad = safe_dialog_response()
        bad["unexpected"] = "sensitive text that must not be exported"
        capture = self.capture(payload=bad)
        rendered = json.dumps(capture, sort_keys=True)
        self.assertFalse(capture["response_schema_valid"])
        self.assertGreater(capture["response_error_count"], 0)
        self.assertNotIn("sensitive text", rendered)
        self.assertNotIn("unexpected", rendered)

    def test_write_preview_and_commit_are_rejected_for_h2(self):
        for operation_id in ("previewTelegramSend", "commitTelegramSend", "previewTelegramFiles", "commitTelegramFiles"):
            with self.subTest(operation_id=operation_id):
                with self.assertRaisesRegex(ActionE2EEvidenceError, "H2_OPERATION_NOT_READ_ONLY"):
                    self.capture(operation_id=operation_id)

    def test_unknown_operation_fails_closed(self):
        with self.assertRaisesRegex(ActionE2EEvidenceError, "H2_OPERATION_UNKNOWN"):
            self.capture(operation_id="unknownAction")

    def test_source_mock_never_becomes_live_h2_candidate(self):
        capture = self.capture(
            source_classification="SOURCE_MOCK",
            bearer_configured_privately=True,
            chatgpt_action_observed=True,
        )
        summary = summarize_h2_candidate(CANDIDATE_SHA, self.h1_deployed, capture)
        self.assertFalse(summary["live_capture_classification"])
        self.assertFalse(summary["live_evidence_candidate"])
        self.assertFalse(summary["product_h2_pass"])
        self.assertTrue(summary["auditor_adjudication_required"])
        self.assertFalse(summary["deployment_authorized"])

    def test_private_live_candidate_still_never_self_authorizes_h2(self):
        capture = self.capture(
            source_classification="PRIVATE_LIVE_ACTION_CAPTURE",
            bearer_configured_privately=True,
            chatgpt_action_observed=True,
        )
        summary = summarize_h2_candidate(CANDIDATE_SHA, self.h1_deployed, capture)
        self.assertTrue(summary["h1_deployed_schema_match"])
        self.assertTrue(summary["schema_binding_match"])
        self.assertTrue(summary["read_only_operation"])
        self.assertTrue(summary["live_evidence_candidate"])
        self.assertFalse(summary["product_h2_pass"])
        self.assertTrue(summary["auditor_adjudication_required"])
        self.assertFalse(summary["production_mutated"])
        self.assertFalse(summary["private_values_recorded"])
        validate_h2_summary(summary)

    def test_h1_source_mock_cannot_support_live_h2_candidate(self):
        h1_mock = compare_deployed_action_schema(
            CANDIDATE_SHA,
            self.document,
            source_classification="SOURCE_MOCK",
        )
        capture = self.capture(
            source_classification="PRIVATE_LIVE_ACTION_CAPTURE",
            bearer_configured_privately=True,
            chatgpt_action_observed=True,
        )
        summary = summarize_h2_candidate(CANDIDATE_SHA, h1_mock, capture)
        self.assertFalse(summary["h1_deployed_schema_match"])
        self.assertFalse(summary["live_evidence_candidate"])

    def test_non_200_or_invalid_response_cannot_support_live_candidate(self):
        capture = self.capture(
            status=429,
            headers={
                "Content-Type": "application/json",
                "Retry-After": "1",
            },
            payload={
                "ok": False,
                "request_id": "0123456789abcdef",
                "error": {
                    "code": "rate_limited",
                    "message": "Rate limited",
                    "retry_after_seconds": 1,
                    "details": {},
                },
            },
            source_classification="PRIVATE_LIVE_ACTION_CAPTURE",
            bearer_configured_privately=True,
            chatgpt_action_observed=True,
        )
        self.assertTrue(capture["response_schema_valid"])
        summary = summarize_h2_candidate(CANDIDATE_SHA, self.h1_deployed, capture)
        self.assertFalse(summary["response_200_schema_valid"])
        self.assertFalse(summary["live_evidence_candidate"])

    def test_candidate_and_deployed_schema_binding_fail_closed(self):
        capture = self.capture(
            source_classification="PRIVATE_LIVE_ACTION_CAPTURE",
            bearer_configured_privately=True,
            chatgpt_action_observed=True,
        )
        with self.assertRaisesRegex(ActionE2EEvidenceError, "H2_CANDIDATE_BINDING_MISMATCH"):
            summarize_h2_candidate("3" * 40, self.h1_deployed, capture)

        bad_h1 = copy.deepcopy(self.h1_deployed)
        bad_h1["observed_schema_sha256"] = "f" * 64
        bad_h1["expected_schema_sha256"] = "f" * 64
        with self.assertRaisesRegex(ActionE2EEvidenceError, "H2_DEPLOYED_SCHEMA_BINDING_MISMATCH"):
            summarize_h2_candidate(CANDIDATE_SHA, bad_h1, capture)

    def test_summary_mutation_cannot_claim_product_h2_or_deployment(self):
        capture = self.capture(
            source_classification="PRIVATE_LIVE_ACTION_CAPTURE",
            bearer_configured_privately=True,
            chatgpt_action_observed=True,
        )
        summary = summarize_h2_candidate(CANDIDATE_SHA, self.h1_deployed, capture)
        for key in ("product_h2_pass", "deployment_authorized", "production_mutated", "private_values_recorded"):
            bad = copy.deepcopy(summary)
            bad[key] = True
            with self.assertRaisesRegex(ActionE2EEvidenceError, "H2_SUMMARY_MUST_NOT_SELF_AUTHORIZE"):
                validate_h2_summary(bad)

    def test_capture_and_h1_loaders_reject_extra_private_fields(self):
        capture = self.capture()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            capture_path = root / "capture.json"
            capture_path.write_text(json.dumps(capture), encoding="utf-8")
            self.assertEqual(load_h2_capture(capture_path)["operation_id"], "listTelegramDialogs")

            bad_capture = dict(capture)
            bad_capture["response_body"] = "private"
            capture_path.write_text(json.dumps(bad_capture), encoding="utf-8")
            with self.assertRaisesRegex(ActionE2EEvidenceError, "H2_CAPTURE_SHAPE_INVALID"):
                load_h2_capture(capture_path)

            h1_path = root / "h1.json"
            h1_path.write_text(json.dumps(self.h1_deployed), encoding="utf-8")
            self.assertEqual(load_h1_summary(h1_path)["candidate_sha"], CANDIDATE_SHA)

    @unittest.skipUnless(hasattr(os, "symlink"), "symlink unavailable")
    def test_h2_evidence_symlink_is_rejected(self):
        capture = self.capture()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            real = root / "capture.json"
            real.write_text(json.dumps(capture), encoding="utf-8")
            link = root / "link.json"
            try:
                os.symlink(real, link)
            except OSError:
                self.skipTest("symlink creation unavailable")
            with self.assertRaisesRegex(ActionE2EEvidenceError, "H2_EVIDENCE_FILE_UNSAFE"):
                load_h2_capture(link)


if __name__ == "__main__":
    unittest.main()
