# -*- coding: utf-8 -*-
from __future__ import annotations

import math
import unittest

from ops.dev06_action_e2e_evidence import ActionE2EEvidenceError, build_read_capture


CANDIDATE_SHA = "4" * 40


def safe_dialog_response():
    return {
        "ok": True,
        "request_id": "0123456789abcdef",
        "data": {"items": [], "next_cursor": None, "scanned": 0},
    }


class _MustNotBeStringified:
    def __str__(self):
        raise AssertionError("secret-bearing unknown header value was coerced")


class Finalwave27H1H2SecurityTests(unittest.TestCase):
    def capture(self, *, headers=None, payload=None):
        return build_read_capture(
            CANDIDATE_SHA,
            "listTelegramDialogs",
            200,
            {"Content-Type": "application/json; charset=utf-8"} if headers is None else headers,
            safe_dialog_response() if payload is None else payload,
            source_classification="SOURCE_MOCK",
            bearer_configured_privately=False,
            chatgpt_action_observed=False,
        )

    def test_unknown_sensitive_header_value_is_never_coerced(self):
        capture = self.capture(headers={
            "Content-Type": "application/json; charset=utf-8",
            "Authorization": _MustNotBeStringified(),
            "Cookie": _MustNotBeStringified(),
            "X-Private-Diagnostic": _MustNotBeStringified(),
        })
        self.assertTrue(capture["response_schema_valid"])
        self.assertFalse(capture["private_values_recorded"])

    def test_duplicate_casefolded_contract_header_fails_closed(self):
        with self.assertRaisesRegex(ActionE2EEvidenceError, "H2_RESPONSE_HEADERS_INVALID"):
            self.capture(headers={
                "Content-Type": "application/json",
                "content-type": "application/json",
            })

    def test_oversized_private_response_collection_fails_before_schema_walk(self):
        with self.assertRaisesRegex(ActionE2EEvidenceError, "H2_RESPONSE_PAYLOAD_BOUNDS_INVALID"):
            self.capture(payload={"oversized": [None] * 2049})

    def test_nonfinite_private_response_number_fails_closed(self):
        for value in (math.nan, math.inf, -math.inf):
            with self.subTest(value=value):
                with self.assertRaisesRegex(ActionE2EEvidenceError, "H2_RESPONSE_PAYLOAD_BOUNDS_INVALID"):
                    self.capture(payload={"unsafe_number": value})


if __name__ == "__main__":
    unittest.main()
