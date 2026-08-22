# -*- coding: utf-8 -*-
"""Deterministic DEV5 Round-2 fuzz/property regressions; no private inputs."""
from __future__ import annotations

import hashlib
import io
import json
import threading
import unittest
import zipfile

from ops import acceptance_contracts as ac
from ops import evidence_privacy as privacy
from ops import dev5_round2_oracles as r2


def sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class TraversalFuzzTests(unittest.TestCase):
    def test_encoded_backslash_absolute_drive_dot_and_confusable_traversal_fail(self):
        bad = (
            "../x", "a/../x", "/etc/passwd", "//server/share", "C:/temp/x",
            "a\\..\\x", "%2e%2e/x", "%252e%252e/x", "a%2fb", "a%5cb",
            "a/./b", "a//b", "a∕..∕b", "a／..／b", "a＼..＼b", "a\x00b",
        )
        for value in bad:
            with self.subTest(value=value), self.assertRaises(ac.ContractError):
                ac.safe_relative_path(value)

    def test_safe_unicode_relative_paths_remain_intact(self):
        for value in ("docs/звіт.txt", "voice/Повідомлення.ogg", "photo/фото-01.jpg"):
            with self.subTest(value=value):
                self.assertEqual(value, ac.safe_relative_path(value))


class JsonAndRangeFuzzTests(unittest.TestCase):
    def test_json_type_utf8_size_and_content_length_matrix(self):
        invalid = (b"{", b"[]", b"null", b"\xff", "[]", "42", "true")
        for raw in invalid:
            with self.subTest(raw=repr(raw)), self.assertRaises(ac.ControlledInputError):
                ac.parse_json_object(raw)
        with self.assertRaises(ac.ControlledInputError):
            ac.parse_json_object(b'{"x":1}', content_length=100)
        with self.assertRaises(ac.ControlledInputError):
            ac.parse_json_object(b'{"x":1}', max_bytes=3)
        self.assertEqual({"x": 1}, ac.parse_json_object(b'{"x":1}', content_length=7))

    def test_integer_boundaries_reject_bool_and_out_of_range(self):
        self.assertEqual(0, ac.bounded_int(0, minimum=0, maximum=10))
        self.assertEqual(10, ac.bounded_int(10, minimum=0, maximum=10))
        for value in (True, False, -1, 11, 1.5, "1", None):
            with self.subTest(value=value), self.assertRaises(ac.ControlledInputError):
                ac.bounded_int(value, minimum=0, maximum=10)


class AuthFuzzTests(unittest.TestCase):
    def test_bearer_header_matrix_fails_closed(self):
        expected = sha("correct-token")
        cases = {
            None: "MISSING_AUTH",
            "": "MISSING_AUTH",
            " Bearer correct-token": "MALFORMED_AUTH",
            "Bearer correct-token ": "MALFORMED_AUTH",
            "bearer correct-token": "MALFORMED_AUTH",
            "Basic correct-token": "MALFORMED_AUTH",
            "Bearer two words": "MALFORMED_AUTH",
            "Bearer wrong-token": "WRONG_AUTH",
            "Bearer correct-token": "AUTHORIZED",
        }
        for header, outcome in cases.items():
            with self.subTest(header=header):
                self.assertEqual(outcome, ac.bearer_auth_outcome(header, expected_token_sha256=expected))


class EvidenceSemanticFuzzTests(unittest.TestCase):
    def test_short_ascii_cyrillic_and_private_like_refs_are_not_public_evidence_refs(self):
        invalid = (
            "test:Olena", "chat:family", "person:ivan", "file:report", "private-note",
            "Олена", "чат:родина", "github:run:0", "github:run:abc", "test:sha256:short",
        )
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(ValueError):
                privacy.validate_evidence_ref(value)

    def test_structured_ci_hash_refs_and_environment_classes_are_accepted(self):
        valid_refs = (
            "github:run:32474951701",
            "github:job:96749261701",
            "github:commit:" + "a" * 40,
            "test:sha256:" + "b" * 64,
            "external:sha256:" + "c" * 64,
        )
        for value in valid_refs:
            self.assertEqual(value, privacy.validate_evidence_ref(value))
        for env in ("github-ci", "synthetic", "reference-snapshot", "local-test", "hostiq-staging"):
            self.assertEqual(env, privacy.validate_environment_class(env))
        for env in ("prod-chat", "Олена", "private", "github-ci-person"):
            with self.assertRaises(ValueError):
                privacy.validate_environment_class(env)

    def test_hash_private_identifier_is_namespace_separated_and_never_returns_raw_label(self):
        first = privacy.hash_private_identifier("користувач", namespace="chat")
        second = privacy.hash_private_identifier("користувач", namespace="file")
        self.assertRegex(first, r"^[0-9a-f]{64}$")
        self.assertNotEqual(first, second)
        self.assertNotIn("користувач", first)


class ZipPropertyTests(unittest.TestCase):
    def test_casefold_and_unicode_normalization_collisions_are_rejected(self):
        with self.assertRaises(ac.ContractError):
            ac.build_zip([("Docs/A.txt", b"a"), ("docs/a.txt", b"b")])
        composed = "docs/é.txt"
        decomposed = "docs/e\u0301.txt"
        with self.assertRaises(ac.ContractError):
            ac.build_zip([(composed, b"a"), (decomposed, b"b")])

    def test_member_and_total_caps_and_crc(self):
        with self.assertRaises(ac.ContractError):
            ac.build_zip([("a", b"1"), ("b", b"2")], max_members=1)
        with self.assertRaises(ac.ContractError):
            ac.build_zip([("a", b"12")], max_member_bytes=1)
        with self.assertRaises(ac.ContractError):
            ac.build_zip([("a", b"12"), ("b", b"34")], max_total_bytes=3)
        payload = ac.build_zip([("док/а.txt", b"abc")])
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            self.assertIsNone(archive.testzip())


class AccessibilityStructuralTruthTests(unittest.TestCase):
    def test_structural_analysis_never_claims_human_nvda_pass(self):
        html = "<h1>Setup</h1><label for='x'>Code</label><input id='x'><button>Continue</button><div role='status' id='s'></div>"
        report = ac.analyze_accessibility(html)
        self.assertTrue(report["structural_only"])
        self.assertFalse(report["human_nvda_pass"])

    def test_duplicate_positive_tabindex_pointer_only_and_broken_error_ref_fail(self):
        html = """
        <h1>Setup</h1>
        <label for='a'>A</label><input id='a' tabindex='1' aria-invalid='true' aria-errormessage='missing'>
        <label for='b'>B</label><input id='b' tabindex='1'>
        <div onmouseover='show()'>Help</div><button>Continue</button><div role='status' id='s'></div>
        """
        report = ac.analyze_accessibility(html)
        self.assertFalse(report["tab_order_valid"])
        self.assertFalse(report["mouse_only_absent"])
        self.assertFalse(report["error_associations_valid"])


class AcceptanceSummaryFuzzTests(unittest.TestCase):
    def test_existing_acceptance_summary_rejects_unstructured_private_refs(self):
        with self.assertRaises(ValueError):
            ac.build_acceptance_run_summary(
                code_sha="a" * 40,
                environment_class="github-ci",
                passed_count=1,
                failed_count=0,
                blocked_count=0,
                evidence_refs=["test:private-label"],
            )
        summary = ac.build_acceptance_run_summary(
            code_sha="a" * 40,
            environment_class="github-ci",
            passed_count=1,
            failed_count=0,
            blocked_count=0,
            evidence_refs=["github:run:32474951701"],
        )
        self.assertEqual(1, summary["test_count"])


class OracleConcurrencyRegressionTests(unittest.TestCase):
    def test_idempotency_different_requests_same_key_never_both_reserve(self):
        store = r2.CrashSafeIdempotencyOracle()
        req_a = r2.CrashSafeIdempotencyOracle.fingerprint(
            operation_kind="SEND", target_sha256=sha("a"), payload_sha256=sha("p"), preview_sha256=sha("v")
        )
        req_b = r2.CrashSafeIdempotencyOracle.fingerprint(
            operation_kind="SEND", target_sha256=sha("b"), payload_sha256=sha("p"), preview_sha256=sha("v")
        )
        outcomes = []
        lock = threading.Lock()

        def worker(request):
            result = store.reserve("shared-key", request)
            with lock:
                outcomes.append(result)

        threads = [threading.Thread(target=worker, args=(req_a,)), threading.Thread(target=worker, args=(req_b,))]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(1, outcomes.count("RESERVED"))
        self.assertEqual(1, outcomes.count("IDEMPOTENCY_CONFLICT"))


if __name__ == "__main__":
    unittest.main()
