# -*- coding: utf-8 -*-
"""FINALWAVE-41 adversarial regressions for public evidence privacy."""
from __future__ import annotations

import contextlib
import io
import json
import subprocess
import sys
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest import mock

from ops.acceptance_harness import build_result, serialize_result
from ops.evidence_privacy import (
    reject_sensitive_text,
    sanitize_exception,
    sanitize_subprocess_result,
    validate_aggregate_payload,
    validate_evidence_ref,
)
from tools import collect_runtime_evidence as runtime_cli


CANONICAL_SHA = "84691967e5363bc4b88dfae97371d7bf329c105d"
SAFE_DIGEST = "a" * 64


class ExplosivePresence:
    def __bool__(self):
        raise RuntimeError("/private/path/should-never-escape")

    def __str__(self):
        raise RuntimeError("private-label-should-never-escape")

    def __repr__(self):
        raise RuntimeError("repr-should-never-escape")


class PrivateAttributeError(RuntimeError):
    pass


class FinalWave41EvidencePrivacyTests(unittest.TestCase):
    def test_short_ascii_and_cyrillic_private_labels_are_not_evidence_refs(self):
        for value in (
            "chat:Family",
            "person:Alice",
            "file:notes.txt",
            "чат:Родина",
            "особа:Олена",
            "файл:нотатки.txt",
        ):
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate_evidence_ref(value)

        for private_suite in ("FAMILY_CHAT", "РОДИННИЙ_ЧАТ"):
            with self.subTest(private_suite=private_suite), self.assertRaises(ValueError):
                validate_evidence_ref(
                    {"provider": "GITHUB_ACTIONS", "run_id": 123, "suite": private_suite}
                )

    def test_positive_refs_are_provider_ids_hashes_and_reviewed_suites_only(self):
        self.assertEqual(
            {
                "provider": "GITHUB_ACTIONS",
                "run_id": 123,
                "job_id": 456,
                "suite": "ACCEPTANCE_HARNESS",
                "evidence_sha256": SAFE_DIGEST,
            },
            validate_evidence_ref(
                {
                    "provider": "GITHUB_ACTIONS",
                    "run_id": 123,
                    "job_id": 456,
                    "suite": "ACCEPTANCE_HARNESS",
                    "evidence_sha256": SAFE_DIGEST,
                }
            ),
        )
        self.assertEqual(
            {"provider": "HOSTIQ_PRIVATE", "evidence_sha256": SAFE_DIGEST},
            validate_evidence_ref(
                {"provider": "HOSTIQ_PRIVATE", "evidence_sha256": SAFE_DIGEST}
            ),
        )

    def test_mutation_after_validation_is_rejected_before_serialization(self):
        result = build_result(
            criterion="H1",
            code_sha=CANONICAL_SHA,
            environment_class="GITHUB_CI",
            result="BLOCKED",
            evidence_ref={
                "provider": "GITHUB_ACTIONS",
                "run_id": 123,
                "suite": "ACCEPTANCE_HARNESS",
            },
            facts={"schema_valid": True, "success": False},
        )
        result["evidence_ref"]["suite"] = "FamilyChat"
        with self.assertRaises(ValueError):
            serialize_result(result)

    def test_nested_and_huge_opaque_values_fail_closed(self):
        with self.assertRaises(ValueError):
            validate_aggregate_payload(
                {"a": {"b": {"c": {"d": {"e": {"f": "SAFE"}}}}}}
            )
        with self.assertRaises(ValueError):
            reject_sensitive_text("Ab12" * 80)
        with self.assertRaises(ValueError):
            validate_evidence_ref(
                {
                    "provider": "HOSTIQ_PRIVATE",
                    "evidence_sha256": SAFE_DIGEST,
                    "label": "FamilyChat",
                }
            )

    def test_exception_attributes_and_message_are_never_copied(self):
        exc = PrivateAttributeError("/private/path/private-file.txt")
        exc.stdout = "private stdout label"
        exc.stderr = "private stderr label"
        exc.private_path = "/private/path/private-file.txt"
        exc.chat_label = "FamilyChat"
        sanitized = sanitize_exception(exc)
        self.assertEqual({"error_type": "EXCEPTION", "error_present": True}, sanitized)
        public = json.dumps(sanitized, sort_keys=True)
        for private_value in (
            str(exc), exc.stdout, exc.stderr, exc.private_path, exc.chat_label
        ):
            self.assertNotIn(private_value, public)

    def test_subprocess_output_presence_never_calls_arbitrary_conversion_hooks(self):
        with self.assertRaisesRegex(ValueError, "unsupported subprocess stdout type"):
            sanitize_subprocess_result(1, stdout=ExplosivePresence())
        with self.assertRaisesRegex(ValueError, "unsupported subprocess stderr type"):
            sanitize_subprocess_result(1, stderr=ExplosivePresence())

    def test_subprocess_paths_and_private_text_reduce_to_presence_bits(self):
        stdout = "/private/path/user-file.txt"
        stderr = "FamilyChat private failure detail"
        sanitized = sanitize_subprocess_result(7, stdout=stdout, stderr=stderr)
        self.assertEqual(
            {"return_code": 7, "stdout_present": True, "stderr_present": True},
            sanitized,
        )
        public = json.dumps(sanitized, sort_keys=True)
        self.assertNotIn(stdout, public)
        self.assertNotIn(stderr, public)

    def test_subprocess_output_type_policy_rejects_subclasses(self):
        class PrivateStr(str):
            def __len__(self):
                raise RuntimeError("private-len-detail")

        with self.assertRaises(ValueError):
            sanitize_subprocess_result(0, stdout=PrivateStr("FamilyChat"))

    def test_concurrent_sanitization_is_content_independent(self):
        private_outputs = [f"/private/path/file-{index}.txt" for index in range(64)]
        with ThreadPoolExecutor(max_workers=8) as pool:
            rows = list(
                pool.map(
                    lambda value: sanitize_subprocess_result(0, stdout=value, stderr=""),
                    private_outputs,
                )
            )
        expected = {"return_code": 0, "stdout_present": True, "stderr_present": False}
        self.assertTrue(all(row == expected for row in rows))
        serialized = json.dumps(rows, sort_keys=True)
        self.assertTrue(all(value not in serialized for value in private_outputs))

    def test_process_boundary_restarts_with_same_privacy_projection(self):
        script = (
            "import json; "
            "from ops.evidence_privacy import sanitize_subprocess_result; "
            "print(json.dumps(sanitize_subprocess_result(0, "
            "stdout='/private/path/restart-canary.txt', stderr='FamilyChat')))"
        )
        first = subprocess.run(
            [sys.executable, "-c", script],
            check=True,
            capture_output=True,
            text=True,
        )
        second = subprocess.run(
            [sys.executable, "-c", script],
            check=True,
            capture_output=True,
            text=True,
        )
        self.assertEqual(first.stdout, second.stdout)
        self.assertNotIn("restart-canary", first.stdout)
        self.assertNotIn("FamilyChat", first.stdout)
        self.assertEqual(
            {"return_code": 0, "stdout_present": True, "stderr_present": True},
            json.loads(first.stdout),
        )

    def test_runtime_evidence_cli_failure_stdout_is_fixed_code_only(self):
        failure = PrivateAttributeError("/private/path/runtime-canary.txt")
        failure.private_path = "/private/path/runtime-canary.txt"
        output = io.StringIO()
        with mock.patch.object(runtime_cli, "collect_runtime_evidence", side_effect=failure):
            with contextlib.redirect_stdout(output):
                rc = runtime_cli.main()
        self.assertEqual(2, rc)
        self.assertEqual("RUNTIME_EVIDENCE_BLOCKED\n", output.getvalue())
        self.assertNotIn(type(failure).__name__, output.getvalue())
        self.assertNotIn("runtime-canary", output.getvalue())

    def test_h1_h2_public_acceptance_results_remain_non_authorizing_typed_evidence(self):
        for criterion in ("H1", "H2"):
            with self.subTest(criterion=criterion):
                result = build_result(
                    criterion=criterion,
                    code_sha=CANONICAL_SHA,
                    environment_class="GITHUB_CI",
                    result="BLOCKED",
                    evidence_ref={
                        "provider": "GITHUB_ACTIONS",
                        "run_id": 123,
                        "suite": "ACCEPTANCE_HARNESS",
                    },
                    facts={"schema_valid": True, "success": False},
                )
                serialized = serialize_result(result)
                self.assertNotIn("FamilyChat", serialized)
                self.assertNotIn("/private/path", serialized)
                self.assertNotIn("deployment_authorized", serialized)
                self.assertNotIn("product_pass", serialized)


if __name__ == "__main__":
    unittest.main()
