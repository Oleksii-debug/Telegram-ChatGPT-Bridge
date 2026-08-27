# -*- coding: utf-8 -*-
from __future__ import annotations

import copy
import hashlib
import json
import threading
import unittest

from ops import dev5_round2_oracles as r2


def h(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


class Clock:
    def __init__(self, value=0.0):
        self.value = float(value)

    def __call__(self):
        return self.value


class RateLimitOracleTests(unittest.TestCase):
    def test_rollover_retry_actor_separation_and_pruning(self):
        clock = Clock(9.5)
        limiter = r2.StrictFixedWindowOracle(2, window_seconds=10, clock=clock, max_actors=2)
        self.assertTrue(limiter.consume("actor-a").allowed)
        self.assertTrue(limiter.consume("actor-a").allowed)
        denied = limiter.consume("actor-a")
        self.assertFalse(denied.allowed)
        self.assertEqual(1, denied.retry_after_seconds)
        self.assertTrue(limiter.consume("actor-b").allowed)
        self.assertEqual(2, limiter.tracked_actor_count)
        clock.value = 10.0
        self.assertTrue(limiter.consume("actor-c").allowed)
        self.assertEqual(1, limiter.tracked_actor_count)

    def test_backward_nan_negative_and_actor_capacity_fail_closed(self):
        clock = Clock(20)
        limiter = r2.StrictFixedWindowOracle(1, clock=clock, max_actors=1)
        limiter.consume("a")
        clock.value = 19
        with self.assertRaises(r2.OracleError):
            limiter.consume("a")
        clock2 = Clock(1)
        limiter2 = r2.StrictFixedWindowOracle(1, clock=clock2, max_actors=1)
        limiter2.consume("a")
        with self.assertRaises(r2.OracleError):
            limiter2.consume("b")
        for bad in (float("nan"), float("inf"), -1):
            clock3 = Clock(0)
            clock3.value = bad
            candidate = r2.StrictFixedWindowOracle(1, clock=clock3)
            with self.assertRaises(r2.OracleError):
                candidate.consume("a")

    def test_concurrent_same_actor_never_exceeds_limit(self):
        clock = Clock(5)
        limiter = r2.StrictFixedWindowOracle(7, window_seconds=60, clock=clock)
        allowed = []
        lock = threading.Lock()

        def worker():
            decision = limiter.consume("same-actor")
            with lock:
                allowed.append(decision.allowed)

        threads = [threading.Thread(target=worker) for _ in range(30)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(7, sum(allowed))
        self.assertEqual(23, len(allowed) - sum(allowed))


class IdempotencyOracleTests(unittest.TestCase):
    def setUp(self):
        self.req = r2.CrashSafeIdempotencyOracle.fingerprint(
            operation_kind="SEND", target_sha256=h("t"), payload_sha256=h("p"), preview_sha256=h("v")
        )
        self.other = r2.CrashSafeIdempotencyOracle.fingerprint(
            operation_kind="SEND", target_sha256=h("x"), payload_sha256=h("p"), preview_sha256=h("v")
        )

    def test_reservation_restart_requires_reconciliation_not_repeat(self):
        store = r2.CrashSafeIdempotencyOracle()
        self.assertEqual("RESERVED", store.reserve("req-1", self.req))
        restarted = r2.CrashSafeIdempotencyOracle.from_state(store.export_state())
        self.assertEqual("RECONCILE_REQUIRED", restarted.reserve("req-1", self.req))
        self.assertEqual("IDEMPOTENCY_CONFLICT", restarted.reserve("req-1", self.other))

    def test_commit_retry_and_tombstone_never_reenable_key(self):
        store = r2.CrashSafeIdempotencyOracle()
        store.reserve("req-1", self.req)
        store.complete("req-1", self.req)
        self.assertEqual("COMMITTED", store.reserve("req-1", self.req))
        store.prune_terminal_detail("req-1")
        self.assertEqual("TOMBSTONE_REUSE", store.reserve("req-1", self.req))
        self.assertEqual("IDEMPOTENCY_CONFLICT", store.reserve("req-1", self.other))

    def test_corrupt_persistence_and_contradictory_state_fail_closed(self):
        store = r2.CrashSafeIdempotencyOracle()
        store.reserve("req-1", self.req)
        state = store.export_state()
        state["entries"]["req-1"]["state"] = "COMMITTED"
        with self.assertRaises(r2.OracleError):
            r2.CrashSafeIdempotencyOracle.from_state(state)
        state = store.export_state()
        state["integrity_sha256"] = "0" * 64
        with self.assertRaises(r2.OracleError):
            r2.CrashSafeIdempotencyOracle.from_state(state)

    def test_concurrent_reservation_has_one_writer_and_reconcile_for_rest(self):
        store = r2.CrashSafeIdempotencyOracle()
        outcomes = []
        lock = threading.Lock()

        def worker():
            result = store.reserve("same-key", self.req)
            with lock:
                outcomes.append(result)

        threads = [threading.Thread(target=worker) for _ in range(20)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(1, outcomes.count("RESERVED"))
        self.assertEqual(19, outcomes.count("RECONCILE_REQUIRED"))


class DownloadCheckpointOracleTests(unittest.TestCase):
    def valid(self, status="partial"):
        return {
            "schema": 1,
            "job_id": "job1",
            "status": status,
            "items": [
                {"item_id": "i1", "expected_size": 3, "expected_sha256": h("a")},
                {"item_id": "i2", "expected_size": 4, "expected_sha256": h("b")},
            ],
            "results": {"i1": "file-1"},
            "failures": {"i2": {"code": "timeout"}},
        }

    def test_semantically_valid_partial_checkpoint(self):
        self.assertEqual([], r2.validate_download_checkpoint_snapshot(self.valid(), existing_file_refs={"file-1"}))

    def test_complete_missing_result_and_missing_file_record_fail(self):
        payload = self.valid("complete")
        errors = r2.validate_download_checkpoint_snapshot(payload, existing_file_refs=set())
        self.assertIn("CHECKPOINT_COMPLETE_INCONSISTENT", errors)
        self.assertIn("CHECKPOINT_MISSING_FILE_RECORD", errors)

    def test_result_failure_overlap_duplicate_item_and_bad_expected_hash_fail(self):
        payload = self.valid()
        payload["failures"]["i1"] = {"code": "timeout"}
        payload["items"].append(copy.deepcopy(payload["items"][0]))
        payload["items"][0]["expected_sha256"] = "bad"
        errors = r2.validate_download_checkpoint_snapshot(payload, existing_file_refs={"file-1"})
        self.assertIn("CHECKPOINT_RESULT_FAILURE_OVERLAP", errors)
        self.assertIn("CHECKPOINT_DUPLICATE_ITEM", errors)
        self.assertIn("CHECKPOINT_EXPECTED_HASH", errors)

    def test_pending_checkpoint_cannot_have_prior_outcomes(self):
        errors = r2.validate_download_checkpoint_snapshot(self.valid("pending"), existing_file_refs={"file-1"})
        self.assertIn("CHECKPOINT_PENDING_HAS_OUTCOMES", errors)


class OpenApiDriftOracleTests(unittest.TestCase):
    def registry(self):
        return [
            r2.RouteRecord("health", "/health", "GET", "PUBLIC", "READ"),
            r2.RouteRecord("readMessages", "/messages", "GET", "PROTECTED", "READ"),
            r2.RouteRecord("sendPreview", "/send/preview", "POST", "PROTECTED", "PREVIEW"),
            r2.RouteRecord("sendCommit", "/send/commit", "POST", "PROTECTED", "COMMIT", "sendPreview"),
        ]

    def response(self):
        return {
            "content": {
                "application/json": {
                    "schema": {
                        "type": "object",
                        "required": ["error"],
                        "properties": {"error": {"type": "string"}},
                    }
                }
            }
        }

    def safe_schema(self):
        error = self.response()
        return {
            "openapi": "3.1.0",
            "paths": {
                "/health": {"get": {"operationId": "health", "responses": {"200": {}}}},
                "/messages": {
                    "get": {
                        "operationId": "readMessages",
                        "security": [{"bearerAuth": []}],
                        "responses": {"401": error},
                    }
                },
                "/send/preview": {
                    "post": {
                        "operationId": "sendPreview",
                        "security": [{"bearerAuth": []}],
                        "responses": {"400": error},
                    }
                },
                "/send/commit": {
                    "post": {
                        "operationId": "sendCommit",
                        "security": [{"bearerAuth": []}],
                        "responses": {"409": error},
                    }
                },
            },
        }

    def test_safe_registry_schema_exact_match(self):
        self.assertEqual([], r2.validate_openapi_drift(self.safe_schema(), self.registry()))

    def test_undocumented_sensitive_and_nonexistent_documented_routes_fail(self):
        schema = self.safe_schema()
        schema["paths"]["/admin"] = {
            "post": {"operationId": "admin", "security": [{"bearerAuth": []}], "responses": {}}
        }
        del schema["paths"]["/messages"]
        errors = r2.validate_openapi_drift(schema, self.registry())
        self.assertIn("OPENAPI_UNREGISTERED_OPERATION", errors)
        self.assertIn("OPENAPI_REGISTERED_ROUTE_MISSING", errors)

    def test_missing_bearer_orphan_write_duplicate_operation_and_marker_contradiction(self):
        schema = self.safe_schema()
        schema["paths"]["/messages"]["get"].pop("security")
        schema["paths"]["/send/commit"]["post"]["operationId"] = "sendPreview"
        schema["paths"]["/send/commit"]["post"]["x-write-operation"] = False
        errors = r2.validate_openapi_drift(schema, self.registry())
        self.assertIn("OPENAPI_PROTECTED_WITHOUT_SECURITY", errors)
        self.assertIn("OPENAPI_DUPLICATE_OPERATION_ID", errors)
        self.assertIn("OPENAPI_SELF_MARKER_CONTRADICTION", errors)
        broken = [
            r2.RouteRecord("health", "/health", "GET", "PUBLIC", "READ"),
            r2.RouteRecord("write", "/write", "POST", "PROTECTED", "WRITE", "missing"),
        ]
        broken_schema = {
            "openapi": "3.1.0",
            "paths": {
                "/health": {"get": {"operationId": "health", "responses": {}}},
                "/write": {
                    "post": {"operationId": "write", "security": [{"bearerAuth": []}], "responses": {}}
                },
            },
        }
        self.assertIn("OPENAPI_ORPHAN_WRITE", r2.validate_openapi_drift(broken_schema, broken))

    def test_setup_examples_private_material_and_unstructured_errors_fail(self):
        schema = self.safe_schema()
        schema["servers"] = [{"url": "https://example.invalid/setup-private-key"}]
        schema["paths"]["/messages"]["get"]["responses"]["401"] = {"description": "plain"}
        errors = r2.validate_openapi_drift(schema, self.registry())
        self.assertIn("OPENAPI_PRIVATE_MATERIAL_EXPOSED", errors)
        self.assertIn("OPENAPI_UNSTRUCTURED_ERROR", errors)


class AccessibilityEdgeOracleTests(unittest.TestCase):
    def test_broken_and_self_aria_refs_duplicate_ids_and_form_submit_semantics(self):
        html = "<form><span id='x'>Name</span><span id='x'>Dup</span><input id='field' aria-labelledby='field missing'></form>"
        errors = r2.validate_accessibility_edges(html)
        self.assertIn("A11Y_DUPLICATE_ID", errors)
        self.assertIn("A11Y_BROKEN_ARIA_REFERENCE", errors)
        self.assertIn("A11Y_SELF_LABEL_REFERENCE", errors)
        self.assertIn("A11Y_FORM_WITHOUT_SUBMIT_SEMANTICS", errors)

    def test_pointer_only_and_non_native_control_fail(self):
        html = "<div role='button' tabindex='0' onclick='go()'>Go</div><span onmouseover='tip()'>Tip</span>"
        errors = r2.validate_accessibility_edges(html)
        self.assertIn("A11Y_NON_NATIVE_CONTROL_KEYBOARD", errors)
        self.assertIn("A11Y_POINTER_ONLY_INTERACTION", errors)

    def test_native_form_and_resolved_aria_refs_are_structurally_ok(self):
        html = "<form><span id='lab'>Name</span><input aria-labelledby='lab'><button type='submit'>Continue</button></form>"
        self.assertEqual([], r2.validate_accessibility_edges(html))


class PrivacySafeSummaryTests(unittest.TestCase):
    def test_exact_counts_and_numeric_ci_refs_only(self):
        summary = r2.privacy_safe_ci_summary(
            code_sha="a" * 40,
            environment_class="github-ci",
            test_count=152,
            passed_count=152,
            failed_count=0,
            blocked_count=0,
            run_id=32474951701,
            job_id=96749261701,
        )
        encoded = json.dumps(summary, sort_keys=True)
        self.assertNotIn("message", encoded.casefold())
        self.assertEqual(152, summary["passed_count"])

    def test_count_mismatch_private_environment_and_text_ci_ids_fail(self):
        with self.assertRaises(r2.OracleError):
            r2.privacy_safe_ci_summary(
                code_sha="a" * 40,
                environment_class="private-chat",
                test_count=1,
                passed_count=1,
                failed_count=0,
                blocked_count=0,
            )
        with self.assertRaises(r2.OracleError):
            r2.privacy_safe_ci_summary(
                code_sha="a" * 40,
                environment_class="github-ci",
                test_count=2,
                passed_count=1,
                failed_count=0,
                blocked_count=0,
            )
        with self.assertRaises(r2.OracleError):
            r2.privacy_safe_ci_summary(
                code_sha="a" * 40,
                environment_class="github-ci",
                test_count=1,
                passed_count=1,
                failed_count=0,
                blocked_count=0,
                run_id="synthetic-label",
            )


if __name__ == "__main__":
    unittest.main()
