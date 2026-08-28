# -*- coding: utf-8 -*-
from __future__ import annotations

import math
import threading
import unittest

from ops.acceptance_contracts import ContractError, FixedWindowRateLimiter, PreviewCommitStore
from ops.devc_portable_qa import (
    EVIDENCE_CLASSES,
    EXPECTED_PREDECESSOR_SHAS,
    PortableQAError,
    QARoute,
    acceptance_plan,
    analyze_accessibility_source,
    classify_bearer_shape,
    coverage_counts,
    discover_candidate_routes,
    live_protocols,
    predecessor_reference_interfaces,
    predecessor_sha_matrix_valid,
    privacy_safe_sequence_summary,
    probe_integration_interface_compatibility,
    strict_relative_path,
    validate_acceptance_plan,
    validate_public_summary,
    validate_route_action_contract,
)


class MutableClock:
    def __init__(self, value: float = 0.0) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value


class AcceptanceTruthTests(unittest.TestCase):
    def test_exact_67_and_truth_boundaries(self):
        plan = acceptance_plan()
        self.assertEqual(67, len(plan))
        self.assertEqual(set(EVIDENCE_CLASSES), set(coverage_counts(plan)))
        self.assertEqual(67, sum(coverage_counts(plan).values()))
        for criterion in ("K1", "K2", "K3", "K4", "K5"):
            self.assertEqual("LIVE_EXTERNAL_REQUIRED", plan[criterion].evidence_class)
        self.assertTrue(plan["K5"].explicit_write_approval_required)
        for criterion in ("I1", "I4", "I6"):
            self.assertTrue(plan[criterion].human_verification_required)

    def test_pass_label_missing_and_identity_mismatch_fail(self):
        plan = acceptance_plan()
        changed = dict(plan)
        item = plan["B8"]
        changed["B8"] = type(item)("B8", "PASS")
        with self.assertRaises(PortableQAError):
            validate_acceptance_plan(changed)
        missing = dict(plan)
        missing.pop("D1")
        with self.assertRaises(PortableQAError):
            validate_acceptance_plan(missing)
        mismatch = dict(plan)
        mismatch["D1"] = type(plan["D1"])("D2", plan["D1"].evidence_class)
        with self.assertRaises(PortableQAError):
            validate_acceptance_plan(mismatch)

    def test_predecessor_sha_matrix(self):
        self.assertTrue(predecessor_sha_matrix_valid())
        self.assertEqual({"DEV1", "DEV2", "DEV3", "DEV4", "DEV5"}, set(EXPECTED_PREDECESSOR_SHAS))


class Dev1RateAndIdempotencyTests(unittest.TestCase):
    def test_rate_rollover_invalid_time_capacity_and_concurrency(self):
        clock = MutableClock(0.0)
        limiter = FixedWindowRateLimiter(2, window_seconds=10, clock=clock, max_actors=2)
        self.assertTrue(limiter.consume("actor-a").allowed)
        self.assertTrue(limiter.consume("actor-a").allowed)
        denied = limiter.consume("actor-a")
        self.assertFalse(denied.allowed)
        self.assertEqual(10, denied.retry_after_seconds)
        self.assertTrue(limiter.consume("actor-b").allowed)
        with self.assertRaises(ContractError):
            limiter.consume("actor-c")
        clock.value = 10.0
        self.assertTrue(limiter.consume("actor-c").allowed)
        self.assertEqual(1, limiter.tracked_actors)

        for bad in (-1.0, math.nan, math.inf, -math.inf):
            bad_clock = MutableClock(bad)
            with self.assertRaises(ContractError):
                FixedWindowRateLimiter(1, clock=bad_clock).consume("actor")
        clock2 = MutableClock(20.0)
        limiter2 = FixedWindowRateLimiter(2, clock=clock2)
        limiter2.consume("actor")
        clock2.value = 19.0
        with self.assertRaises(ContractError):
            limiter2.consume("actor")

        clock3 = MutableClock(0.0)
        limiter3 = FixedWindowRateLimiter(5, clock=clock3)
        decisions: list[bool] = []
        guard = threading.Lock()

        def worker() -> None:
            allowed = limiter3.consume("same-actor").allowed
            with guard:
                decisions.append(allowed)

        threads = [threading.Thread(target=worker) for _ in range(30)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(5, sum(decisions))
        self.assertEqual(30, len(decisions))

    def _store(self):
        store = PreviewCommitStore(retention_seconds=300)
        preview = store.create_preview(
            action="SEND", target_sha256="1" * 64, payload_sha256="2" * 64, now=0, ttl_seconds=10
        )
        return store, preview

    def test_idempotency_replay_conflict_restart_and_tombstone(self):
        store, preview = self._store()
        self.assertEqual("COMMITTED", store.commit(preview, now=1, idempotency_key="idem-a"))
        self.assertEqual("COMMITTED", store.commit(preview, now=999, idempotency_key="idem-a"))
        self.assertEqual(1, store.external_write_count)

        second = store.create_preview(
            action="SEND", target_sha256="1" * 64, payload_sha256="3" * 64, now=0, ttl_seconds=10
        )
        self.assertEqual("IDEMPOTENCY_CONFLICT", store.commit(second, now=2, idempotency_key="idem-a"))
        store.prune(now=1400)
        self.assertEqual("IDEMPOTENCY_RETIRED", store.commit(preview, now=1401, idempotency_key="idem-a"))

        reserved, reserved_preview = self._store()
        self.assertEqual("READY_TO_WRITE", reserved.begin_commit(reserved_preview, now=1, idempotency_key="idem-b"))
        restored = PreviewCommitStore.restore_state(reserved.export_state())
        self.assertEqual("RECONCILE_REQUIRED", restored.begin_commit(reserved_preview, now=2, idempotency_key="idem-b"))
        self.assertEqual(0, restored.external_write_count)


class SecurityAndPrivacyTests(unittest.TestCase):
    def test_bearer_shape_without_credentials(self):
        self.assertEqual("MISSING", classify_bearer_shape(None))
        for bad in ("", "Bearer", "bearer sample", "Bearer  sample", " Bearer sample", "Basic sample", "Bearer sample value"):
            self.assertEqual("MALFORMED", classify_bearer_shape(bad), bad)
        self.assertEqual("SHAPE_VALID", classify_bearer_shape("Bearer placeholder"))

    def test_path_traversal_and_valid_cyrillic(self):
        unsafe = (
            "../x", "a/../x", "/etc/passwd", "C:/temp/x", "C:\\temp\\x", "//server/share",
            "%2e%2e/x", "%252e%252e/x", "a%2f..%2fx", "a%252f..%252fx", "a\\..\\x",
            "a/\u2215/x", "a/\uff0f/x", "a/%00x", "a//x", "./x", "a/./x",
        )
        for value in unsafe:
            with self.assertRaises(PortableQAError, msg=value):
                strict_relative_path(value)
        self.assertEqual("дані/файл.txt", strict_relative_path("дані/файл.txt"))
        self.assertEqual("дані/й.txt", strict_relative_path("дані/и\u0306.txt"))

    def test_public_summary_and_mock_sequence_are_body_free(self):
        safe = {
            "criterion": "B4", "evidence_class": "SYNTHETIC_EXECUTABLE", "count": 2,
            "code_sha": "a" * 40, "sha256": "b" * 64, "success": True,
        }
        validate_public_summary(safe)
        with self.assertRaises(PortableQAError):
            validate_public_summary({"detail": "private label"})
        with self.assertRaises(PortableQAError):
            validate_public_summary({"state": "довільний текст"})
        summary = privacy_safe_sequence_summary(
            {"LIST": 2, "HISTORY": 3, "SEARCH": 1, "MEDIA": 2, "DOWNLOAD": 1, "ARCHIVE": 1, "PREVIEW": 1, "COMMIT_ERROR": 1},
            "c" * 40,
        )
        self.assertRegex(str(summary["operation_sha256"]), r"^[0-9a-f]{64}$")
        self.assertNotIn("body", " ".join(summary))


class RouteActionIntegrationTests(unittest.TestCase):
    def test_predecessor_reference_contract_and_non_action_allowlist(self):
        read_routes, action_routes = predecessor_reference_interfaces()
        self.assertEqual([], validate_route_action_contract(read_routes, action_routes))
        excluded = {route.key for route in read_routes if not route.action_exported}
        self.assertEqual({("GET", "/health"), ("GET", "/api/v1/files/{file_ref}")}, excluded)

    def test_route_schema_negative_mutations(self):
        read_routes, action_routes = predecessor_reference_interfaces()
        missing = tuple(route for route in action_routes if route.path != "/api/v1/search")
        self.assertIn("READ_ACTION_ROUTE_DRIFT", validate_route_action_contract(read_routes, missing))
        extra_public = QARoute("GET", "/public-extra", "public.extra", "public", "read", False)
        self.assertIn("PUBLIC_ALLOWLIST_DRIFT", validate_route_action_contract(read_routes + (extra_public,), action_routes))
        commit_index = next(i for i, route in enumerate(action_routes) if route.operation_class == "write_commit")
        original = action_routes[commit_index]
        unsafe_commit = QARoute(
            original.method, original.path, original.operation_id, original.access, original.operation_class, True,
            action=original.action, pair_operation_id=original.pair_operation_id,
            explicit_user_command_required=False, consequential=False,
        )
        mutated = action_routes[:commit_index] + (unsafe_commit,) + action_routes[commit_index + 1 :]
        defects = validate_route_action_contract(read_routes, mutated)
        self.assertIn("COMMIT_NOT_CONSEQUENTIAL", defects)
        self.assertIn("COMMIT_MISSING_EXPLICIT_COMMAND", defects)

    def test_current_candidate_interface_vocabulary_is_fully_reconciled(self):
        discovered = discover_candidate_routes()
        if discovered is None:
            self.assertEqual(["INTEGRATED_CANDIDATE_NOT_PRESENT"], probe_integration_interface_compatibility())
            return
        self.assertEqual([], probe_integration_interface_compatibility())
        try:
            from bridge.integrated_app import validate_unified_registry
        except (ImportError, ModuleNotFoundError):
            return
        parity = validate_unified_registry()
        self.assertGreater(len(parity), 0)


class AccessibilityTests(unittest.TestCase):
    def test_structural_positive(self):
        html = """
        <main><h1>Setup</h1><form>
          <label for="field">Phone</label>
          <input id="field" aria-describedby="help">
          <p id="help" role="status" aria-live="polite">Status</p>
          <button type="submit">Continue</button>
        </form></main>
        """
        self.assertEqual([], analyze_accessibility_source(html))

    def test_structural_negative_matrix(self):
        html = """
        <h1>A</h1><h3>C</h3><form>
          <input id="dup" aria-invalid="true">
          <input id="dup" aria-labelledby="missing">
          <button type="button"></button>
        </form>
        <div role="button" tabindex="2" onmouseover="go()">Continue</div>
        """
        defects = set(analyze_accessibility_source(html))
        expected = {
            "DUPLICATE_ID", "BROKEN_ARIA_REFERENCE", "UNLABELED_INPUT", "UNNAMED_BUTTON",
            "HEADING_LEVEL_JUMP", "FORM_WITHOUT_SUBMIT_SEMANTICS", "INVALID_INPUT_WITHOUT_TEXT_ASSOCIATION",
            "POSITIVE_TABINDEX", "POINTER_ONLY_CONTROL", "NON_NATIVE_CONTROL_MISSING_KEYBOARD_SEMANTICS",
        }
        self.assertTrue(expected.issubset(defects), expected - defects)

    def test_keyboard_and_nvda_remain_human_live(self):
        plan = acceptance_plan()
        for criterion in ("I1", "I4", "I6"):
            self.assertEqual("LIVE_EXTERNAL_REQUIRED", plan[criterion].evidence_class)
            self.assertTrue(plan[criterion].human_verification_required)


class LiveProtocolTests(unittest.TestCase):
    def test_h2_k1_k5_never_auto_execute_and_k5_is_doubly_gated(self):
        protocols = live_protocols()
        self.assertEqual({"H2", "K1", "K2", "K3", "K4", "K5"}, set(protocols))
        self.assertTrue(all(not protocol.execute_now for protocol in protocols.values()))
        gates = set(protocols["K5"].required_gates)
        self.assertIn("INDEPENDENT_AUDITOR_WRITE_APPROVAL", gates)
        self.assertIn("EXPLICIT_USER_COMMIT", gates)
        self.assertIn("SAFE_DESTINATION_CONFIRMED", gates)


if __name__ == "__main__":
    unittest.main()
