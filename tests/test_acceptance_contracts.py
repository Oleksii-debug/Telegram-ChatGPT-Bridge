# -*- coding: utf-8 -*-
from __future__ import annotations

import hashlib
import io
import json
import unittest
import zipfile
from concurrent.futures import ThreadPoolExecutor

from ops import acceptance_contracts as ac


class SecurityContractsTests(unittest.TestCase):
    def test_authorization_contract(self):
        self.assertEqual("MISSING_AUTH", ac.authorization_outcome(auth_present=False, auth_matches=False))
        self.assertEqual("WRONG_AUTH", ac.authorization_outcome(auth_present=True, auth_matches=False))
        self.assertEqual("AUTHORIZED", ac.authorization_outcome(auth_present=True, auth_matches=True))

    def test_bearer_auth_matrix(self):
        expected = hashlib.sha256(b"synthetic-correct-token").hexdigest()
        cases = [
            (None, "MISSING_AUTH"), ("", "MISSING_AUTH"), (" ", "MALFORMED_AUTH"),
            ("Bearer", "MALFORMED_AUTH"), ("bearer synthetic-correct-token", "MALFORMED_AUTH"),
            ("Bearer synthetic wrong", "MALFORMED_AUTH"),
            ("Bearer synthetic-wrong-token", "WRONG_AUTH"),
            ("Bearer synthetic-correct-token", "AUTHORIZED"),
        ]
        for header, expected_state in cases:
            with self.subTest(header=header):
                self.assertEqual(expected_state, ac.bearer_auth_outcome(header, expected_token_sha256=expected))

    def test_path_traversal_adversarial_matrix(self):
        unsafe = (
            "../private", "/absolute", "a\\b", "a/../b", "a/./b", "a//b",
            "C:/windows/system32", "//server/share", "\\\\server\\share",
            "%2e%2e/private", "%252e%252e/private", "a%2fb", "a%5cb",
            "a∕b", "a／b", "a＼b", "nul\x00byte", "./file",
        )
        for value in unsafe:
            with self.subTest(value=repr(value)), self.assertRaises(ac.ContractError):
                ac.safe_relative_path(value)
        self.assertEqual("files/report.txt", ac.safe_relative_path("files/report.txt"))
        self.assertEqual("дані/звіт.txt", ac.safe_relative_path("дані/звіт.txt"))
        self.assertEqual("docs/café.txt", ac.safe_relative_path("docs/cafe\u0301.txt"))

    def test_malformed_json_and_ranges_are_controlled(self):
        self.assertEqual({"ok": True}, ac.parse_json_object(b'{"ok":true}', content_length=11))
        cases = [
            (b"{", 1, "INVALID_JSON", 400),
            (b"[]", 2, "INVALID_JSON_SHAPE", 400),
            (b"{}", -1, "INVALID_CONTENT_LENGTH", 400),
            (b"{}", 1, "INVALID_CONTENT_LENGTH", 400),
            (b"x" * 20, 20, "PAYLOAD_TOO_LARGE", 413),
            (b"\xff", 1, "INVALID_JSON", 400),
        ]
        for raw, length, code, status in cases:
            with self.subTest(code=code):
                with self.assertRaises(ac.ControlledInputError) as ctx:
                    ac.parse_json_object(raw, content_length=length, max_bytes=10)
                self.assertEqual(code, ctx.exception.error_code)
                self.assertEqual(status, ctx.exception.status_code)
        self.assertEqual(5, ac.bounded_int(5, minimum=0, maximum=10))
        for value in (-1, 11, True, 1.5, "5"):
            with self.subTest(value=value), self.assertRaises(ac.ControlledInputError):
                ac.bounded_int(value, minimum=0, maximum=10)

    def test_rate_limit_contract_backward_compatible(self):
        limiter = ac.FixedWindowRateLimiter(2, window_seconds=60)
        self.assertEqual((True, 1), limiter.consume("actor-hash", now=0))
        self.assertEqual((True, 0), limiter.consume("actor-hash", now=1))
        self.assertEqual((False, 0), limiter.consume("actor-hash", now=2))

    def test_rate_limit_window_rollover_actor_and_retry_after(self):
        limiter = ac.FixedWindowRateLimiter(2, window_seconds=10)
        first = limiter.consume_with_metadata("actor-a", now=0)
        second = limiter.consume_with_metadata("actor-a", now=9)
        blocked = limiter.consume_with_metadata("actor-a", now=9.25)
        other = limiter.consume_with_metadata("actor-b", now=9.25)
        rollover = limiter.consume_with_metadata("actor-a", now=10)
        self.assertTrue(first.allowed)
        self.assertEqual(1, first.remaining)
        self.assertTrue(second.allowed)
        self.assertFalse(blocked.allowed)
        self.assertEqual(1, blocked.retry_after_seconds)
        self.assertTrue(other.allowed)
        self.assertTrue(rollover.allowed)
        self.assertEqual(10, rollover.window_start)
        lifetime = ac.FixedWindowRateLimiter(1, window_seconds=5)
        for window in range(50):
            now = window * 5
            self.assertTrue(lifetime.consume_with_metadata("actor", now=now).allowed)
            self.assertFalse(lifetime.consume_with_metadata("actor", now=now + 1).allowed)
        with self.assertRaises(ValueError):
            limiter.consume_with_metadata("bad actor", now=1)
        with self.assertRaises(ValueError):
            limiter.consume_with_metadata("actor", now=float("nan"))


class TelegramFakeTests(unittest.TestCase):
    def test_setup_code_2fa_floodwait_rpc_contracts(self):
        flow = ac.FakeTelegramAuthFlow()
        self.assertEqual("CODE_REQUESTED", flow.request_code())
        self.assertEqual("FLOOD_WAIT", flow.request_code(flood_wait=True))
        self.assertEqual("RPC_ERROR", flow.request_code(rpc_failure=True))
        self.assertEqual("INVALID_CODE", flow.sign_in(code_valid=False))
        self.assertEqual("INVALID_2FA", flow.sign_in(code_valid=True, requires_2fa=True, second_factor_valid=False))
        self.assertEqual("AUTHORIZED", flow.sign_in(code_valid=True, requires_2fa=True, second_factor_valid=True))

    def test_error_matrix_preserves_recoverable_checkpoint(self):
        for outcome in sorted(ac.TELEGRAM_FAKE_OUTCOMES - {"OK"}):
            state = ac.FakeTelegramOperationState()
            state.advance(7)
            result = state.run_outcome(outcome)
            with self.subTest(outcome=outcome):
                self.assertEqual(7, result["checkpoint"])
                self.assertTrue(result["recoverable"])
                self.assertIn(result["state"], {"RETRYABLE", "BLOCKED", "CANCELLED"})
        state = ac.FakeTelegramOperationState()
        state.advance(3)
        self.assertEqual("COMPLETED", state.run_outcome("OK")["state"])
        with self.assertRaises(ValueError):
            ac.FakeTelegramOperationState().run_outcome("PRIVATE_EXCEPTION_TEXT")


class ReadContractsTests(unittest.TestCase):
    def setUp(self):
        self.store = ac.SyntheticMessageStore([
            ac.SyntheticMessage(1, 10, 100, "Привіт світ", 1000),
            ac.SyntheticMessage(2, 10, 101, "Second message", 1001),
            ac.SyntheticMessage(3, 20, 100, "Ще один текст", 1002),
        ])

    def test_dialogs_history_pagination_and_ordering(self):
        self.assertEqual([10, 20], self.store.list_dialogs())
        self.assertEqual([1], [m.message_id for m in self.store.history(10, offset=0, limit=1)])
        self.assertEqual([2], [m.message_id for m in self.store.history(10, offset=1, limit=1)])
        with self.assertRaises(ac.ContractError):
            self.store.history(10, offset=-1)
        with self.assertRaises(ac.ContractError):
            self.store.history(10, limit=101)

    def test_search_filters_unicode_and_empty_results(self):
        self.assertEqual([1], [m.message_id for m in self.store.search(text="привіт")])
        self.assertEqual([3], [m.message_id for m in self.store.search(dialog_id=20, sender_id=100)])
        self.assertEqual([], self.store.search(text="missing"))
        self.assertEqual([2, 3], [m.message_id for m in self.store.search(date_from=1001)])
        self.assertEqual([1, 2], [m.message_id for m in self.store.search(date_to=1001)])


class MediaContractsTests(unittest.TestCase):
    def setUp(self):
        self.a = ac.SyntheticMedia("f1", "DOCUMENT", b"alpha")
        self.b = ac.SyntheticMedia("f2", "VOICE", b"beta")
        self.c = ac.SyntheticMedia("f3", "PHOTO", b"gamma")
        self.job = ac.SyntheticDownloadJob([self.a, self.b, self.c])

    def test_single_download_validates_expected_hash(self):
        self.assertEqual(b"alpha", self.job.download_one("f1", self.a.sha256))
        with self.assertRaises(ac.ContractError):
            self.job.download_one("f1", "0" * 64)
        with self.assertRaises(ac.ContractError):
            self.job.download_one("missing", "0" * 64)

    def test_bulk_download_deduplicates(self):
        result = self.job.bulk(["f1", "f1", "f2", "missing"])
        self.assertEqual({"f1", "f2"}, set(result))

    def test_interrupted_download_actually_resumes_pending_work(self):
        self.job.start_bulk(["f1", "f2", "f3"])
        self.assertTrue(self.job.run_next())
        self.assertEqual({"f1"}, set(self.job.completed))
        self.job.mark_interrupted()
        self.assertGreater(self.job.pending_count, 0)
        resumed = self.job.resume()
        self.assertEqual({"f1", "f2", "f3"}, set(resumed))
        self.assertEqual(0, self.job.pending_count)

    def test_zip_valid_crc_unicode_caps_and_traversal(self):
        payload = ac.build_zip([("docs/звіт.txt", b"a"), ("voice/b.bin", b"b")])
        with zipfile.ZipFile(io.BytesIO(payload), "r") as archive:
            self.assertIsNone(archive.testzip())
            self.assertEqual(["docs/звіт.txt", "voice/b.bin"], sorted(archive.namelist()))
        for entries in (
            [("../escape", b"x")], [("A.txt", b"a"), ("a.txt", b"b")],
            [("x", b"a"), ("y", b"b")],
        ):
            kwargs = {"max_members": 1} if len(entries) == 2 and entries[0][0] == "x" else {}
            with self.subTest(entries=entries), self.assertRaises(ac.ContractError):
                ac.build_zip(entries, **kwargs)
        with self.assertRaises(ac.ContractError):
            ac.build_zip([("large.bin", b"xx")], max_member_bytes=1)


class PrivateFileContractsTests(unittest.TestCase):
    def test_signed_private_file_adversarial_matrix(self):
        store = ac.SignedPrivateFileStore(b"synthetic-signing-key-material")
        digest = hashlib.sha256(b"dummy-file").hexdigest()
        store.add(file_id="file1", relative_path="private/report.bin", content_sha256=digest, max_downloads=1)
        token = store.issue("file1", expires_at=200)
        self.assertEqual("UNAUTHORIZED", store.authorize(token, now=100, authorized=False))
        self.assertEqual("FILE_ID_MISMATCH", store.authorize(token, now=100, authorized=True, requested_file_id="file2"))
        self.assertEqual("PATH_MISMATCH", store.authorize(token, now=100, authorized=True, relative_path="private/other.bin"))
        self.assertEqual("ALLOWED", store.authorize(token, now=100, authorized=True, relative_path="private/report.bin"))
        self.assertEqual("DOWNLOAD_LIMIT", store.authorize(token, now=101, authorized=True))
        store2 = ac.SignedPrivateFileStore(b"synthetic-signing-key-material")
        store2.add(file_id="file1", relative_path="private/report.bin", content_sha256=digest, max_downloads=2)
        token2 = store2.issue("file1", expires_at=200)
        tampered = token2[:-1] + ("0" if token2[-1] != "0" else "1")
        self.assertEqual("INVALID_SIGNATURE", store2.authorize(tampered, now=100, authorized=True))
        self.assertEqual("EXPIRED", store2.authorize(token2, now=201, authorized=True))
        store2.delete("file1")
        self.assertEqual("DELETED", store2.authorize(token2, now=100, authorized=True))


class WriteContractsTests(unittest.TestCase):
    def setUp(self):
        self.store = ac.PreviewCommitStore()
        self.target = hashlib.sha256(b"target").hexdigest()
        self.payload = hashlib.sha256(b"payload").hexdigest()

    def test_preview_commit_single_use_and_idempotency(self):
        key = self.store.create_preview(action="SEND", target_sha256=self.target, payload_sha256=self.payload, now=100)
        self.assertEqual("COMMITTED", self.store.commit(key, now=101, idempotency_key="request-1"))
        self.assertEqual("COMMITTED", self.store.commit(key, now=102, idempotency_key="request-1"))
        self.assertEqual("USED_PREVIEW", self.store.commit(key, now=103, idempotency_key="request-2"))

    def test_preview_commit_families_and_audit_metadata(self):
        for action in ("SEND", "REPLY", "FORWARD", "SEND_FILE", "SEND_FILES"):
            store = ac.PreviewCommitStore()
            key = store.create_preview(action=action, target_sha256=self.target, payload_sha256=self.payload, now=10)
            metadata = store.audit_metadata(key)
            encoded = json.dumps(metadata)
            with self.subTest(action=action):
                self.assertEqual(action, metadata["operation_kind"])
                self.assertEqual(self.payload, metadata["payload_sha256"])
                self.assertNotIn("payload body", encoded)
                self.assertEqual("COMMITTED", store.commit(key, now=11, idempotency_key="req-" + action.lower()))

    def test_idempotency_fingerprint_and_retry_after_expiry(self):
        first = self.store.create_preview(action="SEND", target_sha256=self.target, payload_sha256=self.payload, now=100, ttl_seconds=5)
        self.assertEqual("COMMITTED", self.store.commit(first, now=101, idempotency_key="shared-key"))
        self.assertEqual("COMMITTED", self.store.commit(first, now=999, idempotency_key="shared-key"))
        other_payload = hashlib.sha256(b"other").hexdigest()
        second = self.store.create_preview(action="SEND", target_sha256=self.target, payload_sha256=other_payload, now=100)
        self.assertEqual("IDEMPOTENCY_CONFLICT", self.store.commit(second, now=101, idempotency_key="shared-key"))

    def test_expired_invalid_and_mismatched_idempotency_fail_safely(self):
        key = self.store.create_preview(action="REPLY", target_sha256=self.target, payload_sha256=self.payload, now=100, ttl_seconds=5)
        self.assertEqual("EXPIRED_PREVIEW", self.store.commit(key, now=106, idempotency_key="request-1"))
        self.assertEqual("INVALID_PREVIEW", self.store.commit("missing", now=101, idempotency_key="request-2"))
        self.assertEqual("INVALID_IDEMPOTENCY_KEY", self.store.commit(key, now=101, idempotency_key=" bad "))

    def test_concurrent_same_request_commits_once_semantically(self):
        key = self.store.create_preview(action="FORWARD", target_sha256=self.target, payload_sha256=self.payload, now=100)
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(lambda _: self.store.commit(key, now=101, idempotency_key="concurrent-1"), range(8)))
        self.assertEqual(["COMMITTED"] * 8, results)
        self.assertTrue(self.store.audit_metadata(key)["used"])

    def test_idempotency_restart_state(self):
        key = self.store.create_preview(action="SEND_FILE", target_sha256=self.target, payload_sha256=self.payload, now=100)
        self.assertEqual("COMMITTED", self.store.commit(key, now=101, idempotency_key="restart-1"))
        restored = ac.PreviewCommitStore.from_state(self.store.export_state())
        self.assertEqual("COMMITTED", restored.commit(key, now=500, idempotency_key="restart-1"))
        bad_state = self.store.export_state()
        bad_state["idempotency"]["restart-1"]["request_sha256"] = "bad"
        with self.assertRaises(ac.ContractError):
            ac.PreviewCommitStore.from_state(bad_state)


class ReliabilityContractsTests(unittest.TestCase):
    def test_resumable_job_timeout_checkpoint_and_no_backward_move(self):
        job = ac.ResumableJob(timeout_ms=5000)
        job.advance(2)
        job.fail()
        self.assertEqual(2, job.resume())
        with self.assertRaises(ac.ContractError):
            job.advance(1)
        job.complete()
        self.assertEqual("COMPLETED", job.state)
        with self.assertRaises(ac.ContractError):
            job.resume()


class OpenApiContractsTests(unittest.TestCase):
    @staticmethod
    def error_response():
        return {
            "description": "controlled",
            "content": {"application/json": {"schema": {
                "type": "object", "required": ["error"],
                "properties": {"error": {"type": "string"}},
            }}},
        }

    def registry(self):
        return [
            ac.RoutePolicy("health", "/health", "GET", "PUBLIC", "READ"),
            ac.RoutePolicy("messages", "/messages", "GET", "PROTECTED", "READ"),
            ac.RoutePolicy("sendPreview", "/send/preview", "POST", "PROTECTED", "PREVIEW"),
            ac.RoutePolicy("sendCommit", "/send/commit", "POST", "PROTECTED", "COMMIT", "sendPreview"),
        ]

    def safe_schema(self):
        error = self.error_response()
        return {
            "openapi": "3.1.0",
            "paths": {
                "/health": {"get": {"operationId": "health", "responses": {"200": {}}}},
                "/messages": {"get": {
                    "operationId": "messages", "security": [{"bearerAuth": []}],
                    "responses": {"200": {}, "401": error, "429": error, "500": error, "503": error},
                }},
                "/send/preview": {"post": {
                    "operationId": "sendPreview", "security": [{"bearerAuth": []}],
                    "responses": {"200": {}, "400": error, "401": error, "429": error, "500": error},
                }},
                "/send/commit": {"post": {
                    "operationId": "sendCommit", "security": [{"bearerAuth": []}],
                    "responses": {"200": {}, "400": error, "401": error, "409": error, "429": error, "500": error},
                }},
            },
        }

    def test_registry_defaults_protected_without_self_marker(self):
        schema = self.safe_schema()
        self.assertEqual([], ac.validate_openapi_contract(schema, route_registry=self.registry()))
        del schema["paths"]["/messages"]["get"]["security"]
        self.assertIn("PROTECTED_WITHOUT_SECURITY", ac.validate_openapi_contract(schema, route_registry=self.registry()))
        inferred = {"openapi": "3.1.0", "paths": {"/messages": {"get": {"responses": {"200": {}}}}}}
        self.assertIn("PROTECTED_WITHOUT_SECURITY", ac.validate_openapi_contract(inferred))

    def test_x_marker_omission_cannot_bypass_write_policy(self):
        schema = self.safe_schema()
        schema["paths"]["/orphan"] = {"post": {"responses": {"200": {}}, "security": [{"bearerAuth": []}]}}
        errors = ac.validate_openapi_contract(schema)
        self.assertIn("WRITE_WITHOUT_PREVIEW_ROUTE", errors)

    def test_orphan_write_and_commit_routes_are_rejected(self):
        with self.assertRaises(ac.ContractError):
            ac.build_route_registry([
                ac.RoutePolicy("commit", "/send/commit", "POST", "PROTECTED", "COMMIT", "missingPreview"),
            ])
        schema = self.safe_schema()
        del schema["paths"]["/send/preview"]
        self.assertIn("ROUTE_REGISTRY_OPERATION_MISSING", ac.validate_openapi_contract(schema, route_registry=self.registry()))
        self.assertIn("WRITE_WITHOUT_PREVIEW_ROUTE", ac.validate_openapi_contract(schema, route_registry=self.registry()))

    def test_private_setup_route_is_rejected_from_paths_and_server_material(self):
        schema = self.safe_schema()
        schema["paths"]["/setup-private"] = {"get": {"responses": {"200": {}}}}
        self.assertIn("PRIVATE_SETUP_ROUTE_EXPOSED", ac.validate_openapi_contract(schema))
        schema = self.safe_schema()
        schema["servers"] = [{"url": "https://example.invalid/setup-PrivateRoute123456"}]
        self.assertIn("PRIVATE_SETUP_ROUTE_EXPOSED", ac.validate_openapi_contract(schema, route_registry=self.registry()))
        schema = self.safe_schema()
        schema["info"] = {"description": "ordinary setup documentation is allowed"}
        self.assertNotIn("PRIVATE_SETUP_ROUTE_EXPOSED", ac.validate_openapi_contract(schema, route_registry=self.registry()))

    def test_structured_error_response_policy(self):
        schema = self.safe_schema()
        self.assertEqual([], ac.validate_structured_error_responses(schema))
        bad = self.safe_schema()
        bad["paths"]["/messages"]["get"]["responses"]["401"] = {"description": "plain text"}
        self.assertIn("ERROR_RESPONSE_NOT_JSON", ac.validate_structured_error_responses(bad))
        bad = self.safe_schema()
        props = bad["paths"]["/messages"]["get"]["responses"]["401"]["content"]["application/json"]["schema"]["properties"]
        props["traceback"] = {"type": "string"}
        self.assertIn("PRIVATE_ERROR_FIELD_EXPOSED", ac.validate_structured_error_responses(bad))


class AccessibilityContractsTests(unittest.TestCase):
    def test_accessible_keyboard_structure(self):
        html = """
        <h1>Setup</h1><h2>Account</h2>
        <label for='phone'>Phone</label><input id='phone'>
        <button>Continue</button><div id='status' aria-live='polite'></div>
        """
        report = ac.analyze_accessibility(html)
        self.assertTrue(report["labels_present"])
        self.assertTrue(report["accessible_names_present"])
        self.assertTrue(report["heading_order_valid"])
        self.assertTrue(report["tab_order_valid"])
        self.assertTrue(report["status_messages_accessible"])
        self.assertTrue(report["mouse_only_absent"])
        self.assertTrue(report["structural_only"])
        self.assertFalse(report["human_nvda_pass"])

    def test_labels_nested_aria_and_broken_refs(self):
        good = """
        <h1>Setup</h1><label>Phone <input id='p'></label>
        <span id='name'>Email</span><input aria-labelledby='name'><input aria-label='Code'>
        <div id='status' role='status'></div>
        """
        self.assertTrue(ac.analyze_accessibility(good)["labels_present"])
        for bad in (
            "<h1>Setup</h1><input id='x' aria-labelledby='missing'><div id='status' role='status'></div>",
            "<h1>Setup</h1><input aria-label=''><div id='status' role='status'></div>",
        ):
            self.assertFalse(ac.analyze_accessibility(bad)["labels_present"])

    def test_accessible_names_and_icon_only_controls(self):
        good = "<h1>Setup</h1><button aria-label='Continue'><span aria-hidden='true'>▶</span></button><div id='status' role='status'></div>"
        self.assertTrue(ac.analyze_accessibility(good)["accessible_names_present"])
        bad = "<h1>Setup</h1><button><span aria-hidden='true'>▶</span></button><div id='status' role='status'></div>"
        self.assertFalse(ac.analyze_accessibility(bad)["accessible_names_present"])
        duplicate = "<h1>Setup</h1><button>Go</button><button>Go</button><div id='status' role='status'></div>"
        self.assertFalse(ac.analyze_accessibility(duplicate)["ambiguous_names_absent"])

    def test_tab_order_hidden_disabled_and_positive_tabindex(self):
        good = """
        <h1>Setup</h1><button>One</button><input aria-label='Two'>
        <button disabled>Disabled</button><button hidden>Hidden</button>
        <a href='/safe'>Three</a><div id='status' role='status'></div>
        """
        report = ac.analyze_accessibility(good)
        self.assertTrue(report["tab_order_valid"])
        self.assertEqual(3, report["focusable_count"])
        positive = "<h1>Setup</h1><button tabindex='2'>B</button><button tabindex='1'>A</button><div id='status' role='status'></div>"
        self.assertFalse(ac.analyze_accessibility(positive)["tab_order_valid"])
        essential = "<h1>Setup</h1><button tabindex='-1' data-essential='true'>Commit</button><div id='status' role='status'></div>"
        self.assertFalse(ac.analyze_accessibility(essential)["focus_reachable"])

    def test_heading_policy_missing_h1_jump_and_multiple_h1(self):
        valid_multiple = "<h1>Setup</h1><h2>A</h2><h1>Help</h1><h2>B</h2><div id='status' role='status'></div>"
        self.assertTrue(ac.analyze_accessibility(valid_multiple)["heading_order_valid"])
        for bad in (
            "<h2>No H1</h2><div id='status' role='status'></div>",
            "<h1>A</h1><h3>Jump</h3><div id='status' role='status'></div>",
        ):
            self.assertFalse(ac.analyze_accessibility(bad)["heading_order_valid"])

    def test_live_status_and_error_association(self):
        good = """
        <h1>Setup</h1><label for='code'>Code</label>
        <input id='code' aria-invalid='true' aria-errormessage='code-error'>
        <p id='code-error' role='alert'>Invalid code</p><div id='status' role='status'></div>
        """
        report = ac.analyze_accessibility(good)
        self.assertTrue(report["status_messages_accessible"])
        self.assertTrue(report["error_associations_valid"])
        bad = "<h1>Setup</h1><label for='x'>X</label><input id='x' aria-invalid='true' aria-errormessage='missing'><div aria-live='polite'></div>"
        report = ac.analyze_accessibility(bad)
        self.assertFalse(report["error_associations_valid"])
        self.assertFalse(report["status_messages_accessible"])

    def test_non_native_mouse_only_controls_require_keyboard_semantics(self):
        bad = "<h1>Setup</h1><div onclick='go()'>Go</div><div id='status' role='status'></div>"
        self.assertFalse(ac.analyze_accessibility(bad)["mouse_only_absent"])
        good = "<h1>Setup</h1><div role='button' tabindex='0' onclick='go()' onkeydown='key(event)'>Go</div><div id='status' role='status'></div>"
        self.assertTrue(ac.analyze_accessibility(good)["mouse_only_absent"])
        pointer = "<h1>Setup</h1><div onmouseover='show()'>Help</div><div id='status' role='status'></div>"
        self.assertFalse(ac.analyze_accessibility(pointer)["mouse_only_absent"])

    def test_report_has_rule_ids_counts_only_no_private_snippets(self):
        private_label = "Synthetic Private Person"
        html = f"<h1>Setup</h1><input aria-label='{private_label}'><div id='status' role='status'></div>"
        report = ac.analyze_accessibility(html)
        encoded = json.dumps(report["rule_results"], ensure_ascii=False)
        self.assertNotIn(private_label, encoded)
        self.assertEqual(len(report["rule_results"]), len({item["rule_id"] for item in report["rule_results"]}))
        self.assertTrue(all(set(item) == {"rule_id", "status", "findings_count"} for item in report["rule_results"]))


class CoverageContractsTests(unittest.TestCase):
    def test_coverage_report_contains_all_67_without_product_pass(self):
        report = ac.coverage_report()
        self.assertEqual(67, len(report))
        self.assertEqual(67, len({item["criterion"] for item in report}))
        self.assertNotIn("PASS", {item["coverage"] for item in report})
        self.assertEqual("SYNTHETIC_EXECUTABLE", next(item["coverage"] for item in report if item["criterion"] == "F5"))
        self.assertEqual("LIVE_EXTERNAL_REQUIRED", next(item["coverage"] for item in report if item["criterion"] == "K5"))
        self.assertEqual("REAL_SOURCE_REQUIRED", next(item["coverage"] for item in report if item["criterion"] == "I1"))
        self.assertEqual("REAL_SOURCE_REQUIRED", next(item["coverage"] for item in report if item["criterion"] == "I6"))
        self.assertEqual("REAL_SOURCE_REQUIRED", next(item["coverage"] for item in report if item["criterion"] == "H1"))

    def test_every_synthetic_criterion_has_specific_test_mapping(self):
        ac.validate_coverage_mapping()
        for item in ac.coverage_report():
            if item["coverage"] == "SYNTHETIC_EXECUTABLE":
                self.assertTrue(item["tests"], item["criterion"])
                self.assertTrue(all(name.startswith("test_") for name in item["tests"]))
            else:
                self.assertEqual([], item["tests"])

    def test_final_scenarios_never_claim_synthetic_pass_or_unapproved_write(self):
        k4 = ac.final_scenario_definition("K4")
        k5 = ac.final_scenario_definition("K5")
        self.assertFalse(k4["synthetic_pass_allowed"])
        self.assertFalse(k4["requires_explicit_write_approval"])
        self.assertTrue(k5["requires_explicit_write_approval"])
        self.assertTrue(k5["requires_live_telegram"])

    def test_privacy_safe_acceptance_run_summary(self):
        summary = ac.build_acceptance_run_summary(
            code_sha="a" * 40, environment_class="github-ci",
            passed_count=100, failed_count=2, blocked_count=3,
            evidence_refs=["github:run:32461101553", "github:job:96708043115"],
        )
        self.assertEqual(105, summary["test_count"])
        self.assertNotIn("message_body", json.dumps(summary))
        with self.assertRaises(ValueError):
            ac.build_acceptance_run_summary(
                code_sha="a" * 40, environment_class="github-ci",
                passed_count=1, failed_count=0, blocked_count=0,
                evidence_refs=["test:PrivateChatName"],
            )


if __name__ == "__main__":
    unittest.main()
