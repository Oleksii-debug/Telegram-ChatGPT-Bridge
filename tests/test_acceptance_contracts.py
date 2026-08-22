# -*- coding: utf-8 -*-
from __future__ import annotations

import hashlib
import io
import json
import unittest
import zipfile

from ops import acceptance_contracts as ac


class SecurityContractsTests(unittest.TestCase):
    def test_authorization_contract(self):
        self.assertEqual("MISSING_AUTH", ac.authorization_outcome(auth_present=False, auth_matches=False))
        self.assertEqual("WRONG_AUTH", ac.authorization_outcome(auth_present=True, auth_matches=False))
        self.assertEqual("AUTHORIZED", ac.authorization_outcome(auth_present=True, auth_matches=True))

    def test_path_traversal_contract(self):
        for value in ("../private", "/absolute", "a\\b", "a/../b"):
            with self.subTest(value=value), self.assertRaises(ac.ContractError):
                ac.safe_relative_path(value)
        self.assertEqual("files/report.txt", ac.safe_relative_path("files/report.txt"))

    def test_rate_limit_contract(self):
        limiter = ac.FixedWindowRateLimiter(2)
        self.assertEqual((True, 1), limiter.consume("actor-hash"))
        self.assertEqual((True, 0), limiter.consume("actor-hash"))
        self.assertEqual((False, 0), limiter.consume("actor-hash"))


class TelegramFakeTests(unittest.TestCase):
    def test_setup_code_2fa_floodwait_rpc_contracts(self):
        flow = ac.FakeTelegramAuthFlow()
        self.assertEqual("CODE_REQUESTED", flow.request_code())
        self.assertEqual("FLOOD_WAIT", flow.request_code(flood_wait=True))
        self.assertEqual("RPC_ERROR", flow.request_code(rpc_failure=True))
        self.assertEqual("INVALID_CODE", flow.sign_in(code_valid=False))
        self.assertEqual("INVALID_2FA", flow.sign_in(code_valid=True, requires_2fa=True, second_factor_valid=False))
        self.assertEqual("AUTHORIZED", flow.sign_in(code_valid=True, requires_2fa=True, second_factor_valid=True))


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

    def test_search_filters_unicode_and_empty_results(self):
        self.assertEqual([1], [m.message_id for m in self.store.search(text="привіт")])
        self.assertEqual([3], [m.message_id for m in self.store.search(dialog_id=20, sender_id=100)])
        self.assertEqual([], self.store.search(text="missing"))
        self.assertEqual([2, 3], [m.message_id for m in self.store.search(date_from=1001)])


class MediaContractsTests(unittest.TestCase):
    def setUp(self):
        self.a = ac.SyntheticMedia("f1", "DOCUMENT", b"alpha")
        self.b = ac.SyntheticMedia("f2", "VOICE", b"beta")
        self.job = ac.SyntheticDownloadJob([self.a, self.b])

    def test_single_download_validates_expected_hash(self):
        self.assertEqual(b"alpha", self.job.download_one("f1", self.a.sha256))
        with self.assertRaises(ac.ContractError):
            self.job.download_one("f1", "0" * 64)

    def test_bulk_download_deduplicates(self):
        result = self.job.bulk(["f1", "f1", "f2"])
        self.assertEqual({"f1", "f2"}, set(result))

    def test_interrupted_download_is_recoverable(self):
        self.job.download_one("f1", self.a.sha256)
        self.job.mark_interrupted()
        resumed = self.job.resume()
        self.assertEqual({"f1": b"alpha"}, resumed)

    def test_zip_is_valid_and_traversal_safe(self):
        payload = ac.build_zip({"docs/a.txt": b"a", "voice/b.bin": b"b"})
        with zipfile.ZipFile(io.BytesIO(payload), "r") as archive:
            self.assertEqual(["docs/a.txt", "voice/b.bin"], sorted(archive.namelist()))
        with self.assertRaises(ac.ContractError):
            ac.build_zip({"../escape": b"x"})

    def test_private_file_serving_contract(self):
        self.assertEqual("PRIVATE_FILE_DENIED", ac.private_file_access(authorized=False))
        self.assertEqual("PRIVATE_FILE_ALLOWED", ac.private_file_access(authorized=True))


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

    def test_expired_and_invalid_preview_fail_safely(self):
        key = self.store.create_preview(action="REPLY", target_sha256=self.target, payload_sha256=self.payload, now=100, ttl_seconds=5)
        self.assertEqual("EXPIRED_PREVIEW", self.store.commit(key, now=106, idempotency_key="request-1"))
        self.assertEqual("INVALID_PREVIEW", self.store.commit("missing", now=101, idempotency_key="request-2"))

    def test_audit_metadata_contains_hashes_not_payload_body(self):
        key = self.store.create_preview(action="FORWARD", target_sha256=self.target, payload_sha256=self.payload, now=100)
        metadata = self.store.audit_metadata(key)
        encoded = json.dumps(metadata)
        self.assertEqual("FORWARD", metadata["operation_kind"])
        self.assertNotIn("payload body", encoded)
        self.assertEqual(self.payload, metadata["payload_sha256"])


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


class OpenApiContractsTests(unittest.TestCase):
    def test_safe_schema_contract(self):
        schema = {
            "openapi": "3.1.0",
            "paths": {
                "/health": {"get": {"responses": {"200": {}}, "x-protected": False}},
                "/messages": {"get": {"responses": {"200": {}}, "x-protected": True, "security": [{"bearerAuth": []}]}},
                "/send/preview": {"post": {"responses": {"200": {}}, "x-protected": True, "security": [{"bearerAuth": []}], "x-write-operation": True, "x-preview-commit": True}},
            },
        }
        self.assertEqual([], ac.validate_openapi_contract(schema))

    def test_schema_rejects_private_setup_and_unsafe_write(self):
        schema = {
            "openapi": "3.1.0",
            "paths": {
                "/setup-private": {"get": {"responses": {"200": {}}}},
                "/send": {"post": {"responses": {"200": {}}, "x-protected": True, "security": [{"bearerAuth": []}], "x-write-operation": True}},
            },
        }
        errors = ac.validate_openapi_contract(schema)
        self.assertIn("PRIVATE_SETUP_ROUTE_EXPOSED", errors)
        self.assertIn("WRITE_WITHOUT_PREVIEW_COMMIT", errors)


class AccessibilityContractsTests(unittest.TestCase):
    def test_accessible_keyboard_structure(self):
        html = """
        <h1>Setup</h1><h2>Account</h2>
        <label for='phone'>Phone</label><input id='phone'>
        <button>Continue</button><div aria-live='polite'>Status</div>
        """
        report = ac.analyze_accessibility(html)
        self.assertTrue(report["labels_present"])
        self.assertTrue(report["accessible_names_present"])
        self.assertTrue(report["heading_order_valid"])
        self.assertTrue(report["mouse_only_absent"])

    def test_missing_label_heading_jump_and_mouse_only_are_detected(self):
        html = """
        <h1>Setup</h1><h3>Skipped</h3>
        <input id='phone'><button aria-label='Continue'></button>
        <div onclick='doThing()'>Mouse only</div>
        """
        report = ac.analyze_accessibility(html)
        self.assertFalse(report["labels_present"])
        self.assertFalse(report["heading_order_valid"])
        self.assertFalse(report["mouse_only_absent"])


class CoverageContractsTests(unittest.TestCase):
    def test_coverage_report_contains_all_67_without_product_pass(self):
        report = ac.coverage_report()
        self.assertEqual(67, len(report))
        self.assertEqual(67, len({item["criterion"] for item in report}))
        self.assertNotIn("PASS", {item["coverage"] for item in report})
        self.assertEqual("SYNTHETIC_EXECUTABLE", next(item["coverage"] for item in report if item["criterion"] == "F5"))
        self.assertEqual("LIVE_EXTERNAL_REQUIRED", next(item["coverage"] for item in report if item["criterion"] == "K5"))

    def test_final_scenarios_never_claim_synthetic_pass_or_unapproved_write(self):
        k4 = ac.final_scenario_definition("K4")
        k5 = ac.final_scenario_definition("K5")
        self.assertFalse(k4["synthetic_pass_allowed"])
        self.assertFalse(k4["requires_explicit_write_approval"])
        self.assertTrue(k5["requires_explicit_write_approval"])
        self.assertTrue(k5["requires_live_telegram"])


if __name__ == "__main__":
    unittest.main()
