# -*- coding: utf-8 -*-
"""Adapted DEV5 fuzz/property regressions for the integrated candidate.

These tests preserve the predecessor adversarial vectors while executing them
against the actual authoritative DEV1/DEV3/DEV4/DEV_A interfaces.  They do not
restore rejected DEV5 acceptance/evidence implementations and never use live
Telegram, HOSTiQ, or credential material.
"""
from __future__ import annotations

import hashlib
import io
import json
import tempfile
import threading
import unicodedata
import unittest
import zipfile
from pathlib import Path

from bridge.app import BridgeApplication, ReadAppConfig
from bridge.archive import ArchiveBuilder, ArchiveLimits, safe_archive_name
from bridge.errors import BridgeError, HiddenNotFound
from bridge.security import BearerGuard, RateLimitDecision
from bridge.storage import FileRecordStore
from bridge.validation import bounded_int, validate_file_ref
from ops import acceptance_contracts as ac
from ops import acceptance_harness as harness
from ops import dev5_round2_oracles as r2
from ops import evidence_privacy as privacy
from ops.integration_interfaces import RoutePolicy, SAFE_ROUTE_CLASSES, WritePreview
from ops.release_guard import SafetyError
from ops.snapshot_candidate import canonical_path


def sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class _AllowLimiter:
    def check(self, actor: str) -> RateLimitDecision:
        del actor
        return RateLimitDecision(True, remaining=9)


_AUTH = "t" * 32


def _read_wsgi(raw: bytes, *, content_type: str = "application/json", content_length: int | None = None) -> dict:
    app = BridgeApplication(
        config=ReadAppConfig(auth_secret=_AUTH),
        rate_limiter=_AllowLimiter(),
    )
    environ = {
        "REQUEST_METHOD": "POST",
        "PATH_INFO": "/api/v1/dialogs/list",
        "QUERY_STRING": "",
        "CONTENT_TYPE": content_type,
        "CONTENT_LENGTH": str(len(raw) if content_length is None else content_length),
        "HTTP_AUTHORIZATION": "Bearer " + _AUTH,
        "wsgi.input": io.BytesIO(raw),
    }
    captured: dict[str, object] = {}

    def start_response(status, headers):
        captured["status"] = status
        captured["headers"] = dict(headers)

    body = b"".join(app(environ, start_response))
    captured["body"] = body
    captured["json"] = json.loads(body.decode("utf-8"))
    return captured


class TraversalFuzzTests(unittest.TestCase):
    def test_canonical_package_paths_fail_closed(self):
        bad = (
            "../x", "a/../x", "/etc/passwd", "//server/share",
            "a\\..\\x", "a/./b", "a//b", "a\x00b", "docs/e\u0301.txt",
        )
        for value in bad:
            with self.subTest(value=value), self.assertRaises(SafetyError):
                canonical_path(value)

    def test_encoded_windows_and_confusable_values_are_not_file_refs(self):
        bad = (
            "C:/temp/x", "%2e%2e/x", "%252e%252e/x", "a%2fb", "a%5cb",
            "a∕..∕b", "a／..／b", "a＼..＼b", "a\x00b",
        )
        for value in bad:
            with self.subTest(value=value), self.assertRaises(BridgeError):
                validate_file_ref(value)

    def test_safe_unicode_relative_paths_remain_nfc(self):
        for value in ("docs/звіт.txt", "voice/Повідомлення.ogg", "photo/фото-01.jpg"):
            with self.subTest(value=value):
                self.assertEqual(value, canonical_path(value))
                self.assertEqual(value, unicodedata.normalize("NFC", value))


class JsonAndRangeFuzzTests(unittest.TestCase):
    def test_actual_wsgi_json_type_utf8_and_length_matrix(self):
        cases = {
            b"{": "malformed_json",
            b"[]": "invalid_json_shape",
            b"null": "invalid_json_shape",
            b"\xff": "invalid_utf8",
            b'{"x":1,"x":2}': "duplicate_field",
        }
        for raw, code in cases.items():
            with self.subTest(raw=repr(raw)):
                result = _read_wsgi(raw)
                self.assertEqual(code, result["json"]["error"]["code"])
        self.assertEqual(
            "invalid_content_type",
            _read_wsgi(b"{}", content_type="text/plain")["json"]["error"]["code"],
        )
        self.assertEqual(
            "incomplete_body",
            _read_wsgi(b"{}", content_length=3)["json"]["error"]["code"],
        )
        self.assertEqual(
            "request_too_large",
            _read_wsgi(b"{}", content_length=999999)["json"]["error"]["code"],
        )

    def test_actual_integer_boundaries_reject_coercion(self):
        self.assertEqual(0, bounded_int(0, field="n", default=5, minimum=0, maximum=10))
        self.assertEqual(10, bounded_int(10, field="n", default=5, minimum=0, maximum=10))
        self.assertEqual(5, bounded_int(None, field="n", default=5, minimum=0, maximum=10))
        for value in (True, False, -1, 11, 1.5, "1"):
            with self.subTest(value=value), self.assertRaises(BridgeError):
                bounded_int(value, field="n", default=5, minimum=0, maximum=10)


class AuthFuzzTests(unittest.TestCase):
    def test_actual_bearer_guard_matrix_fails_closed(self):
        guard = BearerGuard(_AUTH)
        invalid = (
            None,
            "",
            " Bearer " + _AUTH,
            "Bearer " + _AUTH + " ",
            "bearer " + _AUTH,
            "Basic " + _AUTH,
            "Bearer two words",
            "Bearer " + ("w" * 32),
        )
        for header in invalid:
            environ = {}
            if header is not None:
                environ["HTTP_AUTHORIZATION"] = header
            with self.subTest(header=header), self.assertRaises(HiddenNotFound):
                guard.require(environ)
        guard.require({"HTTP_AUTHORIZATION": "Bearer " + _AUTH})


class EvidenceSemanticFuzzTests(unittest.TestCase):
    def test_private_like_legacy_refs_are_rejected(self):
        invalid = (
            "test:Olena", "chat:family", "person:ivan", "file:report", "private-note",
            "Олена", "чат:родина", "github:run:0", "github:run:abc", "test:sha256:short",
        )
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(ValueError):
                privacy.validate_evidence_ref(value)

    def test_structured_refs_and_reviewed_environment_classes_are_accepted(self):
        github = {
            "provider": "GITHUB_ACTIONS",
            "run_id": 32474951701,
            "job_id": 96749261701,
            "suite": "INTEGRATION_SUITE",
        }
        self.assertEqual(github, privacy.validate_evidence_ref(github))
        synthetic = {
            "provider": "SYNTHETIC_TEST",
            "suite": "UNIT_SUITE",
            "evidence_sha256": "b" * 64,
        }
        self.assertEqual(synthetic, privacy.validate_evidence_ref(synthetic))
        external = {"provider": "HOSTIQ_PRIVATE", "evidence_sha256": "c" * 64}
        self.assertEqual(external, privacy.validate_evidence_ref(external))
        self.assertEqual("GITHUB_CI", privacy.validate_environment_class("github-ci"))
        self.assertEqual("SYNTHETIC", privacy.validate_environment_class("synthetic"))
        self.assertEqual("HOSTIQ_PRIVATE_STAGING", privacy.validate_environment_class("HOSTIQ_PRIVATE_STAGING"))
        for env in ("reference-snapshot", "hostiq-staging", "prod-chat", "Олена", "private"):
            with self.subTest(env=env), self.assertRaises(ValueError):
                privacy.validate_environment_class(env)

    def test_private_identifiers_are_hash_only_and_namespace_separated(self):
        first = sha("chat\x00користувач")
        second = sha("file\x00користувач")
        facts = privacy.validate_facts(
            {"chat_sha256": first, "file_sha256": second},
            allowed_keys={"chat_sha256", "file_sha256"},
        )
        self.assertEqual(first, facts["chat_sha256"])
        self.assertNotEqual(first, second)
        self.assertNotIn("користувач", json.dumps(facts, ensure_ascii=False))
        with self.assertRaises(ValueError):
            privacy.validate_facts(
                {"chat_sha256": "користувач"}, allowed_keys={"chat_sha256"}
            )


class IntegratedArchivePropertyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.store = FileRecordStore(root / "state" / "files.sqlite3", root / "files")
        self.output = root / "archives"
        self.counter = 0

    def _add(self, name: str, content: bytes):
        self.counter += 1
        path = self.store.root / f"source-{self.counter}.bin"
        path.write_bytes(content)
        return self.store.add(path, name=name, mime_type="application/octet-stream")

    def test_casefold_and_unicode_normalization_collisions_are_disambiguated(self):
        rows = [
            self._add("A.txt", b"a"),
            self._add("a.txt", b"b"),
            self._add("é.txt", b"c"),
            self._add("e\u0301.txt", b"d"),
        ]
        builder = ArchiveBuilder(files=self.store, output_dir=self.output)
        archive_record = builder.build([row.file_ref for row in rows], archive_name="пакет.zip")
        with zipfile.ZipFile(archive_record.path, "r") as archive:
            names = archive.namelist()
            self.assertEqual(4, len(names))
            self.assertIsNone(archive.testzip())
            keys = [unicodedata.normalize("NFC", name).casefold() for name in names]
            self.assertEqual(len(keys), len(set(keys)))
            self.assertTrue(all(name == unicodedata.normalize("NFC", name) for name in names))

    def test_member_total_caps_crc_and_safe_names_use_actual_archive_builder(self):
        first = self._add("../звіт.txt", b"12")
        second = self._add("інший.txt", b"34")
        member_limited = ArchiveBuilder(
            files=self.store, output_dir=self.output / "member", limits=ArchiveLimits(max_members=1, max_total_bytes=100)
        )
        with self.assertRaises(BridgeError) as member_error:
            member_limited.build([first.file_ref, second.file_ref])
        self.assertEqual("zip_member_limit", member_error.exception.code)
        size_limited = ArchiveBuilder(
            files=self.store, output_dir=self.output / "size", limits=ArchiveLimits(max_members=10, max_total_bytes=3)
        )
        with self.assertRaises(BridgeError) as size_error:
            size_limited.build([first.file_ref, second.file_ref])
        self.assertEqual("zip_size_limit", size_error.exception.code)
        valid = ArchiveBuilder(files=self.store, output_dir=self.output / "valid")
        result = valid.build([first.file_ref])
        with zipfile.ZipFile(result.path, "r") as archive:
            self.assertIsNone(archive.testzip())
            self.assertEqual(["звіт.txt"], archive.namelist())
        self.assertEqual("звіт.txt", safe_archive_name("../../звіт.txt"))


class AccessibilityStructuralTruthTests(unittest.TestCase):
    def test_existing_structural_analysis_never_claims_human_nvda_pass(self):
        html = "<h1>Setup</h1><label for='x'>Code</label><input id='x'><button>Continue</button>"
        report = ac.analyze_accessibility(html)
        self.assertTrue(report["keyboard_operable"])
        self.assertTrue(report["labels_present"])
        self.assertTrue(report["accessible_names_present"])
        self.assertNotIn("human_nvda_pass", report)
        self.assertNotIn("nvda_pass", report)

    def test_pointer_only_negative_is_preserved_without_overclaiming_tab_or_status(self):
        html = "<h1>Setup</h1><div onclick='go()'>Mouse only</div><button>Continue</button>"
        report = ac.analyze_accessibility(html)
        self.assertFalse(report["keyboard_operable"])
        self.assertFalse(report["mouse_only_absent"])
        self.assertNotIn("tab_order_valid", report)
        self.assertNotIn("human_nvda_pass", report)


class AcceptanceEvidenceAdaptationTests(unittest.TestCase):
    def test_authoritative_harness_rejects_private_ref_and_accepts_structured_ci_ref(self):
        common = dict(
            criterion="B4",
            code_sha="a" * 40,
            environment_class="github-ci",
            result="PASS",
            facts={"success": True, "tree_scan_passed": True, "history_scan_passed": True, "findings_count": 0},
        )
        with self.assertRaises(ValueError):
            harness.build_result(evidence_ref="test:private-label", **common)
        result = harness.build_result(
            evidence_ref={
                "provider": "GITHUB_ACTIONS",
                "run_id": 32474951701,
                "job_id": 96749261701,
                "suite": "INTEGRATION_SUITE",
            },
            **common,
        )
        self.assertEqual("GITHUB_CI", result["environment_class"])
        serialized = harness.serialize_result(result)
        self.assertNotIn("private-label", serialized)
        self.assertIn("GITHUB_ACTIONS", serialized)


class IntegrationInterfaceCompatibilityTests(unittest.TestCase):
    def test_dev3_dev4_vocabulary_is_representable_without_weakening_write_policy(self):
        zero = "0" * 64
        preview = WritePreview(zero, "SEND_FILES", zero, zero, 1)
        self.assertEqual("SEND_FILES", preview.operation_kind)
        read = RoutePolicy("POST", "/api/v1/dialogs/list", "dialogs.list", "PROTECTED_READ")
        action = RoutePolicy("POST", "/api/v1/dialogs/list", "listTelegramDialogs", "PROTECTED_READ")
        signed = RoutePolicy("GET", "/api/v1/files/{file_ref}", "files.content", "PROTECTED_OR_SIGNED")
        self.assertEqual("dialogs.list", read.operation_id)
        self.assertEqual("listTelegramDialogs", action.operation_id)
        self.assertEqual("PROTECTED_OR_SIGNED", signed.classification)
        self.assertIn("PROTECTED_OR_SIGNED", SAFE_ROUTE_CLASSES)
        with self.assertRaises(ValueError):
            RoutePolicy("POST", "/api/v1/messages/send/commit", "commitTelegramSend", "PROTECTED_WRITE")
        committed = RoutePolicy(
            "POST", "/api/v1/messages/send/commit", "commitTelegramSend", "PROTECTED_WRITE", True
        )
        self.assertTrue(committed.preview_commit_required)


class OracleConcurrencyRegressionTests(unittest.TestCase):
    def test_idempotency_different_requests_same_key_never_both_reserve(self):
        store = r2.CrashSafeIdempotencyOracle()
        req_a = r2.CrashSafeIdempotencyOracle.fingerprint(
            operation_kind="SEND", target_sha256=sha("a"), payload_sha256=sha("p"), preview_sha256=sha("v")
        )
        req_b = r2.CrashSafeIdempotencyOracle.fingerprint(
            operation_kind="SEND", target_sha256=sha("b"), payload_sha256=sha("p"), preview_sha256=sha("v")
        )
        outcomes: list[str] = []
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
