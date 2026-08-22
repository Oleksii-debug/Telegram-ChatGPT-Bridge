# -*- coding: utf-8 -*-
from __future__ import annotations

import io
import json
import tempfile
import threading
import unittest
from pathlib import Path

from bridge.app import BridgeApplication, ReadAppConfig
from bridge.audit import AuditLog
from bridge.models import DialogRecord, EntityRef, MediaRecord, MessageRecord, Page
from bridge.security import RateLimitDecision
from bridge.integrated_app import UnifiedBridgeApplication, validate_unified_registry
from ops import openapi_registry
from ops.devc_release_qa import (
    assess_release_root,
    keyboard_nvda_protocol,
    release_live_protocols,
    validate_dependency_envelope,
    validate_devb_evidence_interface,
    validate_passenger_wsgi_source,
    validate_prepared_release_metadata,
)
from ops.release_package import validate_public_release_tree
from ops.telegram_write_adapter import DeterministicFakeTelegramClient, TelegramRuntimeConfig, TelegramWriteAdapter
from ops.write_endpoint_policy import FixedWindowEndpointLimiter

ROOT = Path(__file__).resolve().parents[1]
TOKEN = "devc-release-test-bearer-000000000001"
SIGN = "devc-release-test-signing-000000000001"
H = "a" * 64
SHA = "b" * 40


class AllowLimiter:
    def check(self, _actor):
        return RateLimitDecision(True, remaining=100)


class IntegratedBackend:
    def __init__(self):
        self.calls: list[tuple[str, dict]] = []
        self.dialogs = (
            DialogRecord("2", "group", "Synthetic Group", "preview", 1, False, "2026-08-21T09:00:00+00:00"),
        )
        self.messages = (
            MessageRecord(
                2,
                "2",
                "2026-08-21T09:00:00+00:00",
                "synthetic private body marker",
                EntityRef("20", "user", "Synthetic Person"),
                media=(MediaRecord("document", "tg_2_0123456789abcdefabcd", "sample.txt", "text/plain", 3),),
            ),
        )

    def list_dialogs(self, **kw):
        self.calls.append(("dialogs", kw))
        return Page(self.dialogs, None, 1)

    def history(self, **kw):
        self.calls.append(("history", kw))
        return Page(self.messages, None, 1)

    def search(self, **kw):
        self.calls.append(("search", kw))
        return Page(self.messages, None, 1)

    def get_message(self, **kw):
        self.calls.append(("message", kw))
        return self.messages[0]

    def download_media(self, **kw):
        self.calls.append(("download", kw))
        destination = Path(kw["destination"])
        destination.write_bytes(b"abc")
        return {"path": str(destination)}


def request(app, path: str, body=None, *, method="POST", auth=True, raw: bytes | None = None):
    payload = raw if raw is not None else json.dumps(body or {}, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    env = {
        "REQUEST_METHOD": method,
        "PATH_INFO": path,
        "QUERY_STRING": "",
        "wsgi.input": io.BytesIO(payload),
        "CONTENT_TYPE": "application/json",
        "CONTENT_LENGTH": str(len(payload)),
    }
    if auth:
        env["HTTP_AUTHORIZATION"] = "Bearer " + TOKEN
    seen: dict = {}

    def start(status, headers):
        seen["status"] = status
        seen["headers"] = dict(headers)

    output = b"".join(app(env, start))
    seen["raw"] = output
    if seen["headers"].get("Content-Type", "").startswith("application/json"):
        seen["json"] = json.loads(output.decode("utf-8"))
    return seen


class ReleasePackageIndependentTests(unittest.TestCase):
    def test_actual_parent_package_passes_independent_and_canonical_validators(self):
        wsgi = (ROOT / "passenger_wsgi.py").read_text(encoding="utf-8")
        req = (ROOT / "requirements.txt").read_text(encoding="utf-8")
        lock = (ROOT / "requirements.lock").read_text(encoding="utf-8")
        self.assertEqual([], validate_passenger_wsgi_source(wsgi))
        defects, direct, locked = validate_dependency_envelope(req, lock)
        self.assertEqual([], defects)
        self.assertEqual((1, 4), (direct, locked))
        result = validate_public_release_tree(
            ROOT,
            paths=("passenger_wsgi.py", "requirements.txt", "requirements.lock", "bridge/app.py"),
        )
        self.assertEqual(4, result["dependencies"]["package_count"])
        assessment = assess_release_root(ROOT)
        self.assertEqual("READY_FOR_PREPARE", assessment.status, assessment.defect_codes)

    def test_wsgi_rebind_mutation_is_rejected_by_devc_oracle(self):
        good = '"""safe"""\nfrom bridge.app import application\n__all__ = ["application"]\n'
        self.assertEqual([], validate_passenger_wsgi_source(good))
        bad = good + "application = None\n"
        self.assertIn("PASSENGER_WSGI_APPLICATION_REBOUND", validate_passenger_wsgi_source(bad))

    def test_wsgi_wrong_import_call_private_path_and_missing_are_rejected(self):
        self.assertIn("PASSENGER_WSGI_MISSING", validate_passenger_wsgi_source(None))
        self.assertIn(
            "PASSENGER_WSGI_CANONICAL_IMPORT_MISSING",
            validate_passenger_wsgi_source("from bridge.integrated_app import application\n"),
        )
        self.assertIn(
            "PASSENGER_WSGI_IMPORT_SIDE_EFFECT_RISK",
            validate_passenger_wsgi_source("from bridge.app import application\napplication()\n"),
        )
        self.assertIn(
            "PASSENGER_WSGI_PRIVATE_MATERIAL",
            validate_passenger_wsgi_source('"""/home/example TG_API_HASH"""\nfrom bridge.app import application\n'),
        )

    def test_dependency_missing_lock_bad_hash_floating_and_version_mismatch_fail(self):
        defects, _, _ = validate_dependency_envelope("Telethon==1.44.0\n", None)
        self.assertIn("REQUIREMENTS_LOCK_MISSING", defects)
        defects, _, _ = validate_dependency_envelope("Telethon>=1.44\n", f"Telethon==1.44.0 --hash=sha256:{H}\n")
        self.assertIn("REQUIREMENTS_INPUT_NOT_EXACT_PIN", defects)
        defects, _, _ = validate_dependency_envelope("Telethon==1.44.0\n", "Telethon==1.44.0 --hash=sha256:1234\n")
        self.assertIn("REQUIREMENTS_LOCK_NOT_EXACT_HASH_PIN", defects)
        defects, _, _ = validate_dependency_envelope("Telethon==1.44.0\n", f"Telethon==1.43.0 --hash=sha256:{H}\n")
        self.assertIn("DIRECT_LOCK_VERSION_MISMATCH", defects)

    def test_private_runtime_artifact_blocks_release_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "passenger_wsgi.py").write_text("from bridge.app import application\n", encoding="utf-8")
            (root / "requirements.txt").write_text("Telethon==1.44.0\n", encoding="utf-8")
            (root / "requirements.lock").write_text(f"Telethon==1.44.0 --hash=sha256:{H}\n", encoding="utf-8")
            (root / ".env").write_text("synthetic=not-a-secret\n", encoding="utf-8")
            result = assess_release_root(root)
            self.assertEqual("INTERNAL_RELEASE_BLOCKER", result.status)
            self.assertIn("PRIVATE_RUNTIME_ARTIFACT_IN_RELEASE", result.defect_codes)


class PreparedReleaseTruthTests(unittest.TestCase):
    @staticmethod
    def valid_meta():
        return {
            "schema_version": 2,
            "repository": "Oleksii-debug/Telegram-ChatGPT-Bridge",
            "approved_ref": "refs/heads/work3/integration-release-candidate",
            "sha": SHA,
            "configured_python_version": "3.11.16",
            "python_version": "3.11.16",
            "approved_python_identity": {"path": "/synthetic/python", "realpath": "/synthetic/python", "version": "3.11.16"},
            "source_manifest_sha256": H,
            "requirements_lock_sha256": H,
            "requirements_test_lock_sha256": None,
            "payload_manifest_sha256": H,
            "runtime_entries": [],
            "persistent_state_mode": "shared_external",
            "immutable_permission_policy": "no-write-bits-v1",
        }

    def test_runtime_entries_are_persistent_bindings_not_startup_accounting(self):
        self.assertEqual([], validate_prepared_release_metadata(self.valid_meta(), SHA))

    def test_stale_sha_bad_python_hash_and_runtime_entry_shape_fail(self):
        meta = self.valid_meta()
        meta["sha"] = "c" * 40
        meta["python_version"] = "3.10.99"
        meta["requirements_lock_sha256"] = None
        meta["runtime_entries"] = ["session", "session"]
        defects = validate_prepared_release_metadata(meta, SHA)
        self.assertIn("PREPARED_METADATA_STALE_SHA", defects)
        self.assertIn("PREPARED_METADATA_BUILT_PYTHON_INVALID", defects)
        self.assertIn("PREPARED_METADATA_HASH_MISSING_OR_INVALID", defects)
        self.assertIn("PREPARED_METADATA_RUNTIME_ENTRIES_INVALID", defects)


class DevBEvidenceTruthTests(unittest.TestCase):
    @staticmethod
    def payload(*, mode="LIVE_SERVER", lifecycle_class="FIRST_HAND_LIVE"):
        return {
            "schema_version": 1,
            "candidate_sha": SHA,
            "evidence_classes": {
                "source": "FIRST_HAND_LIVE",
                "runtime": "PRIVATE_SERVER_EVIDENCE",
                "lifecycle": lifecycle_class,
            },
            "server_manifest": {"artifact_sha256": H, "manifest_sha256": H, "file_count": 42},
            "reconciliation": {
                "artifact_sha256": H, "status": "EXACT_ACCOUNTED", "server_file_count": 42,
                "candidate_file_count": 100, "unreviewed_difference_count": 0, "startup_accounted": True,
            },
            "runtime": {
                "artifact_sha256": H, "collector_context": "APPLICATION_PROCESS",
                "python_major_minor": "3.11", "runtime_compliance": "PYTHON_3_11_APPLICATION_CONTEXT_CONFIRMED",
                "application_import_ok": True, "passenger_context_present": True, "wsgi_sha256": H,
            },
            "lifecycle": {
                "mode": mode, "candidate_sha": SHA,
                **{step: "PASS" for step in (
                    "backup", "restart", "running_identity", "health", "unauth_smoke", "auth_smoke", "resume", "rollback"
                )},
            },
            "privacy": {"private_values_copied": False, "raw_response_copied": False},
        }

    def test_live_semantics_pass(self):
        self.assertEqual([], validate_devb_evidence_interface(self.payload(), SHA))

    def test_simulation_and_cli_runtime_cannot_self_promote(self):
        simulated = self.payload(mode="TEST_SIMULATION", lifecycle_class="TEST_SIMULATION")
        self.assertIn("DEVB_SIMULATION_CANNOT_SATISFY_LIVE", validate_devb_evidence_interface(simulated, SHA))
        cli = self.payload()
        cli["runtime"]["collector_context"] = "PRIVATE_CLI_CANDIDATE"
        self.assertIn("DEVB_PASSENGER_CLAIM_UNSUPPORTED", validate_devb_evidence_interface(cli, SHA))

    def test_exact_reconciliation_and_privacy_are_fail_closed(self):
        payload = self.payload()
        payload["reconciliation"]["unreviewed_difference_count"] = 1
        payload["privacy"]["raw_response_copied"] = True
        defects = validate_devb_evidence_interface(payload, SHA)
        self.assertIn("DEVB_EXACT_RECONCILIATION_UNSUPPORTED", defects)
        self.assertIn("DEVB_PRIVACY_BOUNDARY_VIOLATION", defects)


class IntegratedReleaseSequenceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.backend = IntegratedBackend()
        self.audit = AuditLog()
        read = BridgeApplication(
            config=ReadAppConfig(
                auth_secret=TOKEN,
                file_signing_secret=SIGN,
                private_root=Path(self.tmp.name),
                public_base_url="https://bridge.example.invalid",
            ),
            backend=self.backend,
            rate_limiter=AllowLimiter(),
            audit=self.audit,
        )
        self.fake = DeterministicFakeTelegramClient()
        adapter = TelegramWriteAdapter(
            TelegramRuntimeConfig(
                application_id_ref=12345,
                application_hash_ref="synthetic-hash-reference",
                session_reference="synthetic-session-reference",
                synthetic_test_mode=True,
            ),
            lambda: self.fake,
        )
        self.app = UnifiedBridgeApplication(
            read_app=read,
            write_adapter=adapter,
            write_limiter=FixedWindowEndpointLimiter(limit=100, window_seconds=60, clock=lambda: 120.0),
        )

    def test_continuous_mocked_read_media_file_archive_write_sequence(self):
        self.assertTrue(request(self.app, "/health", method="GET", auth=False, raw=b"")["json"]["ready"])
        self.assertTrue(request(self.app, "/api/v1/dialogs/list", {"limit": 10})["status"].startswith("200"))
        self.assertTrue(request(self.app, "/api/v1/history/read", {"chat": "2"})["status"].startswith("200"))
        self.assertTrue(request(self.app, "/api/v1/search", {"text": "synthetic"})["status"].startswith("200"))
        media = request(self.app, "/api/v1/media/metadata", {"chat": "2", "message_id": 2})
        self.assertEqual("document", media["json"]["data"]["media"][0]["type"])

        item = {
            "chat": "2", "message_id": 2, "file_ref": "tg_2_0123456789abcdefabcd",
            "name": "sample.txt", "mime_type": "text/plain", "expected_size": 3,
        }
        single = request(self.app, "/api/v1/downloads/single", item)["json"]["data"]
        self.assertEqual(3, single["size"])
        bulk = request(self.app, "/api/v1/downloads/bulk", {"items": [dict(item, name="bulk.txt")]})["json"]["data"]
        self.assertIn("job_id", bulk)
        resumed = request(self.app, "/api/v1/downloads/resume", {"job_id": bulk["job_id"]})
        self.assertTrue(resumed["status"].startswith("200"))

        refs = [single["file_ref"]]
        for record in bulk.get("files", []):
            if isinstance(record, dict) and isinstance(record.get("file_ref"), str):
                refs.append(record["file_ref"])
        archive = request(self.app, "/api/v1/archives/create", {"file_refs": refs, "name": "bundle.zip"})
        self.assertTrue(archive["status"].startswith("200"), archive)
        file_meta = request(self.app, "/api/v1/files/get", {"file_ref": single["file_ref"]})
        self.assertNotIn("path", file_meta["json"]["data"])
        file_bytes = request(self.app, f"/api/v1/files/{single['file_ref']}", method="GET", raw=b"")
        self.assertEqual(b"abc", file_bytes["raw"])

        preview_paths = (
            ("/api/v1/messages/send/preview", {"chat": "100", "text": "synthetic write"}),
            ("/api/v1/messages/reply/preview", {"chat": "100", "reply_to_message_id": 1, "text": "reply"}),
            ("/api/v1/messages/forward/preview", {"from_chat": "200", "to_chat": "100", "message_ids": [1]}),
            ("/api/v1/files/send/preview", {
                "chat": "100", "files": [{"file_ref": single["file_ref"], "sha256": single["sha256"], "size": single["size"]}],
                "caption": "", "voice_note": False,
            }),
        )
        previews = []
        for path, body in preview_paths:
            response = request(self.app, path, body)
            self.assertTrue(response["status"].startswith("200"), (path, response))
            previews.append((path, response["json"]["data"]))
        self.assertEqual([], self.fake.external_writes)

        send_preview = previews[0][1]
        blocked = request(self.app, "/api/v1/messages/send/commit", {
            "preview_token": send_preview["preview_token"], "idempotency_key": "release-idem-0001",
            "explicit_user_command": False,
        })
        self.assertTrue(blocked["status"].startswith("409"), blocked)
        commit_body = {
            "preview_token": send_preview["preview_token"], "idempotency_key": "release-idem-0001",
            "explicit_user_command": True,
        }
        first = request(self.app, "/api/v1/messages/send/commit", commit_body)
        replay = request(self.app, "/api/v1/messages/send/commit", commit_body)
        self.assertTrue(first["status"].startswith("200"), first)
        self.assertTrue(replay["status"].startswith("200"), replay)
        self.assertFalse(first["json"]["data"]["idempotent_replay"])
        self.assertTrue(replay["json"]["data"]["idempotent_replay"])
        self.assertEqual(1, len(self.fake.external_writes))

        audit_text = json.dumps(self.audit.events, ensure_ascii=False)
        self.assertNotIn("synthetic private body marker", audit_text)
        self.assertNotIn("Synthetic Person", audit_text)
        self.assertNotIn(TOKEN, audit_text)
        self.assertNotIn(str(Path(self.tmp.name)), audit_text)

    def test_authentication_precedes_private_body_parsing_on_read_and_write(self):
        marker = b"PRIVATE_BODY_NOT_JSON"
        read = request(self.app, "/api/v1/dialogs/list", auth=False, raw=marker)
        write = request(self.app, "/api/v1/messages/send/preview", auth=False, raw=marker)
        self.assertTrue(read["status"].startswith("404"))
        self.assertTrue(write["status"].startswith("404"))
        self.assertNotIn(marker, read["raw"])
        self.assertNotIn(marker, write["raw"])
        self.assertEqual([], self.backend.calls)
        self.assertEqual([], self.fake.external_writes)

    def test_route_and_action_registry_are_deterministic_and_setup_free(self):
        schema1 = openapi_registry.build_action_openapi("https://bridge.example.invalid")
        schema2 = openapi_registry.build_action_openapi("https://bridge.example.invalid")
        self.assertEqual(schema1, schema2)
        self.assertEqual(17, len(openapi_registry.OPERATIONS))
        self.assertEqual(9, len(validate_unified_registry()))
        text = json.dumps(schema1, sort_keys=True).casefold()
        for marker in ("setup", "login_code", "session_string", "tg_api_hash"):
            self.assertNotIn(marker, text)

    def test_parallel_read_and_preview_namespaces_do_not_cross_effect_boundary(self):
        errors: list[str] = []
        barrier = threading.Barrier(8)

        def worker(index: int):
            try:
                barrier.wait(timeout=5)
                if index % 2:
                    response = request(self.app, "/api/v1/dialogs/list", {"limit": 1})
                else:
                    response = request(self.app, "/api/v1/messages/send/preview", {"chat": "100", "text": f"p{index}"})
                if not response["status"].startswith("200"):
                    errors.append(response["status"])
            except BaseException as exc:  # captured for deterministic assertion
                errors.append(type(exc).__name__)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)
        self.assertEqual([], errors)
        self.assertEqual([], self.fake.external_writes)


class ExternalProtocolTests(unittest.TestCase):
    def test_h1_h5_and_k1_k5_are_prepared_but_never_executed_here(self):
        protocols = release_live_protocols()
        self.assertEqual({"H1", "H2", "H3", "H4", "H5", "K1", "K2", "K3", "K4", "K5"}, set(protocols))
        self.assertTrue(all(item.execute_now is False for item in protocols.values()))
        self.assertTrue({
            "INDEPENDENT_AUDITOR_WRITE_APPROVAL", "SAFE_DESTINATION_CONFIRMED", "EXPLICIT_USER_COMMIT"
        }.issubset(protocols["K5"].required_gates))

    def test_keyboard_nvda_protocol_keeps_human_gate_explicit(self):
        protocol = keyboard_nvda_protocol()
        self.assertEqual(7, len(protocol))
        self.assertEqual(len(protocol), len({step[0] for step in protocol}))
        self.assertTrue(any(step[0] == "I4_ORDER" for step in protocol))
        self.assertTrue(any(step[0] == "I6_STATUS" for step in protocol))


if __name__ == "__main__":
    unittest.main()
