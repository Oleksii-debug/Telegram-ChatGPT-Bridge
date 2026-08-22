# -*- coding: utf-8 -*-
"""DEV_C gates for the current unified DEV_A validation head.

All Telegram behavior here uses deterministic synthetic adapters. Nothing in
this module performs live Telegram, HOSTiQ or ChatGPT Action I/O. Release-package
checks are static/non-live and return bounded defect codes rather than exposing
file contents in evidence.
"""
from __future__ import annotations

import ast
import io
import json
import os
import re
import tempfile
import unittest
from pathlib import Path

try:
    from bridge.app import BridgeApplication, ReadAppConfig
    from bridge.audit import AuditLog
    from bridge.integrated_app import UnifiedBridgeApplication, validate_unified_registry
    from bridge.models import DialogRecord, EntityRef, MediaRecord, MessageRecord, Page
    from bridge.routes import registry_snapshot
    from bridge.security import RateLimitDecision
    from ops import openapi_registry
    from ops.openapi_registry import OperationClass
    from ops.telegram_write_adapter import (
        DeterministicFakeTelegramClient,
        TelegramRuntimeConfig,
        TelegramWriteAdapter,
    )
    from ops.write_endpoint_policy import FixedWindowEndpointLimiter
    CANDIDATE_COMPONENTS_AVAILABLE = True
except (ImportError, ModuleNotFoundError):
    CANDIDATE_COMPONENTS_AVAILABLE = False


TEST_AUTH_SECRET = "devc-placeholder-auth-secret-0001"
TEST_SIGNING_SECRET = "devc-placeholder-signing-secret-0001"
REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
_REQUIRED_RELEASE_FILES = ("passenger_wsgi.py", "requirements.txt", "requirements.lock")
_REQUIREMENT_NAME_RE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9_.-]*)")
_LOCKED_REQUIREMENT_RE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9_.-]*)==([^\s;\\]+)")
_HASH_RE = re.compile(r"--hash=sha256:([0-9a-fA-F]{64})(?:\s|$)")


class AllowReadLimiter:
    def check(self, _actor_class):
        return RateLimitDecision(True, remaining=99)


class EmptyReadBackend:
    def list_dialogs(self, **_kwargs):
        return Page(tuple(), None, 0)

    def history(self, **_kwargs):
        return Page(tuple(), None, 0)

    def search(self, **_kwargs):
        return Page(tuple(), None, 0)

    def get_message(self, **_kwargs):
        raise AssertionError("not used by DEV_C integrated QA")

    def download_media(self, **_kwargs):
        raise AssertionError("not used by DEV_C integrated QA")


class ScenarioReadBackend:
    """Deterministic read/media backend for one continuous Action-style flow."""

    def __init__(self):
        self.calls: list[tuple[str, dict]] = []
        self.media_bytes = b"devc-synthetic-media-payload"
        self.source_ref = "tg_2_0123456789abcdefabcd"
        self.private_title = "DEV_C_PRIVATE_CHAT_LABEL"
        self.private_sender = "DEV_C_PRIVATE_PERSON_LABEL"
        self.private_body = "DEV_C_PRIVATE_MESSAGE_BODY"
        media = MediaRecord(
            "document",
            self.source_ref,
            "devc-private-file.bin",
            "application/octet-stream",
            len(self.media_bytes),
        )
        self.dialogs = (
            DialogRecord("2", "group", self.private_title, None, 1, False, "2026-08-22T18:00:00+00:00"),
        )
        self.messages = (
            MessageRecord(
                2,
                "2",
                "2026-08-22T18:00:00+00:00",
                self.private_body,
                EntityRef("20", "user", self.private_sender),
                media=(media,),
            ),
        )

    def list_dialogs(self, **kwargs):
        self.calls.append(("dialogs", kwargs))
        return Page(self.dialogs, None, len(self.dialogs))

    def history(self, **kwargs):
        self.calls.append(("history", kwargs))
        return Page(self.messages, None, len(self.messages))

    def search(self, **kwargs):
        self.calls.append(("search", kwargs))
        return Page(self.messages, None, len(self.messages))

    def get_message(self, **kwargs):
        self.calls.append(("message", kwargs))
        return self.messages[0]

    def download_media(self, **kwargs):
        self.calls.append(("download", kwargs))
        target = Path(kwargs["destination"])
        target.write_bytes(self.media_bytes)
        return {"path": str(target)}


def _request(app, path: str, body: dict | None = None, *, method: str = "POST", auth: bool = True) -> dict:
    raw = json.dumps(body or {}, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    environ = {
        "REQUEST_METHOD": method,
        "PATH_INFO": path,
        "QUERY_STRING": "",
        "wsgi.input": io.BytesIO(raw),
        "CONTENT_TYPE": "application/json",
        "CONTENT_LENGTH": str(len(raw)),
    }
    if auth:
        environ["HTTP_AUTHORIZATION"] = f"Bearer {TEST_AUTH_SECRET}"
    seen: dict = {}

    def start_response(status, headers):
        seen["status"] = status
        seen["headers"] = dict(headers)

    payload = b"".join(app(environ, start_response))
    seen["raw"] = payload
    content_type = seen["headers"].get("Content-Type", "")
    if content_type.startswith("application/json"):
        seen["payload"] = json.loads(payload.decode("utf-8"))
    return seen


def _normalise_requirement_name(value: str) -> str | None:
    match = _REQUIREMENT_NAME_RE.match(value)
    if match is None:
        return None
    return match.group(1).replace("_", "-").casefold()


def _logical_requirement_blocks(text: str) -> list[str]:
    blocks: list[str] = []
    current = ""
    for raw in text.splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        current = f"{current} {stripped}".strip() if current else stripped
        if current.endswith("\\"):
            current = current[:-1].rstrip()
            continue
        blocks.append(current)
        current = ""
    if current:
        blocks.append(current)
    return blocks


def _passenger_wsgi_defects(path: Path) -> set[str]:
    defects: set[str] = set()
    if path.is_symlink() or not path.is_file():
        return {"UNSAFE_PASSENGER_WSGI_TOPOLOGY"}
    try:
        text = path.read_text(encoding="utf-8")
        tree = ast.parse(text, filename="passenger_wsgi.py")
    except (OSError, UnicodeError, SyntaxError):
        return {"PASSENGER_WSGI_PARSE_ERROR"}

    import_ok = False
    for node in tree.body:
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            continue
        if isinstance(node, ast.ImportFrom):
            if (
                node.module == "bridge.app"
                and node.level == 0
                and len(node.names) == 1
                and node.names[0].name == "application"
                and node.names[0].asname is None
            ):
                import_ok = True
                continue
        defects.add("PASSENGER_WSGI_IMPORT_SIDE_EFFECT")
    if not import_ok:
        defects.add("PASSENGER_WSGI_WRONG_IMPORT")
    if any(isinstance(node, ast.Call) for node in ast.walk(tree)):
        defects.add("PASSENGER_WSGI_IMPORT_SIDE_EFFECT")
    return defects


def _requirements_defects(input_path: Path, lock_path: Path) -> set[str]:
    defects: set[str] = set()
    if input_path.is_symlink() or (input_path.exists() and not input_path.is_file()):
        defects.add("UNSAFE_REQUIREMENTS_INPUT_TOPOLOGY")
    if lock_path.is_symlink() or (lock_path.exists() and not lock_path.is_file()):
        defects.add("UNSAFE_REQUIREMENTS_LOCK_TOPOLOGY")
    if defects:
        return defects

    input_names: set[str] = set()
    if input_path.exists():
        try:
            input_blocks = _logical_requirement_blocks(input_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError):
            defects.add("REQUIREMENTS_INPUT_UNREADABLE")
            input_blocks = []
        if not input_blocks:
            defects.add("REQUIREMENTS_INPUT_EMPTY")
        for block in input_blocks:
            lowered = block.casefold()
            if lowered.startswith(("-e ", "--editable ", "-r ", "--requirement ")) or "git+" in lowered or " @ " in block or "://" in block:
                defects.add("REQUIREMENTS_INPUT_UNSAFE_SOURCE")
                continue
            name = _normalise_requirement_name(block)
            if name is None:
                defects.add("REQUIREMENTS_INPUT_INVALID")
            else:
                input_names.add(name)

    lock_names: set[str] = set()
    if lock_path.exists():
        try:
            lock_blocks = _logical_requirement_blocks(lock_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError):
            defects.add("REQUIREMENTS_LOCK_UNREADABLE")
            lock_blocks = []
        if not lock_blocks:
            defects.add("REQUIREMENTS_LOCK_EMPTY")
        for block in lock_blocks:
            lowered = block.casefold()
            if lowered.startswith(("-e ", "--editable ", "-r ", "--requirement ")) or "git+" in lowered or " @ " in block or "://" in block:
                defects.add("REQUIREMENTS_LOCK_UNSAFE_SOURCE")
                continue
            match = _LOCKED_REQUIREMENT_RE.match(block)
            if match is None:
                defects.add("REQUIREMENTS_LOCK_UNPINNED")
                continue
            name = match.group(1).replace("_", "-").casefold()
            lock_names.add(name)
            if _HASH_RE.search(block) is None:
                defects.add("REQUIREMENTS_LOCK_MISSING_HASH")

    if input_path.exists() and not lock_path.exists():
        defects.add("MISSING_REQUIREMENTS_LOCK")
    if lock_path.exists() and input_path.exists() and not input_names.issubset(lock_names):
        defects.add("REQUIREMENTS_INPUT_LOCK_DRIFT")
    if lock_path.exists() and "telethon" not in lock_names:
        defects.add("TELETHON_NOT_LOCKED")
    return defects


def _release_package_defects(root: Path) -> list[str]:
    """Return bounded Release-to-Live package defect codes without content evidence."""
    defects: set[str] = set()
    for name in _REQUIRED_RELEASE_FILES:
        if not (root / name).exists():
            defects.add(f"MISSING_{name.upper().replace('.', '_')}")
    passenger = root / "passenger_wsgi.py"
    if passenger.exists():
        defects.update(_passenger_wsgi_defects(passenger))
    defects.update(_requirements_defects(root / "requirements.txt", root / "requirements.lock"))
    return sorted(defects)


@unittest.skipUnless(CANDIDATE_COMPONENTS_AVAILABLE, "unified candidate components not present on this validation head")
class IntegratedCandidateContractTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.read_app = BridgeApplication(
            config=ReadAppConfig(
                auth_secret=TEST_AUTH_SECRET,
                file_signing_secret=TEST_SIGNING_SECRET,
                private_root=Path(self.tmp.name),
                public_base_url="https://bridge.example.invalid",
            ),
            backend=EmptyReadBackend(),
            rate_limiter=AllowReadLimiter(),
        )
        self.fake_client = DeterministicFakeTelegramClient()
        self.write_adapter = TelegramWriteAdapter(
            TelegramRuntimeConfig(
                application_id_ref=12345,
                application_hash_ref="synthetic-hash-reference",
                session_reference="synthetic-session-reference",
                synthetic_test_mode=True,
            ),
            lambda: self.fake_client,
        )
        self.app = UnifiedBridgeApplication(
            read_app=self.read_app,
            write_adapter=self.write_adapter,
            write_limiter=FixedWindowEndpointLimiter(limit=100, window_seconds=60, clock=lambda: 120.0),
        )

    @staticmethod
    def _read_registry_keys() -> set[tuple[str, str]]:
        return {(str(item["method"]).upper(), str(item["path"])) for item in registry_snapshot("/api/v1")}

    @staticmethod
    def _action_keys() -> set[tuple[str, str]]:
        return {(str(item.method).upper(), str(item.path)) for item in openapi_registry.OPERATIONS}

    def test_every_action_operation_resolves_on_unified_runtime_dispatch(self):
        """H1/H4 prerequisite: no generated Action operation may be a phantom."""
        unresolved = []
        for spec in openapi_registry.OPERATIONS:
            resolved = self.app._operation_for_request(str(spec.method).upper(), str(spec.path))
            if resolved is None or resolved.operation_id != spec.operation_id:
                unresolved.append((str(spec.method).upper(), str(spec.path)))
        self.assertEqual([], unresolved)
        self.assertEqual(
            {
                (str(spec.method).upper(), str(spec.path))
                for spec in openapi_registry.OPERATIONS
                if spec.operation_class is OperationClass.READ
            },
            set(validate_unified_registry()),
        )

    def test_all_four_write_previews_reach_unified_handler_without_external_write(self):
        """F1-F4/H4 prerequisite: all preview actions exist and are side-effect free."""
        assert self.read_app.files is not None
        file_path = self.read_app.files.root / "voice.ogg"
        file_path.write_bytes(b"synthetic-voice-bytes")
        os.chmod(file_path, 0o600)
        record = self.read_app.files.add(file_path, name="voice.ogg", mime_type="audio/ogg")

        cases = (
            ("/api/v1/messages/send/preview", {"chat": "100", "text": "preview"}),
            ("/api/v1/messages/reply/preview", {"chat": "100", "reply_to_message_id": 1, "text": "reply"}),
            ("/api/v1/messages/forward/preview", {"from_chat": "200", "to_chat": "100", "message_ids": [1]}),
            (
                "/api/v1/files/send/preview",
                {
                    "chat": "100",
                    "files": [{"file_ref": record.file_ref, "sha256": record.sha256, "size": record.size}],
                    "caption": "",
                    "voice_note": True,
                },
            ),
        )
        for path, body in cases:
            with self.subTest(path=path):
                response = _request(self.app, path, body)
                self.assertTrue(str(response["status"]).startswith("200"), response)
                self.assertIn("preview_token", response["payload"]["data"])
        self.assertEqual([], self.fake_client.external_writes)
        self.assertEqual(0, self.fake_client.connect_count)

    def test_commit_requires_explicit_current_user_command_and_replay_is_exactly_once(self):
        preview = _request(
            self.app,
            "/api/v1/messages/send/preview",
            {"chat": "100", "text": "synthetic exactly once"},
        )["payload"]["data"]
        blocked = _request(
            self.app,
            "/api/v1/messages/send/commit",
            {
                "preview_token": preview["preview_token"],
                "idempotency_key": "devc-idem-000001",
                "explicit_user_command": False,
            },
        )
        self.assertTrue(str(blocked["status"]).startswith("409"), blocked)
        self.assertEqual([], self.fake_client.external_writes)

        body = {
            "preview_token": preview["preview_token"],
            "idempotency_key": "devc-idem-000001",
            "explicit_user_command": True,
        }
        first = _request(self.app, "/api/v1/messages/send/commit", body)
        second = _request(self.app, "/api/v1/messages/send/commit", body)
        self.assertTrue(str(first["status"]).startswith("200"), first)
        self.assertTrue(str(second["status"]).startswith("200"), second)
        self.assertFalse(first["payload"]["data"]["idempotent_replay"])
        self.assertTrue(second["payload"]["data"]["idempotent_replay"])
        self.assertEqual(1, len(self.fake_client.external_writes))

    def test_unauthenticated_write_is_hidden_before_private_body_processing(self):
        response = _request(
            self.app,
            "/api/v1/messages/send/preview",
            {"chat": "100", "text": "private synthetic body"},
            auth=False,
        )
        self.assertTrue(str(response["status"]).startswith("404"), response)
        self.assertEqual([], self.fake_client.external_writes)

    def test_openapi_schema_is_deterministic_and_commit_strict(self):
        first = openapi_registry.build_action_openapi("https://bridge.example.invalid")
        second = openapi_registry.build_action_openapi("https://bridge.example.invalid")
        self.assertEqual(first, second)
        self.assertNotIn("setup", " ".join(first.get("paths", {})).casefold())
        for spec in openapi_registry.OPERATIONS:
            operation = first["paths"][spec.path][str(spec.method).lower()]
            if spec.operation_class is not OperationClass.WRITE_COMMIT:
                continue
            schema = operation["requestBody"]["content"]["application/json"]["schema"]
            self.assertFalse(schema.get("additionalProperties", True))
            self.assertEqual(
                {"preview_token", "idempotency_key", "explicit_user_command"},
                set(schema.get("required", [])),
            )
            explicit = schema["properties"]["explicit_user_command"]
            self.assertIs(explicit.get("const"), True)
            self.assertIs(operation.get("x-openai-isConsequential"), True)

    def test_read_router_non_action_exclusions_are_only_health_and_binary_serving(self):
        read = self._read_registry_keys()
        action = self._action_keys()
        extra = read - action
        self.assertEqual(
            {("GET", "/health"), ("GET", "/api/v1/files/{file_ref}")},
            extra,
        )

    def test_release_package_gate_truthfully_reports_current_p1(self):
        """Round-2 truth gate: old source candidate is green but not deployable."""
        self.assertEqual(
            ["MISSING_PASSENGER_WSGI_PY", "MISSING_REQUIREMENTS_LOCK", "MISSING_REQUIREMENTS_TXT"],
            _release_package_defects(REPOSITORY_ROOT),
        )

    def test_release_package_gate_accepts_canonical_wsgi_and_hash_locked_telethon(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "passenger_wsgi.py").write_text(
                '"""Canonical Passenger entry point."""\nfrom bridge.app import application\n',
                encoding="utf-8",
            )
            (root / "requirements.txt").write_text("Telethon>=1,<2\n", encoding="utf-8")
            (root / "requirements.lock").write_text(
                "Telethon==1.42.0 \\\n    --hash=sha256:" + "a" * 64 + "\n",
                encoding="utf-8",
            )
            self.assertEqual([], _release_package_defects(root))

    def test_release_package_gate_rejects_wrong_wsgi_and_unhashed_or_drifting_lock(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "passenger_wsgi.py").write_text(
                "from bridge.integrated_app import application\napplication()\n",
                encoding="utf-8",
            )
            (root / "requirements.txt").write_text("Telethon>=1,<2\nDependencyOnly>=1\n", encoding="utf-8")
            (root / "requirements.lock").write_text("Telethon==1.42.0\n", encoding="utf-8")
            defects = set(_release_package_defects(root))
            self.assertTrue(
                {
                    "PASSENGER_WSGI_IMPORT_SIDE_EFFECT",
                    "PASSENGER_WSGI_WRONG_IMPORT",
                    "REQUIREMENTS_INPUT_LOCK_DRIFT",
                    "REQUIREMENTS_LOCK_MISSING_HASH",
                }.issubset(defects),
                defects,
            )

    def test_continuous_mocked_action_sequence_and_restart_are_private_and_exactly_once(self):
        """Round-2 integrated user-flow prerequisite without network or live writes."""
        scenario_root = Path(self.tmp.name) / "scenario"
        audit = AuditLog()
        backend = ScenarioReadBackend()
        read_app = BridgeApplication(
            config=ReadAppConfig(
                auth_secret=TEST_AUTH_SECRET,
                file_signing_secret=TEST_SIGNING_SECRET,
                private_root=scenario_root,
                public_base_url="https://bridge.example.invalid",
            ),
            backend=backend,
            rate_limiter=AllowReadLimiter(),
            audit=audit,
        )
        fake = DeterministicFakeTelegramClient()
        adapter = TelegramWriteAdapter(
            TelegramRuntimeConfig(
                application_id_ref=12345,
                application_hash_ref="synthetic-hash-reference",
                session_reference="synthetic-session-reference",
                synthetic_test_mode=True,
            ),
            lambda: fake,
        )
        app = UnifiedBridgeApplication(
            read_app=read_app,
            write_adapter=adapter,
            write_limiter=FixedWindowEndpointLimiter(limit=200, window_seconds=60, clock=lambda: 180.0),
        )

        dialogs = _request(app, "/api/v1/dialogs/list", {"limit": 10})
        history = _request(app, "/api/v1/history/read", {"chat": "2", "limit": 10})
        scoped = _request(app, "/api/v1/search", {"chat": "2", "text": "synthetic"})
        global_search = _request(app, "/api/v1/search", {"text": "synthetic"})
        media = _request(app, "/api/v1/media/metadata", {"chat": "2", "message_id": 2})
        for response in (dialogs, history, scoped, global_search, media):
            self.assertTrue(str(response["status"]).startswith("200"), response)

        item = {
            "chat": "2",
            "message_id": 2,
            "file_ref": backend.source_ref,
            "name": "scenario.bin",
            "mime_type": "application/octet-stream",
            "expected_size": len(backend.media_bytes),
        }
        single = _request(app, "/api/v1/downloads/single", item)
        self.assertTrue(str(single["status"]).startswith("200"), single)
        single_file = single["payload"]["data"]

        bulk_items = [
            item,
            {**item, "message_id": 3, "file_ref": "tg_3_0123456789abcdefabcd", "name": "scenario-2.bin"},
        ]
        bulk = _request(app, "/api/v1/downloads/bulk", {"items": bulk_items})
        self.assertTrue(str(bulk["status"]).startswith("200"), bulk)
        bulk_data = bulk["payload"]["data"]
        self.assertEqual("complete", bulk_data["status"])
        resumed = _request(app, "/api/v1/downloads/resume", {"job_id": bulk_data["job_id"]})
        self.assertEqual("complete", resumed["payload"]["data"]["status"])

        archive_refs = [single_file["file_ref"], bulk_data["files"][0]["file_ref"]]
        archive = _request(app, "/api/v1/archives/create", {"file_refs": archive_refs, "name": "scenario.zip"})
        self.assertTrue(str(archive["status"]).startswith("200"), archive)
        metadata = _request(app, "/api/v1/files/get", {"file_ref": single_file["file_ref"]})
        self.assertTrue(str(metadata["status"]).startswith("200"), metadata)
        binary = _request(app, f"/api/v1/files/{single_file['file_ref']}", method="GET")
        self.assertTrue(str(binary["status"]).startswith("200"), binary)
        self.assertEqual(backend.media_bytes, binary["raw"])

        previews = []
        for path, body in (
            ("/api/v1/messages/send/preview", {"chat": "100", "text": backend.private_body}),
            ("/api/v1/messages/reply/preview", {"chat": "100", "reply_to_message_id": 1, "text": backend.private_body}),
            ("/api/v1/messages/forward/preview", {"from_chat": "200", "to_chat": "100", "message_ids": [1]}),
            (
                "/api/v1/files/send/preview",
                {
                    "chat": "100",
                    "files": [
                        {
                            "file_ref": single_file["file_ref"],
                            "sha256": single_file["sha256"],
                            "size": single_file["size"],
                        }
                    ],
                    "caption": "",
                    "voice_note": False,
                },
            ),
        ):
            response = _request(app, path, body)
            self.assertTrue(str(response["status"]).startswith("200"), response)
            previews.append((path, response["payload"]["data"]))
        self.assertEqual([], fake.external_writes)

        send_preview = previews[0][1]
        commit_body = {
            "preview_token": send_preview["preview_token"],
            "idempotency_key": "devc-continuous-idem-0001",
            "explicit_user_command": False,
        }
        blocked = _request(app, "/api/v1/messages/send/commit", commit_body)
        self.assertTrue(str(blocked["status"]).startswith("409"), blocked)
        self.assertEqual([], fake.external_writes)

        commit_body["explicit_user_command"] = True
        first = _request(app, "/api/v1/messages/send/commit", commit_body)
        replay = _request(app, "/api/v1/messages/send/commit", commit_body)
        self.assertTrue(str(first["status"]).startswith("200"), first)
        self.assertTrue(str(replay["status"]).startswith("200"), replay)
        self.assertEqual(1, len(fake.external_writes))
        self.assertFalse(first["payload"]["data"]["idempotent_replay"])
        self.assertTrue(replay["payload"]["data"]["idempotent_replay"])

        evidence_text = json.dumps(audit.events, ensure_ascii=False, sort_keys=True)
        for private_value in (
            backend.private_title,
            backend.private_sender,
            backend.private_body,
            "devc-private-file.bin",
            TEST_AUTH_SECRET,
            TEST_SIGNING_SECRET,
            str(scenario_root),
        ):
            self.assertNotIn(private_value, evidence_text)

        # Combined restart proof: the private file registry, completed download
        # checkpoint and committed idempotency record survive a fresh app object.
        restarted_backend = ScenarioReadBackend()
        restarted_read = BridgeApplication(
            config=ReadAppConfig(
                auth_secret=TEST_AUTH_SECRET,
                file_signing_secret=TEST_SIGNING_SECRET,
                private_root=scenario_root,
                public_base_url="https://bridge.example.invalid",
            ),
            backend=restarted_backend,
            rate_limiter=AllowReadLimiter(),
            audit=AuditLog(),
        )
        restarted_fake = DeterministicFakeTelegramClient()
        restarted_adapter = TelegramWriteAdapter(
            TelegramRuntimeConfig(
                application_id_ref=12345,
                application_hash_ref="synthetic-hash-reference",
                session_reference="synthetic-session-reference",
                synthetic_test_mode=True,
            ),
            lambda: restarted_fake,
        )
        restarted = UnifiedBridgeApplication(
            read_app=restarted_read,
            write_adapter=restarted_adapter,
            write_limiter=FixedWindowEndpointLimiter(limit=200, window_seconds=60, clock=lambda: 240.0),
        )
        after_restart_file = _request(restarted, "/api/v1/files/get", {"file_ref": single_file["file_ref"]})
        self.assertTrue(str(after_restart_file["status"]).startswith("200"), after_restart_file)
        after_restart_resume = _request(restarted, "/api/v1/downloads/resume", {"job_id": bulk_data["job_id"]})
        self.assertEqual("complete", after_restart_resume["payload"]["data"]["status"])
        after_restart_replay = _request(restarted, "/api/v1/messages/send/commit", commit_body)
        self.assertTrue(str(after_restart_replay["status"]).startswith("200"), after_restart_replay)
        self.assertTrue(after_restart_replay["payload"]["data"]["idempotent_replay"])
        self.assertEqual([], restarted_fake.external_writes)


if __name__ == "__main__":
    unittest.main()
