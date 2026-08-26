"""FINALWAVE-38 credential-free runtime composition regressions.

These tests perform no network calls, use no real Telegram credentials, and
exercise only synthetic/private temporary state.
"""
from __future__ import annotations

import asyncio
import io
import json
import multiprocessing
import os
import sqlite3
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from bridge.app import ReadAppConfig
from bridge.backend import TelethonReadBackend, UnavailableReadBackend
from bridge.phase_aware_write_app import PhaseAwareUnifiedBridgeApplication
from bridge.runtime import PrivateTelegramReferences, SQLiteReadRateLimiter, SQLiteWriteRateLimiter
from bridge.runtime_composition import build_production_application_from_env
from bridge.storage import FileRecordStore
from bridge.upload_snapshot import UploadFileIdentity, open_verified_upload_batch
from ops.phase_aware_write_adapter import PhaseAwareTelegramWriteAdapter
from ops.runtime_write_reliability import RollbackSafeReliableWriteStoreProxy
from ops.secure_write_store import WriteStateSecurityError
from ops.structured_safe_write import SafeWriteMetadataFailure, StructuredSafePersistentWriteStore
from ops.telegram_write_adapter import TelegramContractError, TelegramRuntimeConfig
from ops.write_endpoint_policy import EndpointContext
from ops.write_safety import WriteSafetyError


def _schema_bootstrap_worker(db_path: str, result_queue) -> None:
    try:
        StructuredSafePersistentWriteStore(Path(db_path), preview_ttl_seconds=300)
        result_queue.put("ok")
    except BaseException as exc:
        result_queue.put(type(exc).__name__)


def _commit_race_worker(db_path: str, preview_token: str, idempotency_key: str,
                        effect_path: str, barrier, result_queue) -> None:
    try:
        store = StructuredSafePersistentWriteStore(Path(db_path), preview_ttl_seconds=300)
        proxy = RollbackSafeReliableWriteStoreProxy(store, clock=lambda: 101.0)
        barrier.wait(10)

        def external_write(_payload):
            fd = os.open(effect_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            try:
                os.write(fd, b"effect\n")
            finally:
                os.close(fd)
            return {"operation": "SEND", "message_ids": [101], "chat_id": 100, "count": 1}

        result = proxy.commit(
            preview_token,
            expected_action="SEND",
            idempotency_key=idempotency_key,
            external_write=external_write,
            now=101,
        )
        result_queue.put(("ok", bool(result.idempotent_replay)))
    except BaseException as exc:
        result_queue.put(("error", str(getattr(exc, "code", type(exc).__name__))))


def _crash_inside_calling_worker(db_path: str, preview_token: str, idempotency_key: str) -> None:
    store = StructuredSafePersistentWriteStore(Path(db_path), preview_ttl_seconds=300)
    proxy = RollbackSafeReliableWriteStoreProxy(store, clock=lambda: 101.0)

    def crash_after_calling(_payload):
        os._exit(23)

    proxy.commit(
        preview_token,
        expected_action="SEND",
        idempotency_key=idempotency_key,
        external_write=crash_after_calling,
        now=101,
    )
    os._exit(91)


class _SyntheticEntity:
    id = 100


class _SyntheticMessage:
    id = 101
    chat_id = 100


class _SyntheticRpcError(Exception):
    pass


class _PreEffectFailureClient:
    def __init__(self):
        self.mutations = 0

    async def connect(self):
        return None

    async def disconnect(self):
        return None

    async def is_user_authorized(self):
        return True

    async def get_entity(self, _ref):
        raise _SyntheticRpcError("private-text-must-not-escape")

    async def get_me(self):
        return _SyntheticEntity()

    async def send_message(self, *_args, **_kwargs):
        self.mutations += 1
        return _SyntheticMessage()


class _PostEffectFailureClient(_PreEffectFailureClient):
    async def get_me(self):
        return _SyntheticEntity()

    async def send_message(self, *_args, **_kwargs):
        self.mutations += 1
        raise RuntimeError("post-effect-private-detail")


class _SuccessfulWriteClient(_PreEffectFailureClient):
    async def get_me(self):
        return _SyntheticEntity()

    async def send_message(self, *_args, **_kwargs):
        self.mutations += 1
        return _SyntheticMessage()


class RuntimeCompositionTests(unittest.TestCase):
    AUTH = "synthetic-bearer-reference-1234567890"

    @staticmethod
    def _private_config(root: Path) -> ReadAppConfig:
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(root, 0o700)
        return ReadAppConfig(auth_secret=RuntimeCompositionTests.AUTH, private_root=root)

    @staticmethod
    def _synthetic_refs() -> PrivateTelegramReferences:
        return PrivateTelegramReferences(
            application_id_ref=100_023,
            application_hash_ref="a" * 32,
            session_reference="synthetic-reference-material-" + ("x" * 24),
        )

    @staticmethod
    def _synthetic_writer_config() -> TelegramRuntimeConfig:
        return TelegramRuntimeConfig(
            application_id_ref=100_023,
            application_hash_ref="a" * 32,
            session_reference="synthetic-reference-material-" + ("x" * 24),
            synthetic_test_mode=True,
        )

    @staticmethod
    def _call(app, path: str, payload: dict, *, token: str | None = None) -> tuple[str, bytes]:
        raw = json.dumps(payload).encode("utf-8")
        captured: dict[str, object] = {}

        def start_response(status, headers):
            captured["status"] = status
            captured["headers"] = dict(headers)

        environ = {
            "REQUEST_METHOD": "POST",
            "PATH_INFO": path,
            "QUERY_STRING": "",
            "CONTENT_TYPE": "application/json",
            "CONTENT_LENGTH": str(len(raw)),
            "wsgi.input": io.BytesIO(raw),
        }
        if token is not None:
            environ["HTTP_AUTHORIZATION"] = f"Bearer {token}"
        body = b"".join(app(environ, start_response))
        return str(captured.get("status")), body

    def test_passenger_import_still_resolves_lazy_runtime_wrapper_without_telethon_import(self):
        import bridge
        import bridge.app as app_module
        import passenger_wsgi
        from bridge import runtime_wsgi

        before = {name for name in sys.modules if name == "telethon" or name.startswith("telethon.")}
        self.assertIs(passenger_wsgi.application, runtime_wsgi.application)
        self.assertIs(bridge.application, runtime_wsgi.application)
        self.assertIs(app_module.application, runtime_wsgi.application)
        after = {name for name in sys.modules if name == "telethon" or name.startswith("telethon.")}
        self.assertEqual(before, after)

    def test_private_runtime_without_telegram_refs_wires_persistent_helpers_but_is_not_ready(self):
        with tempfile.TemporaryDirectory() as td:
            private_root = Path(td) / "private"
            config = self._private_config(private_root)
            with mock.patch.object(ReadAppConfig, "from_env", return_value=config), \
                 mock.patch("bridge.runtime_composition.load_private_telegram_references", return_value=None):
                app = build_production_application_from_env()

            self.assertIsInstance(app, PhaseAwareUnifiedBridgeApplication)
            self.assertIsInstance(app.read_app.backend, UnavailableReadBackend)
            self.assertIsInstance(app.read_app.rate_limiter, SQLiteReadRateLimiter)
            self.assertIsInstance(app._write_limiter, SQLiteWriteRateLimiter)
            self.assertIsNone(app.write_adapter)
            self.assertIsInstance(app.write_store, RollbackSafeReliableWriteStoreProxy)
            self.assertIsInstance(app.write_store.store, StructuredSafePersistentWriteStore)
            self.assertEqual(private_root / "state" / "audit.jsonl", app.read_app.audit.path)

            captured: dict[str, object] = {}

            def start_response(status, _headers):
                captured["status"] = status

            body = b"".join(app({"REQUEST_METHOD": "GET", "PATH_INFO": "/health"}, start_response))
            payload = json.loads(body.decode("utf-8"))
            self.assertEqual("200 OK", captured["status"])
            self.assertFalse(payload["ready"])
            self.assertEqual("configured", payload["components"]["write_store"])
            self.assertEqual("configured", payload["components"]["write_rate_limit"])
            self.assertEqual("unconfigured", payload["components"]["telegram_writer"])

    def test_complete_refs_wire_read_writer_reliability_snapshot_and_one_session_lock_without_telethon_import(self):
        with tempfile.TemporaryDirectory() as td:
            private_root = Path(td) / "private"
            config = self._private_config(private_root)
            fake_raw_client = object()
            before = {name for name in sys.modules if name == "telethon" or name.startswith("telethon.")}
            with mock.patch.object(ReadAppConfig, "from_env", return_value=config), \
                 mock.patch("bridge.runtime_composition.load_private_telegram_references", return_value=self._synthetic_refs()), \
                 mock.patch("bridge.runtime_composition._raw_telethon_factory", return_value=lambda: fake_raw_client):
                app = build_production_application_from_env()
            after = {name for name in sys.modules if name == "telethon" or name.startswith("telethon.")}

            self.assertEqual(before, after)
            self.assertIsInstance(app.read_app.backend, TelethonReadBackend)
            self.assertIsInstance(app.write_adapter, PhaseAwareTelegramWriteAdapter)
            self.assertIsInstance(app.write_store, RollbackSafeReliableWriteStoreProxy)
            self.assertTrue(callable(app._upload_batch_factory))
            read_client = app.read_app.backend.client_factory()
            write_lock = app.write_adapter.session_lock_factory()
            read_lock = read_client._lock_factory()
            expected = private_root / "locks" / "telegram-session.lock"
            self.assertEqual(expected, write_lock.path)
            self.assertEqual(write_lock.path, read_lock.path)

    def test_unconfigured_commit_fails_before_preview_consumption_or_external_effect(self):
        with tempfile.TemporaryDirectory() as td:
            config = self._private_config(Path(td) / "private")
            with mock.patch.object(ReadAppConfig, "from_env", return_value=config), \
                 mock.patch("bridge.runtime_composition.load_private_telegram_references", return_value=None):
                app = build_production_application_from_env()

            preview = app.write_coordinator.preview(
                "previewTelegramSend",
                EndpointContext(authenticated=True, actor_sha256="a" * 64),
                {"target": "saved", "text": "synthetic preview text"},
            )
            status, body = self._call(
                app,
                "/api/v1/messages/send/commit",
                {
                    "preview_token": preview.token,
                    "idempotency_key": "synthetic-idempotency-001",
                    "explicit_user_command": True,
                },
                token=self.AUTH,
            )
            self.assertTrue(status.startswith("503 "), status)
            self.assertIn(b"telegram_writer_unconfigured", body)
            self.assertIsNotNone(app.write_store.get_preview(preview.token))
            with app.write_store.store._connect() as con:
                count = int(con.execute("SELECT COUNT(*) FROM idempotency").fetchone()[0])
            self.assertEqual(0, count)

    def test_persistent_audit_sink_is_owner_private_and_metadata_only(self):
        with tempfile.TemporaryDirectory() as td:
            config = self._private_config(Path(td) / "private")
            with mock.patch.object(ReadAppConfig, "from_env", return_value=config), \
                 mock.patch("bridge.runtime_composition.load_private_telegram_references", return_value=None):
                app = build_production_application_from_env()
            app.read_app.audit.write("runtime_test", status=200, count=1)
            path = app.read_app.audit.path
            self.assertIsNotNone(path)
            self.assertEqual(0o600, stat.S_IMODE(path.stat().st_mode))
            line = path.read_text("ascii")
            self.assertIn('"status":200', line)
            self.assertNotIn("synthetic preview text", line)

    def test_secure_write_store_rejects_broad_mode_existing_database_before_sqlite_open(self):
        with tempfile.TemporaryDirectory() as td:
            state = Path(td) / "state"
            state.mkdir(mode=0o700)
            os.chmod(state, 0o700)
            db_path = state / "writes.sqlite3"
            db_path.write_bytes(b"not-a-database")
            os.chmod(db_path, 0o644)
            with self.assertRaises(WriteStateSecurityError) as ctx:
                StructuredSafePersistentWriteStore(db_path)
            self.assertEqual("write_state_database_mode_unsafe", ctx.exception.code)

    def test_fresh_write_schema_bootstrap_is_serialized_across_eight_processes(self):
        with tempfile.TemporaryDirectory() as td:
            state = Path(td) / "state"
            state.mkdir(mode=0o700)
            os.chmod(state, 0o700)
            db_path = state / "writes.sqlite3"
            ctx = multiprocessing.get_context("spawn")
            queue = ctx.Queue()
            workers = [ctx.Process(target=_schema_bootstrap_worker, args=(str(db_path), queue)) for _ in range(8)]
            for worker in workers:
                worker.start()
            for worker in workers:
                worker.join(20)
            results = [queue.get(timeout=5) for _ in workers]
            self.assertEqual([0] * len(workers), [worker.exitcode for worker in workers])
            self.assertEqual(["ok"] * len(workers), results)
            with sqlite3.connect(db_path) as con:
                rows = con.execute("SELECT value FROM meta WHERE key='schema_version'").fetchall()
            self.assertEqual([("1",)], rows)

    def test_process_shared_commit_race_performs_exactly_one_synthetic_external_effect(self):
        with tempfile.TemporaryDirectory() as td:
            state = Path(td) / "state"
            state.mkdir(mode=0o700)
            os.chmod(state, 0o700)
            db_path = state / "writes.sqlite3"
            store = StructuredSafePersistentWriteStore(db_path)
            parent_proxy = RollbackSafeReliableWriteStoreProxy(store, clock=lambda: 100.0)
            preview = parent_proxy.create_preview("SEND", {"target": "saved", "text": "synthetic"}, now=100)
            idem = "synthetic-idempotency-race"
            effect_path = str(Path(td) / "effect.log")

            ctx = multiprocessing.get_context("spawn")
            barrier = ctx.Barrier(2)
            queue = ctx.Queue()
            workers = [
                ctx.Process(
                    target=_commit_race_worker,
                    args=(str(db_path), preview.token, idem, effect_path, barrier, queue),
                )
                for _ in range(2)
            ]
            for worker in workers:
                worker.start()
            for worker in workers:
                worker.join(20)
            results = [queue.get(timeout=5) for _ in workers]
            self.assertEqual([0, 0], [worker.exitcode for worker in workers])
            self.assertTrue(all(result[0] in {"ok", "error"} for result in results), results)
            self.assertTrue(all(result[0] == "ok" or result[1] == "write_in_progress" for result in results), results)
            lines = Path(effect_path).read_bytes().splitlines()
            self.assertEqual([b"effect"], lines)
            with store._connect() as con:
                key_hash = store._idempotency_hash(idem)
                row = con.execute("SELECT state FROM idempotency WHERE key_hash=?", (key_hash,)).fetchone()
            self.assertEqual("COMMITTED", row["state"])

    def test_real_process_death_inside_calling_recovers_to_ambiguous_without_replay(self):
        with tempfile.TemporaryDirectory() as td:
            state = Path(td) / "state"
            state.mkdir(mode=0o700)
            os.chmod(state, 0o700)
            db_path = state / "writes.sqlite3"
            store = StructuredSafePersistentWriteStore(db_path)
            parent_proxy = RollbackSafeReliableWriteStoreProxy(store, clock=lambda: 100.0)
            preview = parent_proxy.create_preview("SEND", {"target": "saved", "text": "synthetic"}, now=100)
            idem = "synthetic-idempotency-crash"

            ctx = multiprocessing.get_context("spawn")
            worker = ctx.Process(target=_crash_inside_calling_worker, args=(str(db_path), preview.token, idem))
            worker.start()
            worker.join(20)
            self.assertEqual(23, worker.exitcode)

            restarted_store = StructuredSafePersistentWriteStore(db_path)
            restarted = RollbackSafeReliableWriteStoreProxy(restarted_store, clock=lambda: 102.0)
            report = restarted.recover_on_startup(now=102)
            self.assertEqual(1, report.calling_recovered)
            key_hash = restarted_store._idempotency_hash(idem)
            with restarted_store._connect() as con:
                row = con.execute("SELECT state FROM idempotency WHERE key_hash=?", (key_hash,)).fetchone()
                marker_count = con.execute("SELECT COUNT(*) FROM runtime_commit_guard").fetchone()[0]
            self.assertEqual("AMBIGUOUS", row["state"])
            self.assertEqual(0, marker_count)
            with self.assertRaises(WriteSafetyError) as ctx_error:
                restarted.commit(
                    preview.token,
                    expected_action="SEND",
                    idempotency_key=idem,
                    external_write=lambda _payload: {"unexpected": True},
                    now=103,
                )
            self.assertEqual("write_outcome_unknown_reconciliation_required", ctx_error.exception.code)

    def test_snapshot_factory_pins_exact_bytes_and_exposes_no_writable_descriptor(self):
        with tempfile.TemporaryDirectory() as td:
            private = Path(td) / "private"
            files = private / "files"
            state = private / "state"
            files.mkdir(mode=0o700, parents=True)
            state.mkdir(mode=0o700, parents=True)
            source = files / "sample.bin"
            source.write_bytes(b"AAAA")
            os.chmod(source, 0o600)
            store = FileRecordStore(state / "files.sqlite3", files)
            record = store.add(source, name="sample.bin")
            batch = open_verified_upload_batch(
                store,
                (UploadFileIdentity(record.file_ref, record.sha256, record.size),),
            )
            self.assertIsNotNone(batch)
            upload = batch.files[0]
            self.assertFalse(upload.writable())
            with self.assertRaises(io.UnsupportedOperation):
                upload.fileno()
            source.write_bytes(b"BBBB")
            upload.seek(0)
            self.assertEqual(b"AAAA", upload.read())
            batch.close()
            self.assertTrue(upload.closed)

    def test_phase_aware_writer_rejects_pathname_fallback_before_client_creation(self):
        calls = []
        adapter = PhaseAwareTelegramWriteAdapter(
            self._synthetic_writer_config(),
            lambda: calls.append("client") or object(),
        )
        with self.assertRaises(SafeWriteMetadataFailure) as ctx:
            asyncio.run(adapter.send_files_async("saved", ["/tmp/legacy-path.bin"]))
        self.assertEqual("invalid_file_reference", ctx.exception.code)
        self.assertEqual([], calls)

    def test_phase_aware_writer_classifies_read_preflight_failure_safe_but_not_post_effect_failure(self):
        pre_client = _PreEffectFailureClient()
        pre_adapter = PhaseAwareTelegramWriteAdapter(self._synthetic_writer_config(), lambda: pre_client)
        with self.assertRaises(SafeWriteMetadataFailure) as pre_ctx:
            asyncio.run(pre_adapter.send_async("@validname", "synthetic"))
        self.assertEqual("telegram_rpc_error", pre_ctx.exception.code)
        self.assertEqual(0, pre_client.mutations)

        post_client = _PostEffectFailureClient()
        post_adapter = PhaseAwareTelegramWriteAdapter(self._synthetic_writer_config(), lambda: post_client)
        with self.assertRaises(TelegramContractError) as post_ctx:
            asyncio.run(post_adapter.send_async("saved", "synthetic"))
        self.assertNotIsInstance(post_ctx.exception, SafeWriteMetadataFailure)
        self.assertEqual("telegram_operation_failed", post_ctx.exception.code)
        self.assertEqual(1, post_client.mutations)

    def test_phase_aware_writer_success_returns_valid_receipt(self):
        client = _SuccessfulWriteClient()
        adapter = PhaseAwareTelegramWriteAdapter(self._synthetic_writer_config(), lambda: client)
        receipt = asyncio.run(adapter.send_async("saved", "synthetic"))
        self.assertEqual("SEND", receipt.operation)
        self.assertEqual((101,), receipt.message_ids)
        self.assertEqual(1, client.mutations)

    def test_runtime_wsgi_redacts_strong_builder_failure_and_does_not_cache_failure(self):
        from bridge import runtime_wsgi

        runtime_wsgi.reset_runtime_application_for_tests()
        captured: dict[str, object] = {}

        def start_response(status, headers):
            captured["status"] = status
            captured["headers"] = dict(headers)

        with mock.patch(
            "bridge.runtime_composition.build_production_application_from_env",
            side_effect=RuntimeError("private-startup-detail"),
        ):
            body = b"".join(runtime_wsgi.application({}, start_response))
        self.assertEqual("500 Internal Server Error", captured["status"])
        self.assertIn(b"startup_configuration_error", body)
        self.assertNotIn(b"private-startup-detail", body)
        self.assertIsNone(runtime_wsgi._default_application)


if __name__ == "__main__":
    unittest.main()
