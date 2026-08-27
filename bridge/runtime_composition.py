"""Canonical production dependency composition for Passenger.

Construction is local-only: no Telegram connection and no Telethon import occur
while this factory runs.  Private Telegram references stay in process memory and
are consumed only when an actual read/write operation asks a lazy client factory
for a client.
"""
from __future__ import annotations

from typing import Any, Mapping

from .app import BridgeApplication, ReadAppConfig
from .audit import AuditLog
from .backend import TelethonReadBackend, TelethonReadConfig, UnavailableReadBackend
from .phase_aware_write_app import PhaseAwareUnifiedBridgeApplication
from .runtime import (
    SQLiteReadRateLimiter,
    SQLiteWriteRateLimiter,
    _ReadSessionLockedClient,
    _SQLiteFixedWindowStore,
    _bounded_int_env,
    _private_directory,
    _raw_telethon_factory,
    load_private_telegram_references,
)
from .upload_snapshot import UploadFileIdentity, open_verified_upload_batch

from ops.phase_aware_write_adapter import PhaseAwareTelegramWriteAdapter
from ops.runtime_write_reliability import RollbackSafeReliableWriteStoreProxy
from ops.structured_safe_write import StructuredSafePersistentWriteStore
from ops.telegram_session_lock import TelegramSessionLock
from ops.telegram_write_adapter import TelegramRuntimeConfig


def _snapshot_factory(store: Any, identities: tuple[Mapping[str, Any], ...]) -> Any:
    if store is None:
        return None
    converted: list[UploadFileIdentity] = []
    for raw in identities:
        if set(raw) != {"file_id", "sha256", "size"}:
            raise ValueError("invalid upload identity")
        size = raw.get("size")
        if isinstance(size, bool) or not isinstance(size, int):
            raise ValueError("invalid upload identity")
        converted.append(
            UploadFileIdentity(
                file_ref=str(raw.get("file_id") or ""),
                sha256=str(raw.get("sha256") or ""),
                size=size,
            )
        )
    return open_verified_upload_batch(store, tuple(converted))


def build_production_application_from_env() -> PhaseAwareUnifiedBridgeApplication:
    """Build the strongest reviewed non-live runtime composition from env refs."""

    read_config = ReadAppConfig.from_env()
    if read_config.private_root is None:
        # No private state means no write store, persistent rate limiter, audit
        # leaf, file registry or Telegram session.  Keep every protected feature
        # fail closed rather than creating state in an implicit location.
        return PhaseAwareUnifiedBridgeApplication(
            read_app=BridgeApplication(config=read_config),
            upload_batch_factory=_snapshot_factory,
        )

    private_root = _private_directory(read_config.private_root)
    state_root = _private_directory(private_root / "state")

    quota_store = _SQLiteFixedWindowStore(state_root / "rate_limit.sqlite3")
    window_seconds = _bounded_int_env("BRIDGE_RATE_WINDOW_SECONDS", 60, 10, 3_600)
    read_limit = _bounded_int_env("BRIDGE_READ_RATE_LIMIT", 120, 1, 10_000)
    write_limit = _bounded_int_env("BRIDGE_WRITE_RATE_LIMIT", 20, 1, 1_000)
    read_limiter = SQLiteReadRateLimiter(quota_store, limit=read_limit, window_seconds=window_seconds)
    write_limiter = SQLiteWriteRateLimiter(quota_store, limit=write_limit, window_seconds=window_seconds)

    preview_ttl = _bounded_int_env("BRIDGE_PREVIEW_TTL_SECONDS", 300, 30, 1_800)
    secure_store = StructuredSafePersistentWriteStore(
        state_root / "writes.sqlite3",
        preview_ttl_seconds=preview_ttl,
    )
    reliable_store = RollbackSafeReliableWriteStoreProxy(secure_store)
    # Local-only recovery: guarded orphan CALLING is terminalized to AMBIGUOUS;
    # no callback and therefore no Telegram effect can occur during startup.
    reliable_store.recover_on_startup()

    refs = load_private_telegram_references()
    backend: Any = UnavailableReadBackend()
    writer: PhaseAwareTelegramWriteAdapter | None = None
    if refs is not None:
        raw_factory = _raw_telethon_factory(refs)
        lock_path = private_root / "locks" / "telegram-session.lock"

        def session_lock_factory() -> TelegramSessionLock:
            return TelegramSessionLock(
                lock_path,
                timeout_seconds=float(_bounded_int_env("TELEGRAM_LOCK_TIMEOUT_SECONDS", 20, 1, 60)),
            )

        def read_client_factory() -> Any:
            return _ReadSessionLockedClient(raw_factory(), session_lock_factory)

        request_timeout = _bounded_int_env("TELEGRAM_REQUEST_TIMEOUT_SECONDS", 30, 1, 120)
        flood_cap = _bounded_int_env("TELEGRAM_FLOOD_WAIT_CAP_SECONDS", 30, 1, 300)
        backend = TelethonReadBackend(
            client_factory=read_client_factory,
            config=TelethonReadConfig(
                request_timeout_seconds=request_timeout,
                dialog_scan_limit=_bounded_int_env("TELEGRAM_DIALOG_SCAN_LIMIT", 2_000, 1, 20_000),
                search_scan_limit=_bounded_int_env("TELEGRAM_SEARCH_SCAN_LIMIT", 5_000, 1, 50_000),
                flood_wait_cap_seconds=flood_cap,
            ),
        )
        writer = PhaseAwareTelegramWriteAdapter(
            TelegramRuntimeConfig(
                application_id_ref=refs.application_id_ref,
                application_hash_ref=refs.application_hash_ref,
                session_reference=refs.session_reference,
                request_timeout_seconds=float(request_timeout),
                max_flood_wait_seconds=flood_cap,
                max_send_chars=_bounded_int_env("TELEGRAM_MAX_SEND_CHARS", 4_096, 256, 4_096),
                max_forward_messages=_bounded_int_env("TELEGRAM_MAX_FORWARD_MESSAGES", 100, 1, 100),
                max_send_files=_bounded_int_env("TELEGRAM_MAX_SEND_FILES", 10, 1, 10),
            ),
            raw_factory,
            session_lock_factory=session_lock_factory,
        )

    config = ReadAppConfig(
        auth_secret=read_config.auth_secret,
        file_signing_secret=read_config.file_signing_secret,
        private_root=private_root,
        public_base_url=read_config.public_base_url,
        api_prefix=read_config.api_prefix,
        max_json_bytes=read_config.max_json_bytes,
        max_json_depth=read_config.max_json_depth,
        max_json_nodes=read_config.max_json_nodes,
        max_limit=read_config.max_limit,
        max_search_scan=read_config.max_search_scan,
        signed_file_ttl_seconds=read_config.signed_file_ttl_seconds,
    )
    read_app = BridgeApplication(
        config=config,
        backend=backend,
        rate_limiter=read_limiter,
        audit=AuditLog(state_root / "audit.jsonl"),
    )
    return PhaseAwareUnifiedBridgeApplication(
        read_app=read_app,
        write_adapter=writer,
        write_limiter=write_limiter,
        preview_ttl_seconds=preview_ttl,
        write_store=reliable_store,
        upload_batch_factory=_snapshot_factory,
    )


__all__ = ["build_production_application_from_env"]
