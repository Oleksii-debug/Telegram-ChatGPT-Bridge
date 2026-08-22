"""Production dependency construction for the unified Telegram Bridge WSGI app.

Importing this module is network-free and does not materialize a Telegram client.
Actual credential values remain server-side only. The builder consumes the
existing private environment references lazily on the first WSGI request and
keeps a deliberately fail-closed application when Telegram references are not
configured yet.
"""
from __future__ import annotations

import hashlib
import os
import sqlite3
import stat
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from .app import BridgeApplication, ReadAppConfig
from .backend import TelethonReadBackend, TelethonReadConfig, UnavailableReadBackend
from .errors import BridgeError
from .security import RateLimitDecision, RejectingRateLimiter
from .integrated_app import UnifiedBridgeApplication

from ops.telegram_session_lock import TelegramSessionLock
from ops.telegram_write_adapter import TelegramRuntimeConfig, TelegramWriteAdapter
from ops.write_endpoint_policy import EndpointPolicyError


class RuntimeBootstrapError(RuntimeError):
    """Stable, non-secret production bootstrap failure."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, repr=False)
class PrivateTelegramReferences:
    """In-memory references loaded only from the private server environment."""

    application_id_ref: int
    application_hash_ref: str
    session_reference: str


def _bounded_int_env(name: str, default: int, minimum: int, maximum: int) -> int:
    raw = os.getenv(name)
    if raw in (None, ""):
        return default
    try:
        value = int(raw)
    except (TypeError, ValueError) as exc:
        raise RuntimeBootstrapError("invalid_runtime_numeric_setting") from exc
    if isinstance(value, bool) or not minimum <= value <= maximum:
        raise RuntimeBootstrapError("runtime_numeric_setting_out_of_range")
    return value


def load_private_telegram_references() -> PrivateTelegramReferences | None:
    """Load Telegram references without logging, serializing or returning names/values.

    An entirely absent Telegram configuration is a valid bootstrap-not-ready
    state. A partial/malformed configuration is an error because silently
    downgrading it to "unconfigured" would hide a server configuration defect.
    """

    identifier_raw = os.getenv("TG_API_ID")
    digest_ref = os.getenv("TG_API_HASH")
    session_ref = os.getenv("TG_SESSION_STRING")
    present = [identifier_raw not in (None, ""), digest_ref not in (None, ""), session_ref not in (None, "")]
    if not any(present):
        return None
    if not all(present):
        raise RuntimeBootstrapError("telegram_runtime_references_incomplete")
    try:
        identifier = int(str(identifier_raw))
    except (TypeError, ValueError) as exc:
        raise RuntimeBootstrapError("telegram_application_identifier_invalid") from exc
    if identifier <= 0 or identifier > 2_147_483_647:
        raise RuntimeBootstrapError("telegram_application_identifier_invalid")
    digest = str(digest_ref)
    if len(digest) != 32 or any(ch not in "0123456789abcdefABCDEF" for ch in digest):
        raise RuntimeBootstrapError("telegram_application_reference_invalid")
    session = str(session_ref)
    if not 16 <= len(session) <= 65_536 or any(ord(ch) < 32 for ch in session):
        raise RuntimeBootstrapError("telegram_session_reference_invalid")
    return PrivateTelegramReferences(identifier, digest, session)


def _ensure_private_directory(path: Path) -> Path:
    lexical = Path(os.path.abspath(os.path.expanduser(str(path))))
    if lexical.exists():
        if lexical.is_symlink() or not lexical.is_dir() or Path(os.path.realpath(lexical)) != lexical:
            raise RuntimeBootstrapError("unsafe_private_runtime_root")
        st = lexical.stat()
        if hasattr(os, "geteuid") and st.st_uid != os.geteuid():
            raise RuntimeBootstrapError("unsafe_private_runtime_owner")
        if stat.S_IMODE(st.st_mode) & 0o077:
            raise RuntimeBootstrapError("unsafe_private_runtime_mode")
    else:
        lexical.mkdir(parents=True, mode=0o700)
        try:
            os.chmod(lexical, 0o700)
        except OSError as exc:
            raise RuntimeBootstrapError("private_runtime_mode_failed") from exc
    return lexical


class _SQLiteFixedWindowStore:
    """Small process-safe quota store shared by read and write endpoint limiters."""

    def __init__(self, database_path: Path, *, clock: Callable[[], float] = time.time):
        self.database_path = Path(database_path)
        self.clock = clock
        parent = _ensure_private_directory(self.database_path.parent)
        if self.database_path.parent != parent:
            raise RuntimeBootstrapError("unsafe_rate_limit_path")
        if self.database_path.exists() and self.database_path.is_symlink():
            raise RuntimeBootstrapError("unsafe_rate_limit_database")
        self._initialize()

    @staticmethod
    def _digest(value: str) -> str:
        return hashlib.sha256(value.encode("utf-8", "strict")).hexdigest()

    def _connect(self) -> sqlite3.Connection:
        try:
            connection = sqlite3.connect(str(self.database_path), timeout=5.0, isolation_level=None)
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute("PRAGMA busy_timeout=5000")
            try:
                os.chmod(self.database_path, 0o600)
            except OSError:
                connection.close()
                raise RuntimeBootstrapError("rate_limit_database_mode_failed") from None
            return connection
        except RuntimeBootstrapError:
            raise
        except sqlite3.Error as exc:
            raise RuntimeBootstrapError("rate_limit_database_unavailable") from exc

    def _tighten_sidecars(self) -> None:
        for suffix in ("-wal", "-shm"):
            path = Path(str(self.database_path) + suffix)
            if path.exists():
                if path.is_symlink() or not path.is_file():
                    raise RuntimeBootstrapError("unsafe_rate_limit_database_sidecar")
                try:
                    os.chmod(path, 0o600)
                except OSError as exc:
                    raise RuntimeBootstrapError("rate_limit_database_mode_failed") from exc

    def _initialize(self) -> None:
        connection = self._connect()
        try:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS fixed_window_quota ("
                "namespace TEXT NOT NULL, actor_hash TEXT NOT NULL, operation_hash TEXT NOT NULL, "
                "window_start INTEGER NOT NULL, count INTEGER NOT NULL, "
                "PRIMARY KEY(namespace, actor_hash, operation_hash))"
            )
        except sqlite3.Error as exc:
            raise RuntimeBootstrapError("rate_limit_database_unavailable") from exc
        finally:
            connection.close()
            self._tighten_sidecars()

    def take(self, *, namespace: str, actor: str, operation: str, limit: int, window_seconds: int) -> tuple[bool, int, int]:
        if not namespace or len(namespace) > 32 or not operation or len(operation) > 256:
            raise RuntimeBootstrapError("invalid_rate_limit_namespace")
        if not isinstance(actor, str) or not actor or len(actor) > 512:
            raise RuntimeBootstrapError("invalid_rate_limit_actor")
        now = int(self.clock())
        if now < 0:
            raise RuntimeBootstrapError("invalid_rate_limit_clock")
        window_start = (now // window_seconds) * window_seconds
        retry_after = max(1, window_start + window_seconds - now)
        actor_hash = self._digest(actor)
        operation_hash = self._digest(operation)
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "DELETE FROM fixed_window_quota WHERE window_start < ?",
                (window_start - (2 * window_seconds),),
            )
            row = connection.execute(
                "SELECT window_start, count FROM fixed_window_quota "
                "WHERE namespace=? AND actor_hash=? AND operation_hash=?",
                (namespace, actor_hash, operation_hash),
            ).fetchone()
            count = 0
            if row is not None and int(row[0]) == window_start:
                count = int(row[1])
            if count >= limit:
                connection.execute("COMMIT")
                return False, 0, retry_after
            count += 1
            connection.execute(
                "INSERT INTO fixed_window_quota(namespace,actor_hash,operation_hash,window_start,count) "
                "VALUES(?,?,?,?,?) ON CONFLICT(namespace,actor_hash,operation_hash) DO UPDATE SET "
                "window_start=excluded.window_start,count=excluded.count",
                (namespace, actor_hash, operation_hash, window_start, count),
            )
            connection.execute("COMMIT")
            return True, limit - count, 0
        except RuntimeBootstrapError:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        except sqlite3.Error as exc:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise RuntimeBootstrapError("rate_limit_database_unavailable") from exc
        finally:
            connection.close()
            self._tighten_sidecars()


class SQLiteReadRateLimiter:
    def __init__(self, store: _SQLiteFixedWindowStore, *, limit: int, window_seconds: int):
        self.store = store
        self.limit = limit
        self.window_seconds = window_seconds

    def check(self, actor: str) -> RateLimitDecision:
        try:
            allowed, remaining, retry = self.store.take(
                namespace="read", actor=actor, operation="read-api", limit=self.limit, window_seconds=self.window_seconds
            )
        except RuntimeBootstrapError as exc:
            raise BridgeError("Rate limiter is unavailable", status=503, code="rate_limiter_unavailable") from exc
        return RateLimitDecision(allowed=allowed, remaining=remaining, retry_after_seconds=retry or None)


class SQLiteWriteRateLimiter:
    def __init__(self, store: _SQLiteFixedWindowStore, *, limit: int, window_seconds: int):
        self.store = store
        self.limit = limit
        self.window_seconds = window_seconds

    def consume(self, actor_sha256: str, operation_id: str) -> tuple[int, int]:
        try:
            allowed, remaining, retry = self.store.take(
                namespace="write", actor=actor_sha256, operation=operation_id, limit=self.limit, window_seconds=self.window_seconds
            )
        except RuntimeBootstrapError as exc:
            raise EndpointPolicyError("rate_limiter_unavailable", status=503) from exc
        if not allowed:
            raise EndpointPolicyError("rate_limited", status=429, retry_after_seconds=retry)
        reset_at = int(self.store.clock()) + self.window_seconds
        return remaining, reset_at


class _ReadSessionLockedClient:
    """Delegate a Telethon client while holding the same private session lock used by writes."""

    def __init__(self, client: Any, lock_factory: Callable[[], TelegramSessionLock]):
        self._client = client
        self._lock_factory = lock_factory
        self._lock: TelegramSessionLock | None = None

    async def connect(self) -> Any:
        if self._lock is not None:
            raise RuntimeBootstrapError("telegram_session_lock_reentry")
        lock = self._lock_factory()
        lock.__enter__()
        self._lock = lock
        try:
            return await self._client.connect()
        except BaseException:
            self._release_lock()
            raise

    async def disconnect(self) -> Any:
        try:
            return await self._client.disconnect()
        finally:
            self._release_lock()

    def _release_lock(self) -> None:
        lock, self._lock = self._lock, None
        if lock is not None:
            lock.__exit__(None, None, None)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._client, name)


def _raw_telethon_factory(refs: PrivateTelegramReferences) -> Callable[[], Any]:
    def create_client() -> Any:
        try:
            from telethon import TelegramClient
            from telethon.sessions import StringSession
        except Exception as exc:
            raise RuntimeBootstrapError("telethon_runtime_unavailable") from exc
        return TelegramClient(StringSession(refs.session_reference), refs.application_id_ref, refs.application_hash_ref)
    return create_client


def build_production_application_from_env() -> UnifiedBridgeApplication:
    """Construct the canonical server application without performing Telegram I/O."""

    read_config = ReadAppConfig.from_env()
    if read_config.private_root is None:
        return UnifiedBridgeApplication(read_app=BridgeApplication(config=read_config))

    private_root = _ensure_private_directory(read_config.private_root)
    state_root = _ensure_private_directory(private_root / "state")
    quota_store = _SQLiteFixedWindowStore(state_root / "rate_limit.sqlite3")
    window_seconds = _bounded_int_env("BRIDGE_RATE_WINDOW_SECONDS", 60, 10, 3600)
    read_limit = _bounded_int_env("BRIDGE_READ_RATE_LIMIT", 120, 1, 10_000)
    write_limit = _bounded_int_env("BRIDGE_WRITE_RATE_LIMIT", 20, 1, 1_000)
    read_limiter = SQLiteReadRateLimiter(quota_store, limit=read_limit, window_seconds=window_seconds)
    write_limiter = SQLiteWriteRateLimiter(quota_store, limit=write_limit, window_seconds=window_seconds)

    refs = load_private_telegram_references()
    backend: Any = UnavailableReadBackend()
    writer: TelegramWriteAdapter | None = None
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
        writer = TelegramWriteAdapter(
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

    read_app = BridgeApplication(
        config=ReadAppConfig(
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
        ),
        backend=backend,
        rate_limiter=read_limiter,
    )
    return UnifiedBridgeApplication(
        read_app=read_app,
        write_adapter=writer,
        write_limiter=write_limiter,
        preview_ttl_seconds=_bounded_int_env("BRIDGE_PREVIEW_TTL_SECONDS", 300, 30, 1800),
    )


__all__ = [
    "PrivateTelegramReferences",
    "RuntimeBootstrapError",
    "SQLiteReadRateLimiter",
    "SQLiteWriteRateLimiter",
    "build_production_application_from_env",
    "load_private_telegram_references",
]
