"""Fail-closed production dependency construction for Telegram Bridge.

Importing this module is network-free and does not construct a Telegram client.
Private Telegram references are read only from the server environment when the
lazy WSGI wrapper builds the application on first request.  No reference value
is logged, serialized, persisted to Git, or returned by these helpers.
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
from .integrated_app import UnifiedBridgeApplication
from .security import RateLimitDecision

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
    """Private references held in memory only; repr deliberately hides values."""

    application_id_ref: int
    application_hash_ref: str
    session_reference: str


@dataclass(frozen=True)
class _FixedWindowOutcome:
    """One atomic fixed-window decision derived from one persisted clock sample."""

    allowed: bool
    remaining: int
    retry_after_seconds: int
    reset_at_epoch: int


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
    """Load all-or-none Telegram references from the private server environment."""

    identifier_ref = os.getenv("TG_API_ID")
    digest_ref = os.getenv("TG_API_HASH")
    session_ref = os.getenv("TG_SESSION_STRING")
    present = (
        identifier_ref not in (None, ""),
        digest_ref not in (None, ""),
        session_ref not in (None, ""),
    )
    if not any(present):
        return None
    if not all(present):
        raise RuntimeBootstrapError("telegram_runtime_references_incomplete")
    try:
        identifier_value = int(str(identifier_ref))
    except (TypeError, ValueError) as exc:
        raise RuntimeBootstrapError("telegram_application_identifier_invalid") from exc
    if identifier_value <= 0 or identifier_value > 2_147_483_647:
        raise RuntimeBootstrapError("telegram_application_identifier_invalid")

    digest_value = str(digest_ref)
    if len(digest_value) != 32 or any(ch not in "0123456789abcdefABCDEF" for ch in digest_value):
        raise RuntimeBootstrapError("telegram_application_reference_invalid")
    session_ref = str(session_ref)
    if not 16 <= len(session_ref) <= 65_536 or any(ord(ch) < 32 for ch in session_ref):
        raise RuntimeBootstrapError("telegram_session_reference_invalid")
    return PrivateTelegramReferences(identifier_value, digest_value, session_ref)


def _private_directory(path: Path) -> Path:
    """Return an owner-private canonical directory; unsafe existing state is fatal."""

    lexical = Path(os.path.abspath(os.path.expanduser(str(path))))
    if lexical.exists():
        st = os.lstat(lexical)
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
            raise RuntimeBootstrapError("unsafe_private_runtime_root")
        if Path(os.path.realpath(lexical)) != lexical:
            raise RuntimeBootstrapError("unsafe_private_runtime_root")
        if hasattr(os, "geteuid") and st.st_uid != os.geteuid():
            raise RuntimeBootstrapError("unsafe_private_runtime_owner")
        if stat.S_IMODE(st.st_mode) != 0o700:
            raise RuntimeBootstrapError("unsafe_private_runtime_mode")
        return lexical

    try:
        lexical.mkdir(parents=True, mode=0o700)
        os.chmod(lexical, 0o700)
    except OSError as exc:
        raise RuntimeBootstrapError("private_runtime_create_failed") from exc
    st = os.lstat(lexical)
    if not stat.S_ISDIR(st.st_mode) or stat.S_IMODE(st.st_mode) != 0o700:
        raise RuntimeBootstrapError("private_runtime_mode_failed")
    if hasattr(os, "geteuid") and st.st_uid != os.geteuid():
        raise RuntimeBootstrapError("unsafe_private_runtime_owner")
    return lexical


def _validate_private_regular(path: Path, *, mode: int = 0o600) -> None:
    st = os.lstat(path)
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
        raise RuntimeBootstrapError("unsafe_rate_limit_database")
    if hasattr(os, "geteuid") and st.st_uid != os.geteuid():
        raise RuntimeBootstrapError("unsafe_rate_limit_database_owner")
    if st.st_nlink != 1:
        raise RuntimeBootstrapError("unsafe_rate_limit_database_hardlink")
    if stat.S_IMODE(st.st_mode) != mode:
        raise RuntimeBootstrapError("unsafe_rate_limit_database_mode")


def _prepare_private_database(path: Path) -> None:
    """Create 0600 database inode before SQLite opens it; never normalize unsafe state."""

    if path.exists() or path.is_symlink():
        _validate_private_regular(path)
        return
    flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | int(getattr(os, "O_NOFOLLOW", 0)) | int(getattr(os, "O_CLOEXEC", 0))
    try:
        fd = os.open(path, flags, 0o600)
    except FileExistsError:
        _validate_private_regular(path)
        return
    except OSError as exc:
        raise RuntimeBootstrapError("rate_limit_database_create_failed") from exc
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or stat.S_IMODE(st.st_mode) != 0o600:
            raise RuntimeBootstrapError("unsafe_rate_limit_database")
        if hasattr(os, "geteuid") and st.st_uid != os.geteuid():
            raise RuntimeBootstrapError("unsafe_rate_limit_database_owner")
    finally:
        os.close(fd)


class _SQLiteFixedWindowStore:
    """Small process-safe quota store shared by read and write endpoint limiters."""

    def __init__(self, database_path: Path, *, clock: Callable[[], float] = time.time):
        self.database_path = Path(database_path)
        self.clock = clock
        parent = _private_directory(self.database_path.parent)
        if self.database_path.parent != parent:
            raise RuntimeBootstrapError("unsafe_rate_limit_path")
        _prepare_private_database(self.database_path)
        self._initialize()

    @staticmethod
    def _digest(value: str) -> str:
        return hashlib.sha256(value.encode("utf-8", "strict")).hexdigest()

    def _validate_sidecars(self) -> None:
        for suffix in ("-wal", "-shm"):
            path = Path(str(self.database_path) + suffix)
            if path.exists() or path.is_symlink():
                _validate_private_regular(path)

    def _connect(self) -> sqlite3.Connection:
        _validate_private_regular(self.database_path)
        self._validate_sidecars()
        try:
            connection = sqlite3.connect(str(self.database_path), timeout=5.0, isolation_level=None)
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute("PRAGMA busy_timeout=5000")
            # SQLite may have just created WAL/SHM files. Tighten immediately and
            # reject any topology mismatch before returning the connection.
            for suffix in ("-wal", "-shm"):
                sidecar = Path(str(self.database_path) + suffix)
                if sidecar.exists():
                    st = os.lstat(sidecar)
                    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
                        connection.close()
                        raise RuntimeBootstrapError("unsafe_rate_limit_database_sidecar")
                    if hasattr(os, "geteuid") and st.st_uid != os.geteuid():
                        connection.close()
                        raise RuntimeBootstrapError("unsafe_rate_limit_database_owner")
                    os.chmod(sidecar, 0o600)
                    _validate_private_regular(sidecar)
            return connection
        except RuntimeBootstrapError:
            raise
        except (OSError, sqlite3.Error) as exc:
            raise RuntimeBootstrapError("rate_limit_database_unavailable") from exc

    def _initialize(self) -> None:
        connection = self._connect()
        try:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS fixed_window_quota ("
                "namespace TEXT NOT NULL, actor_hash TEXT NOT NULL, operation_hash TEXT NOT NULL, "
                "window_start INTEGER NOT NULL, count INTEGER NOT NULL, "
                "PRIMARY KEY(namespace, actor_hash, operation_hash))"
            )
            connection.execute(
                "CREATE TABLE IF NOT EXISTS fixed_window_clock ("
                "singleton INTEGER PRIMARY KEY CHECK(singleton=1), "
                "high_water INTEGER NOT NULL CHECK(high_water>=0))"
            )
        except sqlite3.Error as exc:
            raise RuntimeBootstrapError("rate_limit_database_unavailable") from exc
        finally:
            connection.close()
            self._validate_sidecars()

    def take(
        self,
        *,
        namespace: str,
        actor: str,
        operation: str,
        limit: int,
        window_seconds: int,
    ) -> tuple[bool, int, int]:
        outcome = self.take_outcome(
            namespace=namespace,
            actor=actor,
            operation=operation,
            limit=limit,
            window_seconds=window_seconds,
        )
        return outcome.allowed, outcome.remaining, outcome.retry_after_seconds

    def take_outcome(
        self,
        *,
        namespace: str,
        actor: str,
        operation: str,
        limit: int,
        window_seconds: int,
    ) -> _FixedWindowOutcome:
        """Return enforcement and reset metadata from the same atomic decision."""

        if not namespace or len(namespace) > 32 or not operation or len(operation) > 256:
            raise RuntimeBootstrapError("invalid_rate_limit_namespace")
        if not isinstance(actor, str) or not actor or len(actor) > 512:
            raise RuntimeBootstrapError("invalid_rate_limit_actor")
        if not 1 <= limit <= 10_000 or not 1 <= window_seconds <= 3_600:
            raise RuntimeBootstrapError("invalid_rate_limit_policy")
        now = int(self.clock())
        if now < 0:
            raise RuntimeBootstrapError("invalid_rate_limit_clock")
        window_start = (now // window_seconds) * window_seconds
        window_end = window_start + window_seconds
        retry_after = max(1, window_end - now)
        actor_hash = self._digest(actor)
        operation_hash = self._digest(operation)
        connection = self._connect()
        transaction_open = False
        try:
            connection.execute("BEGIN IMMEDIATE")
            transaction_open = True
            clock_row = connection.execute(
                "SELECT high_water FROM fixed_window_clock WHERE singleton=1"
            ).fetchone()
            if clock_row is not None and now < int(clock_row[0]):
                connection.execute("ROLLBACK")
                transaction_open = False
                raise RuntimeBootstrapError("rate_limit_clock_moved_backward")
            if clock_row is None:
                connection.execute(
                    "INSERT INTO fixed_window_clock(singleton,high_water) VALUES(1,?)",
                    (now,),
                )
            elif now > int(clock_row[0]):
                connection.execute(
                    "UPDATE fixed_window_clock SET high_water=? WHERE singleton=1",
                    (now,),
                )
            connection.execute(
                "DELETE FROM fixed_window_quota WHERE window_start < ?",
                (window_start - (2 * window_seconds),),
            )
            row = connection.execute(
                "SELECT window_start, count FROM fixed_window_quota "
                "WHERE namespace=? AND actor_hash=? AND operation_hash=?",
                (namespace, actor_hash, operation_hash),
            ).fetchone()
            count = int(row[1]) if row is not None and int(row[0]) == window_start else 0
            if count >= limit:
                connection.execute("COMMIT")
                transaction_open = False
                return _FixedWindowOutcome(False, 0, retry_after, window_end)
            count += 1
            connection.execute(
                "INSERT INTO fixed_window_quota(namespace,actor_hash,operation_hash,window_start,count) "
                "VALUES(?,?,?,?,?) ON CONFLICT(namespace,actor_hash,operation_hash) DO UPDATE SET "
                "window_start=excluded.window_start,count=excluded.count",
                (namespace, actor_hash, operation_hash, window_start, count),
            )
            connection.execute("COMMIT")
            transaction_open = False
            return _FixedWindowOutcome(True, limit - count, 0, window_end)
        except RuntimeBootstrapError:
            if transaction_open:
                try:
                    connection.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
            raise
        except sqlite3.Error as exc:
            if transaction_open:
                try:
                    connection.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
            raise RuntimeBootstrapError("rate_limit_database_unavailable") from exc
        finally:
            connection.close()
            self._validate_sidecars()


class SQLiteReadRateLimiter:
    def __init__(self, store: _SQLiteFixedWindowStore, *, limit: int, window_seconds: int):
        self.store = store
        self.limit = limit
        self.window_seconds = window_seconds

    def check(self, actor: str) -> RateLimitDecision:
        try:
            outcome = self.store.take_outcome(
                namespace="read",
                actor=actor,
                operation="read-api",
                limit=self.limit,
                window_seconds=self.window_seconds,
            )
        except RuntimeBootstrapError as exc:
            raise BridgeError("Rate limiter is unavailable", status=503, code="rate_limiter_unavailable") from exc
        return RateLimitDecision(
            allowed=outcome.allowed,
            remaining=outcome.remaining,
            retry_after_seconds=outcome.retry_after_seconds or None,
        )


class SQLiteWriteRateLimiter:
    def __init__(self, store: _SQLiteFixedWindowStore, *, limit: int, window_seconds: int):
        self.store = store
        self.limit = limit
        self.window_seconds = window_seconds

    def consume(self, actor_sha256: str, operation_id: str) -> tuple[int, int]:
        try:
            outcome = self.store.take_outcome(
                namespace="write",
                actor=actor_sha256,
                operation=operation_id,
                limit=self.limit,
                window_seconds=self.window_seconds,
            )
        except RuntimeBootstrapError as exc:
            raise EndpointPolicyError("rate_limiter_unavailable", status=503) from exc
        if not outcome.allowed:
            raise EndpointPolicyError(
                "rate_limited",
                status=429,
                retry_after_seconds=outcome.retry_after_seconds,
            )
        return outcome.remaining, outcome.reset_at_epoch


class _ReadSessionLockedClient:
    """Hold the same private process lock for a read client connect→disconnect lifecycle."""

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

    async def __call__(self, request: Any) -> Any:
        """Forward raw Telethon requests while retaining the session lock."""

        return await self._client(request)

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
        return TelegramClient(
            StringSession(refs.session_reference),
            refs.application_id_ref,
            refs.application_hash_ref,
        )

    return create_client


def build_production_application_from_env() -> UnifiedBridgeApplication:
    """Construct dependencies without opening a Telegram connection."""

    read_config = ReadAppConfig.from_env()
    if read_config.private_root is None:
        return UnifiedBridgeApplication(read_app=BridgeApplication(config=read_config))

    private_root = _private_directory(read_config.private_root)
    state_root = _private_directory(private_root / "state")
    quota_store = _SQLiteFixedWindowStore(state_root / "rate_limit.sqlite3")
    window_seconds = _bounded_int_env("BRIDGE_RATE_WINDOW_SECONDS", 60, 10, 3_600)
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
        preview_ttl_seconds=_bounded_int_env("BRIDGE_PREVIEW_TTL_SECONDS", 300, 30, 1_800),
    )


__all__ = [
    "PrivateTelegramReferences",
    "RuntimeBootstrapError",
    "SQLiteReadRateLimiter",
    "SQLiteWriteRateLimiter",
    "build_production_application_from_env",
    "load_private_telegram_references",
]
