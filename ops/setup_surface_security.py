# -*- coding: utf-8 -*-
"""Credential-free security core for the one-time Telegram setup surface.

This module deliberately does not talk to Telegram and never stores API hashes,
phone numbers, login codes, 2FA passwords, StringSession values, bearer tokens,
or the private setup route itself. It provides the durable one-time gate,
replay/rate-limit state, accessible markup, and privacy-safe protocol facts that
a later live setup adapter can compose with Telethon behind an independent gate.
"""
from __future__ import annotations

import hashlib
import hmac
import html
import os
import re
import secrets
import sqlite3
import stat
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping
from urllib.parse import urlsplit


class SetupSurfaceError(RuntimeError):
    """Stable fail-closed setup error containing only a public error code."""

    def __init__(self, code: str, *, status: int = 400):
        super().__init__(code)
        self.code = code
        self.status = status


STAGE_START = "START"
STAGE_CODE = "CODE"
STAGE_PASSWORD = "PASSWORD"
STAGE_SESSION_READY = "SESSION_READY"
STAGE_FINALIZING = "FINALIZING"
STAGE_DISABLED = "DISABLED"
STAGES = frozenset({STAGE_START, STAGE_CODE, STAGE_PASSWORD, STAGE_SESSION_READY, STAGE_FINALIZING, STAGE_DISABLED})

OUTCOME_CODE_SENT = "CODE_SENT"
OUTCOME_NEEDS_2FA = "NEEDS_2FA"
OUTCOME_AUTHORIZED = "AUTHORIZED"
OUTCOME_BEGIN_FINALIZATION = "BEGIN_FINALIZATION"

_ALLOWED_TRANSITIONS = {
    (STAGE_START, OUTCOME_CODE_SENT): STAGE_CODE,
    (STAGE_CODE, OUTCOME_NEEDS_2FA): STAGE_PASSWORD,
    (STAGE_CODE, OUTCOME_AUTHORIZED): STAGE_SESSION_READY,
    (STAGE_PASSWORD, OUTCOME_AUTHORIZED): STAGE_SESSION_READY,
    (STAGE_SESSION_READY, OUTCOME_BEGIN_FINALIZATION): STAGE_FINALIZING,
}

_ROUTE_RE = re.compile(r"^[A-Za-z0-9_-]{32,128}$")
_TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{32,192}$")
_SAFE_STATUS_CODES = frozenset({
    "READY",
    "CODE_SENT",
    "LOGIN_CODE_REJECTED",
    "TWO_FACTOR_REQUIRED",
    "TWO_FACTOR_REJECTED",
    "SESSION_PERSISTED",
    "SETUP_DISABLED",
    "RATE_LIMITED",
    "FORM_EXPIRED",
    "INVALID_REQUEST",
    "SERVICE_UNAVAILABLE",
})


@dataclass(frozen=True, repr=False)
class SetupChallenge:
    stage: str
    token: str
    expires_at: int

    def public_facts(self) -> dict[str, Any]:
        """Return non-secret facts only; the form token is intentionally omitted."""
        return {"stage": self.stage, "expires_at": self.expires_at, "token_present": True}


@dataclass(frozen=True)
class SetupTransition:
    previous_stage: str
    stage: str
    disabled: bool

    def public_facts(self) -> dict[str, Any]:
        return {
            "previous_stage": self.previous_stage,
            "stage": self.stage,
            "disabled": self.disabled,
        }


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", "strict")).hexdigest()


def _require_private_directory(path: Path) -> Path:
    lexical = Path(os.path.abspath(os.path.expanduser(str(path))))
    if not lexical.exists():
        try:
            lexical.mkdir(parents=True, mode=0o700)
            os.chmod(lexical, 0o700)
        except OSError as exc:
            raise SetupSurfaceError("private_setup_state_create_failed", status=503) from exc
    try:
        st = os.lstat(lexical)
    except OSError as exc:
        raise SetupSurfaceError("private_setup_state_unavailable", status=503) from exc
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        raise SetupSurfaceError("unsafe_private_setup_state_root", status=503)
    if Path(os.path.realpath(lexical)) != lexical:
        raise SetupSurfaceError("unsafe_private_setup_state_root", status=503)
    if hasattr(os, "geteuid") and st.st_uid != os.geteuid():
        raise SetupSurfaceError("unsafe_private_setup_state_owner", status=503)
    if stat.S_IMODE(st.st_mode) != 0o700:
        raise SetupSurfaceError("unsafe_private_setup_state_mode", status=503)
    return lexical


def _validate_private_regular(path: Path) -> None:
    try:
        st = os.lstat(path)
    except OSError as exc:
        raise SetupSurfaceError("private_setup_database_unavailable", status=503) from exc
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
        raise SetupSurfaceError("unsafe_private_setup_database", status=503)
    if hasattr(os, "geteuid") and st.st_uid != os.geteuid():
        raise SetupSurfaceError("unsafe_private_setup_database_owner", status=503)
    if stat.S_IMODE(st.st_mode) != 0o600:
        raise SetupSurfaceError("unsafe_private_setup_database_mode", status=503)


def _prepare_private_database(path: Path) -> None:
    _require_private_directory(path.parent)
    if path.exists() or path.is_symlink():
        _validate_private_regular(path)
        return
    flags = (
        os.O_RDWR
        | os.O_CREAT
        | os.O_EXCL
        | int(getattr(os, "O_NOFOLLOW", 0))
        | int(getattr(os, "O_CLOEXEC", 0))
    )
    try:
        fd = os.open(path, flags, 0o600)
    except FileExistsError:
        _validate_private_regular(path)
        return
    except OSError as exc:
        raise SetupSurfaceError("private_setup_database_create_failed", status=503) from exc
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or stat.S_IMODE(st.st_mode) != 0o600:
            raise SetupSurfaceError("unsafe_private_setup_database", status=503)
        if hasattr(os, "geteuid") and st.st_uid != os.geteuid():
            raise SetupSurfaceError("unsafe_private_setup_database_owner", status=503)
    finally:
        os.close(fd)


class SetupSurfaceStore:
    """Process-safe durable gate state; no Telegram credential value is accepted."""

    TOKEN_TTL_SECONDS = 600
    WINDOW_SECONDS = 60
    ACTOR_LIMITS = {
        "OPEN": 12,
        STAGE_START: 4,
        STAGE_CODE: 6,
        STAGE_PASSWORD: 4,
        STAGE_SESSION_READY: 3,
    }
    GLOBAL_LIMITS = {
        "OPEN": 36,
        STAGE_START: 12,
        STAGE_CODE: 18,
        STAGE_PASSWORD: 10,
        STAGE_SESSION_READY: 8,
    }

    def __init__(
        self,
        database_path: Path,
        *,
        clock: Callable[[], float] = time.time,
        token_factory: Callable[[], str] | None = None,
    ) -> None:
        self.database_path = Path(database_path)
        self.clock = clock
        self.token_factory = token_factory or (lambda: secrets.token_urlsafe(32))
        _prepare_private_database(self.database_path)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        _validate_private_regular(self.database_path)
        try:
            conn = sqlite3.connect(str(self.database_path), timeout=5.0, isolation_level=None)
            conn.execute("PRAGMA journal_mode=DELETE")
            conn.execute("PRAGMA synchronous=FULL")
            conn.execute("PRAGMA busy_timeout=5000")
            return conn
        except sqlite3.Error as exc:
            raise SetupSurfaceError("private_setup_database_unavailable", status=503) from exc

    def _initialize(self) -> None:
        conn = self._connect()
        try:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS setup_gate ("
                "singleton INTEGER PRIMARY KEY CHECK(singleton=1), "
                "route_sha256 TEXT, stage TEXT NOT NULL, token_sha256 TEXT, "
                "token_expires INTEGER, generation INTEGER NOT NULL, disabled INTEGER NOT NULL, "
                "created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL)"
            )
            conn.execute(
                "CREATE TABLE IF NOT EXISTS setup_quota ("
                "scope_sha256 TEXT NOT NULL, stage TEXT NOT NULL, window_start INTEGER NOT NULL, "
                "count INTEGER NOT NULL, PRIMARY KEY(scope_sha256, stage))"
            )
            conn.execute(
                "CREATE TABLE IF NOT EXISTS setup_clock ("
                "singleton INTEGER PRIMARY KEY CHECK(singleton=1), high_water INTEGER NOT NULL)"
            )
        except sqlite3.Error as exc:
            raise SetupSurfaceError("private_setup_database_unavailable", status=503) from exc
        finally:
            conn.close()

    def arm_once(self, route_secret: str) -> None:
        """Arm a fresh gate once. Re-arming requires out-of-band state replacement."""
        self._validate_route_secret(route_secret)
        now = self._now()
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            self._enforce_clock(conn, now)
            row = conn.execute("SELECT stage,disabled FROM setup_gate WHERE singleton=1").fetchone()
            if row is not None:
                conn.execute("ROLLBACK")
                raise SetupSurfaceError("setup_gate_already_initialized", status=409)
            conn.execute(
                "INSERT INTO setup_gate(singleton,route_sha256,stage,token_sha256,token_expires,generation,disabled,created_at,updated_at) "
                "VALUES(1,?,?,NULL,NULL,0,0,?,?)",
                (_digest(route_secret), STAGE_START, now, now),
            )
            conn.execute("COMMIT")
        except SetupSurfaceError:
            raise
        except sqlite3.Error as exc:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise SetupSurfaceError("private_setup_database_unavailable", status=503) from exc
        finally:
            conn.close()

    def status(self) -> dict[str, Any]:
        """Return privacy-safe durable state; route/token digests are never returned."""
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT stage,token_expires,generation,disabled FROM setup_gate WHERE singleton=1"
            ).fetchone()
        finally:
            conn.close()
        if row is None:
            return {
                "initialized": False,
                "stage": None,
                "challenge_active": False,
                "generation": 0,
                "disabled": False,
            }
        now = self._now()
        stage, token_expires, generation, disabled = row
        return {
            "initialized": True,
            "stage": str(stage),
            "challenge_active": bool(token_expires is not None and int(token_expires) >= now and not disabled),
            "generation": int(generation),
            "disabled": bool(disabled),
        }

    def open_challenge(self, route_secret: str, *, actor_key: str) -> SetupChallenge:
        self._validate_route_secret(route_secret)
        self._validate_actor(actor_key)
        now = self._now()
        token = self._new_token()
        expires = now + self.TOKEN_TTL_SECONDS
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            self._enforce_clock(conn, now)
            row = self._gate_row(conn)
            self._require_route(row, route_secret)
            self._consume_quota(conn, actor_key, "OPEN", now)
            stage = str(row[1])
            if stage == STAGE_DISABLED or bool(row[6]):
                raise SetupSurfaceError("not_found", status=404)
            generation = int(row[5]) + 1
            conn.execute(
                "UPDATE setup_gate SET token_sha256=?,token_expires=?,generation=?,updated_at=? WHERE singleton=1",
                (_digest(token), expires, generation, now),
            )
            conn.execute("COMMIT")
            return SetupChallenge(stage, token, expires)
        except SetupSurfaceError:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        except sqlite3.Error as exc:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise SetupSurfaceError("private_setup_database_unavailable", status=503) from exc
        finally:
            conn.close()

    def transition(
        self,
        *,
        route_secret: str,
        challenge_token: str,
        actor_key: str,
        expected_stage: str,
        outcome: str,
    ) -> SetupTransition:
        """Consume one form token and durably advance a successful setup outcome."""
        self._validate_route_secret(route_secret)
        self._validate_token(challenge_token)
        self._validate_actor(actor_key)
        if expected_stage not in STAGES or expected_stage == STAGE_DISABLED:
            raise SetupSurfaceError("invalid_setup_stage")
        next_stage = _ALLOWED_TRANSITIONS.get((expected_stage, outcome))
        if next_stage is None:
            raise SetupSurfaceError("invalid_setup_transition")
        now = self._now()
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            self._enforce_clock(conn, now)
            row = self._gate_row(conn)
            self._require_route(row, route_secret)
            self._require_challenge(row, challenge_token, expected_stage, now)
            self._consume_quota(conn, actor_key, expected_stage, now)
            web_gate_closed = next_stage == STAGE_FINALIZING
            conn.execute(
                "UPDATE setup_gate SET route_sha256=?,stage=?,token_sha256=NULL,token_expires=NULL,disabled=?,updated_at=? WHERE singleton=1",
                (None if web_gate_closed else row[0], next_stage, 1 if web_gate_closed else 0, now),
            )
            conn.execute("COMMIT")
            return SetupTransition(expected_stage, next_stage, web_gate_closed)
        except SetupSurfaceError:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        except sqlite3.Error as exc:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise SetupSurfaceError("private_setup_database_unavailable", status=503) from exc
        finally:
            conn.close()

    def record_failure(
        self,
        *,
        route_secret: str,
        challenge_token: str,
        actor_key: str,
        expected_stage: str,
    ) -> SetupChallenge:
        """Consume a failed submission, enforce quotas, and issue a fresh same-stage token."""
        self._validate_route_secret(route_secret)
        self._validate_token(challenge_token)
        self._validate_actor(actor_key)
        if expected_stage not in self.ACTOR_LIMITS:
            raise SetupSurfaceError("invalid_setup_stage")
        now = self._now()
        new_token = self._new_token()
        expires = now + self.TOKEN_TTL_SECONDS
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            self._enforce_clock(conn, now)
            row = self._gate_row(conn)
            self._require_route(row, route_secret)
            self._require_challenge(row, challenge_token, expected_stage, now)
            self._consume_quota(conn, actor_key, expected_stage, now)
            conn.execute(
                "UPDATE setup_gate SET token_sha256=?,token_expires=?,generation=generation+1,updated_at=? WHERE singleton=1",
                (_digest(new_token), expires, now),
            )
            conn.execute("COMMIT")
            return SetupChallenge(expected_stage, new_token, expires)
        except SetupSurfaceError:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        except sqlite3.Error as exc:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise SetupSurfaceError("private_setup_database_unavailable", status=503) from exc
        finally:
            conn.close()

    def complete_finalization(self) -> SetupTransition:
        """Mark the already-closed setup gate complete after private session persistence.

        The web route was cleared before the external persistence step. If the
        process crashes, restart observes FINALIZING with the route still closed.
        """
        now = self._now()
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            self._enforce_clock(conn, now)
            row = self._gate_row(conn)
            if str(row[1]) != STAGE_FINALIZING or not bool(row[6]) or row[0] is not None:
                raise SetupSurfaceError("finalization_not_ready", status=409)
            conn.execute(
                "UPDATE setup_gate SET stage=?,token_sha256=NULL,token_expires=NULL,disabled=1,updated_at=? WHERE singleton=1",
                (STAGE_DISABLED, now),
            )
            conn.execute("COMMIT")
            return SetupTransition(STAGE_FINALIZING, STAGE_DISABLED, True)
        except SetupSurfaceError:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        except sqlite3.Error as exc:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise SetupSurfaceError("private_setup_database_unavailable", status=503) from exc
        finally:
            conn.close()

    @staticmethod
    def _enforce_clock(conn: sqlite3.Connection, now: int) -> None:
        row = conn.execute("SELECT high_water FROM setup_clock WHERE singleton=1").fetchone()
        if row is not None and now < int(row[0]):
            raise SetupSurfaceError("setup_clock_moved_backward", status=503)
        if row is None:
            conn.execute("INSERT INTO setup_clock(singleton,high_water) VALUES(1,?)", (now,))
        elif now > int(row[0]):
            conn.execute("UPDATE setup_clock SET high_water=? WHERE singleton=1", (now,))

    def _consume_quota(self, conn: sqlite3.Connection, actor_key: str, stage: str, now: int) -> None:
        actor_scope = _digest("actor:" + actor_key)
        global_scope = _digest("global")
        window_start = (now // self.WINDOW_SECONDS) * self.WINDOW_SECONDS
        for scope, limit in (
            (actor_scope, self.ACTOR_LIMITS[stage]),
            (global_scope, self.GLOBAL_LIMITS[stage]),
        ):
            row = conn.execute(
                "SELECT window_start,count FROM setup_quota WHERE scope_sha256=? AND stage=?",
                (scope, stage),
            ).fetchone()
            count = int(row[1]) if row is not None and int(row[0]) == window_start else 0
            if count >= limit:
                raise SetupSurfaceError("rate_limited", status=429)
            count += 1
            conn.execute(
                "INSERT INTO setup_quota(scope_sha256,stage,window_start,count) VALUES(?,?,?,?) "
                "ON CONFLICT(scope_sha256,stage) DO UPDATE SET window_start=excluded.window_start,count=excluded.count",
                (scope, stage, window_start, count),
            )

    @staticmethod
    def _validate_route_secret(route_secret: str) -> None:
        if not isinstance(route_secret, str) or not _ROUTE_RE.fullmatch(route_secret):
            raise SetupSurfaceError("not_found", status=404)

    @staticmethod
    def _validate_token(token: str) -> None:
        if not isinstance(token, str) or not _TOKEN_RE.fullmatch(token):
            raise SetupSurfaceError("invalid_form_token", status=400)

    @staticmethod
    def _validate_actor(actor_key: str) -> None:
        if (
            not isinstance(actor_key, str)
            or not 1 <= len(actor_key) <= 512
            or any(ord(ch) < 32 for ch in actor_key)
        ):
            raise SetupSurfaceError("invalid_actor_key", status=400)

    def _new_token(self) -> str:
        token = self.token_factory()
        self._validate_token(token)
        return token

    def _now(self) -> int:
        try:
            now = int(self.clock())
        except Exception as exc:
            raise SetupSurfaceError("setup_clock_unavailable", status=503) from exc
        if now < 0:
            raise SetupSurfaceError("setup_clock_invalid", status=503)
        return now

    @staticmethod
    def _gate_row(conn: sqlite3.Connection) -> tuple[Any, ...]:
        row = conn.execute(
            "SELECT route_sha256,stage,token_sha256,token_expires,updated_at,generation,disabled "
            "FROM setup_gate WHERE singleton=1"
        ).fetchone()
        if row is None:
            raise SetupSurfaceError("not_found", status=404)
        return row

    @staticmethod
    def _require_route(row: tuple[Any, ...], route_secret: str) -> None:
        stored = row[0]
        if bool(row[6]) or row[1] == STAGE_DISABLED or not isinstance(stored, str):
            raise SetupSurfaceError("not_found", status=404)
        if not hmac.compare_digest(stored, _digest(route_secret)):
            raise SetupSurfaceError("not_found", status=404)

    @staticmethod
    def _require_challenge(row: tuple[Any, ...], token: str, expected_stage: str, now: int) -> None:
        if str(row[1]) != expected_stage:
            raise SetupSurfaceError("stale_setup_stage", status=409)
        token_digest, expires = row[2], row[3]
        if not isinstance(token_digest, str) or expires is None:
            raise SetupSurfaceError("form_token_required", status=409)
        if now > int(expires):
            raise SetupSurfaceError("form_expired", status=409)
        if not hmac.compare_digest(token_digest, _digest(token)):
            raise SetupSurfaceError("form_replayed_or_invalid", status=409)


def setup_response_headers() -> tuple[tuple[str, str], ...]:
    return (
        ("Cache-Control", "no-store, max-age=0"),
        ("Pragma", "no-cache"),
        ("X-Content-Type-Options", "nosniff"),
        ("X-Frame-Options", "DENY"),
        ("Referrer-Policy", "no-referrer"),
        ("X-Robots-Tag", "noindex, nofollow, noarchive, nosnippet"),
        ("Content-Security-Policy", "default-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"),
        ("Permissions-Policy", "camera=(), microphone=(), geolocation=()"),
        ("Cross-Origin-Opener-Policy", "same-origin"),
        ("Cross-Origin-Resource-Policy", "same-origin"),
    )


def _status_markup(status_code: str | None) -> str:
    if status_code is None:
        return "<p id='setup-status' role='status' aria-live='polite'>Готово до наступного кроку.</p>"
    if status_code not in _SAFE_STATUS_CODES:
        status_code = "INVALID_REQUEST"
    messages = {
        "READY": "Готово до наступного кроку.",
        "CODE_SENT": "Telegram прийняв запит на код. Введіть отриманий код нижче.",
        "LOGIN_CODE_REJECTED": "Код не прийнято. Перевірте код і спробуйте ще раз.",
        "TWO_FACTOR_REQUIRED": "Telegram вимагає пароль двоетапної перевірки.",
        "TWO_FACTOR_REJECTED": "Пароль не прийнято. Спробуйте ще раз.",
        "SESSION_PERSISTED": "Приватну Telegram-сесію збережено на сервері.",
        "SETUP_DISABLED": "Одноразове налаштування завершено та вимкнено.",
        "RATE_LIMITED": "Забагато спроб. Повторіть пізніше.",
        "FORM_EXPIRED": "Форма застаріла. Відкрийте приватну сторінку налаштування ще раз.",
        "INVALID_REQUEST": "Запит не прийнято. Перевірте введені дані.",
        "SERVICE_UNAVAILABLE": "Сервіс тимчасово недоступний. Повторіть пізніше.",
    }
    role = "alert" if status_code not in {"READY", "CODE_SENT", "SESSION_PERSISTED", "SETUP_DISABLED"} else "status"
    return f"<p id='setup-status' role='{role}' aria-live='polite'>{html.escape(messages[status_code])}</p>"


def render_setup_page(stage: str, challenge_token: str | None, *, status_code: str | None = None) -> str:
    """Render script-free structural markup. Static source readiness is not human NVDA PASS."""
    if stage not in STAGES:
        raise SetupSurfaceError("invalid_setup_stage")
    if stage == STAGE_FINALIZING:
        raise SetupSurfaceError("not_found", status=404)
    if stage != STAGE_DISABLED:
        if challenge_token is None:
            raise SetupSurfaceError("form_token_required")
        SetupSurfaceStore._validate_token(challenge_token)
    status = _status_markup(status_code)
    intro = (
        "<!doctype html><html lang='uk'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<title>Приватне налаштування Telegram Bridge</title></head><body><main>"
        "<h1>Приватне налаштування Telegram Bridge</h1>"
        "<p>Вводьте приватні дані тільки на цій одноразовій сторінці. Не надсилайте код, пароль або ключі в ChatGPT.</p>"
        + status
    )
    if stage == STAGE_DISABLED:
        body = (
            "<h2>Налаштування завершено</h2>"
            "<p>Приватний маршрут вимкнено. Перезапуск і перевірка збереження сесії виконуються підтримкою або автоматизацією.</p>"
        )
        return intro + body + "</main></body></html>"

    hidden = (
        f"<input type='hidden' name='stage_token' value='{html.escape(str(challenge_token), quote=True)}'>"
        f"<input type='hidden' name='stage' value='{stage}'>"
    )
    if stage == STAGE_START:
        fields = (
            "<h2>Крок 1. Дані Telegram API</h2>"
            "<p><label for='api-id'>Telegram API ID</label><br><input id='api-id' name='api_id' inputmode='numeric' autocomplete='off' required></p>"
            "<p><label for='api-hash'>Telegram API hash</label><br><input id='api-hash' type='password' name='api_hash' autocomplete='off' required></p>"
            "<p><label for='phone'>Номер телефону Telegram</label><br><input id='phone' type='tel' name='phone' autocomplete='tel' required></p>"
            "<button type='submit'>Надіслати код Telegram</button>"
        )
    elif stage == STAGE_CODE:
        fields = (
            "<h2>Крок 2. Код Telegram</h2>"
            "<p><label for='login-code'>Код Telegram</label><br><input id='login-code' name='code' inputmode='numeric' autocomplete='one-time-code' required></p>"
            "<button type='submit'>Підтвердити код</button>"
        )
    elif stage == STAGE_PASSWORD:
        fields = (
            "<h2>Крок 3. Двоетапна перевірка</h2>"
            "<p><label for='two-factor'>Пароль двоетапної перевірки</label><br><input id='two-factor' type='password' name='password' autocomplete='current-password' required></p>"
            "<button type='submit'>Підтвердити пароль</button>"
        )
    else:
        fields = (
            "<h2>Авторизацію підтверджено</h2>"
            "<p>Сервер має приватно зберегти Telegram-сесію та одразу вимкнути одноразовий маршрут. Додаткові секрети тут не показуються.</p>"
            "<button type='submit'>Завершити без показу секретів</button>"
        )
    return intro + "<form method='post' aria-describedby='setup-status'>" + hidden + fields + "</form></main></body></html>"


def validate_configured_public_origin(value: str) -> str:
    """Accept only an operator-configured HTTPS origin; never derive it from Host headers."""
    if not isinstance(value, str) or len(value) > 512:
        raise SetupSurfaceError("invalid_public_origin")
    parts = urlsplit(value.strip())
    if (
        parts.scheme.lower() != "https"
        or not parts.hostname
        or parts.username
        or parts.password
        or parts.query
        or parts.fragment
        or parts.path not in {"", "/"}
    ):
        raise SetupSurfaceError("invalid_public_origin")
    return f"https://{parts.netloc}"


def validate_action_schema_excludes_setup(schema: Mapping[str, Any]) -> None:
    """Fail if the Action exposes setup/login/2FA/session inputs or private setup paths."""
    if not isinstance(schema, Mapping):
        raise SetupSurfaceError("invalid_action_schema")
    paths = schema.get("paths")
    if not isinstance(paths, Mapping):
        raise SetupSurfaceError("invalid_action_schema")
    forbidden_path_terms = ("setup", "bootstrap", "authorize", "login", "2fa", "session")
    for path in paths:
        text = str(path).casefold()
        if any(term in text for term in forbidden_path_terms):
            raise SetupSurfaceError("private_setup_exposed_in_action_schema")

    forbidden_field_terms = {
        "api_hash",
        "session",
        "session_string",
        "login_code",
        "2fa",
        "password",
        "phone",
        "setup_route",
        "setup_key",
        "telegram_2fa_password",
    }

    def walk(node: Any, *, parent_key: str = "") -> None:
        if isinstance(node, Mapping):
            for key, value in node.items():
                normalized = str(key).casefold().replace("-", "_")
                if parent_key in {"properties", "headers"} and normalized in forbidden_field_terms:
                    raise SetupSurfaceError("private_setup_field_exposed_in_action_schema")
                walk(value, parent_key=normalized)
        elif isinstance(node, (list, tuple)):
            for value in node:
                walk(value, parent_key=parent_key)

    walk(schema)


def safe_setup_audit_record(*, event: str, stage: str, status_code: str, generation: int) -> dict[str, Any]:
    """Build bounded metadata only; caller cannot attach Telegram/private content."""
    allowed_events = frozenset({"FORM_OPENED", "SUBMISSION_FAILED", "STAGE_ADVANCED", "SETUP_DISABLED"})
    if event not in allowed_events or stage not in STAGES or status_code not in _SAFE_STATUS_CODES:
        raise SetupSurfaceError("invalid_setup_audit_metadata")
    if not isinstance(generation, int) or isinstance(generation, bool) or not 0 <= generation <= 1_000_000:
        raise SetupSurfaceError("invalid_setup_audit_metadata")
    return {"event": event, "stage": stage, "status_code": status_code, "generation": generation}


def later_auth_live_protocol(*, candidate_sha: str) -> tuple[dict[str, Any], ...]:
    """Exact privacy-safe future protocol. It never authorizes or executes a live step."""
    if not isinstance(candidate_sha, str) or not re.fullmatch(r"[0-9a-f]{40}", candidate_sha):
        raise SetupSurfaceError("invalid_candidate_sha")
    steps = (
        ("AUDITOR_GATE", "AUDITOR", False),
        ("VERIFY_DEPLOYED_SHA", "AUTOMATION", False),
        ("VERIFY_PASSENGER_PY311", "AUTOMATION", False),
        ("VERIFY_PRIVATE_SETUP_ROUTE", "SUPPORT_OR_AUTOMATION", False),
        ("OPEN_PRIVATE_SETUP", "USER", False),
        ("ENTER_TELEGRAM_API_ID_HASH_PHONE", "USER", True),
        ("ENTER_LOGIN_CODE", "USER", True),
        ("ENTER_2FA_ONLY_IF_REQUIRED", "USER", True),
        ("DISABLE_SETUP_ROUTE_BEFORE_SESSION_PERSIST", "AUTOMATION", False),
        ("PERSIST_SESSION_PRIVATE_SERVER_SIDE", "AUTOMATION", False),
        ("MARK_SETUP_DISABLED", "AUTOMATION", False),
        ("RESTART_PASSENGER", "SUPPORT_OR_AUTOMATION", False),
        ("VERIFY_SESSION_SURVIVES_RESTART", "AUTOMATION", False),
        ("VERIFY_ACTION_SCHEMA_STILL_EXCLUDES_SETUP", "AUDITOR", False),
        ("RUN_HARMLESS_AUTHENTICATED_READ_SMOKE", "AUDITOR", False),
    )
    return tuple({
        "step_id": step_id,
        "actor": actor,
        "private_user_input": private_input,
        "candidate_sha": candidate_sha,
        "execute_now": False,
        "public_secret_value_allowed": False,
        "user_cpanel_required": False,
    } for step_id, actor, private_input in steps)
