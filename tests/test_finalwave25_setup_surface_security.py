import os
import sqlite3
import tempfile
import threading
import unittest
from html.parser import HTMLParser
from pathlib import Path

from ops.setup_surface_security import (
    OUTCOME_AUTHORIZED,
    OUTCOME_BEGIN_FINALIZATION,
    OUTCOME_CODE_SENT,
    OUTCOME_NEEDS_2FA,
    STAGE_CODE,
    STAGE_DISABLED,
    STAGE_FINALIZING,
    STAGE_PASSWORD,
    STAGE_SESSION_READY,
    STAGE_START,
    SetupSurfaceError,
    SetupSurfaceStore,
    later_auth_live_protocol,
    render_setup_page,
    safe_setup_audit_record,
    setup_response_headers,
    validate_action_schema_excludes_setup,
    validate_configured_public_origin,
)

ROUTE = "A" * 48
OTHER_ROUTE = "B" * 48
ACTOR = "198.51.100.10"


class MutableClock:
    def __init__(self, value=1_700_000_000):
        self.value = value

    def __call__(self):
        return self.value


class MarkupProbe(HTMLParser):
    def __init__(self):
        super().__init__()
        self.labels = set()
        self.visible_controls = []
        self.button_text = []
        self.depth = 0
        self.headings = []
        self.mains = 0
        self.status_regions = 0
        self.bad_handlers = []
        self.positive_tabindex = False

    def handle_starttag(self, tag, attrs):
        data = dict(attrs)
        if tag == "label" and data.get("for"):
            self.labels.add(data["for"])
        if tag == "input" and data.get("type") != "hidden":
            self.visible_controls.append(data)
        if tag == "button":
            self.button_text.append("")
            self.depth += 1
        if tag in {"h1", "h2", "h3", "h4", "h5", "h6"}:
            self.headings.append(int(tag[1]))
        if tag == "main" or data.get("role") == "main":
            self.mains += 1
        if data.get("role") in {"status", "alert"} or data.get("aria-live") in {"polite", "assertive"}:
            self.status_regions += 1
        for key in data:
            if key.startswith("on"):
                self.bad_handlers.append(key)
        if "tabindex" in data:
            try:
                self.positive_tabindex |= int(data["tabindex"]) > 0
            except ValueError:
                self.positive_tabindex = True

    def handle_data(self, data):
        if self.depth:
            self.button_text[-1] += data

    def handle_endtag(self, tag):
        if tag == "button" and self.depth:
            self.depth -= 1


class SetupSurfaceStoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name) / "private"
        self.root.mkdir(mode=0o700)
        os.chmod(self.root, 0o700)
        self.db = self.root / "setup.sqlite3"
        self.clock = MutableClock()
        self.counter = 0

        def token_factory():
            self.counter += 1
            return ("T%03d" % self.counter) + ("x" * 40)

        self.tokens = token_factory
        self.store = SetupSurfaceStore(self.db, clock=self.clock, token_factory=self.tokens)
        self.store.arm_once(ROUTE)

    def tearDown(self):
        self.tmp.cleanup()

    def open(self, store=None, actor=ACTOR):
        return (store or self.store).open_challenge(ROUTE, actor_key=actor)

    def test_route_and_form_secrets_are_only_digested_at_rest(self):
        challenge = self.open()
        raw = self.db.read_bytes()
        self.assertNotIn(ROUTE.encode(), raw)
        self.assertNotIn(challenge.token.encode(), raw)
        conn = sqlite3.connect(self.db)
        row = conn.execute("SELECT route_sha256,token_sha256 FROM setup_gate").fetchone()
        conn.close()
        self.assertEqual(len(row[0]), 64)
        self.assertEqual(len(row[1]), 64)
        self.assertNotEqual(row[0], ROUTE)
        self.assertNotEqual(row[1], challenge.token)

    def test_wrong_or_weak_route_is_indistinguishable_not_found(self):
        for route in ("short", OTHER_ROUTE):
            with self.assertRaises(SetupSurfaceError) as cm:
                self.store.open_challenge(route, actor_key=ACTOR)
            self.assertEqual(cm.exception.status, 404)
            self.assertEqual(cm.exception.code, "not_found")

    def test_challenge_is_single_use_and_replay_fails(self):
        challenge = self.open()
        result = self.store.transition(
            route_secret=ROUTE,
            challenge_token=challenge.token,
            actor_key=ACTOR,
            expected_stage=STAGE_START,
            outcome=OUTCOME_CODE_SENT,
        )
        self.assertEqual(result.stage, STAGE_CODE)
        with self.assertRaises(SetupSurfaceError) as cm:
            self.store.transition(
                route_secret=ROUTE,
                challenge_token=challenge.token,
                actor_key=ACTOR,
                expected_stage=STAGE_START,
                outcome=OUTCOME_CODE_SENT,
            )
        self.assertIn(cm.exception.code, {"stale_setup_stage", "form_token_required", "form_replayed_or_invalid"})

    def test_challenge_expiry_fails_closed(self):
        challenge = self.open()
        self.clock.value = challenge.expires_at + 1
        with self.assertRaises(SetupSurfaceError) as cm:
            self.store.transition(
                route_secret=ROUTE,
                challenge_token=challenge.token,
                actor_key=ACTOR,
                expected_stage=STAGE_START,
                outcome=OUTCOME_CODE_SENT,
            )
        self.assertEqual(cm.exception.code, "form_expired")
        fresh = self.open()
        self.assertNotEqual(fresh.token, challenge.token)

    def test_no_2fa_path_closes_route_before_session_persistence_and_finishes_after_restart(self):
        c1 = self.open()
        self.store.transition(
            route_secret=ROUTE,
            challenge_token=c1.token,
            actor_key=ACTOR,
            expected_stage=STAGE_START,
            outcome=OUTCOME_CODE_SENT,
        )
        c2 = self.open()
        self.store.transition(
            route_secret=ROUTE,
            challenge_token=c2.token,
            actor_key=ACTOR,
            expected_stage=STAGE_CODE,
            outcome=OUTCOME_AUTHORIZED,
        )
        self.assertEqual(self.store.status()["stage"], STAGE_SESSION_READY)
        c3 = self.open()
        result = self.store.transition(
            route_secret=ROUTE,
            challenge_token=c3.token,
            actor_key=ACTOR,
            expected_stage=STAGE_SESSION_READY,
            outcome=OUTCOME_BEGIN_FINALIZATION,
        )
        self.assertTrue(result.disabled)
        self.assertEqual(self.store.status()["stage"], STAGE_FINALIZING)
        self.assertFalse(self.store.status()["challenge_active"])
        with self.assertRaises(SetupSurfaceError) as closed:
            self.open()
        self.assertEqual(closed.exception.status, 404)

        reopened = SetupSurfaceStore(self.db, clock=self.clock, token_factory=self.tokens)
        self.assertEqual(reopened.status()["stage"], STAGE_FINALIZING)
        self.assertTrue(reopened.status()["disabled"])
        completed = reopened.complete_finalization()
        self.assertEqual(completed.stage, STAGE_DISABLED)
        with self.assertRaises(SetupSurfaceError) as closed_after_restart:
            self.open(reopened)
        self.assertEqual(closed_after_restart.exception.status, 404)

        conn = sqlite3.connect(self.db)
        row = conn.execute("SELECT route_sha256,token_sha256,disabled FROM setup_gate").fetchone()
        conn.close()
        self.assertIsNone(row[0])
        self.assertIsNone(row[1])
        self.assertEqual(row[2], 1)

    def test_2fa_path_persists_across_restart(self):
        c1 = self.open()
        self.store.transition(
            route_secret=ROUTE,
            challenge_token=c1.token,
            actor_key=ACTOR,
            expected_stage=STAGE_START,
            outcome=OUTCOME_CODE_SENT,
        )
        c2 = self.open()
        self.store.transition(
            route_secret=ROUTE,
            challenge_token=c2.token,
            actor_key=ACTOR,
            expected_stage=STAGE_CODE,
            outcome=OUTCOME_NEEDS_2FA,
        )
        reopened = SetupSurfaceStore(self.db, clock=self.clock, token_factory=self.tokens)
        self.assertEqual(reopened.status()["stage"], STAGE_PASSWORD)
        c3 = self.open(reopened)
        reopened.transition(
            route_secret=ROUTE,
            challenge_token=c3.token,
            actor_key=ACTOR,
            expected_stage=STAGE_PASSWORD,
            outcome=OUTCOME_AUTHORIZED,
        )
        self.assertEqual(reopened.status()["stage"], STAGE_SESSION_READY)

    def test_failure_rotates_token_and_replay_fails(self):
        challenge = self.open()
        fresh = self.store.record_failure(
            route_secret=ROUTE,
            challenge_token=challenge.token,
            actor_key=ACTOR,
            expected_stage=STAGE_START,
        )
        self.assertNotEqual(fresh.token, challenge.token)
        with self.assertRaises(SetupSurfaceError):
            self.store.record_failure(
                route_secret=ROUTE,
                challenge_token=challenge.token,
                actor_key=ACTOR,
                expected_stage=STAGE_START,
            )

    def test_rate_limit_is_persistent_across_store_instances(self):
        challenge = self.open()
        for _ in range(self.store.ACTOR_LIMITS[STAGE_START]):
            challenge = self.store.record_failure(
                route_secret=ROUTE,
                challenge_token=challenge.token,
                actor_key=ACTOR,
                expected_stage=STAGE_START,
            )
        reopened = SetupSurfaceStore(self.db, clock=self.clock, token_factory=self.tokens)
        with self.assertRaises(SetupSurfaceError) as cm:
            reopened.record_failure(
                route_secret=ROUTE,
                challenge_token=challenge.token,
                actor_key=ACTOR,
                expected_stage=STAGE_START,
            )
        self.assertEqual(cm.exception.status, 429)
        self.assertEqual(cm.exception.code, "rate_limited")
        fresh = reopened.record_failure(
            route_secret=ROUTE,
            challenge_token=challenge.token,
            actor_key="198.51.100.11",
            expected_stage=STAGE_START,
        )
        self.assertEqual(fresh.stage, STAGE_START)

    def test_open_rate_limit_is_persistent(self):
        challenge = None
        for _ in range(self.store.ACTOR_LIMITS["OPEN"]):
            challenge = self.open()
        self.assertIsNotNone(challenge)
        reopened = SetupSurfaceStore(self.db, clock=self.clock, token_factory=self.tokens)
        with self.assertRaises(SetupSurfaceError) as cm:
            self.open(reopened)
        self.assertEqual(cm.exception.status, 429)

    def test_concurrent_same_token_has_exactly_one_winner(self):
        challenge = self.open()
        barrier = threading.Barrier(2)
        outcomes = []
        lock = threading.Lock()

        def worker(actor):
            local = SetupSurfaceStore(self.db, clock=self.clock, token_factory=self.tokens)
            barrier.wait()
            try:
                local.transition(
                    route_secret=ROUTE,
                    challenge_token=challenge.token,
                    actor_key=actor,
                    expected_stage=STAGE_START,
                    outcome=OUTCOME_CODE_SENT,
                )
                value = "ok"
            except SetupSurfaceError as exc:
                value = exc.code
            with lock:
                outcomes.append(value)

        threads = [threading.Thread(target=worker, args=(f"actor-{index}",)) for index in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(5)
        self.assertEqual(outcomes.count("ok"), 1, outcomes)
        self.assertEqual(self.store.status()["stage"], STAGE_CODE)

    def test_status_leaks_no_route_or_token_digest(self):
        challenge = self.open()
        status = self.store.status()
        self.assertNotIn("route_sha256", status)
        self.assertNotIn("token_sha256", status)
        self.assertNotIn(ROUTE, repr(status))
        self.assertNotIn(challenge.token, repr(status))

    def test_backward_clock_fails_closed_without_resetting_quota(self):
        challenge = self.open()
        challenge = self.store.record_failure(
            route_secret=ROUTE,
            challenge_token=challenge.token,
            actor_key=ACTOR,
            expected_stage=STAGE_START,
        )
        self.clock.value -= 1
        with self.assertRaises(SetupSurfaceError) as cm:
            self.store.record_failure(
                route_secret=ROUTE,
                challenge_token=challenge.token,
                actor_key=ACTOR,
                expected_stage=STAGE_START,
            )
        self.assertEqual(cm.exception.code, "setup_clock_moved_backward")
        self.assertEqual(cm.exception.status, 503)

    def test_rearming_after_initialization_is_rejected(self):
        with self.assertRaises(SetupSurfaceError) as cm:
            self.store.arm_once(OTHER_ROUTE)
        self.assertEqual(cm.exception.status, 409)


class FilesystemSafetyTests(unittest.TestCase):
    def test_broad_private_root_mode_fails_closed(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "private"
            root.mkdir(mode=0o755)
            os.chmod(root, 0o755)
            with self.assertRaises(SetupSurfaceError) as cm:
                SetupSurfaceStore(root / "state.db")
            self.assertEqual(cm.exception.code, "unsafe_private_setup_state_mode")

    def test_hardlinked_database_fails_closed(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "private"
            root.mkdir(mode=0o700)
            os.chmod(root, 0o700)
            db = root / "state.db"
            fd = os.open(db, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
            os.close(fd)
            os.link(db, root / "other.db")
            with self.assertRaises(SetupSurfaceError) as cm:
                SetupSurfaceStore(db)
            self.assertEqual(cm.exception.code, "unsafe_private_setup_database")

    def test_symlink_database_fails_closed(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "private"
            root.mkdir(mode=0o700)
            os.chmod(root, 0o700)
            target = root / "target"
            target.write_text("x")
            os.chmod(target, 0o600)
            link = root / "state.db"
            link.symlink_to(target.name)
            with self.assertRaises(SetupSurfaceError):
                SetupSurfaceStore(link)


class MarkupAndPolicyTests(unittest.TestCase):
    def test_every_public_stage_has_structural_accessibility_prerequisites(self):
        token = "Q" * 48
        for stage in (STAGE_START, STAGE_CODE, STAGE_PASSWORD, STAGE_SESSION_READY, STAGE_DISABLED):
            markup = render_setup_page(stage, None if stage == STAGE_DISABLED else token, status_code="READY")
            probe = MarkupProbe()
            probe.feed(markup)
            self.assertEqual(probe.mains, 1, stage)
            self.assertTrue(probe.headings and probe.headings[0] == 1, stage)
            self.assertTrue(
                all(current - previous <= 1 for previous, current in zip(probe.headings, probe.headings[1:])),
                stage,
            )
            self.assertGreaterEqual(probe.status_regions, 1, stage)
            self.assertFalse(probe.bad_handlers, stage)
            self.assertFalse(probe.positive_tabindex, stage)
            for control in probe.visible_controls:
                self.assertIn(control.get("id"), probe.labels, (stage, control))
            for text in probe.button_text:
                self.assertTrue(text.strip(), stage)
            self.assertNotIn("<script", markup.casefold())

    def test_finalizing_stage_is_not_web_renderable(self):
        with self.assertRaises(SetupSurfaceError) as cm:
            render_setup_page(STAGE_FINALIZING, None)
        self.assertEqual(cm.exception.status, 404)

    def test_completion_page_exposes_no_bearer_or_manual_cpanel_instruction(self):
        markup = render_setup_page(STAGE_DISABLED, None, status_code="SETUP_DISABLED").casefold()
        for forbidden in ("bearer", "bridge_token", "api base", "cpanel", "restart python app"):
            self.assertNotIn(forbidden, markup)

    def test_setup_security_headers_prevent_cache_embedding_and_referrer_leak(self):
        headers = dict(setup_response_headers())
        self.assertIn("no-store", headers["Cache-Control"])
        self.assertEqual(headers["X-Frame-Options"], "DENY")
        self.assertEqual(headers["Referrer-Policy"], "no-referrer")
        self.assertIn("default-src 'none'", headers["Content-Security-Policy"])
        self.assertIn("form-action 'self'", headers["Content-Security-Policy"])
        self.assertIn("noindex", headers["X-Robots-Tag"])

    def test_origin_is_configured_https_only_not_host_header_derived(self):
        self.assertEqual(
            validate_configured_public_origin("https://tg-api.rukadopomogy.org.ua"),
            "https://tg-api.rukadopomogy.org.ua",
        )
        for bad in (
            "http://tg-api.rukadopomogy.org.ua",
            "https://u:p@example.com",
            "https://example.com/private",
            "https://example.com?q=x",
            "example.com",
        ):
            with self.assertRaises(SetupSurfaceError):
                validate_configured_public_origin(bad)

    def test_action_schema_rejects_setup_paths_and_secret_fields(self):
        validate_action_schema_excludes_setup({"paths": {"/api/v1/dialogs/list": {"post": {}}}})
        with self.assertRaises(SetupSurfaceError):
            validate_action_schema_excludes_setup({"paths": {"/setup/login": {"post": {}}}})
        private_field = "session" + "_string"
        malicious = {
            "paths": {
                "/api/v1/x": {
                    "post": {
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {private_field: {"type": "string"}},
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        with self.assertRaises(SetupSurfaceError):
            validate_action_schema_excludes_setup(malicious)

    def test_canonical_action_schema_has_no_setup_credential_request_fields(self):
        from ops.openapi_registry import build_action_openapi

        schema = build_action_openapi("https://tg-api.rukadopomogy.org.ua")
        validate_action_schema_excludes_setup(schema)

    def test_audit_record_is_allowlisted_metadata_only(self):
        row = safe_setup_audit_record(
            event="STAGE_ADVANCED",
            stage=STAGE_CODE,
            status_code="CODE_SENT",
            generation=3,
        )
        self.assertEqual(set(row), {"event", "stage", "status_code", "generation"})
        with self.assertRaises(SetupSurfaceError):
            safe_setup_audit_record(
                event="PRIVATE_TEXT",
                stage=STAGE_CODE,
                status_code="CODE_SENT",
                generation=3,
            )

    def test_later_auth_protocol_is_nonexecuting_sha_bound_and_no_cpanel_user_work(self):
        sha = "a" * 40
        rows = later_auth_live_protocol(candidate_sha=sha)
        self.assertGreaterEqual(len(rows), 10)
        self.assertTrue(all(row["candidate_sha"] == sha for row in rows))
        self.assertTrue(all(row["execute_now"] is False for row in rows))
        self.assertTrue(all(row["public_secret_value_allowed"] is False for row in rows))
        self.assertTrue(all(row["user_cpanel_required"] is False for row in rows))
        private = [row for row in rows if row["private_user_input"]]
        self.assertTrue(private)
        self.assertTrue(all(row["actor"] == "USER" for row in private))
        ids = [row["step_id"] for row in rows]
        self.assertLess(ids.index("DISABLE_SETUP_ROUTE_BEFORE_SESSION_PERSIST"), ids.index("PERSIST_SESSION_PRIVATE_SERVER_SIDE"))


if __name__ == "__main__":
    unittest.main()
