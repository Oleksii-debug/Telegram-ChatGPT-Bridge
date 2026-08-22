# -*- coding: utf-8 -*-
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from ops import hostiq_lifecycle


class LifecycleTests(unittest.TestCase):
    def root(self, td):
        root = Path(td) / "private"
        root.mkdir()
        os.chmod(root, 0o700)
        return root

    def file(self, root, name="hook", content="#!/bin/sh\nexit 0\n", mode=0o700):
        p = root / name
        p.write_text(content, encoding="utf-8")
        os.chmod(p, mode)
        return p

    @staticmethod
    def health_payload(*, ready=True):
        components = {
            "auth": "configured",
            "backend": "configured" if ready else "unconfigured",
            "storage": "configured",
            "rate_limit": "configured",
        }
        return json.dumps({"ok": True, "service": "telegram-bridge", "ready": ready, "components": components}).encode()

    def test_private_hook_accepts_owner_only(self):
        with tempfile.TemporaryDirectory() as td:
            root = self.root(td); p = self.file(root)
            self.assertEqual(p, hostiq_lifecycle.validate_private_file(root, p, require_executable=True))

    def test_broad_hook_mode_blocks(self):
        with tempfile.TemporaryDirectory() as td:
            root = self.root(td); p = self.file(root, mode=0o744)
            self.assertRaises(Exception, hostiq_lifecycle.validate_private_file, root, p, require_executable=True)

    def test_broad_root_mode_blocks(self):
        with tempfile.TemporaryDirectory() as td:
            root = self.root(td); os.chmod(root, 0o755); p = self.file(root)
            self.assertRaises(Exception, hostiq_lifecycle.validate_private_file, root, p)

    def test_symlink_file_blocks(self):
        with tempfile.TemporaryDirectory() as td:
            root = self.root(td); target = self.file(root, "target", mode=0o600); link = root / "link"; link.symlink_to(target)
            self.assertRaises(Exception, hostiq_lifecycle.validate_private_file, root, link)

    def test_hardlink_blocks(self):
        with tempfile.TemporaryDirectory() as td:
            root = self.root(td); p = self.file(root, "x", mode=0o600); os.link(p, root / "y")
            self.assertRaises(Exception, hostiq_lifecycle.validate_private_file, root, p)

    def test_path_escape_blocks(self):
        with tempfile.TemporaryDirectory() as td:
            root = self.root(td); outside = Path(td) / "x"; outside.write_text("x"); os.chmod(outside, 0o600)
            self.assertRaises(Exception, hostiq_lifecycle.validate_private_file, root, outside)

    def test_hook_success_nonzero_timeout(self):
        with tempfile.TemporaryDirectory() as td:
            root = self.root(td); ok = self.file(root, "ok"); bad = self.file(root, "bad", "#!/bin/sh\nexit 7\n")
            self.assertEqual("PASS", hostiq_lifecycle.run_private_hook(root, ok, expected_name="restart").status)
            self.assertEqual("HOOK_NONZERO", hostiq_lifecycle.run_private_hook(root, bad, expected_name="restart").detail_code)
            with mock.patch.object(hostiq_lifecycle, "run_private_executable", return_value=-1):
                self.assertEqual("HOOK_TIMEOUT", hostiq_lifecycle.run_private_hook(root, ok, expected_name="restart").detail_code)

    def test_endpoint_requires_https_production_host(self):
        self.assertEqual("https://tg-api.rukadopomogy.org.ua/health", hostiq_lifecycle.validate_endpoint_url("https://tg-api.rukadopomogy.org.ua/health"))
        for url in (
            "http://tg-api.rukadopomogy.org.ua/health",
            "https://evil.example/health",
            "file:///etc/passwd",
            "https://u:p@tg-api.rukadopomogy.org.ua/x",
            "https://tg-api.rukadopomogy.org.ua/setup-abcdefghijklmnop",
        ):
            with self.subTest(url=url), self.assertRaises(Exception):
                hostiq_lifecycle.validate_endpoint_url(url)

    def test_health_200_alone_is_not_enough(self):
        with mock.patch.object(hostiq_lifecycle, "_request", return_value=(200, b"{}", "application/json")):
            self.assertEqual("HEALTH_EXCEPTION", hostiq_lifecycle.health_check("https://tg-api.rukadopomogy.org.ua/health").detail_code)

    def test_legacy_status_ok_shape_is_not_enough(self):
        with mock.patch.object(hostiq_lifecycle, "_request", return_value=(200, b'{"status":"ok"}', "application/json")):
            self.assertEqual("FAIL", hostiq_lifecycle.health_check("https://tg-api.rukadopomogy.org.ua/health").status)

    def test_health_ready_shape_passes(self):
        with mock.patch.object(hostiq_lifecycle, "_request", return_value=(200, self.health_payload(ready=True), "application/json")):
            result = hostiq_lifecycle.health_check("https://tg-api.rukadopomogy.org.ua/health")
            self.assertEqual("PASS", result.status)
            self.assertEqual("HEALTH_READY", result.detail_code)

    def test_health_not_ready_fails_without_explicit_bootstrap_mode(self):
        with mock.patch.object(hostiq_lifecycle, "_request", return_value=(200, self.health_payload(ready=False), "application/json")):
            result = hostiq_lifecycle.health_check("https://tg-api.rukadopomogy.org.ua/health")
            self.assertEqual("FAIL", result.status)
            self.assertEqual("HEALTH_NOT_READY", result.detail_code)

    def test_health_not_ready_can_pass_only_in_explicit_bootstrap_mode(self):
        with mock.patch.object(hostiq_lifecycle, "_request", return_value=(200, self.health_payload(ready=False), "application/json")):
            result = hostiq_lifecycle.health_check("https://tg-api.rukadopomogy.org.ua/health", allow_bootstrap_not_ready=True)
            self.assertEqual("PASS", result.status)
            self.assertEqual("HEALTH_BOOTSTRAP_NOT_READY", result.detail_code)

    def test_health_inconsistent_ready_flag_fails(self):
        body = json.dumps({
            "ok": True,
            "service": "telegram-bridge",
            "ready": True,
            "components": {"auth": "configured", "backend": "unconfigured", "storage": "configured", "rate_limit": "configured"},
        }).encode()
        with mock.patch.object(hostiq_lifecycle, "_request", return_value=(200, body, "application/json")):
            self.assertEqual("FAIL", hostiq_lifecycle.health_check("https://tg-api.rukadopomogy.org.ua/health").status)

    def test_unauth_reject_and_leak_signature(self):
        with mock.patch.object(hostiq_lifecycle, "_request", return_value=(401, b'{"error":"unauthorized"}', "application/json")):
            self.assertEqual("PASS", hostiq_lifecycle.unauthenticated_smoke("https://tg-api.rukadopomogy.org.ua/private").status)
        with mock.patch.object(hostiq_lifecycle, "_request", return_value=(401, b"Traceback (most recent call last)", "text/plain")):
            self.assertEqual("UNAUTH_LEAK_SIGNATURE", hostiq_lifecycle.unauthenticated_smoke("https://tg-api.rukadopomogy.org.ua/private").detail_code)

    def test_unauth_200_fails(self):
        with mock.patch.object(hostiq_lifecycle, "_request", return_value=(200, b"{}", "application/json")):
            self.assertEqual("UNAUTH_NOT_REJECTED", hostiq_lifecycle.unauthenticated_smoke("https://tg-api.rukadopomogy.org.ua/private").detail_code)

    def test_authenticated_smoke_uses_private_reference_but_returns_no_value(self):
        with tempfile.TemporaryDirectory() as td:
            root = self.root(td); bearer = self.file(root, "bearer", "x" * 32, 0o600)
            def fake(url, timeout, token=None):
                self.assertEqual("x" * 32, token)
                return 200, b'{"status":"ready"}', "application/json"
            with mock.patch.object(hostiq_lifecycle, "_request", side_effect=fake):
                result = hostiq_lifecycle.authenticated_smoke("https://tg-api.rukadopomogy.org.ua/private", private_root=root, token_file=bearer)
            self.assertEqual("PASS", result.status)
            self.assertNotIn("x" * 32, repr(result))

    def test_candidate_auth_probe_accepts_truthful_backend_not_ready_without_live_telegram(self):
        with tempfile.TemporaryDirectory() as td:
            root = self.root(td); bearer = self.file(root, "bearer", "x" * 32, 0o600)
            body = b'{"ok":false,"request_id":"abc","error":{"code":"telegram_backend_unconfigured","message":"not ready"}}'
            with mock.patch.object(hostiq_lifecycle, "_request_post_empty_json", return_value=(503, body, "application/json")):
                result = hostiq_lifecycle.candidate_authenticated_read_smoke(
                    "https://tg-api.rukadopomogy.org.ua/api/v1/dialogs/list",
                    private_root=root,
                    token_file=bearer,
                    allow_backend_unconfigured=True,
                )
            self.assertEqual("PASS", result.status)
            self.assertEqual("AUTH_ACCEPTED_BACKEND_NOT_READY", result.detail_code)

    def test_candidate_auth_probe_not_ready_requires_explicit_mode(self):
        with tempfile.TemporaryDirectory() as td:
            root = self.root(td); bearer = self.file(root, "bearer", "x" * 32, 0o600)
            body = b'{"ok":false,"request_id":"abc","error":{"code":"telegram_backend_unconfigured","message":"not ready"}}'
            with mock.patch.object(hostiq_lifecycle, "_request_post_empty_json", return_value=(503, body, "application/json")):
                result = hostiq_lifecycle.candidate_authenticated_read_smoke(
                    "https://tg-api.rukadopomogy.org.ua/api/v1/dialogs/list",
                    private_root=root,
                    token_file=bearer,
                )
            self.assertEqual("FAIL", result.status)

    def test_candidate_auth_probe_rejects_wrong_path_before_network(self):
        with tempfile.TemporaryDirectory() as td:
            root = self.root(td); bearer = self.file(root, "bearer", "x" * 32, 0o600)
            with mock.patch.object(hostiq_lifecycle.urllib.request, "urlopen") as opener:
                result = hostiq_lifecycle.candidate_authenticated_read_smoke(
                    "https://tg-api.rukadopomogy.org.ua/api/v1/send",
                    private_root=root,
                    token_file=bearer,
                    allow_backend_unconfigured=True,
                )
            self.assertEqual("FAIL", result.status)
            opener.assert_not_called()

    def test_short_private_reference_fails_closed(self):
        with tempfile.TemporaryDirectory() as td:
            root = self.root(td); bearer = self.file(root, "bearer", "short", 0o600)
            self.assertEqual("AUTH_EXCEPTION", hostiq_lifecycle.authenticated_smoke("https://tg-api.rukadopomogy.org.ua/private", private_root=root, token_file=bearer).detail_code)

    def test_running_identity_match_mismatch(self):
        with tempfile.TemporaryDirectory() as td:
            root = self.root(td); expected = "a" * 40; p = self.file(root, "sha", expected, 0o600)
            self.assertEqual("IDENTITY_MATCH", hostiq_lifecycle.running_identity(root, p, expected).detail_code)
            self.assertEqual("IDENTITY_MISMATCH", hostiq_lifecycle.running_identity(root, p, "b" * 40).detail_code)

    def test_verify_serving_state(self):
        passed = lambda n: hostiq_lifecycle.HookResult(n, "PASS", None, "OK")
        failed = hostiq_lifecycle.HookResult("h", "FAIL", None, "BAD")
        self.assertEqual("PASS", hostiq_lifecycle.verify_serving_state(health=passed("h"), identity=passed("i"), unauth=passed("u")).status)
        self.assertEqual("FAIL", hostiq_lifecycle.verify_serving_state(health=failed, identity=passed("i"), unauth=passed("u")).status)

    def test_orchestrator_ready_without_rollback(self):
        passed = lambda n: lambda: hostiq_lifecycle.HookResult(n, "PASS", 0, "OK")
        result = hostiq_lifecycle.orchestrate_lifecycle(restart=passed("r"), identity=passed("i"), health=passed("h"), unauth=passed("u"), auth=passed("a"), rollback=passed("rb"), rollback_health=passed("rbh"))
        self.assertEqual("READY_FOR_AUDIT", result["status"])
        self.assertFalse(result["rollback_attempted"])

    def test_orchestrator_failure_rolls_back(self):
        passed = lambda n: lambda: hostiq_lifecycle.HookResult(n, "PASS", 0, "OK")
        failed = lambda n: lambda: hostiq_lifecycle.HookResult(n, "FAIL", 1, "FAIL")
        result = hostiq_lifecycle.orchestrate_lifecycle(restart=passed("r"), identity=failed("i"), health=passed("h"), unauth=passed("u"), auth=None, rollback=passed("rb"), rollback_health=passed("rbh"))
        self.assertEqual("ROLLED_BACK", result["status"])
        self.assertTrue(result["rollback_attempted"])

    def test_orchestrator_unhealthy_rollback_is_critical(self):
        passed = lambda n: lambda: hostiq_lifecycle.HookResult(n, "PASS", 0, "OK")
        failed = lambda n: lambda: hostiq_lifecycle.HookResult(n, "FAIL", 1, "FAIL")
        result = hostiq_lifecycle.orchestrate_lifecycle(restart=failed("r"), identity=passed("i"), health=passed("h"), unauth=passed("u"), auth=None, rollback=passed("rb"), rollback_health=failed("rbh"))
        self.assertEqual("CRITICAL_ROLLBACK_FAILED", result["status"])

    def test_orchestrator_never_copies_arbitrary_hook_detail(self):
        bad = lambda: hostiq_lifecycle.HookResult("anything", "FAIL", 1, "PRIVATE_LABEL_SHOULD_NOT_COPY")
        good = lambda: hostiq_lifecycle.HookResult("anything", "PASS", 0, "PRIVATE_LABEL_SHOULD_NOT_COPY")
        result = hostiq_lifecycle.orchestrate_lifecycle(restart=bad, identity=good, health=good, unauth=good, auth=None, rollback=good, rollback_health=good)
        self.assertNotIn("PRIVATE_LABEL_SHOULD_NOT_COPY", json.dumps(result))
        self.assertEqual("restart", result["failed_stage"])

    def test_private_hook_name_is_allowlisted(self):
        with tempfile.TemporaryDirectory() as td:
            root = self.root(td); p = self.file(root)
            self.assertRaises(Exception, hostiq_lifecycle.run_private_hook, root, p, expected_name="private-label")

    def test_failure_matrix_complete(self):
        self.assertEqual({"RESTART_FAILURE", "IDENTITY_MISMATCH", "HEALTH_FAILURE", "UNAUTH_SMOKE_FAILURE", "AUTH_SMOKE_FAILURE", "RESUME_FAILURE", "ROLLBACK_HEALTH_FAILURE"}, set(hostiq_lifecycle.lifecycle_failure_matrix()))


if __name__ == "__main__":
    unittest.main()
