"""Release-package envelope regression tests.

These tests are credential-free and perform no Telegram/network I/O. They pin the
HOSTiQ Passenger import contract to the unified application surface and make the
runtime dependency envelope explicit before any production deployment gate.
"""
from __future__ import annotations

import io
import json
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class PassengerEnvelopeTests(unittest.TestCase):
    def test_root_passenger_bootstrap_preserves_recovered_import_contract(self):
        source = (ROOT / "passenger_wsgi.py").read_text(encoding="utf-8")
        self.assertIn("from bridge.app import application", source)
        self.assertNotIn("TelegramClient(", source)
        self.assertNotIn("TG_SESSION", source)
        self.assertNotIn("TG_API_HASH", source)

    def test_passenger_import_resolves_to_unified_surface_without_telethon_import(self):
        code = r'''
import sys
import passenger_wsgi
from bridge.integrated_app import application as unified_application
assert passenger_wsgi.application is unified_application
assert passenger_wsgi.application.__module__ == "bridge.integrated_app"
assert not any(name == "telethon" or name.startswith("telethon.") for name in sys.modules)
'''
        result = subprocess.run(
            [sys.executable, "-c", code],
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(0, result.returncode, msg=result.stderr)

    def test_passenger_health_is_unified_fail_closed_health(self):
        code = r'''
import io, json
from passenger_wsgi import application
captured = {}
def start_response(status, headers):
    captured["status"] = status
    captured["headers"] = dict(headers)
environ = {
    "REQUEST_METHOD": "GET",
    "PATH_INFO": "/health",
    "QUERY_STRING": "",
    "CONTENT_TYPE": "",
    "CONTENT_LENGTH": "0",
    "wsgi.input": io.BytesIO(b""),
}
body = b"".join(application(environ, start_response))
payload = json.loads(body.decode("utf-8"))
assert captured["status"] == "200 OK"
assert payload["service"] == "telegram-bridge"
assert payload["ready"] is False
assert set(payload["components"]) == {
    "auth", "backend", "storage", "read_rate_limit", "write_store",
    "write_rate_limit", "telegram_writer",
}
'''
        result = subprocess.run(
            [sys.executable, "-c", code],
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(0, result.returncode, msg=result.stderr)


class DependencyEnvelopeTests(unittest.TestCase):
    def test_direct_runtime_dependency_is_exactly_pinned(self):
        lines = [
            line.strip()
            for line in (ROOT / "requirements.txt").read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        self.assertEqual(["Telethon==1.44.0"], lines)

    def test_hash_lock_contains_complete_exact_telethon_closure(self):
        lock = (ROOT / "requirements.lock").read_text(encoding="utf-8")
        for requirement in (
            "Telethon==1.44.0",
            "pyaes==1.6.1",
            "rsa==4.9.1",
            "pyasn1==0.6.4",
        ):
            self.assertIn(requirement, lock)
        self.assertNotIn(">=", lock)
        self.assertNotIn("~=", lock)
        self.assertNotIn("==*", lock)
        package_lines = [
            line for line in lock.splitlines()
            if line and not line.startswith((" ", "#")) and "==" in line
        ]
        self.assertEqual(4, len(package_lines))
        self.assertGreaterEqual(lock.count("--hash=sha256:"), 4)

    def test_deploy_engine_will_require_lock_when_input_exists(self):
        from ops.deploy_release import _install_locked_requirements
        from ops.release_guard import SafetyError
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "requirements.txt").write_text("Telethon==1.44.0\n", encoding="utf-8")
            with self.assertRaises(SafetyError):
                _install_locked_requirements(
                    Path(sys.executable), root, "requirements.txt", "requirements.lock"
                )


if __name__ == "__main__":
    unittest.main()
