# -*- coding: utf-8 -*-
from __future__ import annotations

import importlib.util
import os
import shutil
import socket
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from ops.release_guard import SafetyError
from ops.release_package import (
    DIRECT_RUNTIME,
    EXPECTED_RUNTIME_LOCK,
    build_release_identity,
    validate_dependency_contract,
    validate_public_release_tree,
    validate_wsgi_contract,
)

ROOT = Path(__file__).resolve().parents[1]


class ReleasePackageContractTests(unittest.TestCase):
    def _minimal_root(self) -> tuple[tempfile.TemporaryDirectory, Path]:
        temp = tempfile.TemporaryDirectory()
        root = Path(temp.name)
        for name in ("passenger_wsgi.py", "requirements.txt", "requirements.lock"):
            shutil.copy2(ROOT / name, root / name)
        return temp, root

    def test_repository_release_package_is_canonical_and_has_no_test_only_dependencies(self):
        result = validate_public_release_tree(ROOT, paths=(
            "passenger_wsgi.py", "requirements.txt", "requirements.lock", "bridge/app.py"
        ))
        self.assertEqual(4, result["dependencies"]["package_count"])
        self.assertFalse(result["dependencies"]["test_dependencies_present"])
        self.assertEqual({"telethon": "1.44.0"}, DIRECT_RUNTIME)
        self.assertEqual({"telethon", "pyaes", "rsa", "pyasn1"}, set(EXPECTED_RUNTIME_LOCK))

    def test_missing_wsgi_fails_closed(self):
        temp, root = self._minimal_root()
        self.addCleanup(temp.cleanup)
        (root / "passenger_wsgi.py").unlink()
        with self.assertRaises(SafetyError):
            validate_wsgi_contract(root)

    def test_wrong_wsgi_import_or_startup_call_fails_closed(self):
        temp, root = self._minimal_root()
        self.addCleanup(temp.cleanup)
        (root / "passenger_wsgi.py").write_text("from bridge.integrated_app import application\n", encoding="utf-8")
        with self.assertRaises(SafetyError):
            validate_wsgi_contract(root)
        (root / "passenger_wsgi.py").write_text(
            "from bridge.app import application\napplication()\n", encoding="utf-8"
        )
        with self.assertRaises(SafetyError):
            validate_wsgi_contract(root)

    def test_requirements_input_without_lock_fails_closed(self):
        temp, root = self._minimal_root()
        self.addCleanup(temp.cleanup)
        (root / "requirements.lock").unlink()
        with self.assertRaises(SafetyError):
            validate_dependency_contract(root)

    def test_tampered_or_unhashed_lock_fails_closed(self):
        temp, root = self._minimal_root()
        self.addCleanup(temp.cleanup)
        lock = root / "requirements.lock"
        original = lock.read_text(encoding="utf-8")
        lock.write_text(original.replace("52fc49", "02fc49", 1), encoding="utf-8")
        with self.assertRaises(SafetyError):
            validate_dependency_contract(root)
        lock.write_text("Telethon==1.44.0\n", encoding="utf-8")
        with self.assertRaises(SafetyError):
            validate_dependency_contract(root)

    def test_floating_direct_requirement_fails_closed(self):
        temp, root = self._minimal_root()
        self.addCleanup(temp.cleanup)
        (root / "requirements.txt").write_text("Telethon>=1.44\n", encoding="utf-8")
        with self.assertRaises(SafetyError):
            validate_dependency_contract(root)

    def test_private_runtime_paths_are_rejected_from_public_manifest(self):
        for path in (".env", "var/session.bin", "state/user.session", "private/config.json", "credentials.json"):
            with self.subTest(path=path):
                with self.assertRaises(SafetyError):
                    validate_public_release_tree(ROOT, paths=(
                        "passenger_wsgi.py", "requirements.txt", "requirements.lock", path
                    ))

    def test_release_identity_is_hash_bound_and_never_authorizes_deployment(self):
        identity = build_release_identity(
            ROOT,
            sha="a" * 40,
            repository="Oleksii-debug/Telegram-ChatGPT-Bridge",
        )
        self.assertEqual("a" * 40, identity["sha"])
        self.assertFalse(identity["private_values_recorded"])
        self.assertFalse(identity["deployment_authorized"])
        self.assertRegex(identity["identity_sha256"], r"^[0-9a-f]{64}$")
        text = repr(identity).casefold()
        self.assertNotIn("session_string", text)
        self.assertNotIn("bearer ", text)

    def test_passenger_import_is_network_free_and_exports_callable(self):
        module_name = "_telegram_bridge_release_wsgi_test"
        spec = importlib.util.spec_from_file_location(module_name, ROOT / "passenger_wsgi.py")
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        module = importlib.util.module_from_spec(spec)
        with mock.patch.object(socket.socket, "connect", side_effect=AssertionError("network call during WSGI import")), \
             mock.patch.object(socket, "create_connection", side_effect=AssertionError("network call during WSGI import")):
            spec.loader.exec_module(module)
        self.assertTrue(callable(module.application))

    def test_no_meaningless_test_requirement_files_are_present(self):
        self.assertFalse((ROOT / "requirements-test.txt").exists())
        self.assertFalse((ROOT / "requirements-test.lock").exists())


if __name__ == "__main__":
    unittest.main()
