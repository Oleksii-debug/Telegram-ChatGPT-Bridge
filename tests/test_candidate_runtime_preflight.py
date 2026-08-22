# -*- coding: utf-8 -*-
from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from ops.candidate_runtime_preflight import validate_candidate_release_envelope
from ops.release_guard import SafetyError


SHA = "a" * 40
H1 = "1" * 64
H2 = "2" * 64


class CandidateRuntimePreflightTests(unittest.TestCase):
    def _candidate(self, root: Path) -> None:
        root.joinpath("passenger_wsgi.py").write_text(
            "from bridge.app import application\n", encoding="utf-8"
        )
        root.joinpath("requirements.txt").write_text(
            "Telethon==1.42.0\n", encoding="utf-8"
        )
        root.joinpath("requirements.lock").write_text(
            "Telethon==1.42.0 \\\n"
            f"    --hash=sha256:{H1} \\\n"
            f"    --hash=sha256:{H2}\n"
            "pyaes==1.6.1 \\\n"
            f"    --hash=sha256:{H1}\n",
            encoding="utf-8",
        )

    def test_valid_exact_envelope_returns_hash_only_projection(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._candidate(root)
            result = validate_candidate_release_envelope(root, candidate_sha=SHA)
            self.assertEqual(2, result["schema_version"])
            self.assertTrue(result["preflight_pass"])
            self.assertTrue(result["fully_hash_locked"])
            self.assertTrue(result["startup_import_contract_ok"])
            self.assertFalse(result["promotion_authorized"])
            self.assertFalse(result["private_runtime_payload_present"])
            self.assertEqual(1, result["direct_package_count"])
            self.assertEqual(2, result["locked_package_count"])
            self.assertFalse(result["test_dependencies"]["present"])
            self.assertNotIn("packages", result)
            self.assertNotIn("root", result)

    def test_missing_wsgi_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); self._candidate(root)
            root.joinpath("passenger_wsgi.py").unlink()
            with self.assertRaises(SafetyError):
                validate_candidate_release_envelope(root, candidate_sha=SHA)

    def test_wrong_wsgi_import_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); self._candidate(root)
            root.joinpath("passenger_wsgi.py").write_text(
                "from bridge.integrated_app import application\n", encoding="utf-8"
            )
            with self.assertRaises(SafetyError):
                validate_candidate_release_envelope(root, candidate_sha=SHA)

    def test_requirements_without_lock_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); self._candidate(root)
            root.joinpath("requirements.lock").unlink()
            with self.assertRaises(SafetyError):
                validate_candidate_release_envelope(root, candidate_sha=SHA)

    def test_unhashed_lock_entry_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); self._candidate(root)
            root.joinpath("requirements.lock").write_text("Telethon==1.42.0\n", encoding="utf-8")
            with self.assertRaises(SafetyError):
                validate_candidate_release_envelope(root, candidate_sha=SHA)

    def test_floating_direct_requirement_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); self._candidate(root)
            root.joinpath("requirements.txt").write_text("Telethon>=1.42\n", encoding="utf-8")
            with self.assertRaises(SafetyError):
                validate_candidate_release_envelope(root, candidate_sha=SHA)

    def test_direct_lock_version_mismatch_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); self._candidate(root)
            root.joinpath("requirements.lock").write_text(
                f"Telethon==1.41.0 --hash=sha256:{H1}\n", encoding="utf-8"
            )
            with self.assertRaises(SafetyError):
                validate_candidate_release_envelope(root, candidate_sha=SHA)

    def test_required_telethon_direct_dependency_cannot_be_omitted(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); self._candidate(root)
            root.joinpath("requirements.txt").write_text("pyaes==1.6.1\n", encoding="utf-8")
            root.joinpath("requirements.lock").write_text(
                f"pyaes==1.6.1 --hash=sha256:{H1}\n", encoding="utf-8"
            )
            with self.assertRaises(SafetyError):
                validate_candidate_release_envelope(root, candidate_sha=SHA)

    def test_duplicate_normalized_lock_package_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); self._candidate(root)
            root.joinpath("requirements.lock").write_text(
                f"Telethon==1.42.0 --hash=sha256:{H1}\n"
                f"telethon==1.42.0 --hash=sha256:{H2}\n",
                encoding="utf-8",
            )
            with self.assertRaises(SafetyError):
                validate_candidate_release_envelope(root, candidate_sha=SHA)

    def test_test_dependency_input_requires_matching_hash_locked_pair(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); self._candidate(root)
            root.joinpath("requirements-test.txt").write_text("pytest==9.0.0\n", encoding="utf-8")
            with self.assertRaises(SafetyError):
                validate_candidate_release_envelope(root, candidate_sha=SHA)
            root.joinpath("requirements-test.lock").write_text(
                f"pytest==9.0.0 --hash=sha256:{H2}\n", encoding="utf-8"
            )
            result = validate_candidate_release_envelope(root, candidate_sha=SHA)
            self.assertTrue(result["test_dependencies"]["present"])
            self.assertEqual(1, result["test_dependencies"]["direct_package_count"])
            self.assertEqual(1, result["test_dependencies"]["locked_package_count"])

    def test_test_dependency_version_mismatch_or_unhashed_entry_fails(self) -> None:
        for lock_text in (
            f"pytest==8.0.0 --hash=sha256:{H2}\n",
            "pytest==9.0.0\n",
        ):
            with self.subTest(lock_text=lock_text), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp); self._candidate(root)
                root.joinpath("requirements-test.txt").write_text("pytest==9.0.0\n", encoding="utf-8")
                root.joinpath("requirements-test.lock").write_text(lock_text, encoding="utf-8")
                with self.assertRaises(SafetyError):
                    validate_candidate_release_envelope(root, candidate_sha=SHA)

    def test_private_runtime_material_never_enters_candidate_package(self) -> None:
        for relative in ("var/state.sqlite3", "sessions/account.session", ".env", "private_config.json"):
            with self.subTest(relative=relative), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp); self._candidate(root)
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("private", encoding="utf-8")
                with self.assertRaises(SafetyError):
                    validate_candidate_release_envelope(root, candidate_sha=SHA)

    @unittest.skipUnless(hasattr(os, "symlink"), "symlink not supported")
    def test_symlinked_required_release_file_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); self._candidate(root)
            target = root.joinpath("real_wsgi.py")
            target.write_text("from bridge.app import application\n", encoding="utf-8")
            root.joinpath("passenger_wsgi.py").unlink()
            os.symlink(target, root.joinpath("passenger_wsgi.py"))
            with self.assertRaises(SafetyError):
                validate_candidate_release_envelope(root, candidate_sha=SHA)

    @unittest.skipUnless(hasattr(os, "link"), "hardlink not supported")
    def test_hardlinked_required_release_file_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); self._candidate(root)
            os.link(root / "requirements.lock", root / "duplicate.lock")
            with self.assertRaises(SafetyError):
                validate_candidate_release_envelope(root, candidate_sha=SHA)

    def test_invalid_candidate_sha_fails_before_release_claim(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); self._candidate(root)
            with self.assertRaises(SafetyError):
                validate_candidate_release_envelope(root, candidate_sha="main")


if __name__ == "__main__":
    unittest.main()
