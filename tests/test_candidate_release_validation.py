# -*- coding: utf-8 -*-
import os
import tempfile
import unittest
from pathlib import Path

from ops import candidate_release_validation as crv
from ops.release_guard import SafetyError


class CandidateReleaseValidationTests(unittest.TestCase):
    SHA = "a" * 40
    TELETHON_HASH = "1" * 64
    PYTEST_HASH = "2" * 64

    def write(self, root: Path, rel: str, text: str) -> Path:
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return path

    def candidate(self, root: Path) -> None:
        self.write(root, "passenger_wsgi.py", "from bridge.app import application\n")
        self.write(root, "requirements.txt", "Telethon==1.40.0\n")
        self.write(
            root,
            "requirements.lock",
            "Telethon==1.40.0 \\\n    --hash=sha256:" + self.TELETHON_HASH + "\n",
        )
        self.write(root, "bridge/app.py", "application = object()\n")
        self.write(root, "tests/test_smoke.py", "import unittest\n")

    def test_valid_package_returns_hash_only_identity_and_never_authorizes(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); self.candidate(root)
            result = crv.validate_candidate_release(root, self.SHA)
            self.assertTrue(result["package_preflight_pass"])
            self.assertTrue(result["telethon_pinned"])
            self.assertFalse(result["promotion_authorized"])
            self.assertFalse(result["private_runtime_payload_present"])
            self.assertEqual("bridge.app.application", result["startup_import_target"])
            self.assertEqual(64, len(result["wsgi_sha256"]))
            self.assertNotIn(str(root), str(result))

    def test_missing_wsgi_or_wrong_import_blocks(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); self.candidate(root)
            (root / "passenger_wsgi.py").unlink()
            with self.assertRaises(SafetyError): crv.validate_candidate_release(root, self.SHA)
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); self.candidate(root)
            self.write(root, "passenger_wsgi.py", "from bridge.integrated_app import application\n")
            with self.assertRaises(SafetyError): crv.validate_candidate_release(root, self.SHA)

    def test_missing_lock_and_unhashed_lock_block(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); self.candidate(root)
            (root / "requirements.lock").unlink()
            with self.assertRaises(SafetyError): crv.validate_candidate_release(root, self.SHA)
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); self.candidate(root)
            self.write(root, "requirements.lock", "Telethon==1.40.0\n")
            with self.assertRaises(SafetyError): crv.validate_candidate_release(root, self.SHA)

    def test_missing_telethon_and_floating_or_url_requirements_block(self):
        bad_inputs = (
            "requests==2.32.0\n",
            "Telethon>=1.40.0\n",
            "Telethon @ https://example.invalid/pkg.whl\n",
            "-r other.txt\n",
        )
        for bad in bad_inputs:
            with self.subTest(bad=bad), tempfile.TemporaryDirectory() as td:
                root = Path(td); self.candidate(root)
                self.write(root, "requirements.txt", bad)
                with self.assertRaises(SafetyError): crv.validate_candidate_release(root, self.SHA)

    def test_direct_and_lock_versions_must_match(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); self.candidate(root)
            self.write(root, "requirements.txt", "Telethon==1.39.0\n")
            with self.assertRaises(SafetyError): crv.validate_candidate_release(root, self.SHA)

    def test_lock_rejects_nonhash_options_and_malformed_hash(self):
        for tail in ("--index-url=https://example.invalid", "--hash=sha256:abc", "--hash=md5:" + "1" * 32):
            with self.subTest(tail=tail), tempfile.TemporaryDirectory() as td:
                root = Path(td); self.candidate(root)
                self.write(root, "requirements.lock", f"Telethon==1.40.0 {tail}\n")
                with self.assertRaises(SafetyError): crv.validate_candidate_release(root, self.SHA)

    def test_optional_test_requirements_are_exact_pair_and_hash_locked(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); self.candidate(root)
            self.write(root, "requirements-test.txt", "pytest==9.0.0\n")
            with self.assertRaises(SafetyError): crv.validate_candidate_release(root, self.SHA)
            self.write(root, "requirements-test.lock", "pytest==9.0.0 --hash=sha256:" + self.PYTEST_HASH + "\n")
            result = crv.validate_candidate_release(root, self.SHA)
            self.assertTrue(result["test_dependencies"]["present"])
            self.assertEqual(1, result["test_dependencies"]["direct_dependency_count"])

    def test_private_runtime_payload_blocks(self):
        for rel in ("var/state.sqlite3", "sessions/account.session", ".env", "private_config.json"):
            with self.subTest(rel=rel), tempfile.TemporaryDirectory() as td:
                root = Path(td); self.candidate(root)
                self.write(root, rel, "private")
                with self.assertRaises(SafetyError): crv.validate_candidate_release(root, self.SHA)

    def test_symlink_and_hardlink_release_controls_block(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); self.candidate(root)
            target = root / "requirements.lock"
            target.unlink(); target.symlink_to(root / "requirements.txt")
            with self.assertRaises(SafetyError): crv.validate_candidate_release(root, self.SHA)
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); self.candidate(root)
            lock = root / "requirements.lock"
            os.link(lock, root / "duplicate.lock")
            with self.assertRaises(SafetyError): crv.validate_candidate_release(root, self.SHA)

    def test_invalid_sha_and_invalid_utf8_block(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); self.candidate(root)
            with self.assertRaises(SafetyError): crv.validate_candidate_release(root, "short")
            (root / "requirements.txt").write_bytes(b"Telethon==1.40.0\xff")
            with self.assertRaises(SafetyError): crv.validate_candidate_release(root, self.SHA)


if __name__ == "__main__":
    unittest.main()
