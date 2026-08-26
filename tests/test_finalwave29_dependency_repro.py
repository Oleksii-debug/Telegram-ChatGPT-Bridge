# -*- coding: utf-8 -*-
from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from ops.dependency_repro import (
    ARTIFACT_POLICY,
    BIT_REPRODUCIBLE_BUILD_CLAIMED,
    REPRODUCIBILITY_MODEL,
    download_command,
    expected_artifact_hashes,
    mutated_wrong_hash_lock,
    offline_install_command,
    validate_artifact_policy,
    validate_python_line,
    verify_downloaded_artifacts,
)
from ops.release_guard import SafetyError
from ops.release_package import EXPECTED_RUNTIME_LOCK, validate_dependency_contract, validate_public_release_tree

ROOT = Path(__file__).resolve().parents[1]


class DependencyReproContractTests(unittest.TestCase):
    def _dependency_root(self) -> tuple[tempfile.TemporaryDirectory, Path]:
        temp = tempfile.TemporaryDirectory()
        root = Path(temp.name)
        shutil.copy2(ROOT / "requirements.txt", root / "requirements.txt")
        shutil.copy2(ROOT / "requirements.lock", root / "requirements.lock")
        return temp, root

    def test_truth_model_never_claims_bit_reproducible_build(self):
        result = validate_artifact_policy()
        self.assertEqual("hash-locked-inputs+sealed-prepared-instance-v1", REPRODUCIBILITY_MODEL)
        self.assertFalse(BIT_REPRODUCIBLE_BUILD_CLAIMED)
        self.assertFalse(result["bit_reproducible_build_claimed"])
        self.assertEqual(("pyaes",), result["source_distribution_packages"])

    def test_exact_telethon_closure_and_optional_cryptg_exclusion(self):
        self.assertEqual({"telethon", "pyaes", "rsa", "pyasn1"}, set(EXPECTED_RUNTIME_LOCK))
        self.assertNotIn("cryptg", EXPECTED_RUNTIME_LOCK)
        self.assertEqual("sdist", ARTIFACT_POLICY["pyaes"]["kind"])
        self.assertEqual("pyaes-1.6.1.tar.gz", ARTIFACT_POLICY["pyaes"]["filename"])
        self.assertEqual(4, len(expected_artifact_hashes()))

    def test_python_gate_accepts_only_311(self):
        validate_python_line((3, 11))
        for version in ((3, 10), (3, 12), (2, 7), (4, 0)):
            with self.subTest(version=version), self.assertRaises(SafetyError):
                validate_python_line(version)

    def test_download_is_hash_locked_but_network_boundary_is_explicit(self):
        command = download_command("python", Path("requirements.lock"), Path("artifacts"))
        self.assertIn("download", command)
        self.assertIn("--require-hashes", command)
        self.assertIn("--no-deps", command)
        self.assertIn("--no-input", command)
        self.assertNotIn("--no-index", command)

    def test_offline_install_is_forced_no_index_no_deps_and_hashes(self):
        command = offline_install_command("python", Path("requirements.lock"), Path("artifacts"))
        for required in ("install", "--no-index", "--find-links", "--require-hashes", "--no-deps", "--no-input"):
            self.assertIn(required, command)

    def test_wrong_hash_negative_lock_changes_only_hash_nibble(self):
        with tempfile.TemporaryDirectory() as td:
            destination = Path(td) / "wrong.lock"
            source = ROOT / "requirements.lock"
            original = source.read_text(encoding="utf-8")
            mutated_wrong_hash_lock(source, destination)
            changed = destination.read_text(encoding="utf-8")
            self.assertEqual(len(original), len(changed))
            self.assertNotEqual(original, changed)
            differences = sum(a != b for a, b in zip(original, changed))
            self.assertEqual(1, differences)

    def test_requirement_directives_urls_extras_and_markers_fail_closed(self):
        bad_lines = (
            "--index-url https://example.invalid/simple\nTelethon==1.44.0\n",
            "Telethon[cryptg]==1.44.0\n",
            "Telethon==1.44.0; python_version >= '3.11'\n",
            "Telethon @ https://example.invalid/telethon.whl\n",
            "-r other.txt\nTelethon==1.44.0\n",
        )
        for content in bad_lines:
            with self.subTest(content=content.splitlines()[0]):
                temp, root = self._dependency_root()
                self.addCleanup(temp.cleanup)
                (root / "requirements.txt").write_text(content, encoding="utf-8")
                with self.assertRaises(SafetyError):
                    validate_dependency_contract(root)

    def test_partial_or_empty_test_dependency_overlay_fails_closed(self):
        temp, root = self._dependency_root()
        self.addCleanup(temp.cleanup)
        (root / "requirements-test.txt").write_text("", encoding="utf-8")
        with self.assertRaises(SafetyError):
            validate_dependency_contract(root)
        (root / "requirements-test.lock").write_text("Telethon==1.44.0\n", encoding="utf-8")
        with self.assertRaises(SafetyError):
            validate_dependency_contract(root)

    def test_private_path_exclusion_covers_case_variants_journals_and_traversal(self):
        forbidden = (
            ".ENV",
            ".env.production",
            "var/state.db",
            "PRIVATE/config.json",
            "sessions/current",
            "state/account.SESSION",
            "state/account.session-journal",
            "credentials.json",
            "token.json",
            "cookies/profile",
            "browser_profiles/default",
            "../escape",
            "/tmp/escape",
        )
        for path in forbidden:
            with self.subTest(path=path), self.assertRaises(SafetyError):
                validate_public_release_tree(
                    ROOT,
                    paths=("passenger_wsgi.py", "requirements.txt", "requirements.lock", path),
                )

    def test_artifact_set_rejects_missing_extra_or_wrong_hash(self):
        with tempfile.TemporaryDirectory() as td:
            directory = Path(td)
            names = [facts["filename"] for facts in ARTIFACT_POLICY.values()]
            for name in names:
                (directory / name).write_bytes(name.encode("ascii"))
            digests = iter(expected_artifact_hashes())
            with mock.patch("ops.dependency_repro.sha256_file", side_effect=lambda _path: next(digests)):
                result = verify_downloaded_artifacts(directory)
            self.assertEqual(4, result["artifact_count"])

            (directory / "unexpected.whl").write_bytes(b"x")
            with self.assertRaises(SafetyError):
                verify_downloaded_artifacts(directory)

    def test_artifact_set_requires_pyaes_source_distribution_filename(self):
        with tempfile.TemporaryDirectory() as td:
            directory = Path(td)
            names = [facts["filename"] for facts in ARTIFACT_POLICY.values()]
            for name in names:
                if name == "pyaes-1.6.1.tar.gz":
                    name = "pyaes-1.6.1-py3-none-any.whl"
                (directory / name).write_bytes(name.encode("ascii"))
            digest_values = list(expected_artifact_hashes())
            with mock.patch("ops.dependency_repro.sha256_file", side_effect=digest_values):
                with self.assertRaises(SafetyError):
                    verify_downloaded_artifacts(directory)


if __name__ == "__main__":
    unittest.main()
