# -*- coding: utf-8 -*-
from __future__ import annotations

import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from ops import deploy_release
from ops.release_guard import SafetyError, sha256_file, sha256_json
from tools import verify_release_prepare as release_prepare


class Finalwave30PrepareIntegrityTests(unittest.TestCase):
    def _restore_writable(self, root: Path) -> None:
        if not root.exists():
            return
        for path in [root, *sorted(root.rglob("*"))]:
            if path.is_symlink():
                continue
            try:
                mode = stat.S_IMODE(path.lstat().st_mode)
                os.chmod(path, mode | stat.S_IWUSR | (stat.S_IXUSR if path.is_dir() else 0))
            except OSError:
                pass

    def _seal_for_shape_check(self, root: Path) -> None:
        for path in sorted(root.rglob("*"), key=lambda item: len(item.parts), reverse=True):
            if path.is_symlink():
                continue
            mode = stat.S_IMODE(path.lstat().st_mode)
            os.chmod(path, mode & ~0o222)
        os.chmod(root, stat.S_IMODE(root.lstat().st_mode) & ~0o222)

    def test_prepared_tree_rejects_embedded_git_metadata(self):
        temp = tempfile.TemporaryDirectory()
        root = Path(temp.name)
        self.addCleanup(temp.cleanup)
        self.addCleanup(self._restore_writable, root)
        (root / ".git").mkdir()
        (root / ".git" / "config").write_text("public-test-only\n", encoding="utf-8")
        self._seal_for_shape_check(root)
        with self.assertRaises(SafetyError):
            release_prepare._verify_prepared_tree_integrity(root)

    @unittest.skipUnless(hasattr(os, "link"), "hardlink test requires os.link")
    def test_prepared_tree_rejects_regular_file_hardlinks(self):
        temp = tempfile.TemporaryDirectory()
        root = Path(temp.name)
        self.addCleanup(temp.cleanup)
        self.addCleanup(self._restore_writable, root)
        first = root / "first.txt"
        second = root / "second.txt"
        first.write_text("same-public-bytes\n", encoding="utf-8")
        os.link(first, second)
        self._seal_for_shape_check(root)
        with self.assertRaises(SafetyError):
            release_prepare._verify_prepared_tree_integrity(root)

    def test_prepared_tree_accepts_readonly_single_link_artifact_without_git(self):
        temp = tempfile.TemporaryDirectory()
        root = Path(temp.name)
        self.addCleanup(temp.cleanup)
        self.addCleanup(self._restore_writable, root)
        (root / "pkg").mkdir()
        (root / "pkg" / "module.py").write_text("VALUE = 1\n", encoding="utf-8")
        self._seal_for_shape_check(root)
        release_prepare._verify_prepared_tree_integrity(root)

    def test_archive_identity_mismatch_fails_closed(self):
        with tempfile.TemporaryDirectory() as repo_td:
            repo = Path(repo_td)

            def fake_export(_repo: Path, _sha: str, destination: Path) -> None:
                (destination / "tracked.txt").write_text("exact-git-bytes\n", encoding="utf-8")

            with mock.patch.object(deploy_release, "git_export", side_effect=fake_export):
                with self.assertRaises(SafetyError):
                    release_prepare._verify_archive_identity(
                        repo,
                        "a" * 40,
                        {"source_manifest_sha256": "0" * 64},
                    )

    def test_final_ref_freshness_recheck_blocks_moved_ref(self):
        with tempfile.TemporaryDirectory() as repo_td, tempfile.TemporaryDirectory() as prepared_td:
            repo = Path(repo_td)
            prepared = Path(prepared_td)
            (prepared / "requirements.lock").write_text("locked\n", encoding="utf-8")
            lock_hash = sha256_file(prepared / "requirements.lock")
            sha = "a" * 40
            meta = {
                "sha": sha,
                "source_manifest_sha256": "1" * 64,
                "requirements_lock_sha256": lock_hash,
                "requirements_test_lock_sha256": None,
                "immutable_permission_policy": "no-write-bits-v1",
                "payload_manifest_sha256": "2" * 64,
            }
            package = {"dependencies": {"package_count": 4}}
            with mock.patch.object(release_prepare, "_git_paths", return_value=["requirements.lock"]), \
                 mock.patch.object(
                     release_prepare,
                     "_prepare_with_bounded_subprocess_stages",
                     return_value=(prepared, meta, "3" * 64),
                 ), \
                 mock.patch.object(deploy_release, "verify_prepared_release", return_value=meta), \
                 mock.patch.object(release_prepare, "_verify_archive_identity"), \
                 mock.patch.object(release_prepare, "_verify_prepared_tree_integrity"), \
                 mock.patch.object(release_prepare, "validate_public_release_tree", return_value=package), \
                 mock.patch.object(release_prepare, "_verify_installed_runtime"), \
                 mock.patch.object(
                     release_prepare,
                     "_build_canonical_envelope_identity",
                     return_value={"identity_sha256": "4" * 64},
                 ), \
                 mock.patch.object(
                     deploy_release,
                     "verify_approved_ref_policy",
                     side_effect=SafetyError("ref moved"),
                 ):
                with self.assertRaises(release_prepare.ReleasePrepareStageError) as raised:
                    release_prepare.verify_exact_candidate(repo, sha, "origin/candidate")
            self.assertEqual("REF_FRESHNESS", raised.exception.stage)

    def test_pyc_bytes_are_inside_the_sealed_payload_hash(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            cache = root / "pkg" / "__pycache__"
            cache.mkdir(parents=True)
            pyc = cache / "module.cpython-311.pyc"
            pyc.write_bytes(b"path-specific-bytecode-v1")
            first = sha256_json(deploy_release._payload_manifest_without_meta(root))
            pyc.write_bytes(b"path-specific-bytecode-v2")
            second = sha256_json(deploy_release._payload_manifest_without_meta(root))
            self.assertNotEqual(first, second)

    @unittest.skipIf(os.name == "nt", "prepared venv symlink contract is POSIX")
    def test_external_venv_python_symlink_is_bound_to_approved_python_identity(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            bindir = root / ".venv" / "bin"
            bindir.mkdir(parents=True)
            link = bindir / "python"
            approved = deploy_release._python_identity(Path(sys.executable))
            if not str(approved["version"]).startswith("3.11."):
                self.skipTest("test requires Python 3.11")
            link.symlink_to(Path(approved["canonical_path"]))
            manifest = deploy_release._payload_manifest_without_meta(root, approved)
            entry = next(item for item in manifest["files"] if item["path"] == ".venv/bin/python")
            self.assertEqual("symlink", entry["type"])
            link.unlink()
            link.symlink_to("/bin/sh")
            with self.assertRaises(SafetyError):
                deploy_release._payload_manifest_without_meta(root, approved)


if __name__ == "__main__":
    unittest.main()
