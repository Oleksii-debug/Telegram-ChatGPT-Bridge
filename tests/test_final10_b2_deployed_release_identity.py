# -*- coding: utf-8 -*-
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from ops.deployed_release_identity import (
    PREPARED_RELEASE_NAME,
    derive_deployed_release_sha,
    require_armed_candidate_matches_deployed,
)
from ops.release_guard import SafetyError


class DeployedReleaseIdentityTests(unittest.TestCase):
    SHA = "a" * 40
    OTHER = "b" * 40

    def _release(self, base: Path, *, dirname=None, metadata_sha=None) -> Path:
        root = base / (dirname or self.SHA)
        root.mkdir()
        (root / PREPARED_RELEASE_NAME).write_text(
            json.dumps({"sha": metadata_sha or self.SHA}), encoding="utf-8"
        )
        return root

    def test_valid_versioned_release_derives_sha(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._release(Path(tmp))
            self.assertEqual(derive_deployed_release_sha(root), self.SHA)
            self.assertEqual(require_armed_candidate_matches_deployed(root, self.SHA), self.SHA)

    def test_wrong_armed_label_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._release(Path(tmp))
            with self.assertRaises(SafetyError):
                require_armed_candidate_matches_deployed(root, self.OTHER)

    def test_metadata_sha_mismatch_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._release(Path(tmp), metadata_sha=self.OTHER)
            with self.assertRaises(SafetyError):
                derive_deployed_release_sha(root)

    def test_non_sha_release_root_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._release(Path(tmp), dirname="current")
            with self.assertRaises(SafetyError):
                derive_deployed_release_sha(root)

    @unittest.skipIf(os.name == "nt", "descriptor-relative POSIX validation")
    def test_persistent_root_replacement_during_metadata_open_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = self._release(base)
            displaced = base / "displaced-release"
            real_open = os.open
            swapped = False

            def swapping_open(path, flags, mode=0o777, *, dir_fd=None):
                nonlocal swapped
                if path == PREPARED_RELEASE_NAME and dir_fd is not None and not swapped:
                    swapped = True
                    root.rename(displaced)
                    replacement = base / self.SHA
                    replacement.mkdir()
                    (replacement / PREPARED_RELEASE_NAME).write_text(
                        json.dumps({"sha": self.OTHER}), encoding="utf-8"
                    )
                return real_open(path, flags, mode, dir_fd=dir_fd)

            with mock.patch("ops.deployed_release_identity.os.open", side_effect=swapping_open):
                with self.assertRaisesRegex(SafetyError, "root changed"):
                    derive_deployed_release_sha(root)
            self.assertTrue(swapped)

    @unittest.skipIf(os.name == "nt", "descriptor-relative POSIX validation")
    def test_metadata_replacement_between_stat_and_open_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._release(Path(tmp))
            metadata = root / PREPARED_RELEASE_NAME
            old = root / "PREPARED_RELEASE.old"
            real_open = os.open
            swapped = False

            def swapping_open(path, flags, mode=0o777, *, dir_fd=None):
                nonlocal swapped
                if path == PREPARED_RELEASE_NAME and dir_fd is not None and not swapped:
                    swapped = True
                    metadata.rename(old)
                    metadata.write_text(json.dumps({"sha": self.SHA}), encoding="utf-8")
                return real_open(path, flags, mode, dir_fd=dir_fd)

            with mock.patch("ops.deployed_release_identity.os.open", side_effect=swapping_open):
                with self.assertRaisesRegex(SafetyError, "metadata changed"):
                    derive_deployed_release_sha(root)
            self.assertTrue(swapped)

    @unittest.skipIf(os.name == "nt", "descriptor-relative POSIX validation")
    def test_parent_path_replacement_cannot_redirect_metadata_open(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = self._release(base)
            displaced = base / "displaced-release"
            real_open = os.open
            swapped = False

            def swapping_open(path, flags, mode=0o777, *, dir_fd=None):
                nonlocal swapped
                if path == PREPARED_RELEASE_NAME and dir_fd is not None and not swapped:
                    swapped = True
                    root.rename(displaced)
                    replacement = base / self.SHA
                    replacement.mkdir()
                    replacement_meta = replacement / PREPARED_RELEASE_NAME
                    replacement_meta.write_text(json.dumps({"sha": self.OTHER}), encoding="utf-8")
                    fd = real_open(path, flags, mode, dir_fd=dir_fd)
                    replacement_meta.unlink()
                    replacement.rmdir()
                    displaced.rename(root)
                    return fd
                return real_open(path, flags, mode, dir_fd=dir_fd)

            with mock.patch("ops.deployed_release_identity.os.open", side_effect=swapping_open):
                self.assertEqual(derive_deployed_release_sha(root), self.SHA)
            self.assertTrue(swapped)

    @unittest.skipIf(os.name == "nt", "symlink creation may require Windows privilege")
    def test_symlink_metadata_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = base / self.SHA
            root.mkdir()
            target = base / "metadata.json"
            target.write_text(json.dumps({"sha": self.SHA}), encoding="utf-8")
            (root / PREPARED_RELEASE_NAME).symlink_to(target)
            with self.assertRaises(SafetyError):
                derive_deployed_release_sha(root)

    @unittest.skipIf(os.name == "nt", "symlink creation may require Windows privilege")
    def test_symlink_release_root_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            real = base / "real"
            real.mkdir()
            (real / PREPARED_RELEASE_NAME).write_text(json.dumps({"sha": self.SHA}), encoding="utf-8")
            link = base / self.SHA
            link.symlink_to(real, target_is_directory=True)
            with self.assertRaises(SafetyError):
                derive_deployed_release_sha(link)


if __name__ == "__main__":
    unittest.main()
