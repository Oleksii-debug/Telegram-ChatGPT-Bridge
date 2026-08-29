# -*- coding: utf-8 -*-
import json
import os
import tempfile
import unittest
from pathlib import Path

from ops.deployed_release_identity import (
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
        (root / "PREPARED_RELEASE.json").write_text(
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

    @unittest.skipIf(os.name == "nt", "symlink creation may require Windows privilege")
    def test_symlink_metadata_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = base / self.SHA
            root.mkdir()
            target = base / "metadata.json"
            target.write_text(json.dumps({"sha": self.SHA}), encoding="utf-8")
            (root / "PREPARED_RELEASE.json").symlink_to(target)
            with self.assertRaises(SafetyError):
                derive_deployed_release_sha(root)

    @unittest.skipIf(os.name == "nt", "symlink creation may require Windows privilege")
    def test_symlink_release_root_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            real = base / "real"
            real.mkdir()
            (real / "PREPARED_RELEASE.json").write_text(json.dumps({"sha": self.SHA}), encoding="utf-8")
            link = base / self.SHA
            link.symlink_to(real, target_is_directory=True)
            with self.assertRaises(SafetyError):
                derive_deployed_release_sha(link)


if __name__ == "__main__":
    unittest.main()
