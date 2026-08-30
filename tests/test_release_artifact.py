# -*- coding: utf-8 -*-
from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from ops.release_guard import SafetyError
from tools.build_release_artifact import MANIFEST_NAME, build_release_artifact

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = "Oleksii-debug/Telegram-ChatGPT-Bridge"


class PortableReleaseArtifactTests(unittest.TestCase):
    def _fixture_repo(self, root: Path) -> tuple[Path, str]:
        repo = root / "repo"
        repo.mkdir()
        for name in ("passenger_wsgi.py", "requirements.txt", "requirements.lock"):
            shutil.copy2(ROOT / name, repo / name)
        subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
        subprocess.run(["git", "config", "user.name", "B4 test"], cwd=repo, check=True)
        subprocess.run(["git", "config", "user.email", "b4-test@example.invalid"], cwd=repo, check=True)
        subprocess.run(["git", "add", "."], cwd=repo, check=True)
        subprocess.run(["git", "commit", "-q", "-m", "fixture"], cwd=repo, check=True)
        sha = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip()
        return repo, sha

    def test_builds_verified_exact_sha_bundle_and_non_authorizing_manifest(self):
        with tempfile.TemporaryDirectory() as temp_name:
            root = Path(temp_name)
            repo, sha = self._fixture_repo(root)
            output = root / "artifact"

            result = build_release_artifact(repo, expected_sha=sha, output_dir=output)

            self.assertEqual(sha, result["source_sha"])
            self.assertEqual(REPOSITORY, result["repository"])
            self.assertFalse(result["private_values_recorded"])
            self.assertFalse(result["deployment_authorized"])
            self.assertRegex(str(result["bundle_sha256"]), r"^[0-9a-f]{64}$")
            self.assertRegex(str(result["artifact_identity_sha256"]), r"^[0-9a-f]{64}$")

            bundle = output / str(result["bundle_file"])
            self.assertTrue(bundle.is_file())
            manifest = json.loads((output / MANIFEST_NAME).read_text(encoding="utf-8"))
            self.assertEqual(result, manifest)

            clone = root / "clone"
            subprocess.run(
                ["git", "clone", "--no-checkout", str(bundle), str(clone)],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            cloned_sha = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=clone, text=True).strip()
            self.assertEqual(sha, cloned_sha)

    def test_wrong_sha_fails_closed_before_artifact_creation(self):
        with tempfile.TemporaryDirectory() as temp_name:
            root = Path(temp_name)
            repo, _sha = self._fixture_repo(root)
            output = root / "artifact"
            with self.assertRaises(SafetyError):
                build_release_artifact(repo, expected_sha="a" * 40, output_dir=output)
            self.assertFalse(output.exists())

    def test_dirty_checkout_fails_closed(self):
        with tempfile.TemporaryDirectory() as temp_name:
            root = Path(temp_name)
            repo, sha = self._fixture_repo(root)
            (repo / "untracked.txt").write_text("must block\n", encoding="utf-8")
            with self.assertRaises(SafetyError):
                build_release_artifact(repo, expected_sha=sha, output_dir=root / "artifact")

    def test_output_inside_source_checkout_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp_name:
            root = Path(temp_name)
            repo, sha = self._fixture_repo(root)
            with self.assertRaises(SafetyError):
                build_release_artifact(repo, expected_sha=sha, output_dir=repo / "artifact")

    def test_nonempty_output_is_rejected_without_overwrite(self):
        with tempfile.TemporaryDirectory() as temp_name:
            root = Path(temp_name)
            repo, sha = self._fixture_repo(root)
            output = root / "artifact"
            output.mkdir()
            sentinel = output / "keep.txt"
            sentinel.write_text("keep\n", encoding="utf-8")
            with self.assertRaises(SafetyError):
                build_release_artifact(repo, expected_sha=sha, output_dir=output)
            self.assertEqual("keep\n", sentinel.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
