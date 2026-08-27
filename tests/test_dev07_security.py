from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from tools import secret_scan, workflow_security


class Dev07WorkflowSecurityTests(unittest.TestCase):
    def good_workflow(self) -> str:
        checkout = "3d3c42e5aac5ba805825da76410c181273ba90b1"
        setup_python = "5fda3b95a4ea91299a34e894583c3862153e4b97"
        return f"""name: guard
on:
  pull_request:
permissions:
  contents: read
jobs:
  guard:
    runs-on: ubuntu-latest
    steps:
      - name: checkout
        uses: actions/checkout@{checkout}
        with:
          persist-credentials: false
          fetch-depth: 0
          clean: true
          lfs: false
          submodules: false
      - name: python
        uses: actions/setup-python@{setup_python}
      - name: history
        run: python tools/secret_scan.py --mode history
"""

    def scan(self, text: str) -> str:
        return "\n".join(workflow_security.scan_workflow_text(".github/workflows/test.yml", text))

    def test_current_repository_workflow_policy_passes(self):
        repo = Path(__file__).resolve().parents[1]
        self.assertEqual(workflow_security.scan_repository(repo), [])

    def test_unpinned_action_fails_closed(self):
        bad = self.good_workflow().replace(
            "actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97",
            "actions/setup-python@v7",
        )
        self.assertIn("not immutable-SHA pinned", self.scan(bad))

    def test_write_permission_fails_closed(self):
        bad = self.good_workflow().replace("contents: read", "contents: write")
        self.assertIn("permissions must be exactly contents: read", self.scan(bad))

    def test_inline_permissions_map_fails_closed(self):
        bad = self.good_workflow().replace("permissions:\n  contents: read", "permissions: {contents: read}")
        self.assertIn("explicit top-level block", self.scan(bad))

    def test_second_job_level_permissions_stanza_fails_closed(self):
        bad = self.good_workflow().replace(
            "    runs-on: ubuntu-latest\n",
            "    runs-on: ubuntu-latest\n    permissions:\n      contents: read\n",
        )
        self.assertIn("exactly one top-level permissions stanza", self.scan(bad))

    def test_pull_request_target_fails_closed(self):
        bad = self.good_workflow().replace("pull_request:", "pull_request_target:")
        self.assertIn("high-risk trigger", self.scan(bad))

    def test_workflow_run_trigger_fails_closed(self):
        bad = self.good_workflow().replace("pull_request:", "workflow_run:")
        self.assertIn("high-risk trigger", self.scan(bad))

    def test_repository_dispatch_trigger_fails_closed(self):
        bad = self.good_workflow().replace("pull_request:", "repository_dispatch:")
        self.assertIn("high-risk trigger", self.scan(bad))

    def test_secret_context_fails_closed_without_echoing_secret_name(self):
        name = "SYNTHETIC_" + "CREDENTIAL"
        expression = "${{ secrets." + name + " }}"
        bad = self.good_workflow() + "      - name: unsafe\n        run: echo '" + expression + "'\n"
        result = self.scan(bad)
        self.assertIn("secret context is forbidden", result)
        self.assertNotIn(name, result)

    def test_secret_context_is_forbidden_even_on_push_only_workflow(self):
        name = "SYNTHETIC_" + "CREDENTIAL"
        expression = "${{ secrets." + name + " }}"
        bad = self.good_workflow().replace("pull_request:", "push:")
        bad += "      - name: unsafe\n        run: echo '" + expression + "'\n"
        result = self.scan(bad)
        self.assertIn("secret context is forbidden", result)
        self.assertNotIn(name, result)

    def test_explicit_github_token_context_fails_closed(self):
        expression = "${{ github." + "token }}"
        bad = self.good_workflow() + "      - name: unsafe\n        run: echo '" + expression + "'\n"
        self.assertIn("github.token exposure", self.scan(bad))

    def test_self_hosted_runner_fails_closed(self):
        bad = self.good_workflow().replace("runs-on: ubuntu-latest", "runs-on: self-hosted")
        self.assertIn("self-hosted runner", self.scan(bad))

    def test_environment_binding_fails_closed(self):
        bad = self.good_workflow().replace(
            "    runs-on: ubuntu-latest\n",
            "    runs-on: ubuntu-latest\n    environment: production\n",
        )
        self.assertIn("environment binding", self.scan(bad))

    def test_checkout_must_disable_persisted_credentials(self):
        bad = self.good_workflow().replace("          persist-credentials: false\n", "")
        self.assertIn("persist-credentials: false", self.scan(bad))

    def test_history_scan_requires_full_history_checkout(self):
        bad = self.good_workflow().replace("fetch-depth: 0", "fetch-depth: 1")
        self.assertIn("fetch-depth: 0", self.scan(bad))

    def test_checkout_requires_clean_true(self):
        bad = self.good_workflow().replace("          clean: true\n", "")
        self.assertIn("clean: true", self.scan(bad))

    def test_checkout_requires_lfs_false(self):
        bad = self.good_workflow().replace("          lfs: false\n", "")
        self.assertIn("lfs: false", self.scan(bad))

    def test_checkout_requires_submodules_false(self):
        bad = self.good_workflow().replace("          submodules: false\n", "")
        self.assertIn("submodules: false", self.scan(bad))

    def test_checkout_ref_override_fails_closed(self):
        bad = self.good_workflow().replace(
            "          submodules: false\n",
            "          submodules: false\n          ref: main\n",
        )
        self.assertIn("checkout ref override is forbidden", self.scan(bad))

    def test_checkout_repository_override_fails_closed(self):
        bad = self.good_workflow().replace(
            "          submodules: false\n",
            "          submodules: false\n          repository: example/other\n",
        )
        self.assertIn("checkout repository override is forbidden", self.scan(bad))

    def test_checkout_token_override_fails_closed_without_echoing_value(self):
        synthetic = "synthetic-placeholder-value"
        bad = self.good_workflow().replace(
            "          submodules: false\n",
            "          submodules: false\n          token: " + synthetic + "\n",
        )
        result = self.scan(bad)
        self.assertIn("checkout token override is forbidden", result)
        self.assertNotIn(synthetic, result)

    def test_artifact_transfer_requires_privacy_review(self):
        sha = "0" * 40
        bad = self.good_workflow() + f"      - name: artifact\n        uses: actions/upload-artifact@{sha}\n"
        self.assertIn("artifact transfer", self.scan(bad))

    def test_cache_action_requires_poisoning_review(self):
        sha = "1" * 40
        bad = self.good_workflow() + f"      - name: cache\n        uses: actions/cache@{sha}\n"
        self.assertIn("cache restore/save", self.scan(bad))

    def test_network_pipe_to_shell_fails_closed(self):
        bad = self.good_workflow() + "      - name: unsafe\n        run: curl https://example.invalid/install | bash\n"
        self.assertIn("pipe-to-interpreter", self.scan(bad))

    def test_local_action_is_allowed(self):
        good = self.good_workflow() + "      - name: local\n        uses: ./.github/actions/local-check\n"
        self.assertEqual(self.scan(good), "")

    def test_group_writable_workflow_file_fails_closed(self):
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)
            root = repo / ".github" / "workflows"
            root.mkdir(parents=True)
            workflow = root / "guard.yml"
            workflow.write_text(self.good_workflow(), encoding="utf-8")
            workflow.chmod(0o664)
            result = "\n".join(workflow_security.scan_repository(repo))
            self.assertIn("unsafe topology/ownership/permissions", result)

    def test_symlinked_workflow_directory_fails_closed(self):
        if not hasattr(os, "symlink"):
            self.skipTest("symlink unavailable")
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)
            github = repo / ".github"
            real = repo / "real-workflows"
            github.mkdir()
            real.mkdir()
            (real / "guard.yml").write_text(self.good_workflow(), encoding="utf-8")
            (github / "workflows").symlink_to(real, target_is_directory=True)
            result = "\n".join(workflow_security.scan_repository(repo))
            self.assertIn("unsafe topology/ownership", result)


class Dev07SecretScannerBoundaryTests(unittest.TestCase):
    def make_repo(self):
        tmp = tempfile.TemporaryDirectory()
        repo = Path(tmp.name)
        subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
        subprocess.run(["git", "config", "user.name", "Synthetic Test"], cwd=repo, check=True)
        subprocess.run(["git", "config", "user.email", "synthetic@example.invalid"], cwd=repo, check=True)
        (repo / "README.md").write_text("safe\n", encoding="utf-8")
        subprocess.run(["git", "add", "README.md"], cwd=repo, check=True)
        subprocess.run(["git", "commit", "-qm", "initial"], cwd=repo, check=True)
        return tmp, repo

    def commit_all(self, repo: Path, message: str) -> None:
        subprocess.run(["git", "add", "-A", "-f"], cwd=repo, check=True)
        subprocess.run(["git", "commit", "-qm", message], cwd=repo, check=True)

    @staticmethod
    def lfs_pointer() -> str:
        version = "version https://" + "git-lfs.github.com/spec/v1"
        return version + "\noid sha256:" + ("1" * 64) + "\nsize 42\n"

    def test_tracked_symlink_is_rejected_without_dereferencing_target(self):
        if not hasattr(os, "symlink"):
            self.skipTest("symlink unavailable")
        tmp, repo = self.make_repo(); self.addCleanup(tmp.cleanup)
        outside = Path(tmp.name).parent / (Path(tmp.name).name + "-outside-secret")
        secret_name = "BRIDGE_" + "TOKEN"
        secret_value = "synthetic-outside-value-1234567890"
        outside.write_text(secret_name + "=" + secret_value + "\n", encoding="utf-8")
        self.addCleanup(lambda: outside.unlink(missing_ok=True))
        link = repo / "external-link"
        link.symlink_to(outside)
        subprocess.run(["git", "add", "external-link"], cwd=repo, check=True)
        result = "\n".join(secret_scan.scan_current_tree(repo))
        self.assertIn("tracked symlink rejected", result)
        self.assertNotIn(secret_name, result)
        self.assertNotIn(secret_value, result)

    def test_gitlink_is_rejected_without_external_object_read(self):
        tmp, repo = self.make_repo(); self.addCleanup(tmp.cleanup)
        fake_sha = "1" * 40
        subprocess.run(
            ["git", "update-index", "--add", "--cacheinfo", f"160000,{fake_sha},vendor/external"],
            cwd=repo,
            check=True,
        )
        result = "\n".join(secret_scan.scan_current_tree(repo))
        self.assertIn("tracked gitlink/submodule rejected", result)
        self.assertNotIn(fake_sha, result)

    def test_git_lfs_pointer_fails_closed_in_current_tree(self):
        tmp, repo = self.make_repo(); self.addCleanup(tmp.cleanup)
        (repo / "opaque.bin").write_text(self.lfs_pointer(), encoding="utf-8")
        subprocess.run(["git", "add", "opaque.bin"], cwd=repo, check=True)
        result = "\n".join(secret_scan.scan_current_tree(repo))
        self.assertIn("Git LFS pointer", result)
        self.assertNotIn("1" * 64, result)

    def test_removed_git_lfs_pointer_is_still_found_in_history(self):
        tmp, repo = self.make_repo(); self.addCleanup(tmp.cleanup)
        path = repo / "opaque.bin"
        path.write_text(self.lfs_pointer(), encoding="utf-8")
        self.commit_all(repo, "add synthetic lfs pointer")
        path.unlink()
        self.commit_all(repo, "remove synthetic lfs pointer")
        current = "\n".join(secret_scan.scan_current_tree(repo))
        history = "\n".join(secret_scan.scan_history(repo))
        self.assertNotIn("Git LFS pointer", current)
        self.assertIn("Git LFS pointer", history)
        self.assertNotIn("1" * 64, history)


if __name__ == "__main__":
    unittest.main()
