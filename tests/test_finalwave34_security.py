from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path

from tools import secret_scan, workflow_security


class Finalwave34SecretScannerTests(unittest.TestCase):
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

    def test_unmerged_index_stage_fails_closed(self):
        tmp, repo = self.make_repo()
        self.addCleanup(tmp.cleanup)
        blob = subprocess.run(
            ["git", "hash-object", "-w", "--stdin"],
            cwd=repo,
            input="synthetic conflict bytes\n",
            text=True,
            capture_output=True,
            check=True,
        ).stdout.strip()
        subprocess.run(
            ["git", "update-index", "--index-info"],
            cwd=repo,
            input=f"100644 {blob} 1\tconflicted.txt\n",
            text=True,
            check=True,
        )
        result = "\n".join(secret_scan.scan_current_tree(repo))
        self.assertIn("unresolved Git index stage rejected", result)
        self.assertNotIn(blob, result)

    def test_telegram_aliases_fail_closed_without_value_echo(self):
        tmp, repo = self.make_repo()
        self.addCleanup(tmp.cleanup)
        aliases = ("TELEGRAM_API_HASH", "TELETHON_SESSION", "SESSION_FILE")
        values = tuple(f"synthetic-private-value-{index}-1234567890" for index in range(len(aliases)))
        (repo / "aliases.conf").write_text(
            "".join(f"{name}={value}\n" for name, value in zip(aliases, values)),
            encoding="utf-8",
        )
        subprocess.run(["git", "add", "aliases.conf"], cwd=repo, check=True)
        result = "\n".join(secret_scan.scan_current_tree(repo))
        for name in aliases:
            self.assertIn(name, result)
        for value in values:
            self.assertNotIn(value, result)

    def test_lfs_extension_pointer_is_rejected(self):
        tmp, repo = self.make_repo()
        self.addCleanup(tmp.cleanup)
        first = "a" * 64
        second = "b" * 64
        pointer = (
            "version https://git-lfs.github.com/spec/v1\n"
            f"ext-0-filter sha256:{first}\n"
            f"oid sha256:{second}\n"
            "size 42\n"
        )
        (repo / "extended.bin").write_text(pointer, encoding="ascii")
        subprocess.run(["git", "add", "extended.bin"], cwd=repo, check=True)
        result = "\n".join(secret_scan.scan_current_tree(repo))
        self.assertIn("Git LFS pointer", result)
        self.assertNotIn(first, result)
        self.assertNotIn(second, result)

    def test_legacy_lfs_pointer_alias_is_rejected(self):
        tmp, repo = self.make_repo()
        self.addCleanup(tmp.cleanup)
        oid = "c" * 64
        pointer = (
            "version http://git-media.io/v/2\n"
            f"oid sha256:{oid}\n"
            "size 42\n"
        )
        (repo / "legacy.bin").write_text(pointer, encoding="ascii")
        subprocess.run(["git", "add", "legacy.bin"], cwd=repo, check=True)
        result = "\n".join(secret_scan.scan_current_tree(repo))
        self.assertIn("Git LFS pointer", result)
        self.assertNotIn(oid, result)

    def test_annotated_tag_message_is_scanned_and_redacted(self):
        tmp, repo = self.make_repo()
        self.addCleanup(tmp.cleanup)
        variable = "SETUP_" + "KEY"
        value = "synthetic-tag-value-1234567890"
        subprocess.run(
            ["git", "tag", "-a", "synthetic-tag", "-m", variable + "=" + value],
            cwd=repo,
            check=True,
        )
        result = "\n".join(secret_scan.scan_history(repo))
        self.assertIn(variable, result)
        self.assertIn("<annotated-tag-message>", result)
        self.assertNotIn(value, result)


class Finalwave34WorkflowPolicyTests(unittest.TestCase):
    CHECKOUT_SHA = "3d3c42e5aac5ba805825da76410c181273ba90b1"
    PYTHON_SHA = "5fda3b95a4ea91299a34e894583c3862153e4b97"

    def workflow(self) -> str:
        return f"""name: guard
on:
  pull_request:
permissions:
  contents: read
jobs:
  guard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@{self.CHECKOUT_SHA}
        with:
          persist-credentials: false
          fetch-depth: 0
          clean: true
          lfs: false
          submodules: false
      - uses: actions/setup-python@{self.PYTHON_SHA}
      - run: python tools/secret_scan.py --mode history
"""

    def findings(self, text: str) -> str:
        return "\n".join(workflow_security.scan_workflow_text(".github/workflows/test.yml", text))

    def test_issue_comment_trigger_is_rejected(self):
        bad = self.workflow().replace("pull_request:", "issue_comment:")
        self.assertIn("high-risk trigger", self.findings(bad))

    def test_workflow_call_trigger_is_rejected(self):
        bad = self.workflow().replace("pull_request:", "workflow_call:")
        self.assertIn("high-risk trigger", self.findings(bad))

    def test_inline_high_risk_trigger_is_rejected(self):
        bad = self.workflow().replace("on:\n  pull_request:\n", "on: [push, pull_request_target]\n")
        self.assertIn("high-risk trigger", self.findings(bad))

    def test_quoted_high_risk_trigger_is_rejected(self):
        bad = self.workflow().replace("  pull_request:\n", "  'pull_request_target':\n")
        self.assertIn("high-risk trigger", self.findings(bad))

    def test_trigger_alias_is_rejected_fail_closed(self):
        bad = self.workflow().replace("on:\n  pull_request:\n", "on: *event_set\n")
        self.assertIn("trigger YAML anchors/aliases are forbidden", self.findings(bad))

    def test_bracket_secret_context_is_rejected_without_echo(self):
        name = "SYNTHETIC_" + "CREDENTIAL"
        expression = "${{ secrets['" + name + "'] }}"
        bad = self.workflow() + "      - run: echo \"" + expression + "\"\n"
        result = self.findings(bad)
        self.assertIn("secret context is forbidden", result)
        self.assertNotIn(name, result)

    def test_raw_secret_context_is_rejected_without_echo(self):
        expression = "${{ toJSON(" + "secrets) }}"
        bad = self.workflow() + "      - run: echo \"" + expression + "\"\n"
        result = self.findings(bad)
        self.assertIn("secret context is forbidden", result)
        self.assertNotIn(expression, result)

    def test_bracket_github_token_context_is_rejected(self):
        expression = "${{ github['" + "token'] }}"
        bad = self.workflow() + "      - run: echo \"" + expression + "\"\n"
        self.assertIn("github.token exposure", self.findings(bad))

    def test_quoted_self_hosted_runner_is_rejected(self):
        bad = self.workflow().replace("runs-on: ubuntu-latest", "runs-on: 'self-hosted'")
        self.assertIn("approved GitHub-hosted runner", self.findings(bad))

    def test_quoted_runs_on_key_cannot_bypass_runner_policy(self):
        bad = self.workflow().replace("runs-on: ubuntu-latest", "'runs-on': 'self-hosted'")
        self.assertIn("approved GitHub-hosted runner", self.findings(bad))

    def test_dynamic_runner_expression_is_rejected(self):
        bad = self.workflow().replace("runs-on: ubuntu-latest", "runs-on: ${{ matrix.runner }}")
        self.assertIn("approved GitHub-hosted runner", self.findings(bad))

    def test_quoted_environment_key_is_rejected(self):
        bad = self.workflow().replace(
            "    runs-on: ubuntu-latest\n",
            "    runs-on: ubuntu-latest\n    'environment': production\n",
        )
        self.assertIn("environment binding", self.findings(bad))

    def test_quoted_unpinned_uses_key_is_rejected(self):
        bad = self.workflow().replace(
            f"uses: actions/setup-python@{self.PYTHON_SHA}",
            "'uses': actions/setup-python@v7",
        )
        self.assertIn("not immutable-SHA pinned", self.findings(bad))

    def test_checkout_path_override_is_rejected(self):
        bad = self.workflow().replace(
            "          submodules: false\n",
            "          submodules: false\n          path: alternate\n",
        )
        self.assertIn("checkout path override is forbidden", self.findings(bad))

    def test_checkout_ssh_key_override_is_rejected_without_echo(self):
        synthetic = "synthetic-placeholder-key-material"
        bad = self.workflow().replace(
            "          submodules: false\n",
            f"          submodules: false\n          ssh-key: {synthetic}\n",
        )
        result = self.findings(bad)
        self.assertIn("checkout ssh-key override is forbidden", result)
        self.assertNotIn(synthetic, result)

    def test_quoted_checkout_token_key_is_rejected_without_echo(self):
        synthetic = "synthetic-placeholder-token-value"
        bad = self.workflow().replace(
            "          submodules: false\n",
            f"          submodules: false\n          'token': {synthetic}\n",
        )
        result = self.findings(bad)
        self.assertIn("checkout token override is forbidden", result)
        self.assertNotIn(synthetic, result)


if __name__ == "__main__":
    unittest.main()
