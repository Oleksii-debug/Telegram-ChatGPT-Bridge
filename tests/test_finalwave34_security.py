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


if __name__ == "__main__":
    unittest.main()
