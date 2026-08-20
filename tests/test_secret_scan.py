# -*- coding: utf-8 -*-
import subprocess
import tempfile
import unittest
from pathlib import Path

from tools import secret_scan


class SecretScanTests(unittest.TestCase):
    def make_repo(self):
        tmp = tempfile.TemporaryDirectory()
        repo = Path(tmp.name)
        subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
        subprocess.run(["git", "config", "user.name", "Synthetic Test"], cwd=repo, check=True)
        subprocess.run(["git", "config", "user.email", "synthetic@example.invalid"], cwd=repo, check=True)
        (repo / "README.md").write_text("synthetic test repository\n", encoding="utf-8")
        subprocess.run(["git", "add", "README.md"], cwd=repo, check=True)
        subprocess.run(["git", "commit", "-qm", "initial"], cwd=repo, check=True)
        return tmp, repo

    def commit_all(self, repo, message):
        subprocess.run(["git", "add", "-A", "-f"], cwd=repo, check=True)
        subprocess.run(["git", "commit", "-qm", message], cwd=repo, check=True)

    def test_current_tree_matrix_rejects_policy_artifacts(self):
        tmp, repo = self.make_repo()
        self.addCleanup(tmp.cleanup)

        env_name = ".env" + ".production"
        key_name = "private" + ".key"
        designated_name = "BRIDGE_KEYS_" + "SECRET.txt"
        (repo / env_name).write_text("SAFE_SYNTHETIC=1\n", encoding="utf-8")
        (repo / key_name).write_text("synthetic-key-file\n", encoding="utf-8")
        (repo / designated_name).write_text("synthetic-designated-file\n", encoding="utf-8")

        variable = "TG_" + "API_HASH"
        value = "synthetic-value-" + "1234567890"
        (repo / "config.txt").write_text(variable + "=" + value + "\n", encoding="utf-8")
        self.commit_all(repo, "add synthetic policy violations")

        findings = secret_scan.scan_current_tree(repo)
        joined = "\n".join(findings)
        self.assertIn(env_name, joined)
        self.assertIn(key_name, joined)
        self.assertIn(designated_name, joined)
        self.assertIn(variable, joined)
        self.assertNotIn(value, joined)

    def test_history_detects_removed_canary(self):
        tmp, repo = self.make_repo()
        self.addCleanup(tmp.cleanup)

        variable = "BRIDGE_" + "TOKEN"
        value = "synthetic-history-" + "1234567890"
        leak = repo / "temporary-config.txt"
        leak.write_text(variable + "=" + value + "\n", encoding="utf-8")
        self.commit_all(repo, "introduce synthetic canary")
        leak.unlink()
        self.commit_all(repo, "remove synthetic canary")

        current = "\n".join(secret_scan.scan_current_tree(repo))
        history = "\n".join(secret_scan.scan_history(repo))
        self.assertNotIn(variable, current)
        self.assertIn(variable, history)
        self.assertNotIn(value, history)

    def test_placeholder_value_is_allowed(self):
        self.assertTrue(secret_scan.is_placeholder("<SECRET>"))
        self.assertTrue(secret_scan.is_placeholder("${{ secrets.EXAMPLE }}"))
        self.assertFalse(secret_scan.is_placeholder("synthetic-real-looking-value"))


if __name__ == "__main__":
    unittest.main()
