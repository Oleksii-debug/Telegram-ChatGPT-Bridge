# -*- coding: utf-8 -*-
import subprocess
import tempfile
import unittest
from pathlib import Path

from tools import strict_history_secret_scan


class StrictHistorySecretScanTests(unittest.TestCase):
    GENERIC_ALIAS = "ses" + "sion"
    PROJECT_SECRET = "TG_SESSION_" + "STRING"

    def make_repo(self):
        tmp = tempfile.TemporaryDirectory()
        repo = Path(tmp.name)
        subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
        subprocess.run(["git", "config", "user.name", "Synthetic Test"], cwd=repo, check=True)
        subprocess.run(["git", "config", "user.email", "synthetic@example.invalid"], cwd=repo, check=True)
        (repo / "README.md").write_text("synthetic\n", encoding="utf-8")
        subprocess.run(["git", "add", "README.md"], cwd=repo, check=True)
        subprocess.run(["git", "commit", "-qm", "initial"], cwd=repo, check=True)
        return tmp, repo

    def commit_file(self, repo: Path, source: str):
        path = repo / "bridge_runtime.py"
        path.write_text(source, encoding="utf-8")
        subprocess.run(["git", "add", path.name], cwd=repo, check=True)
        subprocess.run(["git", "commit", "-qm", "runtime fixture"], cwd=repo, check=True)

    def history(self, source: str) -> str:
        tmp, repo = self.make_repo(); self.addCleanup(tmp.cleanup)
        self.commit_file(repo, source)
        return "\n".join(strict_history_secret_scan.scan_history(repo))

    def alias_line(self, rhs: str, *, indent: str = "    ") -> str:
        return f"{indent}{self.GENERIC_ALIAS} = {rhs}\n"

    def test_environment_derived_session_alias_is_not_a_secret_literal(self):
        source = (
            "import os\n"
            "def load():\n"
            f"    session_ref = os.getenv('{self.PROJECT_SECRET}')\n"
            + self.alias_line("str(session_ref)")
            + f"    return {self.GENERIC_ALIAS}\n"
        )
        findings = self.history(source)
        self.assertNotIn("secret-like assignment SESSION", findings)

    def test_literal_source_still_fails(self):
        source = (
            "def load():\n"
            "    session_ref = 'synthetic-literal-secret-1234567890'\n"
            + self.alias_line("str(session_ref)")
            + f"    return {self.GENERIC_ALIAS}\n"
        )
        findings = self.history(source)
        self.assertIn("secret-like assignment SESSION", findings)
        self.assertNotIn("synthetic-literal-secret-1234567890", findings)

    def test_environment_reference_overwritten_before_alias_still_fails(self):
        source = (
            "import os\n"
            "def load():\n"
            f"    session_ref = os.getenv('{self.PROJECT_SECRET}')\n"
            "    session_ref = 'synthetic-literal-secret-1234567890'\n"
            + self.alias_line("str(session_ref)")
            + f"    return {self.GENERIC_ALIAS}\n"
        )
        findings = self.history(source)
        self.assertIn("secret-like assignment SESSION", findings)

    def test_unknown_origin_still_fails(self):
        source = "def load(session_ref):\n" + self.alias_line("str(session_ref)") + f"    return {self.GENERIC_ALIAS}\n"
        findings = self.history(source)
        self.assertIn("secret-like assignment SESSION", findings)

    def test_structured_session_key_is_not_suppressed(self):
        structured = "    payload = {" + repr(self.GENERIC_ALIAS) + ": session_ref}\n"
        source = (
            "import os\n"
            "def load():\n"
            f"    session_ref = os.getenv('{self.PROJECT_SECRET}')\n"
            + structured
            + "    return payload\n"
        )
        findings = self.history(source)
        self.assertIn("secret-like assignment SESSION", findings)

    def test_nested_control_flow_assignment_is_not_proven_safe(self):
        source = (
            "import os\n"
            "def load(flag):\n"
            f"    session_ref = os.getenv('{self.PROJECT_SECRET}')\n"
            "    if flag:\n"
            + self.alias_line("str(session_ref)", indent="        ")
            + "    return flag\n"
        )
        findings = self.history(source)
        self.assertIn("secret-like assignment SESSION", findings)

    def test_project_secret_indirect_assignment_is_never_suppressed(self):
        assignment = f"    {self.PROJECT_SECRET} = str(source_ref)\n"
        source = (
            "import os\n"
            "def load():\n"
            f"    source_ref = os.getenv('{self.PROJECT_SECRET}')\n"
            + assignment
            + f"    return {self.PROJECT_SECRET}\n"
        )
        findings = self.history(source)
        self.assertIn("secret-like assignment TG_SESSION_STRING", findings)


if __name__ == "__main__":
    unittest.main()
