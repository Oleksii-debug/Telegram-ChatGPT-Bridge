# -*- coding: utf-8 -*-
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from ops import dev06_deployed_action_evidence as evidence
from ops.dev06_runtime_conformance import build_compatible_chatgpt_action_openapi


SOURCE_ROOT = Path(__file__).resolve().parents[1]


class W09ActionEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def git(self, repo: Path, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["git", *args], cwd=repo, check=True, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )

    def make_repo(self, name: str = "repo") -> Path:
        repo = self.root / name
        shutil.copytree(
            SOURCE_ROOT,
            repo,
            ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc", ".pytest_cache"),
        )
        self.git(repo, "init", "-q")
        self.git(repo, "config", "user.email", "w09@example.invalid")
        self.git(repo, "config", "user.name", "W09 Test")
        self.git(repo, "add", "-A")
        self.git(repo, "commit", "-qm", "fixture")
        return repo

    def observed_schema(self) -> Path:
        path = self.root / "observed.json"
        path.write_text(
            json.dumps(build_compatible_chatgpt_action_openapi(evidence.PRODUCTION_BASE_URL), ensure_ascii=False),
            encoding="utf-8",
        )
        return path

    def run_tool(self, repo: Path, tool: str, *args: str, env: dict[str, str] | None = None, timeout: float = 30) -> subprocess.CompletedProcess[str]:
        merged = dict(os.environ)
        for name in evidence._DANGEROUS_ENVIRONMENT:
            merged.pop(name, None)
        if env:
            merged.update(env)
        return subprocess.run(
            [sys.executable, "-I", "-B", os.fspath(repo / tool), "--source-checkout", os.fspath(repo), *args],
            cwd=self.root, env=merged, check=False, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout,
        )

    def h1(self, repo: Path, *args: str, **kwargs) -> subprocess.CompletedProcess[str]:
        return self.run_tool(repo, "tools/verify_dev06_deployed_action.py", "--observed-schema", os.fspath(self.observed_schema()), *args, **kwargs)

    def test_clean_h1_and_h2_are_bound_and_never_self_authorize(self):
        repo = self.make_repo()
        h1 = self.h1(repo)
        self.assertEqual(0, h1.returncode, h1.stderr)
        h1_data = json.loads(h1.stdout)
        self.assertTrue(h1_data["schema_match"])
        self.assertFalse(h1_data["product_h1_pass"])
        self.assertFalse(h1_data["self_authorization"])
        self.assertGreater(h1_data["source_python_file_count"], 10)

        capture = {
            "schema_version": 1,
            "source_classification": "SOURCE_MOCK",
            "source_binding_sha256": h1_data["source_binding_sha256"],
            "deployed_sha": h1_data["candidate_sha"],
            "operation_id": "listTelegramDialogs",
            "method": "POST",
            "http_status": 200,
            "authorized": True,
            "read_only": True,
            "telegram_read_observed": True,
            "request_sha256": "a" * 64,
            "response_sha256": "b" * 64,
        }
        capture_path = self.root / "h2.json"
        capture_path.write_text(json.dumps(capture), encoding="utf-8")
        h2 = self.run_tool(repo, "tools/verify_dev06_action_e2e.py", "--capture", os.fspath(capture_path))
        self.assertEqual(0, h2.returncode, h2.stderr)
        h2_data = json.loads(h2.stdout)
        self.assertEqual(h1_data["candidate_sha"], h2_data["candidate_sha"])
        self.assertFalse(h2_data["product_h2_pass"])
        self.assertFalse(h2_data["self_authorization"])
        self.assertTrue(h2_data["read_only"])

    def test_all_untracked_bootstrap_and_shadow_entries_fail_closed(self):
        repo = self.make_repo()
        for relative in ("sitecustomize.py", "ops/shadow_package/__init__.py"):
            path = repo / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("raise RuntimeError('must not import')\n", encoding="utf-8")
            result = self.h1(repo)
            self.assertEqual(2, result.returncode)
            self.assertIn("SOURCE_CHECKOUT_ALL_FILES_DIRTY", result.stderr)
            if path.name == "__init__.py":
                shutil.rmtree(path.parent)
            else:
                path.unlink()

    def test_assume_unchanged_and_skip_worktree_are_rejected(self):
        for flag in ("--assume-unchanged", "--skip-worktree"):
            repo = self.make_repo(flag.removeprefix("--"))
            target = "ops/dev06_runtime_conformance.py"
            self.git(repo, "update-index", flag, target)
            if flag == "--assume-unchanged":
                with (repo / target).open("a", encoding="utf-8") as stream:
                    stream.write("\n# hidden mutation\n")
            result = self.h1(repo)
            self.assertEqual(2, result.returncode)
            self.assertIn("SOURCE_CHECKOUT_INDEX_FLAGS_UNSAFE", result.stderr)

    def test_hostile_git_environment_and_cross_checkout_fail_closed(self):
        repo = self.make_repo("a")
        hostile = self.h1(repo, env={"GIT_DIR": os.fspath(repo / ".git")})
        self.assertEqual(2, hostile.returncode)
        self.assertIn("SOURCE_EXECUTION_ENVIRONMENT_UNSAFE", hostile.stderr)

        other = self.make_repo("b")
        result = subprocess.run(
            [sys.executable, "-I", "-B", os.fspath(repo / "tools/verify_dev06_deployed_action.py"),
             "--source-checkout", os.fspath(other), "--observed-schema", os.fspath(self.observed_schema())],
            cwd=self.root, check=False, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        self.assertEqual(2, result.returncode)
        self.assertIn("SOURCE_CHECKOUT_EXECUTION_MISMATCH", result.stderr)

        fake_bin = self.root / "fake-bin"
        fake_bin.mkdir()
        fake_git = fake_bin / ("git.exe" if os.name == "nt" else "git")
        fake_git.write_text("not an executable git", encoding="utf-8")
        neutralized = self.h1(repo, env={"PATH": os.fspath(fake_bin)})
        self.assertEqual(0, neutralized.returncode, neutralized.stderr)

    def test_nonrepository_and_nested_checkout_fail_closed(self):
        repo = self.make_repo()
        nested = repo / "ops"
        result = subprocess.run(
            [sys.executable, "-I", "-B", os.fspath(repo / "tools/verify_dev06_deployed_action.py"),
             "--source-checkout", os.fspath(nested), "--observed-schema", os.fspath(self.observed_schema())],
            cwd=self.root, check=False, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        self.assertEqual(2, result.returncode)
        self.assertIn("SOURCE_CHECKOUT_NOT_REPOSITORY_ROOT", result.stderr)
        nonrepo = self.root / "nonrepo"
        nonrepo.mkdir()
        result = subprocess.run(
            [sys.executable, "-I", "-B", os.fspath(repo / "tools/verify_dev06_deployed_action.py"),
             "--source-checkout", os.fspath(nonrepo), "--observed-schema", os.fspath(self.observed_schema())],
            cwd=self.root, check=False, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        self.assertEqual(2, result.returncode)
        self.assertIn("SOURCE_CHECKOUT_GIT_UNAVAILABLE", result.stderr)

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks unavailable")
    def test_final_and_parent_symlink_checkout_paths_fail_closed(self):
        repo = self.make_repo()
        final_link = self.root / "repo-link"
        final_link.symlink_to(repo, target_is_directory=True)
        result = subprocess.run(
            [sys.executable, "-I", "-B", os.fspath(repo / "tools/verify_dev06_deployed_action.py"),
             "--source-checkout", os.fspath(final_link), "--observed-schema", os.fspath(self.observed_schema())],
            cwd=self.root, check=False, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        self.assertEqual(2, result.returncode)
        self.assertIn("SOURCE_CHECKOUT_UNSAFE", result.stderr)

        parent_link = self.root / "parent-link"
        parent_link.symlink_to(self.root, target_is_directory=True)
        parent_path = parent_link / repo.name
        result = subprocess.run(
            [sys.executable, "-I", "-B", os.fspath(repo / "tools/verify_dev06_deployed_action.py"),
             "--source-checkout", os.fspath(parent_path), "--observed-schema", os.fspath(self.observed_schema())],
            cwd=self.root, check=False, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        self.assertEqual(2, result.returncode)
        self.assertIn("SOURCE_CHECKOUT_UNSAFE", result.stderr)

    def test_dirty_import_then_restore_cannot_relabel_clean_head(self):
        repo = self.make_repo()
        target = repo / "ops/dev06_runtime_conformance.py"
        with target.open("a", encoding="utf-8") as stream:
            stream.write("\nDIRTY_IMPORT_MARKER = True\n")
        runner = self.root / "dirty_restore.py"
        runner.write_text(
            "import importlib,json,subprocess,sys\n"
            f"root={str(repo)!r}\n"
            "sys.path.insert(0,root)\n"
            "import ops.dev06_runtime_conformance\n"
            "subprocess.run(['git','checkout','--','ops/dev06_runtime_conformance.py'],cwd=root,check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)\n"
            "from ops.dev06_deployed_action_evidence import compare_deployed_action_schema,DeployedActionEvidenceError\n"
            "doc=ops.dev06_runtime_conformance.build_compatible_chatgpt_action_openapi('https://tg-api.rukadopomogy.org.ua')\n"
            "try: compare_deployed_action_schema(root,doc)\n"
            "except DeployedActionEvidenceError as exc: print(str(exc));raise SystemExit(0)\n"
            "raise SystemExit(9)\n",
            encoding="utf-8",
        )
        result = subprocess.run(
            [sys.executable, "-I", "-B", os.fspath(runner)], cwd=self.root,
            check=False, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("SOURCE_SCHEMA_MODULE_PRELOADED", result.stdout)

    def test_head_switch_and_late_untracked_change_fail_during_binding(self):
        for attack in ("head", "untracked"):
            repo = self.make_repo(attack)
            marker = repo / "docs" / "w09-fixture-marker.txt"
            marker.write_text("second commit\n", encoding="utf-8")
            self.git(repo, "add", os.fspath(marker.relative_to(repo)))
            self.git(repo, "commit", "-qm", "second")
            runner = self.root / f"{attack}_race.py"
            runner.write_text(
                "import os,subprocess,sys\n"
                f"root={str(repo)!r}\n"
                "sys.path.insert(0,root)\n"
                "from ops import dev06_deployed_action_evidence as ev\n"
                "original=ev._prove_python_source_blobs\n"
                "def attack(root_path,entries):\n"
                " result=original(root_path,entries)\n"
                + (" subprocess.run(['git','checkout','--detach','HEAD~1'],cwd=root,check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)\n" if attack == "head" else " (root_path/'late-untracked.py').write_text('x=1\\n',encoding='utf-8')\n")
                + " return result\n"
                "ev._prove_python_source_blobs=attack\n"
                "try: ev.derive_source_binding(root)\n"
                "except ev.DeployedActionEvidenceError as exc: print(str(exc));raise SystemExit(0)\n"
                "raise SystemExit(9)\n",
                encoding="utf-8",
            )
            result = subprocess.run(
                [sys.executable, "-I", "-B", os.fspath(runner)], cwd=self.root,
                check=False, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            self.assertEqual(0, result.returncode, result.stderr)
            expected = "SOURCE_CHECKOUT_CHANGED_DURING_BINDING" if attack == "head" else "SOURCE_CHECKOUT_ALL_FILES_DIRTY"
            self.assertIn(expected, result.stdout)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFO unavailable")
    def test_fifo_observed_schema_fails_without_blocking(self):
        repo = self.make_repo()
        fifo = self.root / "schema.fifo"
        os.mkfifo(fifo)
        started = time.monotonic()
        result = self.run_tool(
            repo, "tools/verify_dev06_deployed_action.py",
            "--observed-schema", os.fspath(fifo), timeout=5,
        )
        self.assertLess(time.monotonic() - started, 5)
        self.assertEqual(2, result.returncode)
        self.assertIn("OBSERVED_SCHEMA_FILE_UNSAFE", result.stderr)

    def test_h2_rejects_write_operation_and_cross_binding(self):
        repo = self.make_repo()
        h1 = json.loads(self.h1(repo).stdout)
        capture = {
            "schema_version": 1, "source_classification": "SOURCE_MOCK",
            "source_binding_sha256": h1["source_binding_sha256"],
            "deployed_sha": h1["candidate_sha"], "operation_id": "commitTelegramSend",
            "method": "POST", "http_status": 200, "authorized": True,
            "read_only": True, "telegram_read_observed": True,
            "request_sha256": "a" * 64, "response_sha256": "b" * 64,
        }
        path = self.root / "write.json"
        path.write_text(json.dumps(capture), encoding="utf-8")
        write = self.run_tool(repo, "tools/verify_dev06_action_e2e.py", "--capture", os.fspath(path))
        self.assertEqual(2, write.returncode)
        self.assertIn("H2_CAPTURE_WRITE_OPERATION_REJECTED", write.stderr)

        capture["operation_id"] = "listTelegramDialogs"
        capture["source_binding_sha256"] = "f" * 64
        path.write_text(json.dumps(capture), encoding="utf-8")
        cross = self.run_tool(repo, "tools/verify_dev06_action_e2e.py", "--capture", os.fspath(path))
        self.assertEqual(2, cross.returncode)
        self.assertIn("H2_CAPTURE_SOURCE_BINDING_INVALID", cross.stderr)

    def test_deployed_h2_capture_requires_observed_telegram_read(self):
        repo = self.make_repo()
        h1 = json.loads(self.h1(repo).stdout)
        capture = {
            "schema_version": 1, "source_classification": "DEPLOYED_CAPTURE",
            "source_binding_sha256": h1["source_binding_sha256"],
            "deployed_sha": h1["candidate_sha"], "operation_id": "listTelegramDialogs",
            "method": "POST", "http_status": 200, "authorized": True,
            "read_only": True, "telegram_read_observed": False,
            "request_sha256": "a" * 64, "response_sha256": "b" * 64,
        }
        path = self.root / "missing-live-read.json"
        path.write_text(json.dumps(capture), encoding="utf-8")
        result = self.run_tool(repo, "tools/verify_dev06_action_e2e.py", "--capture", os.fspath(path))
        self.assertEqual(2, result.returncode)
        self.assertIn("H2_CAPTURE_LIVE_READ_MISSING", result.stderr)

    def test_close_failure_is_bounded_and_does_not_leak_raw_oserror(self):
        path = self.root / "schema.json"
        path.write_text("{}", encoding="utf-8")
        with mock.patch.object(evidence.os, "close", side_effect=OSError("private close detail")):
            with self.assertRaises(evidence.DeployedActionEvidenceError) as caught:
                evidence.load_observed_schema(path)
        self.assertEqual("OBSERVED_SCHEMA_FILE_UNSAFE", str(caught.exception))

    def test_observed_document_change_during_read_fails_closed(self):
        path = self.root / "changing.json"
        path.write_text('{"value":1}', encoding="utf-8")
        original_read = evidence.os.read
        changed = False

        def changing_read(fd, amount):
            nonlocal changed
            data = original_read(fd, amount)
            if data and not changed:
                changed = True
                with path.open("ab") as stream:
                    stream.write(b" ")
            return data

        with mock.patch.object(evidence.os, "read", side_effect=changing_read):
            with self.assertRaises(evidence.DeployedActionEvidenceError) as caught:
                evidence.load_observed_schema(path)
        self.assertEqual("OBSERVED_SCHEMA_FILE_UNSAFE", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
