# -*- coding: utf-8 -*-
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from tools.history_secret_adjudication import (
    ADJUDICATION_FILE,
    filter_exact_history_assignment_findings,
    load_adjudications,
)


class HistorySecretAdjudicationTests(unittest.TestCase):
    SHA = "a" * 40
    PATH = "tests/historical_fixture.py"
    BLOB = b'SESSION_STRING="synthetic-fixed-fixture"\n'

    def make_repo(self):
        tmp = tempfile.TemporaryDirectory()
        repo = Path(tmp.name)
        self.addCleanup(tmp.cleanup)
        return repo

    def finding(self, variable="SESSION_STRING", sha=None, path=None):
        return f"history-blob:{sha or self.SHA}: secret-like assignment {variable} in {path or self.PATH}"

    def write_ledger(self, repo, *, blob=None, sha=None, path=None, variables=None, reason=None):
        data = blob if blob is not None else self.BLOB
        payload = {
            "entries": [
                {
                    "path": path or self.PATH,
                    "git_blob_sha": sha or self.SHA,
                    "sha256": hashlib.sha256(data).hexdigest(),
                    "variables": variables or ["SESSION_STRING"],
                    "reason": reason or "Reviewed deterministic synthetic historical fixture only.",
                }
            ]
        }
        (repo / ADJUDICATION_FILE).write_text(json.dumps(payload) + "\n", encoding="utf-8")

    def test_exact_reviewed_history_assignment_can_be_adjudicated(self):
        repo = self.make_repo()
        self.write_ledger(repo)
        self.assertEqual(
            [],
            filter_exact_history_assignment_findings(
                repo=repo,
                git_blob_sha=self.SHA,
                rel_path=self.PATH,
                blob=self.BLOB,
                findings=[self.finding()],
            ),
        )

    def test_nonassignment_or_current_finding_can_never_be_adjudicated(self):
        repo = self.make_repo()
        self.write_ledger(repo)
        for finding in (
            f"current-tree: secret-like assignment SESSION_STRING in {self.PATH}",
            f"history-blob:{self.SHA}: private key marker in {self.PATH}",
            f"history-blob:{self.SHA}: concrete setup route in {self.PATH}",
            f"history-blob:{self.SHA}: forbidden file {self.PATH}",
        ):
            with self.subTest(finding=finding):
                self.assertEqual(
                    [finding],
                    filter_exact_history_assignment_findings(
                        repo=repo,
                        git_blob_sha=self.SHA,
                        rel_path=self.PATH,
                        blob=self.BLOB,
                        findings=[finding],
                    ),
                )

    def test_blob_path_sha_and_complete_variable_set_are_exact(self):
        repo = self.make_repo()
        self.write_ledger(repo)
        cases = [
            ("b" * 40, self.PATH, self.BLOB, [self.finding(sha="b" * 40)]),
            (self.SHA, "tests/other.py", self.BLOB, [self.finding(path="tests/other.py")]),
            (self.SHA, self.PATH, self.BLOB + b"BRIDGE_TOKEN=x\n", [self.finding(), self.finding("BRIDGE_TOKEN")]),
        ]
        for sha, path, blob, findings in cases:
            with self.subTest(sha=sha, path=path):
                self.assertEqual(
                    findings,
                    filter_exact_history_assignment_findings(
                        repo=repo,
                        git_blob_sha=sha,
                        rel_path=path,
                        blob=blob,
                        findings=findings,
                    ),
                )

    def test_malformed_or_duplicate_ledger_fails_closed(self):
        repo = self.make_repo()
        malformed = [
            {"entries": [{"path": self.PATH}]},
            {"entries": [{
                "path": "../escape.py",
                "git_blob_sha": self.SHA,
                "sha256": hashlib.sha256(self.BLOB).hexdigest(),
                "variables": ["SESSION_STRING"],
                "reason": "Reviewed deterministic synthetic historical fixture only.",
            }]},
            {"entries": [{
                "path": self.PATH,
                "git_blob_sha": self.SHA,
                "sha256": hashlib.sha256(self.BLOB).hexdigest(),
                "variables": ["SESSION_STRING", "SESSION_STRING"],
                "reason": "Reviewed deterministic synthetic historical fixture only.",
            }]},
        ]
        for payload in malformed:
            with self.subTest(payload=payload):
                (repo / ADJUDICATION_FILE).write_text(json.dumps(payload), encoding="utf-8")
                with self.assertRaises(ValueError):
                    load_adjudications(repo)
                findings = [self.finding()]
                self.assertEqual(
                    findings,
                    filter_exact_history_assignment_findings(
                        repo=repo,
                        git_blob_sha=self.SHA,
                        rel_path=self.PATH,
                        blob=self.BLOB,
                        findings=findings,
                    ),
                )
