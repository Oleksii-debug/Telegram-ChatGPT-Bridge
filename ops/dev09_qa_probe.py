# -*- coding: utf-8 -*-
"""DEV09 exact-parent independent QA probes.

QA-only. No network, production mutation, deployment, Passenger restart,
Telegram authorization, or live Telegram read/write. Public outputs are bounded
stable labels, counts, booleans, exact public SHAs, and unittest identifiers.
"""
from __future__ import annotations

import argparse
import functools
import json
import os
import re
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any

from ops.candidate_contracts import (
    candidate_acceptance_coverage,
    integrated_api_inventory,
    validate_candidate_acceptance_coverage,
    validate_integrated_api_inventory,
)

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "integration" / "dev09_qa_v1.json"
EXPECTED_PARENT_SHA = "a4fea8431b999e1bab7d95168ce0fc4d2a20305d"
MAX_FAILURE_IDS = 20
_TEST_ID_RE = re.compile(r"\(([A-Za-z0-9_.]+)\) \.\.\. (?:ERROR|FAIL)$")
_ERROR_HEADER_RE = re.compile(r"^(?:ERROR|FAIL): ([A-Za-z0-9_.]+)$")


def _load_manifest(path: Path = MANIFEST) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    expected_keys = {
        "schema_version", "role", "parent_sha", "target_branch", "qa_paths",
        "production_logic_modified", "deployment_authorized", "live_write_authorized", "product_pass",
    }
    if not isinstance(payload, dict) or set(payload) != expected_keys:
        raise ValueError("DEV09 manifest schema mismatch")
    if payload["schema_version"] != 1 or payload["role"] != "DEV09":
        raise ValueError("DEV09 manifest identity mismatch")
    if payload["parent_sha"] != EXPECTED_PARENT_SHA:
        raise ValueError("DEV09 exact parent mismatch")
    if payload["target_branch"] != "work3/integration-release-candidate":
        raise ValueError("DEV09 target branch mismatch")
    paths = payload["qa_paths"]
    if not isinstance(paths, list) or paths != sorted(set(paths)) or len(paths) != 5:
        raise ValueError("DEV09 QA path allowlist mismatch")
    if any(payload[key] is not False for key in (
        "production_logic_modified", "deployment_authorized", "live_write_authorized", "product_pass"
    )):
        raise ValueError("DEV09 QA safety boundary mismatch")
    return payload


def validate_workflow_parent(event_base_sha: str | None) -> None:
    if event_base_sha is not None and event_base_sha != EXPECTED_PARENT_SHA:
        raise ValueError("DEV09_QA_PARENT_MOVED")


def _validate_archive_members(archive: tarfile.TarFile) -> list[tarfile.TarInfo]:
    members = archive.getmembers()
    for member in members:
        path = PurePosixPath(member.name)
        if path.is_absolute() or ".." in path.parts or member.issym() or member.islnk():
            raise ValueError("DEV09 exact Git archive topology unsafe")
        if not (member.isdir() or member.isfile()):
            raise ValueError("DEV09 exact Git archive contains unsupported member")
    return members


def _bounded_failure_ids(output: str) -> list[str]:
    found: set[str] = set()
    for raw in output.splitlines():
        line = raw.strip()
        match = _TEST_ID_RE.search(line) or _ERROR_HEADER_RE.match(line)
        if match:
            identifier = match.group(1)
            if len(identifier) <= 180:
                found.add(identifier)
        if len(found) >= MAX_FAILURE_IDS:
            break
    return sorted(found)


def _safe_probe_base() -> dict[str, Any]:
    return {
        "parent_sha": EXPECTED_PARENT_SHA,
        "private_values_recorded": False,
        "production_mutated": False,
        "deployment_authorized": False,
        "product_pass": False,
    }


@functools.lru_cache(maxsize=4)
def exported_test_suite_probe(root: Path = ROOT, sha: str = EXPECTED_PARENT_SHA) -> dict[str, Any]:
    root = root.resolve(strict=True)
    if not (root / ".git").exists():
        return {
            **_safe_probe_base(), "classification": "QA_PROBE_UNAVAILABLE",
            "reason": "REPOSITORY_GIT_UNAVAILABLE", "return_code": -1,
            "failure_test_count": 0, "failure_test_ids": [], "git_metadata_present": False,
        }
    with tempfile.TemporaryDirectory(prefix="dev09-suite-probe-") as tmp:
        tmp_root = Path(tmp)
        archive_path = tmp_root / "candidate.tar"
        exported = tmp_root / "exported"
        exported.mkdir()
        with archive_path.open("wb") as handle:
            try:
                subprocess.run(
                    ["git", "archive", "--format=tar", sha], cwd=root, check=True,
                    stdout=handle, stderr=subprocess.DEVNULL, timeout=60,
                )
            except (OSError, subprocess.SubprocessError) as exc:
                raise ValueError("DEV09 exact parent archive unavailable") from exc
        with tarfile.open(archive_path, "r:") as archive:
            members = _validate_archive_members(archive)
            archive.extractall(exported, members=members)
        env = dict(os.environ)
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        completed = subprocess.run(
            [sys.executable, "-B", "-m", "unittest", "discover", "-s", "tests", "-v"],
            cwd=exported, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, encoding="utf-8", errors="replace", timeout=240, check=False,
        )
        failure_ids = _bounded_failure_ids(completed.stdout + "\n" + completed.stderr)
        blocked = completed.returncode != 0
        return {
            **_safe_probe_base(),
            "classification": "BLOCKED_INTERNAL_QA" if blocked else "CLEAR",
            "reason": "EXPORTED_CANONICAL_TEST_FAILURE" if blocked else "NONE",
            "return_code": int(completed.returncode),
            "failure_test_count": len(failure_ids),
            "failure_test_ids": failure_ids,
            "git_metadata_present": (exported / ".git").exists(),
        }


@functools.lru_cache(maxsize=4)
def canonical_provenance_probe(root: Path = ROOT, sha: str = EXPECTED_PARENT_SHA) -> dict[str, Any]:
    root = root.resolve(strict=True)
    if not (root / ".git").exists():
        return {
            **_safe_probe_base(), "classification": "QA_PROBE_UNAVAILABLE",
            "reason": "REPOSITORY_GIT_UNAVAILABLE", "return_code": -1,
        }
    with tempfile.TemporaryDirectory(prefix="dev09-provenance-") as tmp:
        worktree = Path(tmp) / "canonical"
        try:
            added = subprocess.run(
                ["git", "worktree", "add", "--detach", str(worktree), sha], cwd=root,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=60, check=False,
            )
            if added.returncode != 0:
                raise ValueError("DEV09 exact parent worktree unavailable")
            completed = subprocess.run(
                [sys.executable, "tools/verify_integration_provenance.py"], cwd=worktree,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8",
                errors="replace", timeout=60, check=False,
            )
            if completed.returncode == 0:
                classification, reason = "CLEAR", "NONE"
            else:
                classification, reason = "BLOCKED_CANONICAL_PROVENANCE", "PROVENANCE_FAILURE"
            return {**_safe_probe_base(), "classification": classification, "reason": reason, "return_code": int(completed.returncode)}
        finally:
            subprocess.run(
                ["git", "worktree", "remove", "--force", str(worktree)], cwd=root,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30, check=False,
            )


def candidate_truth_snapshot() -> dict[str, Any]:
    coverage = candidate_acceptance_coverage()
    counts = validate_candidate_acceptance_coverage(coverage)
    inventory = integrated_api_inventory()
    validate_integrated_api_inventory(inventory)
    k5 = next(row for row in coverage if row["criterion"] == "K5")
    return {
        "criterion_count": len(coverage), "coverage_counts": counts,
        "product_pass_count": sum(1 for row in coverage if row["product_pass"] is True),
        "route_count": len(inventory),
        "action_operation_count": sum(1 for row in inventory if row["action_operation_id"] is not None),
        "private_surface_count": sum(1 for row in inventory if any(term in row["path"].casefold() for term in ("setup", "login", "session", "2fa"))),
        "k5_evidence_class": k5["evidence_class"],
        "k5_explicit_write_approval_required": k5["explicit_write_approval_required"],
        "product_pass": False, "deployment_authorized": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--suite-probe", action="store_true")
    group.add_argument("--provenance-probe", action="store_true")
    args = parser.parse_args(argv)
    payload = exported_test_suite_probe() if args.suite_probe else canonical_provenance_probe() if args.provenance_probe else candidate_truth_snapshot()
    print(json.dumps(payload, sort_keys=True, separators=(",", ":")))
    return 0


_load_manifest()

if __name__ == "__main__":
    raise SystemExit(main())
