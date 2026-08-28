#!/usr/bin/env python3
"""Fail-closed provenance verifier for the isolated DEV08 reliability overlay.

This is intentionally separate from DEV_A canonical provenance. It never expands
DEV_A's allowlist and grants no deployment authority. It proves that the final
DEV08 net diff contains only role-owned reliability/QA files. One branch-history
exception is explicit: canonical ``ci.yml`` may be temporarily instrumented only
to execute DEV08 tests, then must be restored to the exact canonical blob. The
verifier allows that path in commit history but rejects it from the final net diff.
"""
from __future__ import annotations

import json
import os
import re
import subprocess


ANCHOR_SHA = "f966cc5bffc19d597bf298799e39a9bbbe692b19"
EXPECTED_FINAL_PATHS = frozenset(
    {
        "docs/DEV08_RELIABILITY_CONCURRENCY_RECOVERY.md",
        "docs/DEV08_ROUND2_INTERACTION_FINDINGS.md",
        "ops/dev08_reliability.py",
        "ops/dev08_recovery_extensions.py",
        "tests/test_dev08_reliability.py",
        "tests/test_dev08_round2.py",
        "tools/verify_dev08_provenance.py",
    }
)
HISTORY_ALLOWED_PATHS = EXPECTED_FINAL_PATHS | {".github/workflows/ci.yml"}
_SHA_RE = re.compile(r"^[0-9a-f]{40}$")


class ProvenanceError(RuntimeError):
    pass


def _git(*args: str) -> str:
    try:
        completed = subprocess.run(
            ["git", *args],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ProvenanceError("git provenance query failed") from exc
    return completed.stdout.strip()


def _sha(value: str) -> str:
    value = value.strip().lower()
    if not _SHA_RE.fullmatch(value):
        raise ProvenanceError("invalid git identity")
    return value


def _overlay_head() -> str:
    head = _sha(_git("rev-parse", "HEAD"))
    event = str(os.getenv("GITHUB_EVENT_NAME") or "")
    if event == "pull_request":
        parents = _git("rev-list", "--parents", "-n", "1", head).split()
        if len(parents) != 3:
            raise ProvenanceError("pull request checkout is not an exact two-parent merge")
        return _sha(parents[2])
    return head


def _changed_paths(parent: str, child: str) -> set[str]:
    raw = _git("diff", "--name-only", "--no-renames", parent, child)
    return {line for line in raw.splitlines() if line}


def verify() -> dict[str, object]:
    anchor = _sha(ANCHOR_SHA)
    overlay = _overlay_head()
    _git("cat-file", "-e", f"{anchor}^{{commit}}")
    _git("cat-file", "-e", f"{overlay}^{{commit}}")

    current = overlay
    commit_count = 0
    history_union: set[str] = set()
    while current != anchor:
        row = _git("rev-list", "--parents", "-n", "1", current).split()
        if len(row) != 2:
            raise ProvenanceError("DEV08 overlay must be a linear commit chain")
        parent = _sha(row[1])
        changed = _changed_paths(parent, current)
        if not changed or not changed.issubset(HISTORY_ALLOWED_PATHS):
            raise ProvenanceError("DEV08 commit changed a path outside exact history allowlist")
        history_union.update(changed)
        current = parent
        commit_count += 1
        if commit_count > 48:
            raise ProvenanceError("DEV08 overlay commit bound exceeded")

    final_paths = _changed_paths(anchor, overlay)
    if final_paths != set(EXPECTED_FINAL_PATHS):
        raise ProvenanceError("DEV08 final net diff is incomplete or contains an unexpected path")
    if ".github/workflows/ci.yml" in final_paths:
        raise ProvenanceError("canonical CI was not restored after DEV08 validation")
    if ".github/workflows/ci.yml" not in history_union:
        raise ProvenanceError("DEV08 validation-only CI instrumentation is not traceable")

    result = {
        "schema": 3,
        "anchor_sha": anchor,
        "overlay_head_sha": overlay,
        "commit_count": commit_count,
        "final_path_count": len(final_paths),
        "history_path_count": len(history_union),
        "canonical_ci_restored": True,
        "private_values_recorded": False,
        "deployment_authorized": False,
    }
    return result


def main() -> int:
    try:
        result = verify()
    except ProvenanceError:
        print("DEV08_PROVENANCE_BLOCKED")
        return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    print("DEV08_PROVENANCE_PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
