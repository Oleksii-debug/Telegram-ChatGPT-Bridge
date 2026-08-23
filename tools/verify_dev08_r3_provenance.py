#!/usr/bin/env python3
"""Fail-closed provenance verifier for DEV08 deployment-recovery round 3.

This verifier is intentionally separate from canonical DEV_A provenance. It grants
no merge/deployment authority and never widens canonical integration allowlists.
"""
from __future__ import annotations

import json
import os
import re
import subprocess


ANCHOR_SHA = "00684e834a523f55ea3b61c1a12cb9dc54cfd947"
EXPECTED_FINAL_PATHS = frozenset(
    {
        "docs/DEV08_DEPLOYMENT_RECOVERY_R3.md",
        "ops/dev08_deploy_recovery.py",
        "tests/test_dev08_deploy_recovery.py",
        "tools/verify_dev08_r3_provenance.py",
    }
)
HISTORY_ALLOWED_PATHS = EXPECTED_FINAL_PATHS | {".github/workflows/ci.yml"}
_SHA_RE = re.compile(r"^[0-9a-f]{40}$")


class ProvenanceError(RuntimeError):
    pass


def _git(*args: str) -> str:
    try:
        return subprocess.run(
            ["git", *args],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=30,
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError) as exc:
        raise ProvenanceError("git provenance query failed") from exc


def _sha(value: str) -> str:
    value = value.strip().lower()
    if not _SHA_RE.fullmatch(value):
        raise ProvenanceError("invalid git identity")
    return value


def _overlay_head() -> str:
    head = _sha(_git("rev-parse", "HEAD"))
    if str(os.getenv("GITHUB_EVENT_NAME") or "") == "pull_request":
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
            raise ProvenanceError("DEV08 round3 overlay must remain a linear commit chain")
        parent = _sha(row[1])
        changed = _changed_paths(parent, current)
        if not changed or not changed.issubset(HISTORY_ALLOWED_PATHS):
            raise ProvenanceError("DEV08 round3 commit changed path outside exact history allowlist")
        history_union.update(changed)
        current = parent
        commit_count += 1
        if commit_count > 24:
            raise ProvenanceError("DEV08 round3 commit bound exceeded")

    final_paths = _changed_paths(anchor, overlay)
    if final_paths != set(EXPECTED_FINAL_PATHS):
        raise ProvenanceError("DEV08 round3 final net diff is incomplete or contains unexpected path")
    if ".github/workflows/ci.yml" in final_paths:
        raise ProvenanceError("canonical CI remains modified in DEV08 final net diff")

    return {
        "schema": 1,
        "anchor_sha": anchor,
        "overlay_head_sha": overlay,
        "commit_count": commit_count,
        "final_path_count": len(final_paths),
        "history_path_count": len(history_union),
        "canonical_ci_restored": ".github/workflows/ci.yml" not in final_paths,
        "private_values_recorded": False,
        "deployment_authorized": False,
    }


def main() -> int:
    try:
        result = verify()
    except ProvenanceError:
        print("DEV08_R3_PROVENANCE_BLOCKED")
        return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    print("DEV08_R3_PROVENANCE_PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
