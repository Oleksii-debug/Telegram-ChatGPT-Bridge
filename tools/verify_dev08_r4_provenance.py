#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Fail-closed provenance verifier for the DEV08 persistent-state specialist overlay."""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ANCHOR_SHA = "38e33b829748cbdf255d66aba847aed81f6662c8"
SHA40 = re.compile(r"^[0-9a-f]{40}$")
EXPECTED_PATHS = {
    "docs/DEV08_STATE_MIGRATION_ROLLBACK_R4.md",
    "ops/dev08_state_migration_contract.py",
    "tests/test_dev08_state_migration_contract.py",
    "tools/verify_dev08_r4_provenance.py",
}
EXPECTED_ANCHOR_BLOBS = {
    "ops/release_guard.py": "c77a7f5f2aa902359359fb7921970e3845714c7c",
    "ops/deploy_release.py": "95e5a2d8d4b60d3f08f27875fed4b066c9b3c776",
    "bridge/storage.py": "90cf1d74779d7947ea197010b8ea3011a5a6a705",
    "bridge/app.py": "95a4882fe24e75a3d4141bc1730d185ab70b793d",
    "bridge/runtime.py": "202dd8e84e045641ebb3a73744f657ebaf1dd265",
    "bridge/integrated_app.py": "31b2eb39acb532d5db833cae9caf6b29fe2d172a",
    "ops/write_safety.py": "bd78e1eb62cb067f880010c84ac1db440ad9d04b",
    "bridge/audit.py": "eb3b35f329d44622d9fc2977bf1ddc78aa7f0ab6",
}


class ProvenanceError(RuntimeError):
    pass


def git(*args: str) -> str:
    try:
        return subprocess.check_output(
            ["git", *args], cwd=ROOT, text=True, stderr=subprocess.DEVNULL
        ).strip()
    except subprocess.CalledProcessError as exc:
        raise ProvenanceError("required git provenance query failed") from exc


def overlay_head() -> str:
    explicit = os.environ.get("DEV08_R4_OVERLAY_HEAD", "").strip().casefold()
    if explicit:
        if not SHA40.fullmatch(explicit):
            raise ProvenanceError("explicit DEV08 overlay head is not a full SHA")
        if git("rev-parse", "--verify", f"{explicit}^{{commit}}") != explicit:
            raise ProvenanceError("explicit DEV08 overlay head is unavailable")
        return explicit
    head = git("rev-parse", "HEAD")
    parents = git("rev-list", "--parents", "-n", "1", head).split()
    if len(parents) == 3:
        return parents[2]
    return head


def changed_paths(base: str, head: str) -> set[str]:
    raw = git("diff", "--name-only", f"{base}..{head}")
    return {line for line in raw.splitlines() if line}


def verify() -> dict[str, object]:
    head = overlay_head()
    merge_base = git("merge-base", ANCHOR_SHA, head)
    if merge_base != ANCHOR_SHA:
        raise ProvenanceError("DEV08 overlay is not descended from the exact reviewed anchor")

    for path, expected_blob in EXPECTED_ANCHOR_BLOBS.items():
        actual_blob = git("rev-parse", f"{ANCHOR_SHA}:{path}")
        if actual_blob != expected_blob:
            raise ProvenanceError("reviewed anchor blob identity mismatch")

    paths = changed_paths(ANCHOR_SHA, head)
    if paths != EXPECTED_PATHS:
        raise ProvenanceError("DEV08 final diff contains unexpected or missing paths")

    commit_count = int(git("rev-list", "--count", f"{ANCHOR_SHA}..{head}"))
    if commit_count < 1 or commit_count > 8:
        raise ProvenanceError("DEV08 commit count outside bounded specialist range")

    for commit in git("rev-list", "--reverse", f"{ANCHOR_SHA}..{head}").splitlines():
        commit_paths = changed_paths(f"{commit}^", commit)
        if not commit_paths.issubset(EXPECTED_PATHS):
            raise ProvenanceError("DEV08 history mutates a non-role path")

    path_digest = hashlib.sha256("\n".join(sorted(paths)).encode("utf-8")).hexdigest()
    return {
        "schema": 3,
        "anchor_sha": ANCHOR_SHA,
        "overlay_head": head,
        "merge_base": merge_base,
        "commit_count": commit_count,
        "changed_path_count": len(paths),
        "changed_paths_sha256": path_digest,
        "production_authorized": False,
        "private_values_recorded": False,
        "canonical_mutated": False,
    }


def main() -> int:
    print(json.dumps(verify(), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
