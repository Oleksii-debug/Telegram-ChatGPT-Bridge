#!/usr/bin/env python3
"""Deterministic, non-secret provenance verifier for the DEV_A candidate.

The verifier uses only Git object identity/path metadata from the public checkout.
It never reads environment secrets, Telegram content or private server state.
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path, PurePosixPath
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "integration" / "provenance_v1.json"
RELEASE_OVERRIDE = ROOT / "integration" / "release_to_live_v1.json"


class ProvenanceError(RuntimeError):
    pass


def _git(*args: str) -> str:
    completed = subprocess.run(
        ["git", *args],
        cwd=ROOT,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
    )
    if completed.returncode != 0:
        raise ProvenanceError(f"git command failed: {' '.join(args)}")
    return completed.stdout.strip()


def _blob(ref: str, path: str) -> str:
    value = _git("rev-parse", f"{ref}:{path}")
    if len(value) != 40 or any(ch not in "0123456789abcdef" for ch in value):
        raise ProvenanceError(f"invalid blob identity for {path}")
    return value


def _path_exists(ref: str, path: str) -> bool:
    completed = subprocess.run(
        ["git", "cat-file", "-e", f"{ref}:{path}"],
        cwd=ROOT,
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return completed.returncode == 0


def _parents(commit: str) -> tuple[str, ...]:
    raw = _git("show", "-s", "--format=%P", commit)
    return tuple(raw.split()) if raw else ()


def _assert_ancestor(ancestor: str, descendant: str) -> None:
    completed = subprocess.run(
        ["git", "merge-base", "--is-ancestor", ancestor, descendant],
        cwd=ROOT,
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if completed.returncode != 0:
        raise ProvenanceError("required provenance commit is not an ancestor of candidate HEAD")


def _valid_sha(value: object) -> bool:
    return isinstance(value, str) and len(value) == 40 and all(ch in "0123456789abcdef" for ch in value)


def _safe_sorted_paths(value: object, label: str) -> list[str]:
    if not isinstance(value, list) or not value or value != sorted(set(value)):
        raise ProvenanceError(f"{label} path allowlist invalid")
    for raw in value:
        if not isinstance(raw, str) or not raw:
            raise ProvenanceError(f"{label} path allowlist invalid")
        path = PurePosixPath(raw)
        if path.is_absolute() or ".." in path.parts:
            raise ProvenanceError(f"{label} path allowlist unsafe")
    return value


def _load() -> dict[str, Any]:
    try:
        payload = json.loads(MANIFEST.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ProvenanceError("integration provenance manifest is unreadable") from exc
    if not isinstance(payload, dict) or payload.get("schema_version") != 2:
        raise ProvenanceError("integration provenance manifest schema mismatch")
    return payload


def _load_release_override() -> dict[str, Any]:
    try:
        payload = json.loads(RELEASE_OVERRIDE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ProvenanceError("release-to-live provenance overlay is unreadable") from exc
    if not isinstance(payload, dict) or payload.get("schema_version") != 2:
        raise ProvenanceError("release-to-live provenance overlay schema mismatch")
    if payload.get("round") != "RELEASE_TO_LIVE_ROUND_2":
        raise ProvenanceError("release-to-live provenance round mismatch")
    if payload.get("purpose") != "canonical_release_packaging_runtime_evidence_and_final_qa_integration":
        raise ProvenanceError("release-to-live purpose mismatch")
    checkpoint = payload.get("source_checkpoint")
    if not _valid_sha(checkpoint):
        raise ProvenanceError("release-to-live source checkpoint invalid")
    paths = _safe_sorted_paths(payload.get("paths"), "release-to-live")
    commits = payload.get("trace_commits")
    if not isinstance(commits, list) or not commits:
        raise ProvenanceError("release-to-live trace commits missing")
    for commit in commits:
        if not _valid_sha(commit):
            raise ProvenanceError("release-to-live trace commit invalid")
    if payload.get("runtime_packages") != {
        "Telethon": "1.44.0",
        "pyaes": "1.6.1",
        "rsa": "4.9.1",
        "pyasn1": "0.6.4",
    }:
        raise ProvenanceError("release-to-live runtime package identity mismatch")
    if payload.get("test_only_dependencies") != "NONE_REQUIRED":
        raise ProvenanceError("release-to-live test dependency state invalid")

    dev_b = payload.get("dev_b")
    if not isinstance(dev_b, dict) or dev_b.get("pr") != 11:
        raise ProvenanceError("DEV_B release provenance missing")
    for field in ("sha", "merge_commit", "first_parent"):
        if not _valid_sha(dev_b.get(field)):
            raise ProvenanceError("DEV_B release provenance SHA invalid")
    imported = set(_safe_sorted_paths(dev_b.get("imported_paths"), "DEV_B imported"))
    adapted = set(_safe_sorted_paths(dev_b.get("adapted_paths"), "DEV_B adapted"))
    supersedes = set(_safe_sorted_paths(dev_b.get("supersedes_predecessor_paths"), "DEV_B supersession"))
    if not adapted <= imported or not supersedes <= imported:
        raise ProvenanceError("DEV_B adaptation/supersession escapes imported path set")
    if not imported <= set(paths):
        raise ProvenanceError("DEV_B imported path missing from release-to-live allowlist")

    sync = payload.get("dev_b_round2_sync")
    if not isinstance(sync, dict) or sync.get("pr") != 11:
        raise ProvenanceError("DEV_B Round-2 sync provenance missing")
    if sync.get("sha") != "6f943ee15f053acc5b4f15167c16d431023a35d1":
        raise ProvenanceError("DEV_B Round-2 source checkpoint mismatch")
    if sync.get("merge_commit") != "919d7d409564d7c21e46009e1d76cfa5d1fd602d":
        raise ProvenanceError("DEV_B Round-2 semantic merge identity mismatch")
    if sync.get("first_parent") != "f8b2a3ff0d689966e2f88f3c9efc63cbe5cef8a0":
        raise ProvenanceError("DEV_B Round-2 first-parent checkpoint mismatch")
    exact_sync = set(_safe_sorted_paths(sync.get("exact_blob_paths"), "DEV_B Round-2 exact"))
    retained = set(_safe_sorted_paths(sync.get("retained_dev_a_adaptations"), "DEV_B Round-2 retained"))
    if exact_sync & retained:
        raise ProvenanceError("DEV_B Round-2 exact/retained path overlap")
    if not exact_sync <= set(paths) or not retained <= set(paths):
        raise ProvenanceError("DEV_B Round-2 path missing from release allowlist")
    if sync.get("strict_history_suppression_imported") is not False:
        raise ProvenanceError("DEV_B strict-history suppression layer must not be imported")

    if payload.get("private_values_recorded") is not False:
        raise ProvenanceError("release-to-live overlay records private values")
    if payload.get("production_mutated") is not False or payload.get("deployment_authorized") is not False:
        raise ProvenanceError("release-to-live safety boundary invalid")
    return payload


def _lane_changed_paths(manifest: dict[str, Any]) -> dict[str, set[str]]:
    predecessors = manifest["predecessors"]
    return {
        "PR2": set(manifest["base"]["changed_paths"]),
        "PR3": set(predecessors["DEV5"]["ported_paths"]) | set(predecessors["DEV5"]["rejected_overlaps_preserve_base"]),
        "PR4": set(predecessors["DEV3"]["paths"]),
        "PR5": set(predecessors["DEV2"]["paths"]),
        "PR7": set(predecessors["DEV4"]["paths"]),
    }


def _verify_overlap_matrix(manifest: dict[str, Any]) -> dict[str, int]:
    lanes = _lane_changed_paths(manifest)
    expected_pairs = (
        ("PR2", "PR3"), ("PR2", "PR4"), ("PR2", "PR5"), ("PR2", "PR7"),
        ("PR3", "PR4"), ("PR3", "PR5"), ("PR3", "PR7"),
        ("PR4", "PR5"), ("PR4", "PR7"), ("PR5", "PR7"),
    )
    declared = manifest["overlap_matrix"]
    observed: dict[str, int] = {}
    for left, right in expected_pairs:
        key = f"{left}_{right}"
        count = len(lanes[left] & lanes[right])
        observed[key] = count
        entry = declared.get(key)
        if not isinstance(entry, dict) or entry.get("count") != count:
            raise ProvenanceError("cross-PR overlap matrix mismatch")
        if entry.get("classification") not in {
            "NO_DIRECT_OVERLAP", "SEMANTIC_PRESERVE_DEV1", "SEMANTIC_REVIEW_DEV2_SELECTED"
        }:
            raise ProvenanceError("cross-PR overlap classification invalid")
        if count == 0 and entry.get("classification") != "NO_DIRECT_OVERLAP":
            raise ProvenanceError("zero-overlap pair misclassified")
    if set(declared) != {f"{a}_{b}" for a, b in expected_pairs}:
        raise ProvenanceError("cross-PR overlap matrix has missing/extra pair")
    return observed


def _reject_unexpected_paths(changed: set[str], allowed: set[str]) -> None:
    if changed - allowed:
        raise ProvenanceError("candidate diff contains path outside provenance allowlist")


def _validate_override_subset(data: dict[str, Any], path_key: str) -> set[str]:
    paths = set(data[path_key])
    overrides = set(data.get("dev_a_overrides", []))
    if not overrides <= paths:
        raise ProvenanceError("declared DEV_A override is outside predecessor path set")
    return overrides


def verify_repository() -> dict[str, Any]:
    manifest = _load()
    release_override = _load_release_override()
    head = _git("rev-parse", "HEAD")
    base = str(manifest["base"]["sha"])
    predecessors = manifest["predecessors"]
    dev_b = release_override["dev_b"]
    dev_b_imported = set(dev_b["imported_paths"])
    dev_b_adapted = set(dev_b["adapted_paths"])
    dev_b_supersedes = set(dev_b["supersedes_predecessor_paths"])
    dev_b_sync = release_override["dev_b_round2_sync"]
    dev_b_sync_exact = set(dev_b_sync["exact_blob_paths"])
    dev_b_sync_retained = set(dev_b_sync["retained_dev_a_adaptations"])

    overlap_counts = _verify_overlap_matrix(manifest)

    expected_parent_sets = {
        predecessors["DEV3"]["merge_commit"]: (base, predecessors["DEV3"]["sha"]),
        predecessors["DEV4"]["merge_commit"]: (predecessors["DEV3"]["merge_commit"], predecessors["DEV4"]["sha"]),
        predecessors["DEV2"]["merge_commit"]: (predecessors["DEV4"]["merge_commit"], predecessors["DEV2"]["sha"]),
        predecessors["DEV5"]["merge_commit"]: (predecessors["DEV2"]["merge_commit"], predecessors["DEV5"]["sha"]),
        dev_b["merge_commit"]: (dev_b["first_parent"], dev_b["sha"]),
        dev_b_sync["merge_commit"]: (dev_b_sync["first_parent"], dev_b_sync["sha"]),
    }
    for commit, expected in expected_parent_sets.items():
        actual = _parents(str(commit))
        if actual != tuple(map(str, expected)):
            raise ProvenanceError("semantic merge parent set/order mismatch")
        _assert_ancestor(str(commit), head)

    for commit in manifest["assembly_commits"].values():
        _assert_ancestor(str(commit), head)
    _assert_ancestor(str(release_override["source_checkpoint"]), head)
    for commit in release_override["trace_commits"]:
        _assert_ancestor(str(commit), head)

    predecessor_supersession_owner = set(predecessors["DEV2"]["paths"])
    if not dev_b_supersedes <= predecessor_supersession_owner:
        raise ProvenanceError("DEV_B supersession is outside DEV2 predecessor path set")

    for lane in ("DEV3", "DEV4", "DEV2"):
        data = predecessors[lane]
        source = str(data["sha"])
        overrides = _validate_override_subset(data, "paths")
        for path in data["paths"]:
            if path in overrides or (lane == "DEV2" and path in dev_b_supersedes):
                continue
            if _blob("HEAD", path) != _blob(source, path):
                raise ProvenanceError(f"unexpected post-import mutation: {lane}:{path}")

    dev5 = predecessors["DEV5"]
    dev5_overrides = _validate_override_subset(dev5, "ported_paths")
    for path in dev5["ported_paths"]:
        if path in dev5_overrides:
            continue
        if _blob("HEAD", path) != _blob(str(dev5["sha"]), path):
            raise ProvenanceError(f"DEV5 portable oracle drift: {path}")
    for path in dev5["rejected_overlaps_preserve_base"]:
        if _blob("HEAD", path) != _blob(base, path):
            raise ProvenanceError(f"rejected DEV5 overlap overwrote DEV1 authority: {path}")

    for path in dev_b_imported:
        if path in dev_b_adapted or path in dev_b_sync_exact:
            continue
        if _blob("HEAD", path) != _blob(str(dev_b["sha"]), path):
            raise ProvenanceError(f"unexpected DEV_B imported-path drift: {path}")

    for path in dev_b_sync_exact:
        if _blob("HEAD", path) != _blob(str(dev_b_sync["sha"]), path):
            raise ProvenanceError(f"unexpected DEV_B Round-2 exact-path drift: {path}")

    if dev_b_sync_retained != {
        "ops/server_manifest.py",
        "tests/test_devb_round2_release.py",
        "tests/test_server_manifest.py",
    }:
        raise ProvenanceError("DEV_B Round-2 retained adaptation set mismatch")
    for forbidden in ("tools/strict_history_secret_scan.py", "tests/test_strict_history_secret_scan.py"):
        if _path_exists("HEAD", forbidden):
            raise ProvenanceError("strict-history suppression layer unexpectedly imported")

    allowed_paths: set[str] = set(manifest["dev_a_paths"])
    for lane in ("DEV3", "DEV4", "DEV2"):
        allowed_paths.update(predecessors[lane]["paths"])
    allowed_paths.update(dev5["ported_paths"])
    release_paths = set(release_override["paths"])
    allowed_paths.update(release_paths)

    changed = {
        line.strip()
        for line in _git("diff", "--name-only", f"{base}..HEAD").splitlines()
        if line.strip()
    }
    _reject_unexpected_paths(changed, allowed_paths)
    missing_in_manifest = sorted(path for path in manifest["dev_a_paths"] if path not in changed)
    if missing_in_manifest:
        raise ProvenanceError("declared DEV_A path is absent from candidate diff")
    missing_release_paths = sorted(path for path in release_paths if path not in changed)
    if missing_release_paths:
        raise ProvenanceError("declared release-to-live path is absent from candidate diff")

    safety = manifest["safety_boundary"]
    if safety != {
        "merge": False,
        "deploy": False,
        "passenger_restart": False,
        "live_telegram_write": False,
        "telegram_authorization_state": "USER_TELEGRAM_AUTH_NOT_YET_REQUIRED",
    }:
        raise ProvenanceError("candidate safety boundary manifest mismatch")

    return {
        "schema_version": 2,
        "head": head,
        "base": base,
        "changed_path_count": len(changed),
        "verified_predecessor_count": 6,
        "semantic_merge_count": 6,
        "dev3_override_count": len(_validate_override_subset(predecessors["DEV3"], "paths")),
        "adapted_dev5_path_count": len(dev5_overrides),
        "dev_b_imported_path_count": len(dev_b_imported),
        "dev_b_adapted_path_count": len(dev_b_adapted),
        "dev_b_superseded_path_count": len(dev_b_supersedes),
        "dev_b_round2_sync_path_count": len(dev_b_sync_exact),
        "dev_b_round2_adapted_path_count": len(dev_b_sync_retained),
        "pr2_pr3_overlap_count": overlap_counts["PR2_PR3"],
        "pr2_pr5_overlap_count": overlap_counts["PR2_PR5"],
        "rejected_dev5_overlap_count": len(dev5["rejected_overlaps_preserve_base"]),
        "release_to_live_path_count": len(release_paths),
        "private_values_recorded": False,
    }


def main() -> int:
    result = verify_repository()
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    print("DEV_A_PROVENANCE_PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
