#!/usr/bin/env python3
"""Deterministic, non-secret provenance verifier for the DEV01 canonical candidate.

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

TERMINAL_DEV_B_SHA = "8f2044d7bca9487815f754d614ab781555671a4b"
TERMINAL_DEV_B_MERGE = "c609adfc9a1116aae635a0b14d632a5e59b6c2af"
TERMINAL_DEV_B_FIRST_PARENT = "f135c3ee22e1de229e6820410ffbad85add08e42"
TERMINAL_DEV_B_EXACT = {
    "docs/DEV_B_HOSTIQ_PRODUCTION_READINESS.md",
    "ops/candidate_runtime_preflight.py",
    "ops/devb_run_matrix.py",
    "ops/hostiq_lifecycle.py",
    "ops/passenger_evidence_hook.py",
    "ops/passenger_probe.py",
    "ops/private_control.py",
    "ops/private_evidence.py",
    "ops/production_readiness.py",
    "ops/runtime_evidence.py",
    "tests/test_arm_passenger_evidence.py",
    "tests/test_candidate_runtime_preflight.py",
    "tests/test_dev2_baseline_runtime.py",
    "tests/test_dev2_lifecycle.py",
    "tests/test_devb_cli_entrypoints.py",
    "tests/test_devb_production_readiness.py",
    "tests/test_devb_run_matrix.py",
    "tests/test_passenger_evidence_hook.py",
    "tests/test_passenger_probe.py",
    "tests/test_private_control.py",
    "tests/test_run_passenger_evidence_probe.py",
    "tools/arm_passenger_evidence.py",
    "tools/run_passenger_evidence_probe.py",
    "tools/validate_candidate_runtime_preflight.py",
}
TERMINAL_DEV_B_RETAINED = {
    "docs/DEV_B_DEV_A_RUNTIME_SYNC.md",
    "docs/HOSTIQ_ONE_TIME_SUPPORT_PACKAGE.md",
    "ops/server_manifest.py",
    "tests/test_devb_compile.py",
    "tests/test_devb_round2_release.py",
    "tests/test_server_manifest.py",
}
SINGLE_FINISHER_PARENT_SHA = "e95c5bda689ee7b3d54a2f335d24a13b5ce5eed8"
SINGLE_FINISHER_CHECKPOINT_SHA = "6af7b0a427e53a9f512b5239464bcfe95becacd3"
SINGLE_FINISHER_SOURCES = {
    "PASSENGER_SERVING_EVIDENCE": {
        "pr": 164,
        "source_sha": "1bd34a7e57792ac6e48418aa9bb20369509ee679",
        "disposition": "EXACT_BLOB_ADAPT",
        "exact_blob_paths": [
            "bridge/runtime_wsgi.py",
            "tests/test_finalwave26_wsgi_guard_wiring.py",
        ],
        "excluded_specialist_paths": [],
    },
    "ROLLBACK_SOURCE_BINDING": {
        "pr": 157,
        "source_sha": "ca89aaa48214409a42d15ac5a83d84778f732d5f",
        "disposition": "ADAPTED_HIGH_CLOSED",
        "adapted_paths": [
            "ops/finalwave37_rollback_state_compat.py",
            "tests/test_finalwave37_rollback_state_compat.py",
        ],
        "canonical_extension_paths": [
            ".github/workflows/finalwave37-rollback-state.yml",
        ],
        "excluded_specialist_paths": [],
    },
    "SHARED_COMMIT_GUARD": {
        "pr": 162,
        "source_sha": "e7d194a08a371df49103a90b487e53c75a91b000",
        "disposition": "ADAPTED_HIGH_CLOSED",
        "adapted_paths": [
            "ops/runtime_write_reliability.py",
            "tests/test_final5_task2_write_guard_parent_toctou.py",
        ],
        "excluded_specialist_paths": [
            ".github/workflows/final5-task2-write-guard-toctou.yml",
            "integration/provenance_v1.json",
        ],
    },
}
SINGLE_FINISHER_BLOBS = {
    ".github/workflows/finalwave37-rollback-state.yml": "37236711ba4914f1d1b3fa64a253c9c7dcf9358b",
    "bridge/runtime_wsgi.py": "7e30cb08a2edbebaa483b178c83b396a6963b2f7",
    "ops/finalwave37_rollback_state_compat.py": "34c5cfe4efda01b27d97439a2afe7e03b084d1fe",
    "ops/runtime_write_reliability.py": "38fc7a83539026052f490f9889d17eed22987e73",
    "tests/test_final5_task2_write_guard_parent_toctou.py": "6a20cc708d97617ae0f1e943bb35cb4dfd3304c4",
    "tests/test_finalwave26_wsgi_guard_wiring.py": "9e73fbda857db992b24e2abc0b24010a497fe45b",
    "tests/test_finalwave37_rollback_state_compat.py": "3a12a60d221ccbbf63c8f97c4fe703b9bd32e43c",
}


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


def _load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ProvenanceError(f"{label} is unreadable") from exc
    if not isinstance(payload, dict) or payload.get("schema_version") != 2:
        raise ProvenanceError(f"{label} schema mismatch")
    return payload


def _load() -> dict[str, Any]:
    return _load_json(MANIFEST, "integration provenance manifest")


def _validate_dev_b_history(payload: dict[str, Any], release_paths: set[str]) -> tuple[dict[str, Any], dict[str, Any]]:
    dev_b = payload.get("dev_b")
    if not isinstance(dev_b, dict) or dev_b.get("pr") != 11:
        raise ProvenanceError("DEV_B release provenance missing")
    for field in ("sha", "merge_commit", "first_parent"):
        if not _valid_sha(dev_b.get(field)):
            raise ProvenanceError("DEV_B release provenance SHA invalid")
    imported = set(_safe_sorted_paths(dev_b.get("imported_paths"), "DEV_B imported"))
    adapted = set(_safe_sorted_paths(dev_b.get("adapted_paths"), "DEV_B adapted"))
    supersedes = set(_safe_sorted_paths(dev_b.get("supersedes_predecessor_paths"), "DEV_B supersession"))
    if not adapted <= imported or not supersedes <= imported or not imported <= release_paths:
        raise ProvenanceError("DEV_B release path accounting invalid")

    sync = payload.get("dev_b_round2_sync")
    if not isinstance(sync, dict) or sync.get("pr") != 11:
        raise ProvenanceError("DEV_B Round-2 sync provenance missing")
    if sync.get("sha") != "6f943ee15f053acc5b4f15167c16d431023a35d1":
        raise ProvenanceError("DEV_B Round-2 source checkpoint mismatch")
    if sync.get("merge_commit") != "919d7d409564d7c21e46009e1d76cfa5d1fd602d":
        raise ProvenanceError("DEV_B Round-2 semantic merge identity mismatch")
    if sync.get("first_parent") != "f8b2a3ff0d689966e2f88f3c9efc63cbe5cef8a0":
        raise ProvenanceError("DEV_B Round-2 first-parent checkpoint mismatch")
    exact = set(_safe_sorted_paths(sync.get("exact_blob_paths"), "DEV_B Round-2 exact"))
    retained = set(_safe_sorted_paths(sync.get("retained_dev_a_adaptations"), "DEV_B Round-2 retained"))
    if exact & retained or not (exact | retained) <= release_paths:
        raise ProvenanceError("DEV_B Round-2 path accounting invalid")
    if sync.get("strict_history_suppression_imported") is not False:
        raise ProvenanceError("DEV_B strict-history suppression layer must not be imported")
    return dev_b, sync


def _validate_terminal_dev_b(payload: dict[str, Any], release_paths: set[str]) -> dict[str, Any]:
    terminal = payload.get("dev_b_terminal_sync")
    if not isinstance(terminal, dict) or terminal.get("pr") != 11:
        raise ProvenanceError("DEV_B terminal sync provenance missing")
    if terminal.get("sha") != TERMINAL_DEV_B_SHA:
        raise ProvenanceError("DEV_B terminal source checkpoint mismatch")
    if terminal.get("merge_commit") != TERMINAL_DEV_B_MERGE:
        raise ProvenanceError("DEV_B terminal semantic merge identity mismatch")
    if terminal.get("first_parent") != TERMINAL_DEV_B_FIRST_PARENT:
        raise ProvenanceError("DEV_B terminal first-parent checkpoint mismatch")
    exact = set(_safe_sorted_paths(terminal.get("exact_blob_paths"), "DEV_B terminal exact"))
    retained = set(_safe_sorted_paths(terminal.get("retained_dev_a_adaptations"), "DEV_B terminal retained"))
    if exact != TERMINAL_DEV_B_EXACT:
        raise ProvenanceError("DEV_B terminal exact path set mismatch")
    if retained != TERMINAL_DEV_B_RETAINED:
        raise ProvenanceError("DEV_B terminal retained path set mismatch")
    if exact & retained or not (exact | retained) <= release_paths:
        raise ProvenanceError("DEV_B terminal path accounting invalid")
    if terminal.get("strict_history_suppression_imported") is not False:
        raise ProvenanceError("DEV_B terminal strict-history suppression layer must not be imported")
    if terminal.get("production_mutated") is not False:
        raise ProvenanceError("DEV_B terminal sync may not claim production mutation")
    return terminal


def _validate_dev_c(payload: dict[str, Any], release_paths: set[str]) -> dict[str, Any]:
    dev_c = payload.get("dev_c_qa_sync")
    if not isinstance(dev_c, dict) or dev_c.get("pr") != 16:
        raise ProvenanceError("DEV_C QA sync provenance missing")
    if dev_c.get("sha") != "5758bfdcd9ecee4011fc3caaa3c68eb46ee2af19":
        raise ProvenanceError("DEV_C QA source checkpoint mismatch")
    if dev_c.get("merge_commit") != "df318aa089f754b7a14f624b7c27cca59758cbe8":
        raise ProvenanceError("DEV_C QA semantic merge identity mismatch")
    if dev_c.get("first_parent") != "94c6ab7e3afabd769a63b44b222bfc0bbf067f67":
        raise ProvenanceError("DEV_C QA first-parent checkpoint mismatch")
    exact = set(_safe_sorted_paths(dev_c.get("exact_blob_paths"), "DEV_C QA exact"))
    adapted = set(_safe_sorted_paths(dev_c.get("adapted_paths"), "DEV_C QA adapted"))
    if exact != {"docs/DEV_C_RELEASE_TO_LIVE_QA.md", "ops/devc_release_qa.py"}:
        raise ProvenanceError("DEV_C QA exact path set mismatch")
    if adapted != {"tests/test_devc_release_e2e.py", "tests/test_devc_release_qa.py"}:
        raise ProvenanceError("DEV_C QA adapted path set mismatch")
    if exact & adapted or not (exact | adapted) <= release_paths:
        raise ProvenanceError("DEV_C QA path accounting invalid")
    if dev_c.get("production_logic_modified") is not False:
        raise ProvenanceError("DEV_C QA overlay may not claim production mutation")
    return dev_c


def _load_release_override() -> dict[str, Any]:
    payload = _load_json(RELEASE_OVERRIDE, "release-to-live provenance overlay")
    if payload.get("round") != "RELEASE_TO_LIVE_ROUND_2":
        raise ProvenanceError("release-to-live provenance round mismatch")
    if payload.get("purpose") != "canonical_release_packaging_runtime_evidence_and_final_qa_integration":
        raise ProvenanceError("release-to-live purpose mismatch")
    if not _valid_sha(payload.get("source_checkpoint")):
        raise ProvenanceError("release-to-live source checkpoint invalid")

    paths = set(_safe_sorted_paths(payload.get("paths"), "release-to-live"))
    commits = payload.get("trace_commits")
    if not isinstance(commits, list) or not commits or len(commits) != len(set(commits)):
        raise ProvenanceError("release-to-live trace commits invalid")
    if any(not _valid_sha(commit) for commit in commits):
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

    _validate_dev_b_history(payload, paths)
    _validate_terminal_dev_b(payload, paths)
    _validate_dev_c(payload, paths)

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
        raise ProvenanceError("declared DEV01 override is outside predecessor path set")
    return overrides


def _validate_single_finisher_convergence(manifest: dict[str, Any], head: str) -> dict[str, Any]:
    integrations = manifest.get("swarm_integrations")
    if not isinstance(integrations, dict):
        raise ProvenanceError("swarm integration provenance missing")
    convergence = integrations.get("SWARM10_SINGLE_FINISHER_HIGH_CONVERGENCE")
    if not isinstance(convergence, dict):
        raise ProvenanceError("single-finisher convergence provenance missing")
    if convergence.get("canonical_parent_sha") != SINGLE_FINISHER_PARENT_SHA:
        raise ProvenanceError("single-finisher canonical parent mismatch")
    if convergence.get("canonical_checkpoint_sha") != SINGLE_FINISHER_CHECKPOINT_SHA:
        raise ProvenanceError("single-finisher canonical checkpoint mismatch")
    if convergence.get("sources") != SINGLE_FINISHER_SOURCES:
        raise ProvenanceError("single-finisher source accounting mismatch")
    if convergence.get("candidate_git_blobs") != SINGLE_FINISHER_BLOBS:
        raise ProvenanceError("single-finisher candidate blob ledger mismatch")
    if convergence.get("private_values_recorded") is not False:
        raise ProvenanceError("single-finisher provenance records private values")
    if convergence.get("production_mutated") is not False or convergence.get("deployment_authorized") is not False:
        raise ProvenanceError("single-finisher safety boundary invalid")

    _assert_ancestor(SINGLE_FINISHER_PARENT_SHA, SINGLE_FINISHER_CHECKPOINT_SHA)
    _assert_ancestor(SINGLE_FINISHER_CHECKPOINT_SHA, head)
    for path, expected_blob in SINGLE_FINISHER_BLOBS.items():
        if not _valid_sha(expected_blob) or _blob("HEAD", path) != expected_blob:
            raise ProvenanceError(f"single-finisher candidate blob mismatch: {path}")
    return convergence


def verify_repository() -> dict[str, Any]:
    manifest = _load()
    release = _load_release_override()
    head = _git("rev-parse", "HEAD")
    base = str(manifest["base"]["sha"])
    predecessors = manifest["predecessors"]
    convergence = _validate_single_finisher_convergence(manifest, head)

    dev_b = release["dev_b"]
    dev_b_imported = set(dev_b["imported_paths"])
    dev_b_adapted = set(dev_b["adapted_paths"])
    dev_b_supersedes = set(dev_b["supersedes_predecessor_paths"])

    round2 = release["dev_b_round2_sync"]
    round2_exact = set(round2["exact_blob_paths"])
    round2_retained = set(round2["retained_dev_a_adaptations"])

    terminal = release["dev_b_terminal_sync"]
    terminal_exact = set(terminal["exact_blob_paths"])
    terminal_retained = set(terminal["retained_dev_a_adaptations"])

    dev_c = release["dev_c_qa_sync"]
    dev_c_exact = set(dev_c["exact_blob_paths"])
    dev_c_adapted = set(dev_c["adapted_paths"])

    overlap_counts = _verify_overlap_matrix(manifest)

    expected_parent_sets = {
        predecessors["DEV3"]["merge_commit"]: (base, predecessors["DEV3"]["sha"]),
        predecessors["DEV4"]["merge_commit"]: (predecessors["DEV3"]["merge_commit"], predecessors["DEV4"]["sha"]),
        predecessors["DEV2"]["merge_commit"]: (predecessors["DEV4"]["merge_commit"], predecessors["DEV2"]["sha"]),
        predecessors["DEV5"]["merge_commit"]: (predecessors["DEV2"]["merge_commit"], predecessors["DEV5"]["sha"]),
        dev_b["merge_commit"]: (dev_b["first_parent"], dev_b["sha"]),
        round2["merge_commit"]: (round2["first_parent"], round2["sha"]),
        dev_c["merge_commit"]: (dev_c["first_parent"], dev_c["sha"]),
        terminal["merge_commit"]: (terminal["first_parent"], terminal["sha"]),
    }
    for commit, expected in expected_parent_sets.items():
        if _parents(str(commit)) != tuple(map(str, expected)):
            raise ProvenanceError("semantic merge parent set/order mismatch")
        _assert_ancestor(str(commit), head)

    for commit in manifest["assembly_commits"].values():
        _assert_ancestor(str(commit), head)
    _assert_ancestor(str(release["source_checkpoint"]), head)
    for commit in release["trace_commits"]:
        _assert_ancestor(str(commit), head)

    predecessor_supersession_owner = set(predecessors["DEV2"]["paths"])
    if not dev_b_supersedes <= predecessor_supersession_owner:
        raise ProvenanceError("DEV_B supersession is outside DEV2 predecessor path set")

    for lane in ("DEV3", "DEV4", "DEV2"):
        data = predecessors[lane]
        source = str(data["sha"])
        overrides = _validate_override_subset(data, "paths")
        for path in data["paths"]:
            if path in overrides:
                continue
            if lane == "DEV2" and (path in dev_b_supersedes or path in terminal_exact):
                continue
            if _blob("HEAD", path) != _blob(source, path):
                raise ProvenanceError(f"unexpected post-import mutation: {lane}:{path}")

    dev5 = predecessors["DEV5"]
    dev5_overrides = _validate_override_subset(dev5, "ported_paths")
    for path in dev5["ported_paths"]:
        if path not in dev5_overrides and _blob("HEAD", path) != _blob(str(dev5["sha"]), path):
            raise ProvenanceError(f"DEV5 portable oracle drift: {path}")
    for path in dev5["rejected_overlaps_preserve_base"]:
        if _blob("HEAD", path) != _blob(base, path):
            raise ProvenanceError(f"rejected DEV5 overlap overwrote DEV1 authority: {path}")

    later_owned = round2_exact | terminal_exact | terminal_retained
    for path in dev_b_imported:
        if path in dev_b_adapted or path in later_owned:
            continue
        if _blob("HEAD", path) != _blob(str(dev_b["sha"]), path):
            raise ProvenanceError(f"unexpected DEV_B imported-path drift: {path}")

    for path in round2_exact - terminal_exact:
        if _blob("HEAD", path) != _blob(str(round2["sha"]), path):
            raise ProvenanceError(f"unexpected DEV_B Round-2 exact-path drift: {path}")

    if round2_retained != {
        "ops/server_manifest.py",
        "tests/test_devb_round2_release.py",
        "tests/test_server_manifest.py",
    }:
        raise ProvenanceError("DEV_B Round-2 retained adaptation set mismatch")

    for path in terminal_exact:
        if _blob("HEAD", path) != _blob(str(terminal["sha"]), path):
            raise ProvenanceError(f"unexpected DEV_B terminal exact-path drift: {path}")
    for path in terminal_retained:
        if _blob("HEAD", path) == _blob(str(terminal["sha"]), path):
            raise ProvenanceError(f"DEV_B terminal retained adaptation unexpectedly reverted: {path}")

    for path in dev_c_exact:
        if _blob("HEAD", path) != _blob(str(dev_c["sha"]), path):
            raise ProvenanceError(f"unexpected DEV_C QA exact-path drift: {path}")
    for path in dev_c_adapted:
        if _blob("HEAD", path) == _blob(str(dev_c["sha"]), path):
            raise ProvenanceError(f"DEV_C adapted QA path unexpectedly reverted to stale source blob: {path}")

    for forbidden in ("tools/strict_history_secret_scan.py", "tests/test_strict_history_secret_scan.py"):
        if _path_exists("HEAD", forbidden):
            raise ProvenanceError("strict-history suppression layer unexpectedly imported")

    allowed_paths: set[str] = set(manifest["dev_a_paths"])
    for lane in ("DEV3", "DEV4", "DEV2"):
        allowed_paths.update(predecessors[lane]["paths"])
    allowed_paths.update(dev5["ported_paths"])
    release_paths = set(release["paths"])
    allowed_paths.update(release_paths)

    changed = {
        line.strip()
        for line in _git("diff", "--name-only", f"{base}..HEAD").splitlines()
        if line.strip()
    }
    _reject_unexpected_paths(changed, allowed_paths)

    if any(path not in changed for path in manifest["dev_a_paths"]):
        raise ProvenanceError("declared DEV01 path is absent from candidate diff")
    if any(path not in changed for path in release_paths):
        raise ProvenanceError("declared release-to-live path is absent from candidate diff")

    if manifest["safety_boundary"] != {
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
        "verified_predecessor_count": 8,
        "semantic_merge_count": 8,
        "dev3_override_count": len(_validate_override_subset(predecessors["DEV3"], "paths")),
        "dev4_override_count": len(_validate_override_subset(predecessors["DEV4"], "paths")),
        "adapted_dev5_path_count": len(dev5_overrides),
        "dev_b_imported_path_count": len(dev_b_imported),
        "dev_b_adapted_path_count": len(dev_b_adapted),
        "dev_b_superseded_path_count": len(dev_b_supersedes),
        "dev_b_round2_sync_path_count": len(round2_exact),
        "dev_b_round2_adapted_path_count": len(round2_retained),
        "dev_b_terminal_exact_path_count": len(terminal_exact),
        "dev_b_terminal_retained_path_count": len(terminal_retained),
        "dev_c_exact_path_count": len(dev_c_exact),
        "dev_c_adapted_path_count": len(dev_c_adapted),
        "pr2_pr3_overlap_count": overlap_counts["PR2_PR3"],
        "pr2_pr5_overlap_count": overlap_counts["PR2_PR5"],
        "rejected_dev5_overlap_count": len(dev5["rejected_overlaps_preserve_base"]),
        "release_to_live_path_count": len(release_paths),
        "single_finisher_source_count": len(convergence["sources"]),
        "single_finisher_path_count": len(convergence["candidate_git_blobs"]),
        "private_values_recorded": False,
    }


def main() -> int:
    result = verify_repository()
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    print("DEV_A_PROVENANCE_PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
