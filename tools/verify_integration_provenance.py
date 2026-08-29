#!/usr/bin/env python3
"""Canonical provenance verifier with a narrow FINAL10 composition overlay.

The historical DEV01 verifier is preserved byte-for-byte in the sibling
``verify_integration_provenance_legacy.py``.  This wrapper validates the new
private-use launch composition from exact Git objects, then supplies only the
explicitly superseded historical assumptions to the legacy verifier.  It reads
no secrets and performs no network or production operations.
"""
from __future__ import annotations

import copy
import json
import sys
from pathlib import Path
from typing import Any

if __package__:
    from . import verify_integration_provenance_legacy as legacy
else:
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import verify_integration_provenance_legacy as legacy  # type: ignore

ROOT = legacy.ROOT
MANIFEST = legacy.MANIFEST
RELEASE_OVERRIDE = legacy.RELEASE_OVERRIDE
CANONICAL_MANIFEST = ROOT / "integration" / "canonical_launch_v1.json"

TERMINAL_DEV_B_SHA = legacy.TERMINAL_DEV_B_SHA
TERMINAL_DEV_B_MERGE = legacy.TERMINAL_DEV_B_MERGE
TERMINAL_DEV_B_FIRST_PARENT = legacy.TERMINAL_DEV_B_FIRST_PARENT
TERMINAL_DEV_B_EXACT = legacy.TERMINAL_DEV_B_EXACT
TERMINAL_DEV_B_RETAINED = legacy.TERMINAL_DEV_B_RETAINED
SINGLE_FINISHER_PARENT_SHA = legacy.SINGLE_FINISHER_PARENT_SHA
SINGLE_FINISHER_CHECKPOINT_SHA = legacy.SINGLE_FINISHER_CHECKPOINT_SHA
SINGLE_FINISHER_SOURCES = legacy.SINGLE_FINISHER_SOURCES
SINGLE_FINISHER_BLOBS = legacy.SINGLE_FINISHER_BLOBS
ProvenanceError = legacy.ProvenanceError

_blob = legacy._blob
_path_exists = legacy._path_exists
_parents = legacy._parents
_assert_ancestor = legacy._assert_ancestor
_reject_unexpected_paths = legacy._reject_unexpected_paths
_verify_overlap_matrix = legacy._verify_overlap_matrix


def _safe_paths(value: object, label: str) -> list[str]:
    if not isinstance(value, list) or not value or value != sorted(set(value)):
        raise ProvenanceError(f"{label} path allowlist invalid")
    for path in value:
        if not isinstance(path, str) or not path or path.startswith("/") or ".." in Path(path).parts:
            raise ProvenanceError(f"{label} path allowlist unsafe")
    return value


def _load_canonical() -> dict[str, Any]:
    try:
        payload = json.loads(CANONICAL_MANIFEST.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ProvenanceError("canonical launch provenance is unreadable") from exc
    if not isinstance(payload, dict) or payload.get("schema_version") != 1:
        raise ProvenanceError("canonical launch provenance schema mismatch")
    if payload.get("purpose") != "final10_private_use_canonical_launch_integration":
        raise ProvenanceError("canonical launch purpose mismatch")
    return payload


def _validate_canonical_launch(payload: dict[str, Any]) -> set[str]:
    assembly = payload.get("assembly_sha")
    parent = payload.get("parent_sha")
    if assembly != "7e25e43cf7e8423094271fce6807e247e14b13a0":
        raise ProvenanceError("canonical launch assembly mismatch")
    if parent != "c3fa5fec7059e80f1ec24f3e06f0f750e67e35de":
        raise ProvenanceError("canonical launch parent mismatch")
    if _parents(str(assembly)) != (str(parent),):
        raise ProvenanceError("canonical launch assembly parent mismatch")
    _assert_ancestor(str(assembly), legacy._git("rev-parse", "HEAD"))

    expected_sources = {
        "W09_ACCEPTANCE_ACTION": (166, "9d8b98057b1252736d1cb2fbdf5a93fc71ff4aa3"),
        "DEEP_DIALOG_PAGINATION": (163, "2ecfd599f540444ca331a32e46b2b9a7f7afcd3c"),
        "TYPED_DIALOG_IDENTITY": (168, "b63693b7a49f091768c86bda42f6c8f3a1f5aa9d"),
    }
    sources = payload.get("sources")
    if not isinstance(sources, dict) or set(sources) != set(expected_sources):
        raise ProvenanceError("canonical launch source set mismatch")

    candidate_paths: set[str] = set()
    for name, (pr, sha) in expected_sources.items():
        entry = sources.get(name)
        if not isinstance(entry, dict) or entry.get("pr") != pr or entry.get("sha") != sha:
            raise ProvenanceError(f"canonical launch source identity mismatch: {name}")
        paths = _safe_paths(entry.get("exact_paths"), f"canonical {name}")
        for path in paths:
            if _blob("HEAD", path) != _blob(sha, path):
                raise ProvenanceError(f"canonical source blob mismatch: {name}:{path}")
        candidate_paths.update(paths)

    runtime = payload.get("runtime_composition")
    if not isinstance(runtime, dict) or runtime.get("path") != "bridge/runtime_wsgi.py":
        raise ProvenanceError("canonical runtime composition missing")
    if runtime.get("preserves_parent_passenger_observation") is not True:
        raise ProvenanceError("canonical Passenger observation preservation missing")
    installers = _safe_paths(runtime.get("installer_paths"), "canonical runtime installer")
    if installers != ["bridge/dialog_pagination.py", "bridge/typed_dialog_identity.py"]:
        raise ProvenanceError("canonical runtime installer set mismatch")
    if _blob("HEAD", "bridge/runtime_wsgi.py") != _blob(str(assembly), "bridge/runtime_wsgi.py"):
        raise ProvenanceError("canonical runtime composition drift")
    candidate_paths.add("bridge/runtime_wsgi.py")

    overrides = set(_safe_paths(payload.get("w09_base_authority_overrides"), "canonical W09 override"))
    expected_overrides = {
        "ops/acceptance_contracts.py",
        "ops/acceptance_harness.py",
        "ops/evidence_privacy.py",
        "tests/test_acceptance_harness.py",
    }
    if overrides != expected_overrides:
        raise ProvenanceError("canonical W09 override set mismatch")
    w09_paths = set(sources["W09_ACCEPTANCE_ACTION"]["exact_paths"])
    if not overrides <= w09_paths:
        raise ProvenanceError("canonical W09 override outside accepted source paths")

    provenance_paths = set(_safe_paths(payload.get("provenance_paths"), "canonical provenance"))
    expected_provenance = {
        "integration/canonical_launch_v1.json",
        "tests/test_dev_a_provenance.py",
        "tools/verify_integration_provenance.py",
        "tools/verify_integration_provenance_legacy.py",
    }
    if provenance_paths != expected_provenance:
        raise ProvenanceError("canonical provenance implementation path mismatch")
    candidate_paths.update(provenance_paths)

    if payload.get("specialist_workflows_imported") is not False:
        raise ProvenanceError("canonical launch may not claim specialist workflow import")
    if payload.get("production_mutated") is not False or payload.get("deployment_authorized") is not False:
        raise ProvenanceError("canonical launch safety boundary invalid")
    if payload.get("private_values_recorded") is not False:
        raise ProvenanceError("canonical launch provenance records private values")
    return candidate_paths


def _legacy_manifest_for_canonical(canonical: dict[str, Any], candidate_paths: set[str]) -> dict[str, Any]:
    manifest = copy.deepcopy(legacy._load())
    base = str(manifest["base"]["sha"])

    # The new W09 acceptance implementation deliberately supersedes four old
    # DEV5 rejection decisions.  The remaining historical rejections stay exact.
    overrides = set(canonical["w09_base_authority_overrides"])
    rejected = manifest["predecessors"]["DEV5"]["rejected_overlaps_preserve_base"]
    manifest["predecessors"]["DEV5"]["rejected_overlaps_preserve_base"] = [
        path for path in rejected if path not in overrides
    ]

    # runtime_wsgi is now an explicitly reviewed semantic composition.  Preserve
    # every other single-finisher blob assertion and replace only that one blob.
    runtime_blob = _blob(str(canonical["assembly_sha"]), "bridge/runtime_wsgi.py")
    manifest["swarm_integrations"]["SWARM10_SINGLE_FINISHER_HIGH_CONVERGENCE"]["candidate_git_blobs"][
        "bridge/runtime_wsgi.py"
    ] = runtime_blob

    changed = {
        line.strip()
        for line in legacy._git("diff", "--name-only", f"{base}..HEAD").splitlines()
        if line.strip()
    }
    declared = list(manifest["dev_a_paths"])
    for path in sorted(candidate_paths):
        if path in changed and path not in declared:
            declared.append(path)
    manifest["dev_a_paths"] = declared
    return manifest


def verify_repository() -> dict[str, Any]:
    canonical = _load_canonical()
    candidate_paths = _validate_canonical_launch(canonical)
    patched_manifest = _legacy_manifest_for_canonical(canonical, candidate_paths)
    patched_blobs = dict(legacy.SINGLE_FINISHER_BLOBS)
    patched_blobs["bridge/runtime_wsgi.py"] = _blob(str(canonical["assembly_sha"]), "bridge/runtime_wsgi.py")

    original_load = legacy._load
    original_blobs = legacy.SINGLE_FINISHER_BLOBS
    try:
        legacy._load = lambda: copy.deepcopy(patched_manifest)
        legacy.SINGLE_FINISHER_BLOBS = patched_blobs
        result = legacy.verify_repository()
    finally:
        legacy._load = original_load
        legacy.SINGLE_FINISHER_BLOBS = original_blobs

    result["canonical_launch_source_count"] = len(canonical["sources"])
    result["canonical_launch_path_count"] = len(candidate_paths)
    result["canonical_w09_override_count"] = len(canonical["w09_base_authority_overrides"])
    result["canonical_assembly_sha"] = canonical["assembly_sha"]
    return result


def main() -> int:
    result = verify_repository()
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    print("DEV_A_PROVENANCE_PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
