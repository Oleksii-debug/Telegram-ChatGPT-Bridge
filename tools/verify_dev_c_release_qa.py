#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Fail-closed provenance verifier for the unique DEV_C Release-to-Live QA overlay."""
from __future__ import annotations

import json
import subprocess
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "integration" / "dev_c_release_qa_v1.json"
HEX = set("0123456789abcdef")
ALLOWED_PATHS = frozenset({
    ".github/workflows/devc-release-qa.yml",
    "integration/dev_c_release_qa_v1.json",
    "ops/devc_portable_qa.py",
    "tests/test_devc_portable_qa.py",
    "tests/test_devc_provenance.py",
    "tests/test_devc_round2_concurrency.py",
    "tests/test_devc_runtime_security.py",
    "tools/verify_dev_c_release_qa.py",
})

class DevCProvenanceError(RuntimeError):
    pass

def _sha40(value: object) -> bool:
    return isinstance(value, str) and len(value) == 40 and all(ch in HEX for ch in value)

def _git(*args: str) -> str:
    result = subprocess.run(["git", *args], cwd=ROOT, check=False, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True, encoding="utf-8", timeout=60)
    if result.returncode != 0:
        raise DevCProvenanceError("required Git provenance query failed")
    return result.stdout.strip()

def _safe_paths(value: object) -> tuple[str, ...]:
    if not isinstance(value, list) or not value or value != sorted(set(value)):
        raise DevCProvenanceError("DEV_C path list is not sorted and unique")
    for raw in value:
        if not isinstance(raw, str) or not raw:
            raise DevCProvenanceError("DEV_C path list contains an invalid entry")
        path = PurePosixPath(raw)
        if path.is_absolute() or ".." in path.parts or "*" in raw or "?" in raw:
            raise DevCProvenanceError("DEV_C path list contains unsafe authority")
    if set(value) != ALLOWED_PATHS:
        raise DevCProvenanceError("DEV_C path list differs from exact reviewed allowlist")
    return tuple(value)

def _load_manifest() -> dict:
    try:
        payload = json.loads(MANIFEST.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise DevCProvenanceError("DEV_C provenance manifest is unreadable") from exc
    expected = {"schema_version","round","role","parent_branch","parent_sha","paths",
                "production_logic_changed","private_values_recorded","deployment_authorized"}
    if not isinstance(payload, dict) or set(payload) != expected:
        raise DevCProvenanceError("DEV_C provenance manifest schema mismatch")
    if payload["schema_version"] != 3 or payload["round"] != "RELEASE_TO_LIVE_ROUND_2" or payload["role"] != "DEV_C":
        raise DevCProvenanceError("DEV_C provenance identity mismatch")
    if payload["parent_branch"] != "work3/integration-release-candidate" or not _sha40(payload["parent_sha"]):
        raise DevCProvenanceError("DEV_C parent identity mismatch")
    _safe_paths(payload["paths"])
    if payload["production_logic_changed"] is not False or payload["private_values_recorded"] is not False or payload["deployment_authorized"] is not False:
        raise DevCProvenanceError("DEV_C overlay cannot claim production/private/deploy authority")
    return payload

def verify_repository() -> dict:
    if not (ROOT / ".git").exists():
        raise DevCProvenanceError("DEV_C provenance verification requires full Git checkout")
    payload = _load_manifest()
    parent = payload["parent_sha"]
    head = _git("rev-parse", "--verify", "HEAD^{commit}")
    if not _sha40(head) or _git("merge-base", parent, head) != parent:
        raise DevCProvenanceError("DEV_C branch is not based on exact reviewed parent")
    parents = tuple(_git("show", "-s", "--format=%P", head).split())
    if len(parents) > 1 and parents[0] != parent:
        raise DevCProvenanceError("PR merge-ref first parent differs from reviewed DEV_A SHA")
    changed = tuple(sorted(x for x in _git("diff", "--name-only", parent, head).splitlines() if x))
    if set(changed) != ALLOWED_PATHS or changed != tuple(sorted(ALLOWED_PATHS)):
        raise DevCProvenanceError("DEV_C changed-path set differs from exact QA overlay")
    if any(not (ROOT / rel).is_file() for rel in changed):
        raise DevCProvenanceError("DEV_C reviewed path missing from checkout")
    return {"schema_version":3,"role":"DEV_C","parent_sha":parent,"head_sha":head,
            "dev_c_path_count":len(changed),"production_logic_changed":False,
            "private_values_recorded":False,"deployment_authorized":False}

def main() -> int:
    try:
        result = verify_repository()
    except DevCProvenanceError:
        print("DEV_C_RELEASE_QA_PROVENANCE_BLOCKED")
        return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    print("DEV_C_RELEASE_QA_PROVENANCE_PASS")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
