#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Run the real non-live release PREPARE against an exact candidate SHA.

This tool uses a temporary release root only. It never reads production/private
Telegram state and never performs deploy/restart/switch operations.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from ops.deploy_release import prepare_versioned_release, verify_prepared_release
from ops.release_guard import SafetyError, sha256_file
from ops.release_package import build_release_identity, validate_public_release_tree

REPOSITORY_ID = "Oleksii-debug/Telegram-ChatGPT-Bridge"
EXPECTED_DISTRIBUTIONS = {
    "Telethon": "1.44.0",
    "pyaes": "1.6.1",
    "rsa": "4.9.1",
    "pyasn1": "0.6.4",
}


def _git_paths(repo: Path, sha: str) -> list[str]:
    try:
        output = subprocess.run(
            ["git", "ls-tree", "-r", "--name-only", sha],
            cwd=repo,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=60,
        ).stdout
    except (OSError, subprocess.SubprocessError) as exc:
        raise SafetyError("exact release tree could not be enumerated") from exc
    return [line for line in output.splitlines() if line]


def _prepared_python(prepared: Path) -> Path:
    candidate = prepared / ".venv" / "bin" / "python"
    if not candidate.exists():
        candidate = prepared / ".venv" / "Scripts" / "python.exe"
    if not candidate.is_file():
        raise SafetyError("prepared runtime Python is unavailable")
    return candidate


def _verify_installed_runtime(prepared: Path) -> None:
    py = _prepared_python(prepared)
    expression = (
        "import importlib.metadata as m, passenger_wsgi; "
        "expected=" + repr(EXPECTED_DISTRIBUTIONS) + "; "
        "actual={k:m.version(k) for k in expected}; "
        "assert actual==expected, (actual, expected); "
        "assert callable(passenger_wsgi.application); print('PREPARED_RUNTIME_IMPORT_PASS')"
    )
    env = dict(os.environ)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    try:
        subprocess.run(
            [str(py), "-B", "-c", expression],
            cwd=prepared,
            env=env,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=90,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise SafetyError("prepared runtime dependency/import verification failed") from exc


def verify_exact_candidate(repo: Path, sha: str, approved_ref: str) -> dict[str, object]:
    repo = repo.resolve(strict=True)
    paths = _git_paths(repo, sha)
    # Validate the public package contract against the exact checked-out candidate
    # before the expensive real PREPARE. Git's exact-ref policy is enforced again
    # inside prepare_versioned_release().
    package = validate_public_release_tree(repo, paths=paths)

    with tempfile.TemporaryDirectory(prefix="telegram-bridge-prepare-") as tmp:
        releases_root = Path(tmp) / "releases"
        prepared, meta, manifest_hash = prepare_versioned_release(
            repo=repo,
            sha=sha,
            approved_ref=approved_ref,
            repository_id=REPOSITORY_ID,
            releases_root=releases_root,
            python_executable=sys.executable,
            runtime_entries=[],
        )
        verified = verify_prepared_release(prepared, manifest_hash)
        if verified != meta:
            raise SafetyError("prepared release metadata changed during verification")
        if meta.get("sha") != sha:
            raise SafetyError("prepared release identity does not match candidate SHA")
        if meta.get("requirements_lock_sha256") != sha256_file(repo / "requirements.lock"):
            raise SafetyError("prepared release is not bound to the canonical runtime lock")
        if meta.get("requirements_test_lock_sha256") is not None:
            raise SafetyError("unexpected test-only dependency lock in canonical release")
        if meta.get("immutable_permission_policy") != "no-write-bits-v1":
            raise SafetyError("prepared release immutable permission policy mismatch")
        _verify_installed_runtime(prepared)
        identity = build_release_identity(prepared, sha=sha, repository=REPOSITORY_ID)
        return {
            "state": "NONLIVE_PREPARE_VERIFIED",
            "sha": sha,
            "prepared_manifest_sha256": manifest_hash,
            "prepared_payload_sha256": meta.get("payload_manifest_sha256"),
            "requirements_lock_sha256": meta.get("requirements_lock_sha256"),
            "package_count": package["dependencies"]["package_count"],
            "release_identity_sha256": identity["identity_sha256"],
            "private_values_recorded": False,
            "production_mutated": False,
            "deployment_authorized": False,
        }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", default=".")
    parser.add_argument("--sha", required=True)
    parser.add_argument("--approved-ref", required=True)
    args = parser.parse_args(argv)
    try:
        result = verify_exact_candidate(Path(args.repo), args.sha, args.approved_ref)
    except SafetyError as exc:
        print(f"RELEASE_PREPARE_BLOCKED: {type(exc).__name__}")
        return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
