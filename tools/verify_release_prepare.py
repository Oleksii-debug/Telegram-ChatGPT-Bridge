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
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Callable, TypeVar

# GitHub Actions and one-time operator validation invoke this file directly as
# ``python tools/verify_release_prepare.py``. Direct script execution places
# ``tools/`` rather than the repository root on sys.path, so make the public
# repository package root explicit before importing ``ops``. This changes only
# module resolution; it does not read environment secrets or private state.
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

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
IDENTITY_ENVELOPE = ("passenger_wsgi.py", "requirements.txt", "requirements.lock")
_STAGE_RE = frozenset({
    "TREE_ENUMERATION",
    "PREPARE",
    "PREPARED_VERIFY",
    "PACKAGE_CONTRACT",
    "LOCK_BINDING",
    "RUNTIME_IMPORT",
    "IDENTITY",
})
_T = TypeVar("_T")


class ReleasePrepareStageError(SafetyError):
    """Stable non-secret PREPARE failure carrying only an allowlisted stage."""

    def __init__(self, stage: str):
        if stage not in _STAGE_RE:
            stage = "PREPARED_VERIFY"
        super().__init__("release PREPARE verification failed")
        self.stage = stage


def _at_stage(stage: str, operation: Callable[[], _T]) -> _T:
    try:
        return operation()
    except SafetyError as exc:
        raise ReleasePrepareStageError(stage) from exc


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


def _build_canonical_envelope_identity(prepared: Path, *, sha: str) -> dict[str, object]:
    """Hash the public canonical startup/dependency envelope, never generated venv paths.

    PREPARE separately binds every generated dependency byte through
    ``payload_manifest_sha256``. Release identity intentionally represents the
    reviewed Git-controlled startup/dependency envelope. Recursively scanning
    generated site-packages would misclassify legitimate library namespaces
    such as ``telethon/sessions`` as application private runtime state.
    """
    with tempfile.TemporaryDirectory(prefix="telegram-bridge-envelope-") as tmp:
        root = Path(tmp)
        for name in IDENTITY_ENVELOPE:
            source = prepared / name
            if not source.is_file() or source.is_symlink():
                raise SafetyError("canonical release envelope is missing or unsafe")
            shutil.copy2(source, root / name)
        return build_release_identity(root, sha=sha, repository=REPOSITORY_ID)


def verify_exact_candidate(repo: Path, sha: str, approved_ref: str) -> dict[str, object]:
    """Verify only bytes exported from ``sha``; never trust working-tree bytes.

    Pull-request workflows normally check out a synthetic merge ref. The
    canonical release identity, dependency lock and startup contract therefore
    must be derived from the exact Git object exported by the deployment
    PREPARE transaction, not from files present in that workflow checkout.
    """
    repo = repo.resolve(strict=True)
    paths = _at_stage("TREE_ENUMERATION", lambda: _git_paths(repo, sha))

    with tempfile.TemporaryDirectory(prefix="telegram-bridge-prepare-") as tmp:
        releases_root = Path(tmp) / "releases"
        prepared, meta, manifest_hash = _at_stage(
            "PREPARE",
            lambda: prepare_versioned_release(
                repo=repo,
                sha=sha,
                approved_ref=approved_ref,
                repository_id=REPOSITORY_ID,
                releases_root=releases_root,
                python_executable=sys.executable,
                runtime_entries=[],
            ),
        )
        verified = _at_stage(
            "PREPARED_VERIFY",
            lambda: verify_prepared_release(prepared, manifest_hash),
        )
        if verified != meta:
            raise ReleasePrepareStageError("PREPARED_VERIFY")
        if meta.get("sha") != sha:
            raise ReleasePrepareStageError("PREPARED_VERIFY")

        # Validate package/startup/dependency bytes only after the exact Git SHA
        # has been exported and sealed by PREPARE. ``paths`` is the exact Git
        # tree inventory so generated .venv/metadata cannot expand release scope.
        package = _at_stage(
            "PACKAGE_CONTRACT",
            lambda: validate_public_release_tree(prepared, paths=paths),
        )
        prepared_lock = prepared / "requirements.lock"
        try:
            lock_hash = sha256_file(prepared_lock)
        except (OSError, ValueError) as exc:
            raise ReleasePrepareStageError("LOCK_BINDING") from exc
        if meta.get("requirements_lock_sha256") != lock_hash:
            raise ReleasePrepareStageError("LOCK_BINDING")
        if meta.get("requirements_test_lock_sha256") is not None:
            raise ReleasePrepareStageError("LOCK_BINDING")
        if meta.get("immutable_permission_policy") != "no-write-bits-v1":
            raise ReleasePrepareStageError("LOCK_BINDING")

        _at_stage("RUNTIME_IMPORT", lambda: _verify_installed_runtime(prepared))
        identity = _at_stage(
            "IDENTITY",
            lambda: _build_canonical_envelope_identity(prepared, sha=sha),
        )
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
    except ReleasePrepareStageError as exc:
        print(f"RELEASE_PREPARE_BLOCKED:{exc.stage}")
        return 2
    except SafetyError:
        print("RELEASE_PREPARE_BLOCKED:UNCLASSIFIED")
        return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
