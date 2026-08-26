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
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path, PurePosixPath
from typing import Callable, TypeVar

# GitHub Actions and one-time operator validation invoke this file directly as
# ``python tools/verify_release_prepare.py``. Direct script execution places
# ``tools/`` rather than the repository root on sys.path, so make the public
# repository package root explicit before importing ``ops``. This changes only
# module resolution; it does not read environment secrets or private state.
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ops import deploy_release
from ops.release_guard import (
    SafetyError,
    build_manifest,
    sha256_file,
    sha256_json,
    validate_exact_source_payload,
)
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
    "PREPARE_VENV",
    "PREPARE_DEPENDENCIES",
    "PREPARE_COMPILE",
    "PREPARE_TESTS",
    "PREPARED_VERIFY",
    "ARCHIVE_IDENTITY",
    "ARTIFACT_INTEGRITY",
    "PACKAGE_CONTRACT",
    "LOCK_BINDING",
    "RUNTIME_IMPORT",
    "IDENTITY",
    "REF_FRESHNESS",
})
_TEST_ID_RE = re.compile(r"^[A-Za-z0-9_.]{1,220}$")
_MAX_TEST_DIAGNOSTICS = 8
_T = TypeVar("_T")


class ReleasePrepareStageError(SafetyError):
    """Stable non-secret PREPARE failure with bounded public diagnostics."""

    def __init__(self, stage: str, diagnostics: tuple[str, ...] = ()):
        if stage not in _STAGE_RE:
            stage = "PREPARED_VERIFY"
        safe: list[str] = []
        for value in diagnostics[:_MAX_TEST_DIAGNOSTICS]:
            if isinstance(value, str) and _TEST_ID_RE.fullmatch(value):
                safe.append(value)
        super().__init__("release PREPARE verification failed")
        self.stage = stage
        self.diagnostics = tuple(safe)


def _at_stage(stage: str, operation: Callable[[], _T]) -> _T:
    try:
        return operation()
    except ReleasePrepareStageError:
        raise
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


def _prepare_subprocess_stage(command: list[str]) -> str:
    """Map only known PREPARE subprocess shapes to bounded public stage labels."""
    lowered = [str(part).casefold() for part in command]
    if "-m" in lowered:
        index = lowered.index("-m")
        module = lowered[index + 1] if index + 1 < len(lowered) else ""
        if module == "venv":
            return "PREPARE_VENV"
        if module == "pip" and "install" in lowered:
            return "PREPARE_DEPENDENCIES"
        if module == "compileall":
            return "PREPARE_COMPILE"
        if module == "unittest":
            return "PREPARE_TESTS"
    return "PREPARE"


def _diagnose_prepare_test_failures(command: list[str], cwd: Path | None, timeout: int) -> tuple[str, ...]:
    """Return only public unittest identifiers; never return test output or exceptions.

    The authoritative PREPARE command remains unchanged and has already failed
    when this helper runs. A second isolated discovery pass suppresses stdout,
    stderr, tracebacks and assertion text and emits only failing/erroring test
    IDs. Those IDs are public repository symbols and are validated again before
    they can reach CI output.
    """
    if cwd is None or not command:
        return ()
    expression = r'''
import contextlib
import json
import os
import unittest

suite = unittest.defaultTestLoader.discover("tests")
result = unittest.TestResult()
with open(os.devnull, "w", encoding="utf-8") as sink:
    with contextlib.redirect_stdout(sink), contextlib.redirect_stderr(sink):
        suite.run(result)
ids = sorted({test.id() for test, _ in (result.failures + result.errors)})[:8]
print(json.dumps(ids, separators=(",", ":")))
'''
    env = dict(os.environ)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    try:
        completed = subprocess.run(
            [str(command[0]), "-B", "-c", expression],
            cwd=cwd,
            env=env,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=max(30, min(int(timeout), 300)),
        )
        payload = json.loads(completed.stdout.strip())
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError, ValueError, TypeError):
        return ()
    if not isinstance(payload, list):
        return ()
    safe: list[str] = []
    for value in payload[:_MAX_TEST_DIAGNOSTICS]:
        if isinstance(value, str) and _TEST_ID_RE.fullmatch(value):
            safe.append(value)
    return tuple(safe)


def _prepare_with_bounded_subprocess_stages(**kwargs):
    """Run authoritative deploy PREPARE unchanged, adding bounded diagnostics only.

    The deploy engine remains the sole implementation. This wrapper temporarily
    decorates its internal subprocess helper so a failure reports one allowlisted
    stage. For PREPARE_TESTS only, public unittest IDs may also be reported.
    It never returns stderr/stdout, paths, command arguments, environment values,
    or exception text and always restores the original helper.
    """
    original_run = deploy_release.run

    def classified_run(command: list[str], *, cwd: Path | None = None, timeout: int = 300) -> None:
        stage = _prepare_subprocess_stage(command)
        try:
            original_run(command, cwd=cwd, timeout=timeout)
        except SafetyError as exc:
            diagnostics = ()
            if stage == "PREPARE_TESTS":
                diagnostics = _diagnose_prepare_test_failures(command, cwd, timeout)
            raise ReleasePrepareStageError(stage, diagnostics) from exc

    deploy_release.run = classified_run
    try:
        return deploy_release.prepare_versioned_release(**kwargs)
    finally:
        deploy_release.run = original_run


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


def _verify_archive_identity(repo: Path, sha: str, meta: dict) -> None:
    """Re-export the immutable Git object and bind it to PREPARE source metadata.

    This check deliberately uses repository metadata only outside the prepared
    artifact. The prepared artifact remains portable with no `.git` directory.
    """
    expected = str(meta.get("source_manifest_sha256", ""))
    if not re.fullmatch(r"[0-9a-f]{64}", expected):
        raise SafetyError("prepared source manifest identity is missing or invalid")
    with tempfile.TemporaryDirectory(prefix="telegram-bridge-archive-audit-") as tmp:
        exported = Path(tmp) / "release"
        exported.mkdir()
        deploy_release.git_export(repo, sha, exported)
        validate_exact_source_payload(exported, [])
        observed = sha256_json(build_manifest(exported))
    if observed != expected:
        raise SafetyError("prepared source manifest does not match exact Git archive")


def _verify_prepared_tree_integrity(prepared: Path) -> None:
    """Add fail-closed topology checks around the sealed prepared instance.

    Byte and symlink-target integrity remains authoritative in
    ``deploy_release.verify_prepared_release``. This layer additionally rejects
    repository metadata inside the artifact and regular-file hardlinks, so a
    sealed instance cannot alias a mutable peer inode outside its tree.
    """
    root = prepared.resolve(strict=True)
    uid = os.getuid() if hasattr(os, "getuid") else None
    for path in [root, *sorted(root.rglob("*"))]:
        rel = "" if path == root else path.relative_to(root).as_posix()
        if rel and ".git" in PurePosixPath(rel).parts:
            raise SafetyError("prepared artifact must not contain repository metadata")
        try:
            st = path.lstat()
        except OSError as exc:
            raise SafetyError("prepared artifact topology became unreadable") from exc
        if uid is not None and st.st_uid != uid:
            raise SafetyError("prepared artifact owner is unexpected")
        if path.is_symlink():
            continue
        if stat.S_IMODE(st.st_mode) & 0o222:
            raise SafetyError("prepared artifact retains write permission")
        if path.is_file() and st.st_nlink != 1:
            raise SafetyError("prepared artifact regular-file hardlinks are forbidden")


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
            lambda: _prepare_with_bounded_subprocess_stages(
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
            lambda: deploy_release.verify_prepared_release(prepared, manifest_hash),
        )
        if verified != meta:
            raise ReleasePrepareStageError("PREPARED_VERIFY")
        if meta.get("sha") != sha:
            raise ReleasePrepareStageError("PREPARED_VERIFY")

        _at_stage("ARCHIVE_IDENTITY", lambda: _verify_archive_identity(repo, sha, meta))
        _at_stage("ARTIFACT_INTEGRITY", lambda: _verify_prepared_tree_integrity(prepared))

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

        # PREPARE can take minutes. A ref that was exact at entry but moved while
        # dependencies/tests ran must not yield fresh exact-head evidence.
        _at_stage(
            "REF_FRESHNESS",
            lambda: deploy_release.verify_approved_ref_policy(repo, sha, approved_ref),
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
        suffix = ""
        if exc.diagnostics:
            suffix = ":" + "|".join(exc.diagnostics)
        print(f"RELEASE_PREPARE_BLOCKED:{exc.stage}{suffix}")
        return 2
    except SafetyError:
        print("RELEASE_PREPARE_BLOCKED:UNCLASSIFIED")
        return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
