#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Verify the real locked runtime closure in a clean Python 3.11 environment.

The network is used only for the initial hash-checked artifact fetch.  The
installation phase is then forced offline from those exact artifacts.  This is
non-live verification: it never reads private runtime state and never deploys.
"""
from __future__ import annotations

import argparse
import importlib.metadata
import json
import os
import shutil
import subprocess
import sys
import tempfile
import venv
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ops.dependency_repro import (
    REPRODUCIBILITY_MODEL,
    download_command,
    mutated_wrong_hash_lock,
    offline_install_command,
    validate_artifact_policy,
    validate_python_line,
    verify_downloaded_artifacts,
)
from ops.release_guard import SafetyError
from ops.release_package import validate_dependency_contract, validate_wsgi_contract

EXPECTED_DISTRIBUTIONS = {
    "Telethon": "1.44.0",
    "pyaes": "1.6.1",
    "rsa": "4.9.1",
    "pyasn1": "0.6.4",
}


def _run(command: list[str], *, cwd: Path, env: dict[str, str] | None = None, expect_success: bool = True) -> subprocess.CompletedProcess[str]:
    try:
        completed = subprocess.run(
            command,
            cwd=cwd,
            env=env,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=600,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise SafetyError("dependency verification subprocess failed") from exc
    if expect_success and completed.returncode != 0:
        raise SafetyError("dependency verification subprocess returned failure")
    if not expect_success and completed.returncode == 0:
        raise SafetyError("wrong-hash dependency install unexpectedly succeeded")
    return completed


def _venv_python(root: Path) -> Path:
    candidate = root / "bin" / "python"
    if not candidate.is_file():
        candidate = root / "Scripts" / "python.exe"
    if not candidate.is_file():
        raise SafetyError("clean dependency verification venv has no Python")
    return candidate


def _toolchain_versions(python: Path, cwd: Path) -> dict[str, str | None]:
    expression = (
        "import importlib.metadata as m,json;"
        "\n"
        "def v(n):\n"
        "  try:return m.version(n)\n"
        "  except m.PackageNotFoundError:return None\n"
        "print(json.dumps({'pip':v('pip'),'setuptools':v('setuptools'),'wheel':v('wheel')},sort_keys=True))"
    )
    completed = _run([str(python), "-B", "-c", expression], cwd=cwd)
    try:
        data = json.loads(completed.stdout.strip())
    except json.JSONDecodeError as exc:
        raise SafetyError("build toolchain identity could not be read") from exc
    if not isinstance(data, dict) or not data.get("pip"):
        raise SafetyError("pip is missing from clean Python 3.11 venv")
    return {key: data.get(key) for key in ("pip", "setuptools", "wheel")}


def _verify_installed_versions(python: Path, cwd: Path) -> None:
    expression = (
        "import importlib.metadata as m;"
        "expected=" + repr(EXPECTED_DISTRIBUTIONS) + ";"
        "actual={k:m.version(k) for k in expected};"
        "assert actual==expected,(actual,expected);"
        "import telethon,pyaes,rsa,pyasn1; print('OFFLINE_RUNTIME_IMPORT_PASS')"
    )
    _run([str(python), "-B", "-c", expression], cwd=cwd)


def verify(repo: Path) -> dict[str, object]:
    repo = repo.resolve(strict=True)
    validate_python_line(sys.version_info[:2])
    deps = validate_dependency_contract(repo)
    validate_wsgi_contract(repo)
    policy = validate_artifact_policy()
    lock = repo / "requirements.lock"

    with tempfile.TemporaryDirectory(prefix="tg-bridge-dependency-repro-") as tmp:
        root = Path(tmp)
        artifacts = root / "artifacts"
        artifacts.mkdir(mode=0o700)

        # Network boundary: obtain only the four explicitly hash-locked artifacts.
        _run(download_command(sys.executable, lock, artifacts), cwd=repo)
        artifact_result = verify_downloaded_artifacts(artifacts)

        # Offline boundary: a completely fresh venv may use only the downloaded
        # artifact directory.  --no-build-isolation prevents pyaes' sdist build
        # from silently resolving build requirements over the network.
        clean_venv = root / "clean-venv"
        venv.EnvBuilder(with_pip=True, clear=True).create(clean_venv)
        clean_python = _venv_python(clean_venv)
        toolchain = _toolchain_versions(clean_python, repo)
        offline = offline_install_command(str(clean_python), lock, artifacts)
        offline.insert(offline.index("--find-links"), "--no-build-isolation")
        env = dict(os.environ)
        env.update({
            "PIP_NO_INDEX": "1",
            "PIP_DISABLE_PIP_VERSION_CHECK": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
        })
        _run(offline, cwd=repo, env=env)
        _verify_installed_versions(clean_python, repo)

        # Negative control: the same offline artifacts must not satisfy a lock
        # whose first SHA-256 has been altered by one nibble.
        wrong_lock = root / "requirements-wrong-hash.lock"
        mutated_wrong_hash_lock(lock, wrong_lock)
        wrong_venv = root / "wrong-hash-venv"
        venv.EnvBuilder(with_pip=True, clear=True).create(wrong_venv)
        wrong_python = _venv_python(wrong_venv)
        wrong_command = offline_install_command(str(wrong_python), wrong_lock, artifacts)
        wrong_command.insert(wrong_command.index("--find-links"), "--no-build-isolation")
        _run(wrong_command, cwd=repo, env=env, expect_success=False)

    return {
        "state": "DEPENDENCY_REPRO_VERIFIED",
        "python_line": "3.11",
        "package_count": deps["package_count"],
        "test_dependencies_present": deps["test_dependencies_present"],
        "artifact_count": artifact_result["artifact_count"],
        "pyaes_artifact_kind": artifact_result["pyaes_artifact_kind"],
        "offline_clean_install": True,
        "wrong_hash_rejected": True,
        "build_toolchain_observed": toolchain,
        "reproducibility_model": REPRODUCIBILITY_MODEL,
        "bit_reproducible_build_claimed": False,
        "private_values_recorded": False,
        "production_mutated": False,
        "deployment_authorized": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", default=".")
    args = parser.parse_args(argv)
    try:
        result = verify(Path(args.repo))
    except SafetyError:
        print("DEPENDENCY_REPRO_BLOCKED")
        return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
