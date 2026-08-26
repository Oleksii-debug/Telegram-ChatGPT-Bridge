# -*- coding: utf-8 -*-
"""Dependency reproducibility contracts for the Telegram Bridge release.

This module deliberately separates three claims that are easy to conflate:

* the public requirements are exact and hash locked;
* a successful PREPARE seals every byte of one prepared release instance;
* rebuilding an identical virtualenv on another host is *not* claimed.

The last distinction matters because the Telethon 1.44.0 closure includes
pyaes 1.6.1, whose reviewed PyPI artifact is a source distribution.  Building
that artifact necessarily involves the selected Python/pip/build toolchain.
"""
from __future__ import annotations

import re
from pathlib import Path

from ops.release_guard import SafetyError, sha256_file
from ops.release_package import EXPECTED_RUNTIME_LOCK

REPRODUCIBILITY_MODEL = "hash-locked-inputs+sealed-prepared-instance-v1"
BIT_REPRODUCIBLE_BUILD_CLAIMED = False
PYTHON_LINE = (3, 11)

# Artifact facts bound to the exact hashes already accepted by
# EXPECTED_RUNTIME_LOCK.  pyaes is intentionally explicit because its selected
# hash is the PyPI source distribution, not a wheel.
ARTIFACT_POLICY = {
    "telethon": {"version": "1.44.0", "kind": "wheel", "filename": "telethon-1.44.0-py3-none-any.whl"},
    "pyaes": {"version": "1.6.1", "kind": "sdist", "filename": "pyaes-1.6.1.tar.gz"},
    "rsa": {"version": "4.9.1", "kind": "wheel", "filename": "rsa-4.9.1-py3-none-any.whl"},
    "pyasn1": {"version": "0.6.4", "kind": "wheel", "filename": "pyasn1-0.6.4-py3-none-any.whl"},
}

_SAFE_ARTIFACT_RE = re.compile(r"^[A-Za-z0-9_.+-]+(?:\.whl|\.tar\.gz)$")


def validate_python_line(version_info: tuple[int, int] | list[int]) -> None:
    if tuple(version_info[:2]) != PYTHON_LINE:
        raise SafetyError("dependency verification requires Python 3.11")


def expected_artifact_hashes() -> set[str]:
    return {digest for _version, digest in EXPECTED_RUNTIME_LOCK.values()}


def validate_artifact_policy() -> dict[str, object]:
    if set(ARTIFACT_POLICY) != set(EXPECTED_RUNTIME_LOCK):
        raise SafetyError("dependency artifact policy does not match runtime closure")
    source_only: list[str] = []
    for name, facts in ARTIFACT_POLICY.items():
        version, _digest = EXPECTED_RUNTIME_LOCK[name]
        if facts.get("version") != version:
            raise SafetyError("dependency artifact version policy mismatch")
        filename = str(facts.get("filename", ""))
        if not _SAFE_ARTIFACT_RE.fullmatch(filename):
            raise SafetyError("dependency artifact filename is unsafe")
        kind = facts.get("kind")
        if kind not in {"wheel", "sdist"}:
            raise SafetyError("dependency artifact kind is unsupported")
        if kind == "sdist":
            source_only.append(name)
    return {
        "model": REPRODUCIBILITY_MODEL,
        "bit_reproducible_build_claimed": BIT_REPRODUCIBLE_BUILD_CLAIMED,
        "package_count": len(ARTIFACT_POLICY),
        "source_distribution_packages": tuple(sorted(source_only)),
    }


def verify_downloaded_artifacts(directory: Path) -> dict[str, object]:
    directory = directory.resolve(strict=True)
    files = sorted(path for path in directory.iterdir() if path.is_file() and not path.is_symlink())
    if len(files) != len(EXPECTED_RUNTIME_LOCK):
        raise SafetyError("downloaded dependency artifact count mismatch")
    actual = {sha256_file(path) for path in files}
    if actual != expected_artifact_hashes():
        raise SafetyError("downloaded dependency artifact hashes differ from lock")

    pyaes = [path.name for path in files if path.name.casefold().startswith("pyaes-1.6.1")]
    if pyaes != [ARTIFACT_POLICY["pyaes"]["filename"]]:
        raise SafetyError("pyaes source-distribution boundary changed")
    return {
        "artifact_count": len(files),
        "all_hashes_match_lock": True,
        "pyaes_artifact_kind": "sdist",
    }


def download_command(python: str, lock: Path, destination: Path) -> list[str]:
    return [
        python, "-m", "pip", "download",
        "--disable-pip-version-check", "--no-input", "--require-hashes", "--no-deps",
        "--dest", str(destination), "-r", str(lock),
    ]


def offline_install_command(python: str, lock: Path, artifact_directory: Path) -> list[str]:
    return [
        python, "-m", "pip", "install",
        "--disable-pip-version-check", "--no-input", "--no-index", "--no-deps",
        "--find-links", str(artifact_directory), "--require-hashes", "-r", str(lock),
    ]


def mutated_wrong_hash_lock(source: Path, destination: Path) -> None:
    """Create a deterministic negative-test lock without exposing any private data."""
    text = source.read_text(encoding="utf-8")
    marker = "--hash=sha256:"
    index = text.find(marker)
    if index < 0:
        raise SafetyError("runtime lock has no hash to mutate")
    digest_index = index + len(marker)
    current = text[digest_index]
    replacement = "0" if current != "0" else "1"
    destination.write_text(text[:digest_index] + replacement + text[digest_index + 1 :], encoding="utf-8")
