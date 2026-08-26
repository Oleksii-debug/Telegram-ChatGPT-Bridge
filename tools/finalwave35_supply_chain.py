#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""FINALWAVE35 public-repository supply-chain preflight.

This is a non-deploying, non-secret inspection layer for the exact Git candidate.
It closes repository-shape gaps that are orthogonal to the existing secret scanner:
Git links/symlinks/unmerged stages, Git LFS pointer placeholders, dependency/import
package shadowing, and dependency-contract drift.  It also reports (without
silently waiving) residual PREPARE implementation risks that require canonical
integration-owner changes.
"""
from __future__ import annotations

import argparse
import os
import re
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]

# Import roots that must resolve from the reviewed environment rather than from a
# newly tracked repository-level shadow.  The build-tool names cover ``python -m``
# commands used by PREPARE; dependency names cover the exact runtime closure.
PROTECTED_TOP_LEVEL_IMPORTS = frozenset({
    "telethon", "pyaes", "rsa", "pyasn1",
    "pip", "venv", "ensurepip", "compileall", "unittest",
    "sitecustomize", "usercustomize",
})

# Artifact kind review for the exact hashes already owned by release_package.py.
# pyaes 1.6.1 is intentionally the sole approved source distribution because
# PyPI does not publish a wheel for that release.  All other current hashes are
# reviewed wheel hashes.  This map does not replace the exact hash contract.
APPROVED_ARTIFACT_KINDS = {
    "telethon": "wheel",
    "pyaes": "sdist",
    "rsa": "wheel",
    "pyasn1": "wheel",
}

LFS_HEADER = b"version https://git-lfs.github.com/spec/v1\n"
MAX_LFS_POINTER_BYTES = 4096
SAFE_BLOB_MODES = frozenset({"100644", "100755"})
_SHA1_RE = re.compile(r"^[0-9a-f]{40}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class SupplyChainError(RuntimeError):
    pass


@dataclass(frozen=True)
class GitTreeEntry:
    mode: str
    object_type: str
    oid: str
    path: str


def _git(repo: Path, *args: str, text: bool = False, timeout: int = 60):
    """Run Git without shell expansion and without reflecting stderr into output."""
    try:
        return subprocess.run(
            ["git", *args],
            cwd=repo,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=text,
            timeout=timeout,
        ).stdout
    except (OSError, subprocess.SubprocessError) as exc:
        raise SupplyChainError("Git supply-chain inspection failed") from exc


def _safe_git_path(raw: bytes) -> str:
    try:
        path = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise SupplyChainError("Git tree path is not UTF-8") from exc
    pure = PurePosixPath(path)
    if (
        not path
        or pure.is_absolute()
        or any(part in {"", ".", ".."} for part in pure.parts)
        or "\\" in path
        or "\r" in path
        or "\n" in path
    ):
        raise SupplyChainError("Git tree contains a non-portable/unsafe path")
    return pure.as_posix()


def parse_ls_tree_z(raw: bytes) -> tuple[GitTreeEntry, ...]:
    """Parse ``git ls-tree -r -z`` output and fail closed on unusual records."""
    entries: list[GitTreeEntry] = []
    seen: set[str] = set()
    seen_casefold: set[str] = set()
    for record in raw.split(b"\0"):
        if not record:
            continue
        try:
            meta, raw_path = record.split(b"\t", 1)
            mode_b, type_b, oid_b = meta.split(b" ", 2)
            mode = mode_b.decode("ascii", errors="strict")
            object_type = type_b.decode("ascii", errors="strict")
            oid = oid_b.decode("ascii", errors="strict")
        except (ValueError, UnicodeDecodeError) as exc:
            raise SupplyChainError("Git tree record is malformed") from exc
        path = _safe_git_path(raw_path)
        if path in seen or path.casefold() in seen_casefold:
            raise SupplyChainError("Git tree contains duplicate/case-colliding paths")
        seen.add(path)
        seen_casefold.add(path.casefold())
        if mode not in SAFE_BLOB_MODES or object_type != "blob" or not _SHA1_RE.fullmatch(oid):
            # This rejects symlink mode 120000, gitlink/submodule mode 160000,
            # and any future non-regular leaf topology before archive extraction.
            raise SupplyChainError("Git tree contains non-regular export topology")
        entries.append(GitTreeEntry(mode, object_type, oid, path))
    if not entries:
        raise SupplyChainError("Git candidate tree is empty")
    return tuple(entries)


def parse_ls_files_stage_z(raw: bytes) -> tuple[tuple[str, str], ...]:
    """Reject unresolved index stages and unsafe tracked modes."""
    result: list[tuple[str, str]] = []
    for record in raw.split(b"\0"):
        if not record:
            continue
        try:
            meta, raw_path = record.split(b"\t", 1)
            mode_b, oid_b, stage_b = meta.split(b" ", 2)
            mode = mode_b.decode("ascii", errors="strict")
            oid = oid_b.decode("ascii", errors="strict")
            stage = stage_b.decode("ascii", errors="strict")
        except (ValueError, UnicodeDecodeError) as exc:
            raise SupplyChainError("Git index record is malformed") from exc
        path = _safe_git_path(raw_path)
        if stage != "0":
            raise SupplyChainError("Git index contains unresolved merge stages")
        if mode not in SAFE_BLOB_MODES or not _SHA1_RE.fullmatch(oid):
            raise SupplyChainError("Git index contains symlink/gitlink/non-regular topology")
        result.append((path, oid))
    if not result:
        raise SupplyChainError("Git index is empty")
    return tuple(result)


def _shadow_root(path: str) -> str | None:
    first = PurePosixPath(path).parts[0].casefold()
    if first.endswith(".py"):
        first = first[:-3]
    if first in PROTECTED_TOP_LEVEL_IMPORTS:
        return first
    return None


def validate_no_import_shadowing(paths: tuple[str, ...] | list[str]) -> None:
    shadows = sorted({root for path in paths if (root := _shadow_root(path)) is not None})
    if shadows:
        raise SupplyChainError("tracked source shadows protected Python import roots: " + ",".join(shadows))


def is_lfs_pointer(blob: bytes) -> bool:
    if len(blob) > MAX_LFS_POINTER_BYTES or not blob.startswith(LFS_HEADER):
        return False
    text = blob.decode("ascii", errors="ignore")
    return bool(
        re.search(r"(?m)^oid sha256:[0-9a-f]{64}$", text)
        and re.search(r"(?m)^size [0-9]+$", text)
    )


def validate_artifact_policy() -> dict[str, int]:
    # The exact package/version/hash values remain single-sourced in release_package.
    from ops.release_package import EXPECTED_RUNTIME_LOCK

    if set(APPROVED_ARTIFACT_KINDS) != set(EXPECTED_RUNTIME_LOCK):
        raise SupplyChainError("artifact-kind policy does not match exact runtime lock closure")
    for _name, (_version, digest) in EXPECTED_RUNTIME_LOCK.items():
        if not isinstance(digest, str) or not _SHA256_RE.fullmatch(digest):
            raise SupplyChainError("runtime artifact hash policy is invalid")
    kinds = list(APPROVED_ARTIFACT_KINDS.values())
    if kinds.count("sdist") != 1 or APPROVED_ARTIFACT_KINDS.get("pyaes") != "sdist":
        raise SupplyChainError("unexpected source-distribution policy")
    if any(kind not in {"wheel", "sdist"} for kind in kinds):
        raise SupplyChainError("unsupported runtime artifact kind")
    return {"wheel_count": kinds.count("wheel"), "sdist_count": kinds.count("sdist")}


def validate_dependency_contract_before_install(repo: Path) -> dict[str, object]:
    """Exercise the canonical strict parser as a pre-installable policy check."""
    from ops.release_package import validate_dependency_contract

    result = validate_dependency_contract(repo)
    kinds = validate_artifact_policy()
    return {**result, **kinds}


def audit_prepare_residuals(deploy_source: str) -> tuple[str, ...]:
    """Return explicit residual codes; these are not silently converted to PASS.

    FINALWAVE35 intentionally does not rewrite the canonical deploy engine from a
    parallel specialist branch.  These codes let the integrator distinguish the
    preflight closure supplied here from PREPARE implementation work still owed.
    """
    residuals: list[str] = []
    if '"--require-hashes"' in deploy_source:
        if '"--no-deps"' not in deploy_source:
            residuals.append("PIP_TRANSITIVE_RESOLUTION_NOT_EXPLICITLY_DISABLED")
        if '"--no-build-isolation"' not in deploy_source:
            residuals.append("APPROVED_SDIST_BUILD_ISOLATION_NOT_DISABLED")
        if '"--isolated"' not in deploy_source:
            residuals.append("PIP_AMBIENT_CONFIG_NOT_EXPLICITLY_ISOLATED")
    if '[str(py), "-m", "pip"' in deploy_source or '[str(approved_python_real), "-m", "venv"' in deploy_source:
        residuals.append("PYTHON_SAFE_PATH_NOT_ENABLED_FOR_PREPARE_MODULES")
    if '["tar", "-x"' in deploy_source:
        residuals.append("EXTERNAL_TAR_EXTRACTION_RELIES_ON_PREFLIGHT_TOPOLOGY")
    return tuple(sorted(set(residuals)))


def scan_repository(repo: Path = ROOT, *, ref: str = "HEAD") -> dict[str, object]:
    repo = repo.resolve(strict=True)
    raw_tree = _git(repo, "ls-tree", "-r", "-z", "--full-tree", ref)
    entries = parse_ls_tree_z(raw_tree)
    paths = tuple(entry.path for entry in entries)
    validate_no_import_shadowing(paths)

    # Index-stage check matters for a checked-out candidate and catches merge
    # residue independently of the committed tree parser.
    raw_index = _git(repo, "ls-files", "--stage", "-z")
    parse_ls_files_stage_z(raw_index)

    for entry in entries:
        try:
            size_text = _git(repo, "cat-file", "-s", entry.oid, text=True).strip()
            size = int(size_text)
        except (ValueError, TypeError) as exc:
            raise SupplyChainError("Git blob size is invalid") from exc
        if size <= MAX_LFS_POINTER_BYTES:
            blob = _git(repo, "cat-file", "blob", entry.oid)
            if is_lfs_pointer(blob):
                raise SupplyChainError("Git candidate contains an unresolved LFS pointer")

    dependency = validate_dependency_contract_before_install(repo)
    deploy_path = repo / "ops" / "deploy_release.py"
    try:
        deploy_source = deploy_path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise SupplyChainError("deploy source is unreadable") from exc
    residuals = audit_prepare_residuals(deploy_source)
    return {
        "tracked_blob_count": len(entries),
        "runtime_package_count": dependency["package_count"],
        "wheel_count": dependency["wheel_count"],
        "sdist_count": dependency["sdist_count"],
        "residuals": residuals,
        "production_authorized": False,
        "private_values_recorded": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", default=str(ROOT))
    parser.add_argument("--ref", default="HEAD")
    args = parser.parse_args(argv)
    try:
        result = scan_repository(Path(args.repo), ref=args.ref)
    except (SupplyChainError, RuntimeError, OSError) as exc:
        # Stable class/code only; never reflect subprocess stderr, environment,
        # paths outside the public repository, or file contents.
        print("FINALWAVE35_SUPPLY_CHAIN_PREFLIGHT_FAIL:" + type(exc).__name__)
        return 1
    print(
        "FINALWAVE35_SUPPLY_CHAIN_PREFLIGHT_PASS"
        f":tracked={result['tracked_blob_count']}"
        f":packages={result['runtime_package_count']}"
        f":wheels={result['wheel_count']}"
        f":sdists={result['sdist_count']}"
    )
    for code in result["residuals"]:
        print("FINALWAVE35_RESIDUAL:" + code)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
