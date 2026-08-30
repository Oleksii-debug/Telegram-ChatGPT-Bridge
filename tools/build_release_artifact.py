# -*- coding: utf-8 -*-
"""Build a portable, non-authorizing release artifact for one exact Git SHA.

The artifact is intentionally public-source-only. It contains a Git bundle plus a
small deterministic manifest/checksum document. It never reads runtime secrets,
Telegram sessions, HOSTiQ configuration, cookies, or private evidence.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

# Direct execution (``python tools/build_release_artifact.py``) starts with the
# tools directory on sys.path. Add the repository root so ``ops`` imports work.
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ops.release_guard import SafetyError  # noqa: E402
from ops.release_package import build_release_identity  # noqa: E402

REPOSITORY = "Oleksii-debug/Telegram-ChatGPT-Bridge"
SHA40_RE = re.compile(r"^[0-9a-f]{40}$")
MANIFEST_NAME = "RELEASE_ARTIFACT.json"
BUNDLE_PREFIX = "telegram-chatgpt-bridge"


def _run_git(repo: Path, *args: str, capture: bool = False) -> str:
    """Run Git without shell expansion and without reflecting command stderr."""
    try:
        completed = subprocess.run(
            ["git", "-C", str(repo), *args],
            check=False,
            stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=120,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise SafetyError("release artifact Git operation failed") from exc
    if completed.returncode != 0:
        raise SafetyError("release artifact Git operation failed")
    return completed.stdout.strip() if capture else ""


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(block)
    except OSError as exc:
        raise SafetyError("release artifact file is unreadable") from exc
    return digest.hexdigest()


def _require_exact_clean_checkout(repo: Path, expected_sha: str) -> Path:
    if not SHA40_RE.fullmatch(expected_sha):
        raise SafetyError("release artifact requires an exact Git SHA")
    try:
        repo = repo.expanduser().resolve(strict=True)
    except OSError as exc:
        raise SafetyError("release artifact repository is unavailable") from exc
    if not repo.is_dir() or repo.is_symlink():
        raise SafetyError("release artifact repository topology is unsafe")

    top = _run_git(repo, "rev-parse", "--show-toplevel", capture=True)
    try:
        top_path = Path(top).resolve(strict=True)
    except OSError as exc:
        raise SafetyError("release artifact Git root is unavailable") from exc
    if top_path != repo:
        raise SafetyError("release artifact repository root mismatch")

    actual_sha = _run_git(repo, "rev-parse", "HEAD", capture=True)
    if actual_sha != expected_sha:
        raise SafetyError("release artifact checkout SHA mismatch")
    if _run_git(repo, "status", "--porcelain=v1", "--untracked-files=all", capture=True):
        raise SafetyError("release artifact checkout is not clean")
    return repo


def _prepare_output_dir(repo: Path, output_dir: Path) -> Path:
    output = output_dir.expanduser().absolute()
    try:
        if output.exists() or output.is_symlink():
            info = output.lstat()
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
                raise SafetyError("release artifact output topology is unsafe")
            if any(output.iterdir()):
                raise SafetyError("release artifact output directory is not empty")
        else:
            output.mkdir(parents=True, mode=0o700)
        output = output.resolve(strict=True)
    except SafetyError:
        raise
    except OSError as exc:
        raise SafetyError("release artifact output directory is unavailable") from exc

    if output == repo or repo in output.parents:
        raise SafetyError("release artifact output must be outside the source checkout")
    return output


def _verify_bundle(bundle_path: Path, expected_sha: str) -> None:
    """Prove the bundle can recreate a repository whose HEAD is the exact SHA."""
    with tempfile.TemporaryDirectory(prefix="bridge-release-bundle-verify-") as temp_name:
        verify_root = Path(temp_name)
        try:
            completed = subprocess.run(
                ["git", "clone", "--no-checkout", str(bundle_path), str(verify_root / "repo")],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=120,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise SafetyError("release artifact bundle verification failed") from exc
        if completed.returncode != 0:
            raise SafetyError("release artifact bundle verification failed")
        cloned_sha = _run_git(verify_root / "repo", "rev-parse", "HEAD", capture=True)
        if cloned_sha != expected_sha:
            raise SafetyError("release artifact bundle recreated the wrong SHA")


def build_release_artifact(
    repo: Path,
    *,
    expected_sha: str,
    output_dir: Path,
    repository: str = REPOSITORY,
) -> dict[str, object]:
    """Create and independently verify a portable exact-source Git bundle."""
    repo = _require_exact_clean_checkout(repo, expected_sha)
    output = _prepare_output_dir(repo, output_dir)
    if repository != REPOSITORY:
        raise SafetyError("release artifact repository identity mismatch")

    # Reuse the canonical public release contract. This records only source,
    # WSGI/dependency identity and explicitly remains non-authorizing.
    release_identity = build_release_identity(repo, sha=expected_sha, repository=repository)

    bundle_name = f"{BUNDLE_PREFIX}-{expected_sha}.bundle"
    bundle_path = output / bundle_name
    _run_git(repo, "bundle", "create", str(bundle_path), "HEAD")
    if not bundle_path.is_file() or bundle_path.is_symlink():
        raise SafetyError("release artifact bundle was not created safely")
    _run_git(repo, "bundle", "verify", str(bundle_path))
    _verify_bundle(bundle_path, expected_sha)

    bundle_sha256 = _sha256_file(bundle_path)
    payload: dict[str, object] = {
        "schema_version": 1,
        "artifact_format": "git-bundle+json-v1",
        "repository": repository,
        "source_sha": expected_sha,
        "bundle_file": bundle_name,
        "bundle_sha256": bundle_sha256,
        "release_identity_sha256": release_identity["identity_sha256"],
        "private_values_recorded": False,
        "deployment_authorized": False,
    }
    payload["artifact_identity_sha256"] = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()

    manifest_path = output / MANIFEST_NAME
    try:
        manifest_path.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
            newline="\n",
        )
    except OSError as exc:
        raise SafetyError("release artifact manifest write failed") from exc
    if manifest_path.is_symlink() or not manifest_path.is_file():
        raise SafetyError("release artifact manifest topology is unsafe")

    return payload


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build an exact-SHA portable release artifact")
    parser.add_argument("--repo", default=".", help="repository root")
    parser.add_argument("--sha", required=True, help="exact 40-character source SHA")
    parser.add_argument("--output-dir", required=True, help="new/empty output directory outside the repo")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    try:
        payload = build_release_artifact(
            Path(args.repo),
            expected_sha=args.sha,
            output_dir=Path(args.output_dir),
        )
    except SafetyError as exc:
        print(f"RELEASE_ARTIFACT_BLOCKED: {exc}", file=sys.stderr)
        return 2
    print(
        "RELEASE_ARTIFACT_BUILT "
        f"source_sha={payload['source_sha']} "
        f"artifact_identity_sha256={payload['artifact_identity_sha256']} "
        f"bundle_sha256={payload['bundle_sha256']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
