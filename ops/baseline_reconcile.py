# -*- coding: utf-8 -*-
"""Non-secret reconciliation of a sanitized HOSTiQ baseline against an exact Git ref."""
from __future__ import annotations

import argparse
import json
import subprocess
import tempfile
from pathlib import Path

from ops.release_guard import SafetyError, build_manifest, sha256_json, write_json_atomic
from tools import secret_scan


def _git_export(repo: Path, ref: str, destination: Path) -> str:
    try:
        sha = subprocess.check_output(["git", "rev-parse", "--verify", f"{ref}^{{commit}}"], cwd=repo, text=True).strip()
    except subprocess.SubprocessError as exc:
        raise SafetyError("Git reconciliation ref cannot be resolved") from exc
    archive = subprocess.Popen(["git", "archive", sha], cwd=repo, stdout=subprocess.PIPE)
    extract = subprocess.run(["tar", "-x", "-C", str(destination)], stdin=archive.stdout, check=False)
    if archive.stdout:
        archive.stdout.close()
    if archive.wait() != 0 or extract.returncode != 0:
        raise SafetyError("Git reconciliation export failed")
    return sha


def _manifest_map(manifest: dict) -> dict[str, dict]:
    return {item["path"]: item for item in manifest.get("files", [])}


def reconcile(recovered_root: Path, repo: Path, git_ref: str) -> dict:
    recovered_root = recovered_root.resolve(strict=True)
    repo = repo.resolve(strict=True)
    findings = secret_scan.scan_directory(
        recovered_root,
        allowlist_repo=Path("/__no_public_allowlist__"),
        scope="production-reconciliation",
    )
    if findings:
        raise SafetyError("sanitized recovered baseline failed secret/private-content scan")
    recovered_manifest = build_manifest(recovered_root)
    with tempfile.TemporaryDirectory() as td:
        exported = Path(td) / "git"
        exported.mkdir()
        git_sha = _git_export(repo, git_ref, exported)
        git_manifest = build_manifest(exported)
    left = _manifest_map(recovered_manifest)
    right = _manifest_map(git_manifest)
    recovered_paths = set(left)
    git_paths = set(right)
    added = sorted(recovered_paths - git_paths)
    removed = sorted(git_paths - recovered_paths)
    changed = sorted(
        path for path in recovered_paths & git_paths
        if left[path]["sha256"] != right[path]["sha256"] or left[path]["size"] != right[path]["size"]
    )
    same = sorted((recovered_paths & git_paths) - set(changed))
    return {
        "schema_version": 1,
        "git_ref": git_ref,
        "git_sha": git_sha,
        "recovered_manifest_sha256": sha256_json(recovered_manifest),
        "git_manifest_sha256": sha256_json(git_manifest),
        "recovered_file_count": len(left),
        "git_file_count": len(right),
        "same_count": len(same),
        "added_paths": added,
        "removed_paths": removed,
        "changed_paths": changed,
        "startup_file_changed": "passenger_wsgi.py" in changed or "passenger_wsgi.py" in added or "passenger_wsgi.py" in removed,
        "secret_values_recorded": False,
        "raw_file_content_recorded": False,
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--recovered-root", required=True)
    parser.add_argument("--repo", required=True)
    parser.add_argument("--git-ref", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    try:
        result = reconcile(Path(args.recovered_root), Path(args.repo), args.git_ref)
        write_json_atomic(Path(args.output), result, mode=0o600)
    except (SafetyError, OSError) as exc:
        print(f"RECONCILIATION_BLOCKED: {type(exc).__name__}")
        return 2
    print("RECONCILIATION_READY_FOR_AUDIT")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
