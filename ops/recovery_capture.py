# -*- coding: utf-8 -*-
"""Recovery-only production baseline capture; no cron, mail, or deployment."""
from __future__ import annotations

import argparse
import os
import shutil
import tarfile
from datetime import datetime, timezone
from pathlib import Path

from ops.release_guard import (
    SafetyError,
    build_manifest,
    is_protected_relative,
    sha256_file,
    utc_now_iso,
    validate_recovery_topology,
    write_json_atomic,
)
from tools import secret_scan

SOURCE_ALLOWED_NAMES = {
    "dockerfile", "makefile", "procfile", "passenger_wsgi.py", "requirements.txt",
    "requirements.lock", "pyproject.toml", "setup.cfg", "setup.py", "readme",
    "readme.md", "readme.txt", ".gitignore",
}
SOURCE_ALLOWED_SUFFIXES = {
    ".py", ".pyi", ".txt", ".md", ".rst", ".toml", ".ini", ".cfg",
    ".json", ".yaml", ".yml", ".html", ".htm", ".css", ".js", ".mjs",
    ".cjs", ".ts", ".tsx", ".jsx", ".jinja", ".j2", ".xml", ".svg",
    ".lock", ".sh", ".ps1",
}


def _stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def is_allowed_source_path(relative_path: str) -> bool:
    path = Path(relative_path)
    name = path.name.casefold()
    if name in SOURCE_ALLOWED_NAMES:
        return True
    return path.suffix.casefold() in SOURCE_ALLOWED_SUFFIXES


def private_backup(app_root: Path, output_dir: Path) -> Path:
    backup = output_dir / "PRIVATE_FULL_BACKUP.tar.gz"
    with tarfile.open(backup, "w:gz") as archive:
        archive.add(app_root, arcname=app_root.name, recursive=True)
    os.chmod(backup, 0o600)
    digest = sha256_file(backup)
    hash_file = output_dir / "PRIVATE_FULL_BACKUP.tar.gz.sha256"
    hash_file.write_text(digest + "  PRIVATE_FULL_BACKUP.tar.gz\n", encoding="utf-8")
    os.chmod(hash_file, 0o600)
    return backup


def build_candidate(app_root: Path, candidate: Path) -> tuple[list[dict], list[dict], list[str]]:
    included: list[dict] = []
    excluded: list[dict] = []
    review_findings: list[str] = []
    candidate.mkdir(parents=True, exist_ok=True)
    for path in sorted(app_root.rglob("*")):
        rel = path.relative_to(app_root).as_posix()
        if path.is_symlink():
            excluded.append({"path": rel, "reason": "SYMLINK_FAIL_CLOSED"})
            review_findings.append(
                f"recovery-candidate: source symlink requires private review: {rel}"
            )
            continue
        if not path.is_file():
            continue
        if is_protected_relative(rel):
            excluded.append({"path": rel, "reason": "BUILTIN_PRIVATE_RUNTIME_POLICY"})
            continue
        if not is_allowed_source_path(rel):
            excluded.append({"path": rel, "reason": "NON_SOURCE_REVIEW_REQUIRED"})
            review_findings.append(
                f"recovery-candidate: non-source artifact requires private review: {rel}"
            )
            continue
        target = candidate / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, target)
        included.append(
            {"path": rel, "size": path.stat().st_size, "sha256": sha256_file(path)}
        )
    return included, excluded, review_findings


def capture(
    app_root: Path,
    recovery_root: Path,
    *,
    repo_root: Path | None = None,
    public_root: Path | None = None,
) -> dict:
    topology = validate_recovery_topology(
        app_root, recovery_root, repo_root=repo_root, public_root=public_root
    )
    app_root = topology["app_root"]
    recovery_root = topology["recovery_root"]
    out = recovery_root / _stamp()
    candidate = out / "candidate"
    out.mkdir(parents=True, exist_ok=False)
    os.chmod(out, 0o700)

    backup = private_backup(app_root, out)
    included, excluded, review_findings = build_candidate(app_root, candidate)
    manifest = build_manifest(candidate)
    manifest.update(
        {
            "generated_at": utc_now_iso(),
            "source_root": str(app_root),
            "included": included,
            "excluded": excluded,
            "source_policy": "positive-source-types-plus-hardened-secret-scan",
        }
    )
    write_json_atomic(out / "CANDIDATE_MANIFEST.json", manifest)

    findings = secret_scan.scan_directory(
        candidate, allowlist_repo=Path("/__no_allowlist__"), scope="recovery-candidate"
    )
    findings.extend(review_findings)
    findings = sorted(set(findings))
    status = {
        "generated_at": utc_now_iso(),
        "private_backup_created": True,
        "private_backup_sha256": sha256_file(backup),
        "candidate_file_count": manifest["count"],
        "scanner_finding_count": len(findings),
        "transfer_performed": False,
        "cron_or_deploy_worker_installed": False,
    }
    if findings:
        status["state"] = "CONTAMINATED_BLOCKED"
        finding_file = out / "SCAN_FINDINGS_REDACTED.txt"
        finding_file.write_text("\n".join(findings) + "\n", encoding="utf-8")
        os.chmod(finding_file, 0o600)
        write_json_atomic(out / "RECOVERY_STATUS.json", status)
        return status

    candidate_archive = out / "SANITIZED_CANDIDATE_PRIVATE.tar.gz"
    with tarfile.open(candidate_archive, "w:gz") as archive:
        archive.add(candidate, arcname=".", recursive=True)
    os.chmod(candidate_archive, 0o600)
    status.update(
        {
            "state": "CANDIDATE_READY_FOR_PRIVATE_AUDIT",
            "candidate_archive_sha256": sha256_file(candidate_archive),
        }
    )
    write_json_atomic(out / "RECOVERY_STATUS.json", status)
    return status


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--app-root", required=True)
    parser.add_argument("--recovery-root", required=True)
    parser.add_argument("--repo-root")
    parser.add_argument("--public-root")
    args = parser.parse_args(argv)
    try:
        status = capture(
            Path(args.app_root),
            Path(args.recovery_root),
            repo_root=Path(args.repo_root) if args.repo_root else None,
            public_root=Path(args.public_root) if args.public_root else None,
        )
    except (SafetyError, OSError, tarfile.TarError) as exc:
        print(f"RECOVERY_FAILED: {type(exc).__name__}")
        return 2
    print(status["state"])
    return 0 if status["state"] == "CANDIDATE_READY_FOR_PRIVATE_AUDIT" else 3


if __name__ == "__main__":
    raise SystemExit(main())
