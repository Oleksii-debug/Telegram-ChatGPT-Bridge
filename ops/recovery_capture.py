# -*- coding: utf-8 -*-
"""Recovery-only production baseline capture; no cron, mail, or deployment."""
from __future__ import annotations

import argparse
import os
import shutil
import tarfile
from datetime import datetime, timezone
from pathlib import Path

from ops.release_guard import SafetyError, build_manifest, is_protected_relative, sha256_file, utc_now_iso, write_json_atomic
from tools import secret_scan

def _stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

def private_backup(app_root: Path, output_dir: Path) -> Path:
    backup = output_dir / "PRIVATE_FULL_BACKUP.tar.gz"
    with tarfile.open(backup, "w:gz") as archive:
        archive.add(app_root, arcname=app_root.name, recursive=True)
    os.chmod(backup, 0o600)
    digest = sha256_file(backup)
    hash_file = output_dir / "PRIVATE_FULL_BACKUP.sha256"
    hash_file.write_text(digest + "  PRIVATE_FULL_BACKUP.tar.gz\n", encoding="utf-8")
    os.chmod(hash_file, 0o600)
    return backup

def build_candidate(app_root: Path, candidate: Path) -> tuple[list[dict], list[dict]]:
    included: list[dict] = []; excluded: list[dict] = []
    candidate.mkdir(parents=True, exist_ok=True)
    for path in sorted(app_root.rglob("*")):
        rel = path.relative_to(app_root).as_posix()
        if path.is_symlink():
            excluded.append({"path": rel, "reason": "SYMLINK_FAIL_CLOSED"}); continue
        if not path.is_file(): continue
        if is_protected_relative(rel):
            excluded.append({"path": rel, "reason": "BUILTIN_PRIVATE_RUNTIME_POLICY"}); continue
        target = candidate / rel; target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, target)
        included.append({"path": rel, "size": path.stat().st_size, "sha256": sha256_file(path)})
    return included, excluded

def capture(app_root: Path, recovery_root: Path) -> dict:
    app_root = app_root.resolve()
    if not app_root.is_dir(): raise SafetyError("application root not found")
    out = recovery_root / _stamp(); candidate = out / "candidate"
    out.mkdir(parents=True, exist_ok=False); os.chmod(out, 0o700)
    backup = private_backup(app_root, out)
    included, excluded = build_candidate(app_root, candidate)
    manifest = build_manifest(candidate)
    manifest.update({"generated_at": utc_now_iso(), "source_root": str(app_root), "included": included, "excluded": excluded})
    write_json_atomic(out / "CANDIDATE_MANIFEST.json", manifest)
    findings = secret_scan.scan_directory(candidate, allowlist_repo=Path("/__no_allowlist__"), scope="recovery-candidate")
    for item in excluded:
        if item.get("reason") == "SYMLINK_FAIL_CLOSED":
            findings.append(f"recovery-candidate: source symlink requires private review: {item['path']}")
    findings = sorted(set(findings))
    status = {"generated_at": utc_now_iso(), "private_backup_created": True, "private_backup_sha256": sha256_file(backup), "candidate_file_count": manifest["count"], "scanner_finding_count": len(findings), "transfer_performed": False, "cron_or_deploy_worker_installed": False}
    if findings:
        status["state"] = "CONTAMINATED_BLOCKED"
        finding_file = out / "SCAN_FINDINGS_REDACTED.txt"
        finding_file.write_text("\n".join(findings) + "\n", encoding="utf-8"); os.chmod(finding_file, 0o600)
        write_json_atomic(out / "RECOVERY_STATUS.json", status); return status
    candidate_archive = out / "SANITIZED_CANDIDATE_PRIVATE.tar.gz"
    with tarfile.open(candidate_archive, "w:gz") as archive: archive.add(candidate, arcname=".", recursive=True)
    os.chmod(candidate_archive, 0o600)
    status.update({"state": "CANDIDATE_READY_FOR_PRIVATE_AUDIT", "candidate_archive_sha256": sha256_file(candidate_archive)})
    write_json_atomic(out / "RECOVERY_STATUS.json", status); return status

def main(argv=None) -> int:
    parser = argparse.ArgumentParser(); parser.add_argument("--app-root", required=True); parser.add_argument("--recovery-root", required=True); args = parser.parse_args(argv)
    try: status = capture(Path(args.app_root), Path(args.recovery_root))
    except (SafetyError, OSError, tarfile.TarError) as exc:
        print(f"RECOVERY_FAILED: {type(exc).__name__}"); return 2
    print(status["state"]); return 0 if status["state"] == "CANDIDATE_READY_FOR_PRIVATE_AUDIT" else 3
if __name__ == "__main__": raise SystemExit(main())
