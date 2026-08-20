# -*- coding: utf-8 -*-
"""Future fail-closed versioned deployer. Production execution is not authorized."""
from __future__ import annotations
import argparse
import os
import shutil
import subprocess
import sys
import tarfile
import venv
from pathlib import Path
from ops.release_guard import SafetyError, apply_retention, atomic_switch_link, copy_protected_state, copy_source_without_protected, load_external_approval, restore_link, sha256_file, utc_now_iso, write_json_atomic

def run(command: list[str], *, cwd: Path | None = None, timeout: int = 300) -> None:
    subprocess.run(command, cwd=cwd, check=True, timeout=timeout, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

def git_export(repo: Path, sha: str, destination: Path) -> None:
    if not repo.joinpath(".git").exists(): raise SafetyError("release repository is not a Git checkout")
    resolved = subprocess.run(["git", "rev-parse", "--verify", f"{sha}^{{commit}}"], cwd=repo, check=True, capture_output=True, text=True).stdout.strip()
    if resolved != sha: raise SafetyError("requested SHA is not exact full commit")
    archive = subprocess.Popen(["git", "archive", sha], cwd=repo, stdout=subprocess.PIPE)
    extract = subprocess.run(["tar", "-x", "-C", str(destination)], stdin=archive.stdout, check=False)
    if archive.stdout: archive.stdout.close()
    rc = archive.wait()
    if rc != 0 or extract.returncode != 0: raise SafetyError("git archive extraction failed")

def build_versioned_release(*, repo: Path, sha: str, live_app: Path, releases_root: Path, python_executable: str) -> Path:
    release_root = releases_root / sha
    if release_root.exists(): raise SafetyError("release directory already exists")
    stage_parent = releases_root / (".stage_" + sha); source = stage_parent / "source"; venv_dir = release_root / ".venv"
    stage_parent.mkdir(parents=True); source.mkdir(); release_root.mkdir(parents=True)
    try:
        git_export(repo, sha, source); copy_source_without_protected(source, release_root)
        if live_app.exists() or live_app.is_symlink(): copy_protected_state(live_app.resolve(strict=True), release_root)
        venv.EnvBuilder(with_pip=True, clear=True).create(venv_dir)
        py = venv_dir / "bin/python"
        if not py.exists(): py = venv_dir / "Scripts/python.exe"
        if not py.exists(): raise SafetyError("versioned Python environment was not created")
        lock = release_root / "requirements.lock"; requirements = release_root / "requirements.txt"
        if requirements.exists() and not lock.exists(): raise SafetyError("requirements.txt exists without requirements.lock; dependency release is not immutable")
        if lock.exists(): run([str(py), "-m", "pip", "install", "--require-hashes", "-r", str(lock)], cwd=release_root, timeout=600)
        run([str(py), "-m", "compileall", "-q", str(release_root)], cwd=release_root)
        if not (release_root / "tests").is_dir(): raise SafetyError("required test suite is absent")
        try: run([str(py), "-c", "import pytest"], cwd=release_root)
        except subprocess.CalledProcessError as exc: raise SafetyError("pytest is unavailable in staged environment") from exc
        run([str(py), "-m", "pytest", "-q", str(release_root / "tests")], cwd=release_root, timeout=300)
        shutil.rmtree(stage_parent, ignore_errors=True); return release_root
    except Exception:
        shutil.rmtree(release_root, ignore_errors=True); shutil.rmtree(stage_parent, ignore_errors=True); raise

def run_smoke_hook(path: Path, name: str) -> None:
    if not path.is_file() or path.is_symlink() or not os.access(path, os.X_OK): raise SafetyError(f"required {name} smoke hook is missing or unsafe")
    subprocess.run([str(path)], check=True, timeout=60, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def backup_active(active_link: Path, backup_root: Path, sha: str) -> Path:
    if not active_link.is_symlink(): raise SafetyError("active application path must be a symlink before automated deployment")
    target = active_link.resolve(strict=True); backup_root.mkdir(parents=True, exist_ok=True); backup = backup_root / f"predeploy_{sha}.tar.gz"
    with tarfile.open(backup, "w:gz") as archive: archive.add(target, arcname=target.name, recursive=True)
    os.chmod(backup, 0o600); hash_path = Path(str(backup) + ".sha256"); hash_path.write_text(sha256_file(backup) + "\n", encoding="utf-8"); os.chmod(hash_path, 0o600); return backup

def _must_be_outside_repo(path: Path, repo: Path, label: str) -> None:
    try: path.resolve().relative_to(repo.resolve())
    except ValueError: return
    raise SafetyError(f"{label} must live outside the release repository")

def deploy(*, repo: Path, sha: str, active_link: Path, releases_root: Path, backup_root: Path, approval_file: Path, unauth_hook: Path, auth_hook: Path, status_file: Path) -> int:
    for path, label in ((approval_file, "approval"), (unauth_hook, "unauthenticated smoke hook"), (auth_hook, "authenticated smoke hook")): _must_be_outside_repo(path, repo, label)
    if not active_link.is_symlink(): raise SafetyError("active application path must already be an operator-prepared symlink")
    load_external_approval(approval_file, sha)
    status = {"sha": sha, "started_at": utc_now_iso(), "state": "STARTED"}; write_json_atomic(status_file, status)
    previous = None
    try:
        new_release = build_versioned_release(repo=repo, sha=sha, live_app=active_link, releases_root=releases_root, python_executable=sys.executable)
        backup = backup_active(active_link, backup_root, sha); status["backup_created"] = True
        previous = atomic_switch_link(active_link, new_release)
        run_smoke_hook(unauth_hook, "unauthenticated"); run_smoke_hook(auth_hook, "authenticated")
        removed_releases = apply_retention([p for p in releases_root.iterdir() if p.is_dir() and not p.name.startswith(".stage_")], active=new_release, last_known_good=previous, keep_newest=5)
        removed_backups = apply_retention(sorted(backup_root.glob("*.tar.gz")), active=None, last_known_good=backup, keep_newest=5)
        status.update({"state": "DEPLOYED", "completed_at": utc_now_iso(), "release_root": str(new_release), "retention_removed_release_count": len(removed_releases), "retention_removed_backup_count": len(removed_backups)})
        write_json_atomic(status_file, status); return 0
    except Exception as exc:
        status.update({"failure_type": type(exc).__name__, "rollback_attempted": previous is not None})
        if previous is not None:
            try:
                restore_link(active_link, previous); run_smoke_hook(unauth_hook, "unauthenticated rollback"); run_smoke_hook(auth_hook, "authenticated rollback")
                status.update({"state": "ROLLED_BACK", "completed_at": utc_now_iso()}); write_json_atomic(status_file, status); return 20
            except Exception as rollback_exc:
                status.update({"state": "CRITICAL_ROLLBACK_FAILED", "rollback_failure_type": type(rollback_exc).__name__, "completed_at": utc_now_iso()}); write_json_atomic(status_file, status); return 70
        status.update({"state": "PRELIVE_FAILED", "completed_at": utc_now_iso()}); write_json_atomic(status_file, status); return 10

def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    for name in ("repo","sha","active-link","releases-root","backup-root","approval-file","unauth-smoke-hook","auth-smoke-hook","status-file"): parser.add_argument("--" + name, required=True)
    parser.add_argument("--execute", action="store_true"); args = parser.parse_args(argv)
    if not args.execute:
        print("DRY_RUN_ONLY: pass --execute only after independent audit and private operator authorization"); return 0
    try:
        return deploy(repo=Path(args.repo), sha=args.sha, active_link=Path(args.active_link), releases_root=Path(args.releases_root), backup_root=Path(args.backup_root), approval_file=Path(args.approval_file), unauth_hook=Path(args.unauth_smoke_hook), auth_hook=Path(args.auth_smoke_hook), status_file=Path(args.status_file))
    except SafetyError as exc:
        print(f"DEPLOYMENT_BLOCKED: {type(exc).__name__}"); return 2
if __name__ == "__main__": raise SystemExit(main())
