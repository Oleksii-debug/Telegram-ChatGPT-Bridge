# -*- coding: utf-8 -*-
"""Future fail-closed versioned deployer. Production execution is not authorized."""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import tarfile
from pathlib import Path

from ops.release_guard import (
    SafetyError,
    apply_backup_retention,
    apply_retention,
    atomic_switch_link,
    attach_persistent_state,
    build_manifest,
    cleanup_stale_staging,
    consume_external_approval,
    copy_source_without_protected,
    load_external_approval,
    load_runtime_manifest,
    require_under_control_root,
    restore_link,
    sha256_file,
    sha256_json,
    utc_now_iso,
    validate_deployment_topology,
    validate_persistent_bindings,
    write_json_atomic,
)

FULL_SHA_RE = re.compile(r"^[0-9a-f]{40}$")


def run(command: list[str], *, cwd: Path | None = None, timeout: int = 300) -> None:
    subprocess.run(
        command,
        cwd=cwd,
        check=True,
        timeout=timeout,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def command_output(command: list[str], *, cwd: Path | None = None, timeout: int = 60) -> str:
    return subprocess.run(
        command,
        cwd=cwd,
        check=True,
        timeout=timeout,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    ).stdout.strip()


def validate_python_311(python_executable: str) -> str:
    executable = Path(python_executable)
    if not executable.is_file() or executable.is_symlink() or not os.access(executable, os.X_OK):
        raise SafetyError("approved Python executable is missing or unsafe")
    try:
        version = command_output(
            [str(executable), "-c", "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}')"]
        )
    except (subprocess.SubprocessError, OSError) as exc:
        raise SafetyError("approved Python interpreter could not be verified") from exc
    if not version.startswith("3.11."):
        raise SafetyError("release requires approved Python 3.11")
    return version


def git_export(repo: Path, sha: str, destination: Path) -> None:
    if not repo.joinpath(".git").exists():
        raise SafetyError("release repository is not a Git checkout")
    resolved = command_output(
        ["git", "rev-parse", "--verify", f"{sha}^{{commit}}"], cwd=repo
    )
    if resolved != sha or not FULL_SHA_RE.fullmatch(sha):
        raise SafetyError("requested SHA is not exact full commit")
    archive = subprocess.Popen(["git", "archive", sha], cwd=repo, stdout=subprocess.PIPE)
    extract = subprocess.run(
        ["tar", "-x", "-C", str(destination)], stdin=archive.stdout, check=False
    )
    if archive.stdout:
        archive.stdout.close()
    rc = archive.wait()
    if rc != 0 or extract.returncode != 0:
        raise SafetyError("git archive extraction failed")


def _requirements_lock_hash(release_root: Path) -> str | None:
    lock = release_root / "requirements.lock"
    return sha256_file(lock) if lock.exists() else None


def build_versioned_release(
    *,
    repo: Path,
    sha: str,
    releases_root: Path,
    python_executable: str,
    persistent_state_root: Path,
    runtime_entries: list[str],
    repository_id: str,
    approved_ref: str,
) -> tuple[Path, dict, str]:
    python_version = validate_python_311(python_executable)
    releases_root.mkdir(parents=True, exist_ok=True)
    final_release = releases_root / sha
    if final_release.exists():
        raise SafetyError("release directory already exists")
    stage_parent = releases_root / (".stage_" + sha)
    if stage_parent.exists() or stage_parent.is_symlink():
        raise SafetyError("staging directory already exists")
    source = stage_parent / "source"
    release_temp = stage_parent / "release"
    source.mkdir(parents=True)
    release_temp.mkdir(parents=True)
    (stage_parent / "ACTIVE_LOCK").write_text("building\n", encoding="utf-8")
    try:
        git_export(repo, sha, source)
        copy_source_without_protected(source, release_temp)
        source_manifest = build_manifest(release_temp)
        source_manifest_sha256 = sha256_json(source_manifest)

        requirements = release_temp / "requirements.txt"
        lock = release_temp / "requirements.lock"
        if requirements.exists() and not lock.exists():
            raise SafetyError(
                "requirements.txt exists without requirements.lock; dependency release is not immutable"
            )

        venv_dir = release_temp / ".venv"
        run([python_executable, "-m", "venv", str(venv_dir)], timeout=300)
        py = venv_dir / "bin/python"
        if not py.exists():
            py = venv_dir / "Scripts/python.exe"
        if not py.exists():
            raise SafetyError("versioned Python environment was not created")
        built_version = command_output(
            [str(py), "-c", "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}')"]
        )
        if not built_version.startswith("3.11."):
            raise SafetyError("versioned environment is not Python 3.11")

        if lock.exists():
            run(
                [str(py), "-m", "pip", "install", "--require-hashes", "-r", str(lock)],
                cwd=release_temp,
                timeout=600,
            )
        run([str(py), "-m", "compileall", "-q", str(release_temp)], cwd=release_temp)
        if not (release_temp / "tests").is_dir():
            raise SafetyError("required test suite is absent")
        try:
            run([str(py), "-c", "import pytest"], cwd=release_temp)
        except subprocess.CalledProcessError as exc:
            raise SafetyError("pytest is unavailable in staged environment") from exc
        run(
            [str(py), "-m", "pytest", "-q", str(release_temp / "tests")],
            cwd=release_temp,
            timeout=300,
        )

        attach_persistent_state(release_temp, persistent_state_root, runtime_entries)
        provenance = {
            "repository": repository_id,
            "approved_ref": approved_ref,
            "sha": sha,
            "python_version": built_version,
            "source_manifest_sha256": source_manifest_sha256,
            "requirements_lock_sha256": _requirements_lock_hash(release_temp),
            "persistent_state_mode": "shared_external",
            "generated_at": utc_now_iso(),
        }
        provenance_hash = sha256_json(provenance)
        write_json_atomic(release_temp / "RELEASE_PROVENANCE.json", provenance, mode=0o644)
        (stage_parent / "ACTIVE_LOCK").unlink(missing_ok=True)
        os.replace(release_temp, final_release)
        shutil.rmtree(stage_parent, ignore_errors=True)
        return final_release, provenance, provenance_hash
    except Exception:
        (stage_parent / "ACTIVE_LOCK").unlink(missing_ok=True)
        shutil.rmtree(stage_parent, ignore_errors=True)
        raise


def run_private_hook(path: Path, name: str, *, timeout: int = 60, args: list[str] | None = None) -> None:
    if not path.is_file() or path.is_symlink() or not os.access(path, os.X_OK):
        raise SafetyError(f"required {name} hook is missing or unsafe")
    try:
        subprocess.run(
            [str(path), *(args or [])],
            check=True,
            timeout=timeout,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except subprocess.TimeoutExpired as exc:
        raise SafetyError(f"required {name} hook timed out") from exc
    except subprocess.CalledProcessError as exc:
        raise SafetyError(f"required {name} hook failed") from exc


def verify_running_release(identity_hook: Path, expected_sha: str) -> None:
    if not FULL_SHA_RE.fullmatch(expected_sha):
        raise SafetyError("expected running release identity is not a full SHA")
    run_private_hook(
        identity_hook,
        "running-release identity",
        timeout=45,
        args=[expected_sha],
    )


def _write_hash_pair(archive: Path) -> None:
    hash_path = Path(str(archive) + ".sha256")
    hash_path.write_text(sha256_file(archive) + "  " + archive.name + "\n", encoding="utf-8")
    os.chmod(hash_path, 0o600)


def backup_active(active_link: Path, backup_root: Path, sha: str) -> Path:
    if not active_link.is_symlink():
        raise SafetyError("active application path must be a symlink before automated deployment")
    target = active_link.resolve(strict=True)
    backup_root.mkdir(parents=True, exist_ok=True)
    backup = backup_root / f"code_predeploy_{sha}.tar.gz"
    with tarfile.open(backup, "w:gz", dereference=False) as archive:
        archive.add(target, arcname=target.name, recursive=True)
    os.chmod(backup, 0o600)
    _write_hash_pair(backup)
    return backup


def backup_persistent_state(state_root: Path, backup_root: Path, sha: str) -> Path:
    state_root = state_root.resolve(strict=True)
    backup_root.mkdir(parents=True, exist_ok=True)
    backup = backup_root / f"state_predeploy_{sha}.tar.gz"
    with tarfile.open(backup, "w:gz", dereference=False) as archive:
        archive.add(state_root, arcname="persistent_state", recursive=True)
    os.chmod(backup, 0o600)
    _write_hash_pair(backup)
    return backup


def _active_release_sha(active_link: Path) -> str:
    target = active_link.resolve(strict=True)
    if not FULL_SHA_RE.fullmatch(target.name):
        raise SafetyError("active release directory is not named by a full Git SHA")
    return target.name


def deploy(
    *,
    repo: Path,
    sha: str,
    repository_id: str,
    approved_ref: str,
    ci_run_id: str,
    audit_id: str,
    active_link: Path,
    releases_root: Path,
    backup_root: Path,
    persistent_state_root: Path,
    runtime_manifest: Path,
    control_root: Path,
    approval_file: Path,
    approval_consumption_root: Path,
    quiesce_hook: Path,
    restart_hook: Path,
    identity_hook: Path,
    unauth_hook: Path,
    auth_hook: Path,
    status_file: Path,
    python_executable: str,
    public_root: Path | None = None,
) -> int:
    topology = validate_deployment_topology(
        repo=repo,
        active_link=active_link,
        releases_root=releases_root,
        backup_root=backup_root,
        persistent_state_root=persistent_state_root,
        control_root=control_root,
        public_root=public_root,
    )
    repo = topology["repo"]
    releases_root = topology["releases_root"]
    backup_root = topology["backup_root"]
    persistent_state_root = topology["persistent_state_root"]
    control_root = topology["control_root"]
    active_link = topology["active_link"]

    for path, label in (
        (runtime_manifest, "runtime manifest"),
        (approval_file, "approval"),
        (approval_consumption_root, "approval consumption root"),
        (quiesce_hook, "quiesce hook"),
        (restart_hook, "restart hook"),
        (identity_hook, "running-release identity hook"),
        (unauth_hook, "unauthenticated smoke hook"),
        (auth_hook, "authenticated smoke hook"),
        (status_file, "status file"),
    ):
        require_under_control_root(path, control_root, label)

    if not active_link.is_symlink():
        raise SafetyError("active application path must already be an operator-prepared symlink")
    runtime_entries = load_runtime_manifest(runtime_manifest)
    previous_target = active_link.resolve(strict=True)
    previous_sha = _active_release_sha(active_link)
    validate_persistent_bindings(previous_target, persistent_state_root, runtime_entries)
    cleanup_stale_staging(releases_root, older_than_seconds=86400)

    status = {
        "sha": sha,
        "repository": repository_id,
        "approved_ref": approved_ref,
        "started_at": utc_now_iso(),
        "state": "STARTED",
    }
    write_json_atomic(status_file, status)
    previous = None
    quiesced = False
    approval_consumed = False
    code_backup: Path | None = None
    state_backup: Path | None = None
    try:
        new_release, provenance, provenance_hash = build_versioned_release(
            repo=repo,
            sha=sha,
            releases_root=releases_root,
            python_executable=python_executable,
            persistent_state_root=persistent_state_root,
            runtime_entries=runtime_entries,
            repository_id=repository_id,
            approved_ref=approved_ref,
        )
        approval = load_external_approval(
            approval_file,
            expected_sha=sha,
            expected_repository=repository_id,
            expected_ref=approved_ref,
            expected_manifest_sha256=provenance_hash,
            expected_ci_run_id=ci_run_id,
            expected_audit_id=audit_id,
        )
        consume_external_approval(approval, approval_consumption_root)
        approval_consumed = True
        status.update(
            {
                "approval_id": str(approval["approval_id"]),
                "release_manifest_sha256": provenance_hash,
                "python_version": provenance["python_version"],
            }
        )
        write_json_atomic(status_file, status)

        run_private_hook(quiesce_hook, "quiesce", timeout=90)
        quiesced = True
        code_backup = backup_active(active_link, backup_root / "code", sha)
        state_backup = backup_persistent_state(
            persistent_state_root, backup_root / "state", sha
        )
        status.update({"code_backup_created": True, "state_backup_created": True})
        write_json_atomic(status_file, status)

        previous = atomic_switch_link(active_link, new_release)
        run_private_hook(restart_hook, "restart/reload", timeout=90)
        verify_running_release(identity_hook, sha)
        run_private_hook(unauth_hook, "unauthenticated smoke", timeout=60)
        run_private_hook(auth_hook, "authenticated smoke", timeout=60)
        quiesced = False

        removed_releases = apply_retention(
            [p for p in releases_root.iterdir() if p.is_dir() and not p.name.startswith(".stage_")],
            active=new_release,
            last_known_good=previous,
            keep_newest=5,
        )
        removed_code_backups = apply_backup_retention(
            backup_root / "code", last_known_good=code_backup, keep_newest=5
        )
        removed_state_backups = apply_backup_retention(
            backup_root / "state", last_known_good=state_backup, keep_newest=5
        )
        cleanup_stale_staging(releases_root, older_than_seconds=86400)
        status.update(
            {
                "state": "DEPLOYED",
                "completed_at": utc_now_iso(),
                "release_root": str(new_release),
                "persistent_state_mode": "shared_external",
                "retention_removed_release_count": len(removed_releases),
                "retention_removed_code_backup_count": len(removed_code_backups),
                "retention_removed_state_backup_count": len(removed_state_backups),
            }
        )
        write_json_atomic(status_file, status)
        return 0
    except Exception as exc:
        status.update(
            {
                "failure_type": type(exc).__name__,
                "rollback_attempted": previous is not None,
                "approval_consumed": approval_consumed,
            }
        )
        if previous is not None:
            try:
                restore_link(active_link, previous)
                run_private_hook(restart_hook, "rollback restart/reload", timeout=90)
                verify_running_release(identity_hook, previous_sha)
                run_private_hook(unauth_hook, "unauthenticated rollback smoke", timeout=60)
                run_private_hook(auth_hook, "authenticated rollback smoke", timeout=60)
                status.update(
                    {
                        "state": "ROLLED_BACK",
                        "completed_at": utc_now_iso(),
                        "persistent_state_restored": False,
                        "persistent_state_note": "shared mutable state remains authoritative and is not reverted by code rollback",
                    }
                )
                write_json_atomic(status_file, status)
                return 20
            except Exception as rollback_exc:
                status.update(
                    {
                        "state": "CRITICAL_ROLLBACK_FAILED",
                        "rollback_failure_type": type(rollback_exc).__name__,
                        "completed_at": utc_now_iso(),
                    }
                )
                write_json_atomic(status_file, status)
                return 70
        if quiesced:
            try:
                run_private_hook(restart_hook, "prelive recovery restart/reload", timeout=90)
                verify_running_release(identity_hook, previous_sha)
                run_private_hook(unauth_hook, "prelive recovery unauthenticated smoke", timeout=60)
                run_private_hook(auth_hook, "prelive recovery authenticated smoke", timeout=60)
            except Exception as recovery_exc:
                status.update(
                    {
                        "state": "CRITICAL_PRELIVE_RECOVERY_FAILED",
                        "recovery_failure_type": type(recovery_exc).__name__,
                        "completed_at": utc_now_iso(),
                    }
                )
                write_json_atomic(status_file, status)
                return 71
        status.update({"state": "PRELIVE_FAILED", "completed_at": utc_now_iso()})
        write_json_atomic(status_file, status)
        return 10


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    for name in (
        "repo", "sha", "repository-id", "approved-ref", "ci-run-id", "audit-id",
        "active-link", "releases-root", "backup-root", "persistent-state-root",
        "runtime-manifest", "control-root", "approval-file", "approval-consumption-root",
        "quiesce-hook", "restart-hook", "identity-hook", "unauth-smoke-hook",
        "auth-smoke-hook", "status-file", "python-executable",
    ):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--public-root")
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args(argv)
    if not args.execute:
        print(
            "DRY_RUN_ONLY: pass --execute only after independent audit and private operator authorization"
        )
        return 0
    try:
        return deploy(
            repo=Path(args.repo),
            sha=args.sha,
            repository_id=args.repository_id,
            approved_ref=args.approved_ref,
            ci_run_id=args.ci_run_id,
            audit_id=args.audit_id,
            active_link=Path(args.active_link),
            releases_root=Path(args.releases_root),
            backup_root=Path(args.backup_root),
            persistent_state_root=Path(args.persistent_state_root),
            runtime_manifest=Path(args.runtime_manifest),
            control_root=Path(args.control_root),
            approval_file=Path(args.approval_file),
            approval_consumption_root=Path(args.approval_consumption_root),
            quiesce_hook=Path(args.quiesce_hook),
            restart_hook=Path(args.restart_hook),
            identity_hook=Path(args.identity_hook),
            unauth_hook=Path(args.unauth_smoke_hook),
            auth_hook=Path(args.auth_smoke_hook),
            status_file=Path(args.status_file),
            python_executable=args.python_executable,
            public_root=Path(args.public_root) if args.public_root else None,
        )
    except SafetyError as exc:
        print(f"DEPLOYMENT_BLOCKED: {type(exc).__name__}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
