# -*- coding: utf-8 -*-
"""Audited PREPARE -> APPROVE -> EXECUTE deployment primitives. Production execution is gated."""
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
    SafetyError, apply_backup_retention, apply_retention, atomic_switch_link,
    attach_persistent_state, build_manifest, cleanup_stale_staging,
    consume_external_approval, load_external_approval, load_runtime_manifest,
    restore_link, sha256_file, sha256_json, validate_deployment_topology,
    validate_exact_source_payload, validate_persistent_bindings,
    validate_private_control_dir, validate_private_control_file,
    validate_private_control_root, write_json_atomic, utc_now_iso,
)

FULL_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
SAFE_REF_RE = re.compile(r"^(?:refs/heads/)?[A-Za-z0-9._/-]+$")
PREPARED_META = "PREPARED_RELEASE.json"


def run(command: list[str], *, cwd: Path | None = None, timeout: int = 300) -> None:
    subprocess.run(command, cwd=cwd, check=True, timeout=timeout,
                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)


def command_output(command: list[str], *, cwd: Path | None = None, timeout: int = 60) -> str:
    return subprocess.run(command, cwd=cwd, check=True, timeout=timeout,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True).stdout.strip()


def _canonical_python(python_executable: str) -> Path:
    candidate = Path(python_executable)
    if not candidate.is_absolute() and len(candidate.parts) == 1:
        found = shutil.which(python_executable)
        if found:
            candidate = Path(found)
    try:
        executable = candidate.resolve(strict=True)
    except OSError as exc:
        raise SafetyError("approved Python executable is missing or unsafe") from exc
    if not executable.is_file() or not os.access(executable, os.X_OK):
        raise SafetyError("approved Python executable is missing or unsafe")
    return executable


def validate_python_311(python_executable: str) -> str:
    executable = _canonical_python(python_executable)
    try:
        version = command_output([str(executable), "-c", "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}')"])
    except (subprocess.SubprocessError, OSError) as exc:
        raise SafetyError("approved Python interpreter could not be verified") from exc
    if not version.startswith("3.11."):
        raise SafetyError("release requires approved Python 3.11")
    return version


def verify_approved_ref_policy(repo: Path, sha: str, approved_ref: str) -> str:
    if not FULL_SHA_RE.fullmatch(sha) or not SAFE_REF_RE.fullmatch(approved_ref or ""):
        raise SafetyError("invalid SHA/ref policy input")
    try:
        commit = command_output(["git", "rev-parse", "--verify", f"{sha}^{{commit}}"], cwd=repo)
        ref_commit = command_output(["git", "rev-parse", "--verify", f"{approved_ref}^{{commit}}"], cwd=repo)
    except subprocess.SubprocessError as exc:
        raise SafetyError("approved Git ref/commit cannot be resolved") from exc
    if commit != sha:
        raise SafetyError("requested SHA is not an exact full commit")
    if ref_commit != sha:
        raise SafetyError("approved SHA is not the exact head of approved ref")
    return ref_commit


def git_export(repo: Path, sha: str, destination: Path) -> None:
    if not repo.joinpath(".git").exists():
        raise SafetyError("release repository is not a Git checkout")
    resolved = command_output(["git", "rev-parse", "--verify", f"{sha}^{{commit}}"], cwd=repo)
    if resolved != sha or not FULL_SHA_RE.fullmatch(sha):
        raise SafetyError("requested SHA is not exact full commit")
    archive = subprocess.Popen(["git", "archive", sha], cwd=repo, stdout=subprocess.PIPE)
    extract = subprocess.run(["tar", "-x", "-C", str(destination)], stdin=archive.stdout, check=False)
    if archive.stdout:
        archive.stdout.close()
    rc = archive.wait()
    if rc != 0 or extract.returncode != 0:
        raise SafetyError("git archive extraction failed")


def _safe_venv_symlink(root: Path, link: Path, approved_python_real: Path | None) -> dict:
    rel = link.relative_to(root).as_posix()
    if not rel.startswith(".venv/"):
        raise SafetyError("prepared payload contains unexpected symlink")
    try:
        resolved = link.resolve(strict=True)
        venv_root = (root / ".venv").resolve(strict=True)
    except OSError as exc:
        raise SafetyError("prepared venv symlink is broken") from exc
    inside_venv = resolved == venv_root or venv_root in resolved.parents
    approved_external = approved_python_real is not None and resolved == approved_python_real
    if not inside_venv and not approved_external:
        if not rel.startswith(".venv/bin/") or not resolved.is_file() or not os.access(resolved, os.X_OK):
            raise SafetyError("prepared venv symlink escapes approved venv/Python boundary")
        try:
            version = command_output([str(resolved), "-c", "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')"])
        except (subprocess.SubprocessError, OSError) as exc:
            raise SafetyError("prepared venv external symlink target is not verifiable Python") from exc
        if version != "3.11":
            raise SafetyError("prepared venv external symlink target is not Python 3.11")
    return {"path": rel, "type": "symlink", "target": os.readlink(link)}


def _payload_manifest_without_meta(root: Path, approved_python_real: Path | None = None) -> dict:
    items = []
    for p in sorted(root.rglob("*")):
        if p.is_symlink():
            items.append(_safe_venv_symlink(root, p, approved_python_real))
            continue
        if p.is_file():
            rel = p.relative_to(root).as_posix()
            if rel == PREPARED_META:
                continue
            items.append({"path": rel, "type": "file", "size": p.stat().st_size, "sha256": sha256_file(p)})
    return {"files": items, "count": len(items)}


def _install_locked_requirements(py: Path, source: Path, input_name: str, lock_name: str) -> str | None:
    source_file = source / input_name
    lock = source / lock_name
    if source_file.exists() and not lock.exists():
        raise SafetyError(f"{input_name} exists without {lock_name}; dependencies are not immutable")
    if lock.exists():
        run([str(py), "-m", "pip", "install", "--require-hashes", "-r", str(lock)], cwd=source, timeout=600)
        return sha256_file(lock)
    return None


def prepare_versioned_release(*, repo: Path, sha: str, approved_ref: str, repository_id: str,
                              releases_root: Path, python_executable: str,
                              runtime_entries: list[str]) -> tuple[Path, dict, str]:
    verify_approved_ref_policy(repo, sha, approved_ref)
    configured_version = validate_python_311(python_executable)
    approved_python_real = _canonical_python(python_executable)
    releases_root.mkdir(parents=True, exist_ok=True)
    prepared_root = releases_root / ".prepared"
    prepared_root.mkdir(parents=True, exist_ok=True)
    stage = releases_root / (".stage_prepare_" + sha)
    if stage.exists() or stage.is_symlink():
        raise SafetyError("prepare staging directory already exists")
    source = stage / "release"
    source.mkdir(parents=True)
    (stage / "ACTIVE_LOCK").write_text("preparing\n", encoding="utf-8")
    try:
        git_export(repo, sha, source)
        validate_exact_source_payload(source, runtime_entries)
        source_manifest_sha = sha256_json(build_manifest(source))
        venv_dir = source / ".venv"
        run([str(approved_python_real), "-m", "venv", str(venv_dir)], timeout=300)
        py = venv_dir / "bin/python"
        if not py.exists():
            py = venv_dir / "Scripts/python.exe"
        if not py.exists():
            raise SafetyError("versioned Python environment was not created")
        built_version = command_output([str(py), "-c", "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}')"])
        if not built_version.startswith("3.11."):
            raise SafetyError("versioned environment is not Python 3.11")
        app_lock_hash = _install_locked_requirements(py, source, "requirements.txt", "requirements.lock")
        test_lock_hash = _install_locked_requirements(py, source, "requirements-test.txt", "requirements-test.lock")
        run([str(py), "-m", "compileall", "-q", str(source)], cwd=source)
        if not (source / "tests").is_dir():
            raise SafetyError("required test suite is absent")
        run([str(py), "-m", "unittest", "discover", "-s", "tests", "-v"], cwd=source, timeout=300)
        payload_manifest = _payload_manifest_without_meta(source, approved_python_real)
        prepared = {
            "schema_version": 2,
            "repository": repository_id,
            "approved_ref": approved_ref,
            "sha": sha,
            "configured_python_version": configured_version,
            "python_version": built_version,
            "source_manifest_sha256": source_manifest_sha,
            "requirements_lock_sha256": app_lock_hash,
            "requirements_test_lock_sha256": test_lock_hash,
            "payload_manifest_sha256": sha256_json(payload_manifest),
            "runtime_entries": sorted(runtime_entries),
            "persistent_state_mode": "shared_external",
        }
        prepared_hash = sha256_json(prepared)
        write_json_atomic(source / PREPARED_META, prepared, mode=0o644)
        destination = prepared_root / f"{sha}-{prepared_hash[:16]}"
        if destination.exists() or destination.is_symlink():
            raise SafetyError("prepared release already exists")
        (stage / "ACTIVE_LOCK").unlink(missing_ok=True)
        os.replace(source, destination)
        shutil.rmtree(stage, ignore_errors=True)
        return destination, prepared, prepared_hash
    except Exception:
        (stage / "ACTIVE_LOCK").unlink(missing_ok=True)
        shutil.rmtree(stage, ignore_errors=True)
        raise


def verify_prepared_release(prepared_release: Path, expected_manifest_hash: str) -> dict:
    if not prepared_release.is_dir() or prepared_release.is_symlink():
        raise SafetyError("prepared release missing or unsafe")
    meta_path = prepared_release / PREPARED_META
    if not meta_path.is_file() or meta_path.is_symlink():
        raise SafetyError("prepared release metadata missing")
    try:
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SafetyError("prepared release metadata invalid") from exc
    if sha256_json(meta) != expected_manifest_hash:
        raise SafetyError("prepared release manifest hash mismatch")
    payload = _payload_manifest_without_meta(prepared_release)
    if sha256_json(payload) != meta.get("payload_manifest_sha256"):
        raise SafetyError("prepared release payload changed after approval")
    return meta


def run_private_hook(path: Path, name: str, *, timeout: int = 60, args: list[str] | None = None) -> None:
    try:
        subprocess.run([str(path), *(args or [])], check=True, timeout=timeout,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except subprocess.TimeoutExpired as exc:
        raise SafetyError(f"required {name} hook timed out") from exc
    except subprocess.CalledProcessError as exc:
        raise SafetyError(f"required {name} hook failed") from exc


def verify_running_release(identity_hook: Path, expected_sha: str) -> None:
    if not FULL_SHA_RE.fullmatch(expected_sha):
        raise SafetyError("expected running release identity is not a full SHA")
    run_private_hook(identity_hook, "running-release identity", timeout=45, args=[expected_sha])


def _write_hash_pair(archive: Path) -> None:
    hp = Path(str(archive) + ".sha256")
    hp.write_text(sha256_file(archive) + "  " + archive.name + "\n", encoding="utf-8")
    os.chmod(hp, 0o600)


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


def _validate_control_plane(*, control_root: Path, runtime_manifest: Path, approval_file: Path,
                            approval_consumption_root: Path, quiesce_hook: Path, resume_hook: Path,
                            restart_hook: Path, identity_hook: Path, unauth_hook: Path, auth_hook: Path,
                            status_file: Path) -> None:
    validate_private_control_root(control_root)
    validate_private_control_file(runtime_manifest, control_root, "runtime manifest")
    validate_private_control_file(approval_file, control_root, "approval")
    for path, label in ((quiesce_hook,"quiesce hook"),(resume_hook,"resume hook"),(restart_hook,"restart hook"),
                        (identity_hook,"identity hook"),(unauth_hook,"unauthenticated smoke hook"),(auth_hook,"authenticated smoke hook")):
        validate_private_control_file(path, control_root, label, executable=True)
    validate_private_control_dir(approval_consumption_root, control_root, "approval consumption root", create=True)
    if status_file.exists():
        validate_private_control_file(status_file, control_root, "status file")
    else:
        validate_private_control_dir(status_file.parent, control_root, "status parent")


def _preflight_persistent_sources(state_root: Path, runtime_entries: list[str]) -> None:
    state_root = state_root.resolve(strict=True)
    for rel in runtime_entries:
        source = state_root / rel
        if not source.exists() or source.is_symlink():
            raise SafetyError("persistent state entry missing or unsafe")


def _materialize_final_release(prepared_release: Path, releases_root: Path, sha: str,
                               persistent_state_root: Path, runtime_entries: list[str]) -> Path:
    final_release = releases_root / sha
    stage = releases_root / (".finalize_" + sha)
    if final_release.exists() or final_release.is_symlink():
        raise SafetyError("target release already exists")
    if stage.exists() or stage.is_symlink():
        raise SafetyError("finalization staging directory already exists")
    try:
        shutil.copytree(prepared_release, stage, symlinks=True)
        attach_persistent_state(stage, persistent_state_root, runtime_entries)
        validate_persistent_bindings(stage, persistent_state_root, runtime_entries)
        os.replace(stage, final_release)
        return final_release
    except Exception:
        shutil.rmtree(stage, ignore_errors=True)
        raise


def execute_prepared_release(*, repo: Path, prepared_release: Path, repository_id: str,
                             approved_ref: str, ci_run_id: str, audit_id: str,
                             active_link: Path, releases_root: Path, backup_root: Path,
                             persistent_state_root: Path, runtime_manifest: Path,
                             control_root: Path, approval_file: Path,
                             approval_consumption_root: Path, quiesce_hook: Path,
                             resume_hook: Path, restart_hook: Path, identity_hook: Path,
                             unauth_hook: Path, auth_hook: Path, status_file: Path,
                             public_root: Path | None = None) -> int:
    topology = validate_deployment_topology(repo=repo, active_link=active_link, releases_root=releases_root,
        backup_root=backup_root, persistent_state_root=persistent_state_root, control_root=control_root, public_root=public_root)
    repo=topology["repo"]; releases_root=topology["releases_root"]; backup_root=topology["backup_root"]
    persistent_state_root=topology["persistent_state_root"]; control_root=topology["control_root"]; active_link=topology["active_link"]
    _validate_control_plane(control_root=control_root,runtime_manifest=runtime_manifest,approval_file=approval_file,
        approval_consumption_root=approval_consumption_root,quiesce_hook=quiesce_hook,resume_hook=resume_hook,
        restart_hook=restart_hook,identity_hook=identity_hook,unauth_hook=unauth_hook,auth_hook=auth_hook,status_file=status_file)
    runtime_entries=load_runtime_manifest(runtime_manifest)
    try:
        approval_raw=json.loads(approval_file.read_text(encoding="utf-8"))
    except Exception as exc:
        raise SafetyError("external approval file is invalid") from exc
    expected_hash=str(approval_raw.get("release_manifest_sha256",""))
    if not re.fullmatch(r"[0-9a-f]{64}", expected_hash):
        raise SafetyError("approval prepared-manifest hash is invalid")
    prepared=verify_prepared_release(prepared_release, expected_hash)
    sha=str(prepared.get("sha",""))
    verify_approved_ref_policy(repo, sha, approved_ref)
    if prepared.get("repository") != repository_id or prepared.get("approved_ref") != approved_ref:
        raise SafetyError("prepared release repository/ref mismatch")
    if sorted(runtime_entries) != prepared.get("runtime_entries"):
        raise SafetyError("prepared runtime binding manifest changed")
    approval=load_external_approval(approval_file,expected_sha=sha,expected_repository=repository_id,
        expected_ref=approved_ref,expected_manifest_sha256=expected_hash,expected_ci_run_id=ci_run_id,expected_audit_id=audit_id)

    if not active_link.is_symlink():
        raise SafetyError("active application path must already be an operator-prepared symlink")
    previous_target=active_link.resolve(strict=True)
    previous_sha=_active_release_sha(active_link)
    validate_persistent_bindings(previous_target,persistent_state_root,runtime_entries)
    _preflight_persistent_sources(persistent_state_root,runtime_entries)
    final_release=_materialize_final_release(prepared_release,releases_root,sha,persistent_state_root,runtime_entries)

    try:
        consume_external_approval(approval,approval_consumption_root)
    except Exception:
        shutil.rmtree(final_release,ignore_errors=True)
        raise

    status={"sha":sha,"repository":repository_id,"approved_ref":approved_ref,"started_at":utc_now_iso(),
            "state":"STARTED","release_manifest_sha256":expected_hash,"approval_id":str(approval["approval_id"])}
    write_json_atomic(status_file,status)
    previous=None; quiesce_attempted=False; code_backup=None; state_backup=None
    try:
        quiesce_attempted=True
        run_private_hook(quiesce_hook,"quiesce",timeout=90)
        code_backup=backup_active(active_link,backup_root/"code",sha)
        state_backup=backup_persistent_state(persistent_state_root,backup_root/"state",sha)
        previous=atomic_switch_link(active_link,final_release)
        run_private_hook(restart_hook,"restart/reload",timeout=90)
        verify_running_release(identity_hook,sha)
        run_private_hook(unauth_hook,"unauthenticated smoke",timeout=60)
        run_private_hook(auth_hook,"authenticated smoke",timeout=60)
        run_private_hook(resume_hook,"resume/unquiesce",timeout=90)
        removed_releases=apply_retention([p for p in releases_root.iterdir() if p.is_dir() and not p.name.startswith(".")],active=final_release,last_known_good=previous,keep_newest=5)
        removed_code=apply_backup_retention(backup_root/"code",last_known_good=code_backup,keep_newest=5)
        removed_state=apply_backup_retention(backup_root/"state",last_known_good=state_backup,keep_newest=5)
        cleanup_stale_staging(releases_root,older_than_seconds=86400)
        status.update({"state":"DEPLOYED","completed_at":utc_now_iso(),"release_root":str(final_release),"persistent_state_mode":"shared_external",
            "retention_removed_release_count":len(removed_releases),"retention_removed_code_backup_count":len(removed_code),"retention_removed_state_backup_count":len(removed_state)})
        write_json_atomic(status_file,status); return 0
    except Exception as exc:
        status.update({"failure_type":type(exc).__name__,"rollback_attempted":previous is not None})
        if previous is not None:
            try:
                restore_link(active_link,previous); run_private_hook(restart_hook,"rollback restart/reload",timeout=90); verify_running_release(identity_hook,previous_sha)
                run_private_hook(unauth_hook,"unauthenticated rollback smoke",timeout=60); run_private_hook(auth_hook,"authenticated rollback smoke",timeout=60); run_private_hook(resume_hook,"rollback resume/unquiesce",timeout=90)
                status.update({"state":"ROLLED_BACK","completed_at":utc_now_iso(),"persistent_state_restored":False,
                               "persistent_state_note":"shared mutable state remains authoritative and is not reverted by code rollback"})
                write_json_atomic(status_file,status); return 20
            except Exception as rollback_exc:
                status.update({"state":"CRITICAL_ROLLBACK_FAILED","rollback_failure_type":type(rollback_exc).__name__,"completed_at":utc_now_iso()}); write_json_atomic(status_file,status); return 70
        if quiesce_attempted:
            try:
                run_private_hook(restart_hook,"prelive recovery restart/reload",timeout=90); verify_running_release(identity_hook,previous_sha)
                run_private_hook(unauth_hook,"prelive recovery unauthenticated smoke",timeout=60); run_private_hook(auth_hook,"prelive recovery authenticated smoke",timeout=60); run_private_hook(resume_hook,"prelive resume/unquiesce",timeout=90)
            except Exception as recovery_exc:
                status.update({"state":"CRITICAL_PRELIVE_RECOVERY_FAILED","recovery_failure_type":type(recovery_exc).__name__,"completed_at":utc_now_iso()}); write_json_atomic(status_file,status); return 71
        status.update({"state":"PRELIVE_FAILED","completed_at":utc_now_iso()}); write_json_atomic(status_file,status); return 10


def main(argv=None) -> int:
    parser=argparse.ArgumentParser(); parser.add_argument("mode",choices=("prepare","execute"))
    for name in ("repo","repository-id","approved-ref","releases-root","runtime-manifest","control-root"):
        parser.add_argument("--"+name,required=True)
    for name in ("sha","python-executable","prepared-release","ci-run-id","audit-id","active-link","backup-root","persistent-state-root","approval-file","approval-consumption-root","quiesce-hook","resume-hook","restart-hook","identity-hook","unauth-smoke-hook","auth-smoke-hook","status-file","public-root"):
        parser.add_argument("--"+name)
    args=parser.parse_args(argv)
    try:
        control=Path(args.control_root); validate_private_control_root(control); runtime=Path(args.runtime_manifest); validate_private_control_file(runtime,control,"runtime manifest"); entries=load_runtime_manifest(runtime)
        if args.mode=="prepare":
            if not args.sha or not args.python_executable: raise SafetyError("prepare requires sha and python executable")
            path,meta,digest=prepare_versioned_release(repo=Path(args.repo),sha=args.sha,approved_ref=args.approved_ref,
                repository_id=args.repository_id,releases_root=Path(args.releases_root),python_executable=args.python_executable,runtime_entries=entries)
            print(json.dumps({"state":"PREPARED_FOR_AUDIT","prepared_release":str(path),"release_manifest_sha256":digest,"sha":meta["sha"]},sort_keys=True)); return 0
        required=("prepared_release","ci_run_id","audit_id","active_link","backup_root","persistent_state_root","approval_file","approval_consumption_root","quiesce_hook","resume_hook","restart_hook","identity_hook","unauth_smoke_hook","auth_smoke_hook","status_file")
        if any(not getattr(args,n) for n in required): raise SafetyError("execute is missing required private deployment arguments")
        return execute_prepared_release(repo=Path(args.repo),prepared_release=Path(args.prepared_release),repository_id=args.repository_id,
            approved_ref=args.approved_ref,ci_run_id=args.ci_run_id,audit_id=args.audit_id,active_link=Path(args.active_link),
            releases_root=Path(args.releases_root),backup_root=Path(args.backup_root),persistent_state_root=Path(args.persistent_state_root),
            runtime_manifest=runtime,control_root=control,approval_file=Path(args.approval_file),approval_consumption_root=Path(args.approval_consumption_root),
            quiesce_hook=Path(args.quiesce_hook),resume_hook=Path(args.resume_hook),restart_hook=Path(args.restart_hook),identity_hook=Path(args.identity_hook),
            unauth_hook=Path(args.unauth_smoke_hook),auth_hook=Path(args.auth_smoke_hook),status_file=Path(args.status_file),
            public_root=Path(args.public_root) if args.public_root else None)
    except SafetyError as exc:
        print(f"DEPLOYMENT_BLOCKED: {type(exc).__name__}"); return 2

if __name__=="__main__": raise SystemExit(main())
