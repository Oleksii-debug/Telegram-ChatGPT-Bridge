# -*- coding: utf-8 -*-
"""Single supported Telegram Bridge deployment entrypoint.

The deployment contract is intentionally narrow: process-loss recovery on the
same POSIX host/filesystem. Full host/power-loss durability is not claimed.
"""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import tarfile
from datetime import datetime
from pathlib import Path, PurePosixPath

from ops.deployment_lock_policy import LockPolicyError, hold_deployment_lock, validate_preexisting_lock
from ops.dev08_deploy_recovery import (
    DeploymentRecoveryClassificationError,
    classify_deployment_recovery,
)
from ops.release_guard import (
    SafetyError, apply_backup_retention, apply_retention, atomic_switch_link,
    attach_persistent_state, build_manifest, cleanup_stale_staging,
    consume_external_approval, load_external_approval, load_runtime_manifest,
    restore_link, sha256_file, sha256_json, validate_deployment_topology,
    validate_exact_source_payload, validate_persistent_bindings,
    validate_private_control_dir, validate_private_control_file,
    validate_private_control_root, write_json_atomic, utc_now_iso,
)

try:
    import fcntl
except ImportError:  # pragma: no cover - HOSTiQ production is POSIX
    fcntl = None

FULL_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SAFE_REF_RE = re.compile(r"^(?:refs/heads/)?[A-Za-z0-9._/-]+$")
PREPARED_META = "PREPARED_RELEASE.json"
TRANSACTION_JOURNAL = "DEPLOYMENT_TRANSACTION.json"
TRANSACTION_LOCK = "DEPLOYMENT_TRANSACTION.lock"
IMMUTABLE_PERMISSION_POLICY = "no-write-bits-v1"
JOURNAL_SCHEMA_VERSION = 2
DURABILITY_CONTRACT = "process-loss-same-host-v1"

ACTIVE_STATES = {
    "MATERIALIZING", "MATERIALIZED", "READY_TO_COMMIT", "APPROVAL_COMMITTED",
    "QUIESCED", "BACKED_UP", "SWITCHED", "VERIFIED",
}
TERMINAL_STATES = {
    "PREAPPROVAL_ABORTED", "PRELIVE_RECOVERED", "DEPLOYED", "ROLLED_BACK",
    "APPROVAL_COMMIT_FAILED", "PRECOMMIT_FAILED",
    "CRITICAL_PRELIVE_RECOVERY_FAILED", "CRITICAL_ROLLBACK_FAILED",
    "CRITICAL_TRANSACTION_AMBIGUOUS",
}
ALL_STATES = ACTIVE_STATES | TERMINAL_STATES
LEGAL_TRANSITIONS = {
    "MATERIALIZING": {"MATERIALIZED", "PREAPPROVAL_ABORTED", "CRITICAL_TRANSACTION_AMBIGUOUS"},
    "MATERIALIZED": {"READY_TO_COMMIT", "PREAPPROVAL_ABORTED", "PRECOMMIT_FAILED", "CRITICAL_TRANSACTION_AMBIGUOUS"},
    "READY_TO_COMMIT": {"APPROVAL_COMMITTED", "PREAPPROVAL_ABORTED", "PRELIVE_RECOVERED", "PRECOMMIT_FAILED", "APPROVAL_COMMIT_FAILED", "CRITICAL_PRELIVE_RECOVERY_FAILED", "CRITICAL_TRANSACTION_AMBIGUOUS"},
    "APPROVAL_COMMITTED": {"QUIESCED", "PRELIVE_RECOVERED", "CRITICAL_PRELIVE_RECOVERY_FAILED", "CRITICAL_TRANSACTION_AMBIGUOUS"},
    "QUIESCED": {"BACKED_UP", "PRELIVE_RECOVERED", "CRITICAL_PRELIVE_RECOVERY_FAILED", "CRITICAL_TRANSACTION_AMBIGUOUS"},
    "BACKED_UP": {"SWITCHED", "PRELIVE_RECOVERED", "CRITICAL_PRELIVE_RECOVERY_FAILED", "CRITICAL_TRANSACTION_AMBIGUOUS"},
    "SWITCHED": {"VERIFIED", "ROLLED_BACK", "CRITICAL_ROLLBACK_FAILED", "CRITICAL_TRANSACTION_AMBIGUOUS"},
    "VERIFIED": {"DEPLOYED", "ROLLED_BACK", "CRITICAL_ROLLBACK_FAILED", "CRITICAL_TRANSACTION_AMBIGUOUS"},
}
for _state in TERMINAL_STATES:
    LEGAL_TRANSITIONS[_state] = set()


def run(command: list[str], *, cwd: Path | None = None, timeout: int = 300) -> None:
    try:
        subprocess.run(command, cwd=cwd, check=True, timeout=timeout,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    except (subprocess.SubprocessError, OSError) as exc:
        raise SafetyError("required subprocess failed") from exc


def command_output(command: list[str], *, cwd: Path | None = None, timeout: int = 60) -> str:
    try:
        return subprocess.run(command, cwd=cwd, check=True, timeout=timeout,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True).stdout.strip()
    except (subprocess.SubprocessError, OSError) as exc:
        raise SafetyError("required subprocess could not be verified") from exc


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


def _python_version(executable: Path) -> str:
    return command_output([str(executable), "-c",
        "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}')"])


def _python_identity(executable: Path) -> dict:
    try:
        resolved = executable.resolve(strict=True)
        st = resolved.stat()
    except OSError as exc:
        raise SafetyError("approved Python interpreter identity is unavailable") from exc
    if not resolved.is_file() or not os.access(resolved, os.X_OK):
        raise SafetyError("approved Python interpreter identity is unsafe")
    version = _python_version(resolved)
    if not version.startswith("3.11."):
        raise SafetyError("release requires approved Python 3.11")
    return {
        "canonical_path": str(resolved), "version": version,
        "sha256": sha256_file(resolved), "size": st.st_size,
        "uid": getattr(st, "st_uid", None), "gid": getattr(st, "st_gid", None),
        "mode": stat.S_IMODE(st.st_mode),
    }


def _validated_python_identity(identity: object) -> dict:
    if not isinstance(identity, dict):
        raise SafetyError("approved Python interpreter identity is missing")
    path = str(identity.get("canonical_path", ""))
    digest = str(identity.get("sha256", ""))
    version = str(identity.get("version", ""))
    if not path or not Path(path).is_absolute() or not SHA256_RE.fullmatch(digest) or not version.startswith("3.11."):
        raise SafetyError("approved Python interpreter identity is invalid")
    actual = _python_identity(Path(path))
    if actual != identity:
        raise SafetyError("approved Python interpreter identity changed after PREPARE")
    return actual


def validate_python_311(python_executable: str) -> str:
    return _python_identity(_canonical_python(python_executable))["version"]


def verify_approved_ref_policy(repo: Path, sha: str, approved_ref: str) -> str:
    if not FULL_SHA_RE.fullmatch(sha) or not SAFE_REF_RE.fullmatch(approved_ref or ""):
        raise SafetyError("invalid SHA/ref policy input")
    commit = command_output(["git", "rev-parse", "--verify", f"{sha}^{{commit}}"], cwd=repo)
    ref_commit = command_output(["git", "rev-parse", "--verify", f"{approved_ref}^{{commit}}"], cwd=repo)
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


def _path_is_excluded(rel: str, excluded: set[str]) -> bool:
    rel_path = PurePosixPath(rel)
    return any(rel_path == PurePosixPath(entry) or PurePosixPath(entry) in rel_path.parents
               for entry in excluded)


def _safe_venv_symlink(root: Path, link: Path, approved_python_identity: dict | None) -> dict:
    rel = link.relative_to(root).as_posix()
    if not rel.startswith(".venv/"):
        raise SafetyError("prepared payload contains unexpected symlink")
    try:
        resolved = link.resolve(strict=True)
        venv_root = (root / ".venv").resolve(strict=True)
    except OSError as exc:
        raise SafetyError("prepared venv symlink is broken") from exc
    if resolved == venv_root or venv_root in resolved.parents:
        return {"path": rel, "type": "symlink", "target": os.readlink(link)}
    if not rel.startswith(".venv/bin/"):
        raise SafetyError("prepared venv symlink escapes approved venv/Python boundary")
    expected = _validated_python_identity(approved_python_identity)
    if resolved != Path(expected["canonical_path"]) or _python_identity(resolved) != expected:
        raise SafetyError("prepared venv external symlink target is not the approved Python interpreter")
    return {"path": rel, "type": "symlink", "target": os.readlink(link)}


def _seal_immutable_tree_permissions(root: Path, excluded_paths: list[str] | tuple[str, ...] = ()) -> None:
    excluded = set(excluded_paths)
    uid = os.getuid() if hasattr(os, "getuid") else None
    for path in [root, *sorted(root.rglob("*"))]:
        rel = "" if path == root else path.relative_to(root).as_posix()
        if rel and _path_is_excluded(rel, excluded):
            continue
        try:
            st = path.lstat()
        except OSError as exc:
            raise SafetyError("immutable release path became unreadable while sealing") from exc
        if uid is not None and st.st_uid != uid:
            raise SafetyError("immutable release path owner is unexpected")
        if not path.is_symlink():
            try:
                os.chmod(path, stat.S_IMODE(st.st_mode) & ~0o222)
            except OSError as exc:
                raise SafetyError("immutable release permissions could not be sealed") from exc


def _validate_immutable_tree_permissions(root: Path, excluded_paths: list[str] | tuple[str, ...] = ()) -> None:
    excluded = set(excluded_paths)
    uid = os.getuid() if hasattr(os, "getuid") else None
    for path in [root, *sorted(root.rglob("*"))]:
        rel = "" if path == root else path.relative_to(root).as_posix()
        if rel and _path_is_excluded(rel, excluded):
            continue
        st = path.lstat()
        if uid is not None and st.st_uid != uid:
            raise SafetyError("immutable release path owner is unexpected")
        if not path.is_symlink() and stat.S_IMODE(path.lstat().st_mode) & 0o222:
            raise SafetyError("immutable release path retains write permission")


_strict_seal_immutable_tree = _seal_immutable_tree_permissions
_strict_validate_immutable_tree = _validate_immutable_tree_permissions


def _open_staging_directories(root: Path) -> None:
    uid = os.getuid() if hasattr(os, "getuid") else None
    for path in [root, *sorted(root.rglob("*"))]:
        if path.is_symlink() or not path.is_dir():
            continue
        st = path.stat()
        if uid is not None and st.st_uid != uid:
            raise SafetyError("staging owner mismatch")
        os.chmod(path, stat.S_IMODE(st.st_mode) | stat.S_IWUSR | stat.S_IXUSR)


def _force_remove_tree(path: Path) -> None:
    if not path.exists() and not path.is_symlink():
        return
    if path.is_symlink():
        path.unlink()
        return
    for child in sorted(path.rglob("*"), key=lambda item: len(item.parts), reverse=True):
        if child.is_symlink():
            continue
        try:
            mode = stat.S_IMODE(child.lstat().st_mode)
            os.chmod(child, mode | stat.S_IWUSR | (stat.S_IXUSR if child.is_dir() else 0))
        except OSError:
            pass
    try:
        mode = stat.S_IMODE(path.lstat().st_mode)
        os.chmod(path, mode | stat.S_IWUSR | stat.S_IXUSR)
    except OSError:
        pass
    try:
        shutil.rmtree(path)
    except OSError as exc:
        raise SafetyError("controlled release cleanup failed") from exc


def _payload_manifest_without_meta(root: Path, approved_python_identity: dict | None = None,
                                   excluded_paths: list[str] | tuple[str, ...] = ()) -> dict:
    excluded = set(excluded_paths)
    items = []
    for path in sorted(root.rglob("*")):
        rel = path.relative_to(root).as_posix()
        if _path_is_excluded(rel, excluded):
            continue
        if path.is_symlink():
            items.append(_safe_venv_symlink(root, path, approved_python_identity))
        elif path.is_file() and rel != PREPARED_META:
            items.append({"path": rel, "type": "file", "size": path.stat().st_size,
                          "sha256": sha256_file(path)})
    return {"files": items, "count": len(items)}


def _install_locked_requirements(py: Path, source: Path, input_name: str, lock_name: str) -> str | None:
    source_file = source / input_name
    lock = source / lock_name
    if source_file.exists() and not lock.exists():
        raise SafetyError(f"{input_name} exists without {lock_name}; dependencies are not immutable")
    if lock.exists():
        try:
            run([str(py), "-m", "pip", "install", "--require-hashes", "-r", str(lock)], cwd=source, timeout=600)
        except SafetyError as exc:
            raise SafetyError(f"hash-locked dependency installation failed: {lock_name}") from exc
        return sha256_file(lock)
    return None


def _promote_readonly_directory(source: Path, destination: Path) -> None:
    """Rename a sealed directory while preserving its exact final mode."""
    mode = stat.S_IMODE(source.lstat().st_mode)
    try:
        os.chmod(source, mode | stat.S_IWUSR | stat.S_IXUSR)
        os.replace(source, destination)
        os.chmod(destination, mode)
    except OSError as exc:
        target = destination if destination.exists() and not destination.is_symlink() else source
        if target.exists() and not target.is_symlink():
            try:
                os.chmod(target, mode)
            except OSError:
                pass
        raise SafetyError("sealed release promotion failed") from exc


def prepare_versioned_release(*, repo: Path, sha: str, approved_ref: str, repository_id: str,
                              releases_root: Path, python_executable: str,
                              runtime_entries: list[str]) -> tuple[Path, dict, str]:
    verify_approved_ref_policy(repo, sha, approved_ref)
    approved_python_real = _canonical_python(python_executable)
    approved_python_identity = _python_identity(approved_python_real)
    configured_version = approved_python_identity["version"]
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
        built_version = _python_version(py)
        if not built_version.startswith("3.11."):
            raise SafetyError("versioned environment is not Python 3.11")
        app_lock_hash = _install_locked_requirements(py, source, "requirements.txt", "requirements.lock")
        test_lock_hash = _install_locked_requirements(py, source, "requirements-test.txt", "requirements-test.lock")
        run([str(py), "-m", "compileall", "-q", str(source)], cwd=source)
        if not (source / "tests").is_dir():
            raise SafetyError("required test suite is absent")
        run([str(py), "-m", "unittest", "discover", "-s", "tests", "-v"], cwd=source, timeout=300)
        payload_manifest = _payload_manifest_without_meta(source, approved_python_identity)
        prepared = {
            "schema_version": 2, "repository": repository_id, "approved_ref": approved_ref,
            "sha": sha, "configured_python_version": configured_version,
            "python_version": built_version, "approved_python_identity": approved_python_identity,
            "source_manifest_sha256": source_manifest_sha,
            "requirements_lock_sha256": app_lock_hash,
            "requirements_test_lock_sha256": test_lock_hash,
            "payload_manifest_sha256": sha256_json(payload_manifest),
            "runtime_entries": sorted(runtime_entries), "persistent_state_mode": "shared_external",
            "immutable_permission_policy": IMMUTABLE_PERMISSION_POLICY,
        }
        prepared_hash = sha256_json(prepared)
        write_json_atomic(source / PREPARED_META, prepared, mode=0o444)
        _seal_immutable_tree_permissions(source)
        _validate_immutable_tree_permissions(source)
        if sha256_json(_payload_manifest_without_meta(source, approved_python_identity)) != prepared["payload_manifest_sha256"]:
            raise SafetyError("permission sealing changed prepared payload bytes")
        destination = prepared_root / f"{sha}-{prepared_hash[:16]}"
        if destination.exists() or destination.is_symlink():
            raise SafetyError("prepared release already exists")
        (stage / "ACTIVE_LOCK").unlink(missing_ok=True)
        _promote_readonly_directory(source, destination)
        shutil.rmtree(stage, ignore_errors=True)
        return destination, prepared, prepared_hash
    except Exception:
        try:
            (stage / "ACTIVE_LOCK").unlink(missing_ok=True)
        except OSError:
            pass
        if stage.exists() or stage.is_symlink():
            try:
                _force_remove_tree(stage)
            except Exception:
                pass
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
    if meta.get("immutable_permission_policy") == IMMUTABLE_PERMISSION_POLICY:
        _validate_immutable_tree_permissions(prepared_release)
    else:
        for path in [prepared_release, *sorted(prepared_release.rglob("*"))]:
            if not path.is_symlink() and stat.S_IMODE(path.lstat().st_mode) & 0o022:
                raise SafetyError("prepared release is group/world writable")
    identity = _validated_python_identity(meta.get("approved_python_identity")) if meta.get("approved_python_identity") else None
    payload = _payload_manifest_without_meta(prepared_release, identity)
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


def _write_hash_pair_atomic(archive: Path) -> Path:
    hash_path = Path(str(archive) + ".sha256")
    temp = hash_path.with_name(hash_path.name + ".partial")
    try:
        temp.write_text(sha256_file(archive) + "  " + archive.name + "\n", encoding="utf-8")
        os.chmod(temp, 0o600)
        os.replace(temp, hash_path)
        return hash_path
    except Exception:
        temp.unlink(missing_ok=True)
        raise


def _write_hash_pair(archive: Path) -> None:
    _write_hash_pair_atomic(archive)


def _atomic_backup_directory(source: Path, backup_root: Path, final_name: str, arcname: str) -> Path:
    backup_root.mkdir(parents=True, exist_ok=True)
    final = backup_root / final_name
    partial = backup_root / ("." + final_name + ".partial")
    if final.is_symlink() or partial.is_symlink():
        raise SafetyError("backup target is unsafe")
    if final.exists() or Path(str(final) + ".sha256").exists():
        index = 1
        stem = final_name[:-7] if final_name.endswith(".tar.gz") else final_name
        while True:
            candidate = backup_root / f"{stem}_{index}.tar.gz"
            if not candidate.exists() and not Path(str(candidate) + ".sha256").exists():
                final = candidate
                partial = backup_root / ("." + candidate.name + ".partial")
                break
            index += 1
    partial.unlink(missing_ok=True)
    try:
        with tarfile.open(partial, "w:gz", dereference=False) as archive:
            archive.add(source, arcname=arcname, recursive=True)
        os.chmod(partial, 0o600)
        os.replace(partial, final)
        _write_hash_pair_atomic(final)
        return final
    except Exception as exc:
        partial.unlink(missing_ok=True)
        final.unlink(missing_ok=True)
        Path(str(final) + ".sha256").unlink(missing_ok=True)
        if isinstance(exc, SafetyError):
            raise
        raise SafetyError("backup creation failed") from exc


def backup_active(active_link: Path, backup_root: Path, sha: str) -> Path:
    if not active_link.is_symlink():
        raise SafetyError("active application path must be a symlink before automated deployment")
    target = active_link.resolve(strict=True)
    return _atomic_backup_directory(target, backup_root, f"code_predeploy_{sha}.tar.gz", target.name)


def backup_persistent_state(state_root: Path, backup_root: Path, sha: str) -> Path:
    state_root = state_root.resolve(strict=True)
    return _atomic_backup_directory(state_root, backup_root, f"state_predeploy_{sha}.tar.gz", "persistent_state")


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
    for path, label in (
        (quiesce_hook, "quiesce hook"), (resume_hook, "resume hook"),
        (restart_hook, "restart hook"), (identity_hook, "identity hook"),
        (unauth_hook, "unauthenticated smoke hook"), (auth_hook, "authenticated smoke hook"),
    ):
        validate_private_control_file(path, control_root, label, executable=True)
    validate_private_control_dir(approval_consumption_root, control_root, "approval consumption root", create=True)
    if status_file.exists():
        validate_private_control_file(status_file, control_root, "status file")
    else:
        validate_private_control_dir(status_file.parent, control_root, "status parent")


def _preflight_persistent_sources(state_root: Path, runtime_entries: list[str]) -> None:
    try:
        state_root = state_root.resolve(strict=True)
    except OSError as exc:
        raise SafetyError("persistent state root missing or unsafe") from exc
    for rel in runtime_entries:
        source = state_root / rel
        if not source.exists() or source.is_symlink():
            raise SafetyError("persistent state entry missing or unsafe")


def _runtime_manifest_digest(entries: list[str]) -> str:
    return sha256_json({"paths": sorted(entries)})


def _materialize_final_release(prepared_release: Path, releases_root: Path, sha: str,
                               persistent_state_root: Path, runtime_entries: list[str]) -> Path:
    final = releases_root / sha
    stage = releases_root / (".finalize_" + sha)
    if final.exists() or final.is_symlink():
        raise SafetyError("target release already exists")
    if stage.exists() or stage.is_symlink():
        raise SafetyError("finalization staging directory already exists")
    try:
        shutil.copytree(prepared_release, stage, symlinks=True)
        _open_staging_directories(stage)
        attach_persistent_state(stage, persistent_state_root, runtime_entries)
        validate_persistent_bindings(stage, persistent_state_root, runtime_entries)
        _seal_immutable_tree_permissions(stage, runtime_entries)
        _validate_immutable_tree_permissions(stage, runtime_entries)
        _promote_readonly_directory(stage, final)
        return final
    except BaseException:
        if stage.exists() or stage.is_symlink():
            try:
                _force_remove_tree(stage)
            except Exception:
                pass
        raise


def _verify_final_materialized_release(final_release: Path, prepared_meta: dict,
                                       expected_manifest_hash: str, runtime_entries: list[str]) -> None:
    try:
        final_meta = json.loads((final_release / PREPARED_META).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SafetyError("final release metadata is invalid") from exc
    if final_meta != prepared_meta or sha256_json(final_meta) != expected_manifest_hash:
        raise SafetyError("final release metadata differs from approved prepared metadata")
    identity = _validated_python_identity(prepared_meta.get("approved_python_identity")) if prepared_meta.get("approved_python_identity") else None
    _validate_immutable_tree_permissions(final_release, runtime_entries)
    payload = _payload_manifest_without_meta(final_release, identity, runtime_entries)
    if sha256_json(payload) != prepared_meta.get("payload_manifest_sha256"):
        raise SafetyError("final materialized immutable payload differs from approved prepared payload")


def _best_effort_status(path: Path, status: dict) -> None:
    try:
        write_json_atomic(path, status)
    except Exception:
        pass


def _journal_path(control_root: Path) -> Path:
    return control_root / TRANSACTION_JOURNAL


def _approval_marker_digest(approval: dict) -> str:
    return hashlib.sha256((str(approval["approval_id"]) + "\0" + str(approval["nonce"])).encode()).hexdigest()


def _transaction_id(repository: str, approved_ref: str, sha: str, previous_sha: str,
                    release_manifest_sha256: str, runtime_manifest_sha256: str,
                    approval_marker_sha256: str) -> str:
    return sha256_json({
        "repository": repository, "approved_ref": approved_ref, "sha": sha,
        "previous_sha": previous_sha, "release_manifest_sha256": release_manifest_sha256,
        "runtime_manifest_sha256": runtime_manifest_sha256,
        "approval_marker_sha256": approval_marker_sha256,
    })


def _new_transaction_journal(repository: str, approved_ref: str, sha: str, previous_sha: str,
                             release_manifest_sha256: str, prepared_meta: dict,
                             runtime_entries: list[str], approval: dict) -> dict:
    marker_digest = _approval_marker_digest(approval)
    runtime_digest = _runtime_manifest_digest(runtime_entries)
    now = utc_now_iso()
    return {
        "schema_version": JOURNAL_SCHEMA_VERSION, "durability_contract": DURABILITY_CONTRACT,
        "transaction_id": _transaction_id(repository, approved_ref, sha, previous_sha,
                                             release_manifest_sha256, runtime_digest, marker_digest),
        "repository": repository, "approved_ref": approved_ref, "sha": sha,
        "previous_sha": previous_sha, "release_manifest_sha256": release_manifest_sha256,
        "prepared_payload_sha256": str(prepared_meta.get("payload_manifest_sha256", "")),
        "runtime_manifest_sha256": runtime_digest, "runtime_entries": sorted(runtime_entries),
        "approval_id": str(approval["approval_id"]), "approval_marker_sha256": marker_digest,
        "state": "MATERIALIZING", "created_at": now, "updated_at": now,
    }


def _validate_timestamp(value: object, label: str) -> None:
    text = str(value)
    if not text or len(text) > 80:
        raise SafetyError(f"{label} invalid")
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise SafetyError(f"{label} invalid") from exc
    if parsed.tzinfo is None:
        raise SafetyError(f"{label} invalid")


def _validate_transaction_journal(journal: object) -> dict:
    if not isinstance(journal, dict) or journal.get("schema_version") != JOURNAL_SCHEMA_VERSION:
        raise SafetyError("deployment transaction journal schema unsupported")
    if journal.get("durability_contract") != DURABILITY_CONTRACT:
        raise SafetyError("deployment transaction durability contract mismatch")
    state = str(journal.get("state", ""))
    if state not in ALL_STATES:
        raise SafetyError("deployment transaction journal state invalid")
    for key, regex in (
        ("sha", FULL_SHA_RE), ("previous_sha", FULL_SHA_RE),
        ("release_manifest_sha256", SHA256_RE), ("prepared_payload_sha256", SHA256_RE),
        ("runtime_manifest_sha256", SHA256_RE), ("approval_marker_sha256", SHA256_RE),
        ("transaction_id", SHA256_RE),
    ):
        if not regex.fullmatch(str(journal.get(key, ""))):
            raise SafetyError("deployment transaction journal provenance invalid")
    repository = str(journal.get("repository", ""))
    ref = str(journal.get("approved_ref", ""))
    approval_id = str(journal.get("approval_id", ""))
    if not repository or len(repository) > 200 or not SAFE_REF_RE.fullmatch(ref):
        raise SafetyError("deployment transaction journal provenance invalid")
    if not approval_id or len(approval_id) > 200:
        raise SafetyError("deployment transaction journal approval identity invalid")
    entries = journal.get("runtime_entries")
    if not isinstance(entries, list) or entries != sorted(set(entries)):
        raise SafetyError("deployment transaction journal runtime entries invalid")
    if any(not isinstance(item, str) or not item or len(item) > 240 for item in entries):
        raise SafetyError("deployment transaction journal runtime entries invalid")
    if _runtime_manifest_digest(entries) != journal["runtime_manifest_sha256"]:
        raise SafetyError("deployment transaction runtime digest invalid")
    for key in ("created_at", "updated_at"):
        _validate_timestamp(journal.get(key), key)
    expected = _transaction_id(repository, ref, str(journal["sha"]), str(journal["previous_sha"]),
                               str(journal["release_manifest_sha256"]), str(journal["runtime_manifest_sha256"]),
                               str(journal["approval_marker_sha256"]))
    if expected != journal["transaction_id"]:
        raise SafetyError("deployment transaction id mismatch")
    return dict(journal)


def _load_transaction_journal(control_root: Path) -> dict | None:
    path = _journal_path(control_root)
    if not path.exists():
        return None
    validate_private_control_file(path, control_root, "deployment transaction journal")
    try:
        return _validate_transaction_journal(json.loads(path.read_text(encoding="utf-8")))
    except (OSError, json.JSONDecodeError) as exc:
        raise SafetyError("deployment transaction journal unreadable") from exc


def _write_transaction_journal(control_root: Path, journal: dict) -> dict:
    updated = dict(journal)
    updated["updated_at"] = utc_now_iso()
    updated = _validate_transaction_journal(updated)
    write_json_atomic(_journal_path(control_root), updated, mode=0o600)
    return updated


def _transition_transaction(control_root: Path, journal: dict, state: str, **extra) -> dict:
    current = str(journal.get("state", ""))
    if current not in ALL_STATES or state not in LEGAL_TRANSITIONS[current]:
        raise SafetyError("illegal deployment transaction transition")
    immutable = {
        "schema_version", "durability_contract", "transaction_id", "repository", "approved_ref",
        "sha", "previous_sha", "release_manifest_sha256", "prepared_payload_sha256",
        "runtime_manifest_sha256", "runtime_entries", "approval_id", "approval_marker_sha256", "created_at",
    }
    if immutable.intersection(extra):
        raise SafetyError("deployment transaction immutable provenance cannot change")
    updated = dict(journal)
    updated["state"] = state
    updated.update(extra)
    return _write_transaction_journal(control_root, updated)


def _best_effort_transaction(control_root: Path, journal: dict, state: str, **extra) -> dict:
    try:
        return _transition_transaction(control_root, journal, state, **extra)
    except Exception:
        fallback = dict(journal)
        fallback["state"] = state
        fallback.update(extra)
        return fallback


@contextlib.contextmanager
def _deployment_lock(control_root: Path):
    if fcntl is None:
        raise SafetyError("POSIX deployment lock support unavailable")
    try:
        with hold_deployment_lock(control_root, TRANSACTION_LOCK) as path:
            yield path
    except LockPolicyError as exc:
        raise SafetyError("deployment lock acquisition policy failed") from exc


def _approval_marker_path(consumption_root: Path, digest: str) -> Path:
    if not SHA256_RE.fullmatch(digest):
        raise SafetyError("approval marker digest invalid")
    return consumption_root / (digest + ".consumed.json")


def _validate_consumed_approval_marker(*, control_root: Path, consumption_root: Path,
                                       journal: dict, require_exists: bool) -> bool:
    marker = _approval_marker_path(consumption_root, str(journal["approval_marker_sha256"]))
    if not marker.exists():
        if require_exists:
            raise SafetyError("committed approval marker is missing")
        return False
    validate_private_control_file(marker, control_root, "consumed approval marker")
    try:
        payload = json.loads(marker.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SafetyError("consumed approval marker invalid") from exc
    if not isinstance(payload, dict) or str(payload.get("approval_id", "")) != str(journal["approval_id"]):
        raise SafetyError("consumed approval marker provenance mismatch")
    _validate_timestamp(payload.get("consumed_at"), "consumed_at")
    return True


def _approval_marker_exists(consumption_root: Path, digest: str, *, control_root: Path | None = None,
                            approval_id: str | None = None) -> bool:
    marker = _approval_marker_path(consumption_root, digest)
    if not marker.exists():
        return False
    if control_root is None:
        if marker.is_symlink():
            raise SafetyError("approval marker unsafe")
        return marker.is_file()
    return _validate_consumed_approval_marker(
        control_root=control_root, consumption_root=consumption_root,
        journal={"approval_marker_sha256": digest, "approval_id": approval_id or ""},
        require_exists=True,
    )


def _quarantine_release(final: Path, releases_root: Path, journal: dict) -> Path | None:
    if not final.exists() and not final.is_symlink():
        return None
    if final != releases_root / str(journal["sha"]) or final.is_symlink() or not final.is_dir():
        raise SafetyError("unsafe release quarantine target")
    qroot = releases_root / ".quarantine"
    if qroot.is_symlink():
        raise SafetyError("release quarantine root unsafe")
    qroot.mkdir(mode=0o700, exist_ok=True)
    os.chmod(qroot, 0o700)
    base = f"{journal['sha']}-{str(journal['transaction_id'])[:16]}"
    destination = qroot / base
    index = 0
    while destination.exists() or destination.is_symlink():
        index += 1
        destination = qroot / f"{base}-{index}"
    _promote_readonly_directory(final, destination)
    return destination


def _verify_journal_candidate(final: Path, journal: dict, state_root: Path,
                              runtime_entries: list[str]) -> dict:
    if final.is_symlink() or not final.is_dir():
        raise SafetyError("journal candidate missing or unsafe")
    try:
        meta = json.loads((final / PREPARED_META).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SafetyError("journal candidate metadata invalid") from exc
    if sha256_json(meta) != journal["release_manifest_sha256"]:
        raise SafetyError("journal candidate manifest provenance mismatch")
    if str(meta.get("payload_manifest_sha256", "")) != journal["prepared_payload_sha256"]:
        raise SafetyError("journal candidate payload provenance mismatch")
    if sorted(meta.get("runtime_entries", [])) != sorted(runtime_entries):
        raise SafetyError("journal candidate runtime provenance mismatch")
    validate_persistent_bindings(final, state_root, runtime_entries)
    _verify_final_materialized_release(final, meta, str(journal["release_manifest_sha256"]), runtime_entries)
    return meta


def _recover_previous_release(previous_sha: str, restart: Path, identity: Path, unauth: Path,
                              auth: Path, resume: Path, prefix: str) -> None:
    run_private_hook(restart, f"{prefix} restart/reload", timeout=90)
    verify_running_release(identity, previous_sha)
    run_private_hook(unauth, f"{prefix} unauthenticated smoke", timeout=60)
    run_private_hook(auth, f"{prefix} authenticated smoke", timeout=60)
    run_private_hook(resume, f"{prefix} resume/unquiesce", timeout=90)


def _reconcile_incomplete_transaction(*, control_root: Path, releases_root: Path,
                                      persistent_state_root: Path, runtime_entries: list[str],
                                      active_link: Path, approval_consumption_root: Path,
                                      restart_hook: Path, identity_hook: Path, unauth_hook: Path,
                                      auth_hook: Path, resume_hook: Path, status_file: Path) -> dict | None:
    journal = _load_transaction_journal(control_root)
    if journal is None or journal["state"] in TERMINAL_STATES:
        return journal
    runtime_manifest_matches = (
        journal["runtime_entries"] == sorted(runtime_entries)
        and journal["runtime_manifest_sha256"] == _runtime_manifest_digest(runtime_entries)
    )
    if not runtime_manifest_matches:
        _best_effort_transaction(control_root, journal, "CRITICAL_TRANSACTION_AMBIGUOUS",
                                 reason_code="runtime_manifest_changed")
        raise SafetyError("runtime manifest changed during incomplete transaction recovery")
    sha, previous_sha = str(journal["sha"]), str(journal["previous_sha"])
    final = releases_root / sha
    stage = releases_root / (".finalize_" + sha)
    old = releases_root / previous_sha
    if stage.is_symlink() or not active_link.is_symlink():
        raise SafetyError("transaction recovery path is unsafe")
    try:
        active = active_link.resolve(strict=True)
    except OSError as exc:
        raise SafetyError("transaction recovery active target missing") from exc
    previous = None
    if old.exists() and old.is_dir() and not old.is_symlink():
        try:
            previous = old.resolve(strict=True)
        except OSError:
            previous = None
    state = str(journal["state"])
    try:
        marker = _validate_consumed_approval_marker(
            control_root=control_root, consumption_root=approval_consumption_root,
            journal=journal, require_exists=False,
        )
    except SafetyError as exc:
        _best_effort_transaction(control_root, journal, "CRITICAL_TRANSACTION_AMBIGUOUS",
                                 reason_code="committed_marker_invalid")
        raise SafetyError("committed approval marker is invalid during recovery") from exc
    if state in {"MATERIALIZING", "MATERIALIZED"} and marker:
        _best_effort_transaction(control_root, journal, "CRITICAL_TRANSACTION_AMBIGUOUS",
                                 reason_code="approval_marker_before_ready")
        raise SafetyError("approval marker exists before approval commit boundary")

    final_target = None
    if final.exists() and final.is_dir() and not final.is_symlink():
        try:
            final_target = final.resolve(strict=True)
        except OSError:
            pass

    # A01-11: a process can die after atomic_switch_link() has durably changed
    # the inspectable local symlink but before BACKED_UP -> SWITCHED is persisted.
    # Treat that exact snapshot as recoverable only after deriving every required
    # fact from validated durable evidence. No other pre-switch/candidate-active
    # state is promoted.
    if state == "BACKED_UP" and final_target is not None and active == final_target:
        candidate_verified = False
        try:
            _verify_journal_candidate(final, journal, persistent_state_root, runtime_entries)
            candidate_verified = True
        except Exception:
            candidate_verified = False
        try:
            decision = classify_deployment_recovery(
                journal_state=state,
                active_role="candidate",
                approval_marker_valid=marker,
                runtime_manifest_matches=runtime_manifest_matches,
                candidate_verified=candidate_verified,
                previous_release_available=previous is not None,
            )
        except DeploymentRecoveryClassificationError as exc:
            _best_effort_transaction(control_root, journal, "CRITICAL_TRANSACTION_AMBIGUOUS",
                                     reason_code="recovery_classifier_rejected_evidence")
            raise SafetyError("deployment recovery evidence classification failed") from exc

        if decision.action == "AMBIGUOUS":
            _best_effort_transaction(control_root, journal, "CRITICAL_TRANSACTION_AMBIGUOUS",
                                     reason_code=decision.reason_code)
            raise SafetyError("BACKED_UP candidate-active transaction evidence is ambiguous")
        if decision.action == "ROLLBACK_REQUIRED":
            if previous is None:  # classifier should already reject this; preserve defense in depth.
                _best_effort_transaction(control_root, journal, "CRITICAL_TRANSACTION_AMBIGUOUS",
                                         reason_code="previous_release_missing")
                raise SafetyError("previous release is unavailable for candidate rollback")
            try:
                restore_link(active_link, previous)
                _recover_previous_release(previous_sha, restart_hook, identity_hook, unauth_hook,
                                          auth_hook, resume_hook, "observed-switch candidate rollback")
                quarantine = _quarantine_release(final, releases_root, journal)
                _best_effort_status(status_file, {
                    "state": "PRELIVE_RECOVERED", "sha": sha,
                    "completed_at": utc_now_iso(), "approval_reuse_allowed": False,
                })
                return _transition_transaction(
                    control_root, journal, "PRELIVE_RECOVERED",
                    completed_at=utc_now_iso(), approval_reuse_allowed=False,
                    recovery_mode="candidate_reverification_failed_after_observed_switch",
                    quarantine_name=quarantine.name if quarantine else None,
                )
            except Exception as rollback_exc:
                _best_effort_transaction(control_root, journal, "CRITICAL_PRELIVE_RECOVERY_FAILED",
                                         recovery_failure_type=type(rollback_exc).__name__)
                raise SafetyError("candidate-active BACKED_UP rollback failed") from rollback_exc
        if decision.action != "RECOVER_AS_SWITCHED" or decision.journal_transition != "SWITCHED":
            _best_effort_transaction(control_root, journal, "CRITICAL_TRANSACTION_AMBIGUOUS",
                                     reason_code="unexpected_recovery_classifier_action")
            raise SafetyError("unexpected recovery classification for BACKED_UP candidate-active state")
        if previous is None:
            _best_effort_transaction(control_root, journal, "CRITICAL_TRANSACTION_AMBIGUOUS",
                                     reason_code="previous_release_missing")
            raise SafetyError("previous release unavailable for observed switch recovery")
        try:
            journal = _transition_transaction(
                control_root, journal, "SWITCHED", recovered_at=utc_now_iso(),
                recovery_mode="observed_atomic_switch_before_switched_journal",
            )
            state = "SWITCHED"
        except Exception as persist_exc:
            # We observed the switch but cannot make that observation durable. Restore the
            # previous code first, verify its running lifecycle, then record the legal
            # BACKED_UP -> PRELIVE_RECOVERED terminal state. Persistent state is shared
            # external state and is intentionally not restored here; schema compatibility
            # remains a separate audited release constraint (PR #51).
            try:
                restore_link(active_link, previous)
                _recover_previous_release(previous_sha, restart_hook, identity_hook, unauth_hook,
                                          auth_hook, resume_hook, "switch-journal persistence rollback")
                quarantine = _quarantine_release(final, releases_root, journal)
                recovered = _transition_transaction(
                    control_root, journal, "PRELIVE_RECOVERED",
                    completed_at=utc_now_iso(), approval_reuse_allowed=False,
                    recovery_mode="switched_journal_persist_failed",
                    quarantine_name=quarantine.name if quarantine else None,
                )
                _best_effort_status(status_file, {
                    "state": "ROLLED_BACK", "sha": sha, "completed_at": utc_now_iso(),
                    "recovery_mode": "switched_journal_persist_failed",
                })
                return recovered
            except Exception as rollback_exc:
                _best_effort_transaction(control_root, journal, "CRITICAL_PRELIVE_RECOVERY_FAILED",
                                         recovery_failure_type=type(rollback_exc).__name__)
                raise SafetyError("observed switch could not be durably reconciled") from rollback_exc

    pre_switch = {"MATERIALIZING", "MATERIALIZED", "READY_TO_COMMIT",
                  "APPROVAL_COMMITTED", "QUIESCED", "BACKED_UP"}
    if previous is not None and active == previous and state in pre_switch:
        if stage.exists():
            _force_remove_tree(stage)
        if final.exists() or final.is_symlink():
            _verify_journal_candidate(final, journal, persistent_state_root, runtime_entries)
        if state == "MATERIALIZED" and not final.exists():
            _best_effort_transaction(control_root, journal, "CRITICAL_TRANSACTION_AMBIGUOUS",
                                     reason_code="materialized_candidate_missing")
            raise SafetyError("materialized transaction candidate is missing")
        if state in {"APPROVAL_COMMITTED", "QUIESCED", "BACKED_UP"} and not marker:
            _best_effort_transaction(control_root, journal, "CRITICAL_TRANSACTION_AMBIGUOUS",
                                     reason_code="committed_marker_missing")
            raise SafetyError("committed approval marker is missing")
        consumed = marker or state in {"APPROVAL_COMMITTED", "QUIESCED", "BACKED_UP"}
        if consumed:
            try:
                _recover_previous_release(previous_sha, restart_hook, identity_hook, unauth_hook,
                                          auth_hook, resume_hook, "pre-switch transaction recovery")
                quarantine = _quarantine_release(final, releases_root, journal)
                _best_effort_status(status_file, {
                    "state": "PRELIVE_RECOVERED", "sha": sha,
                    "completed_at": utc_now_iso(), "approval_reuse_allowed": False,
                })
                return _transition_transaction(
                    control_root, journal, "PRELIVE_RECOVERED", completed_at=utc_now_iso(),
                    approval_reuse_allowed=False,
                    quarantine_name=quarantine.name if quarantine else None,
                )
            except Exception as exc:
                _best_effort_transaction(control_root, journal, "CRITICAL_PRELIVE_RECOVERY_FAILED",
                                         recovery_failure_type=type(exc).__name__)
                raise SafetyError("interrupted pre-switch deployment recovery failed") from exc
        quarantine = _quarantine_release(final, releases_root, journal)
        return _transition_transaction(
            control_root, journal, "PREAPPROVAL_ABORTED", completed_at=utc_now_iso(),
            approval_reuse_allowed=True, quarantine_name=quarantine.name if quarantine else None,
        )

    if state in {"SWITCHED", "VERIFIED"}:
        _validate_consumed_approval_marker(control_root=control_root,
            consumption_root=approval_consumption_root, journal=journal, require_exists=True)
        if final_target is not None and active == final_target:
            try:
                _verify_journal_candidate(final, journal, persistent_state_root, runtime_entries)
                run_private_hook(restart_hook, "transaction recovery restart/reload", timeout=90)
                verify_running_release(identity_hook, sha)
                run_private_hook(unauth_hook, "transaction recovery unauthenticated smoke", timeout=60)
                run_private_hook(auth_hook, "transaction recovery authenticated smoke", timeout=60)
                run_private_hook(resume_hook, "transaction recovery resume/unquiesce", timeout=90)
                current = journal
                if state == "SWITCHED":
                    current = _transition_transaction(control_root, current, "VERIFIED", recovered_at=utc_now_iso())
                return _transition_transaction(control_root, current, "DEPLOYED",
                                               completed_at=utc_now_iso(), recovery_mode="resumed_after_switch")
            except Exception as exc:
                if previous is None:
                    _best_effort_transaction(control_root, journal, "CRITICAL_ROLLBACK_FAILED",
                                             rollback_failure_type="PreviousReleaseMissing")
                    raise SafetyError("interrupted switched deployment cannot roll back: previous release missing") from exc
                try:
                    restore_link(active_link, previous)
                    _recover_previous_release(previous_sha, restart_hook, identity_hook, unauth_hook,
                                              auth_hook, resume_hook, "transaction rollback")
                    quarantine = _quarantine_release(final, releases_root, journal)
                    return _best_effort_transaction(control_root, journal, "ROLLED_BACK",
                        completed_at=utc_now_iso(), quarantine_name=quarantine.name if quarantine else None,
                        failure_type=type(exc).__name__)
                except Exception as rollback_exc:
                    _best_effort_transaction(control_root, journal, "CRITICAL_ROLLBACK_FAILED",
                                             rollback_failure_type=type(rollback_exc).__name__)
                    raise SafetyError("interrupted switched deployment recovery failed") from rollback_exc
        if previous is not None and active == previous:
            try:
                _recover_previous_release(previous_sha, restart_hook, identity_hook, unauth_hook,
                                          auth_hook, resume_hook, "transaction rollback recovery")
                quarantine = _quarantine_release(final, releases_root, journal)
                return _best_effort_transaction(control_root, journal, "ROLLED_BACK",
                    completed_at=utc_now_iso(), quarantine_name=quarantine.name if quarantine else None,
                    recovery_mode="previous_already_active")
            except Exception as exc:
                _best_effort_transaction(control_root, journal, "CRITICAL_ROLLBACK_FAILED",
                                         rollback_failure_type=type(exc).__name__)
                raise SafetyError("interrupted switched rollback recovery failed") from exc
    _best_effort_transaction(control_root, journal, "CRITICAL_TRANSACTION_AMBIGUOUS",
                             reason_code="active_target_mismatch")
    raise SafetyError("incomplete transaction active target ambiguous")


def _current_approval_reuse_forbidden(journal: dict | None, approval: dict) -> bool:
    """Only transactions that may have crossed approval commit permanently burn the approval."""
    if not journal or str(journal.get("approval_id", "")) != str(approval.get("approval_id", "")):
        return False
    return str(journal.get("state", "")) not in {
        "PREAPPROVAL_ABORTED", "PRECOMMIT_FAILED", "APPROVAL_COMMIT_FAILED"
    }


def _execute_prepared_release_locked(*, repo: Path, prepared_release: Path, repository_id: str,
                                     approved_ref: str, ci_run_id: str, audit_id: str,
                                     active_link: Path, releases_root: Path, backup_root: Path,
                                     persistent_state_root: Path, runtime_manifest: Path,
                                     control_root: Path, approval_file: Path,
                                     approval_consumption_root: Path, quiesce_hook: Path,
                                     resume_hook: Path, restart_hook: Path, identity_hook: Path,
                                     unauth_hook: Path, auth_hook: Path, status_file: Path) -> int:
    runtime_entries = load_runtime_manifest(runtime_manifest)
    prior = _load_transaction_journal(control_root)
    if prior and prior["state"] in ACTIVE_STATES:
        _reconcile_incomplete_transaction(
            control_root=control_root, releases_root=releases_root,
            persistent_state_root=persistent_state_root, runtime_entries=runtime_entries,
            active_link=active_link, approval_consumption_root=approval_consumption_root,
            restart_hook=restart_hook, identity_hook=identity_hook, unauth_hook=unauth_hook,
            auth_hook=auth_hook, resume_hook=resume_hook, status_file=status_file,
        )
        raise SafetyError("incomplete deployment transaction reconciled; fresh approval required")
    try:
        raw = json.loads(approval_file.read_text(encoding="utf-8"))
    except Exception as exc:
        raise SafetyError("external approval file is invalid") from exc
    expected = str(raw.get("release_manifest_sha256", ""))
    if not SHA256_RE.fullmatch(expected):
        raise SafetyError("approval prepared-manifest hash is invalid")
    prepared = verify_prepared_release(prepared_release, expected)
    sha = str(prepared.get("sha", ""))
    verify_approved_ref_policy(repo, sha, approved_ref)
    if prepared.get("repository") != repository_id or prepared.get("approved_ref") != approved_ref:
        raise SafetyError("prepared release repository/ref mismatch")
    if sorted(runtime_entries) != prepared.get("runtime_entries"):
        raise SafetyError("prepared runtime binding manifest changed")
    approval = load_external_approval(
        approval_file, expected_sha=sha, expected_repository=repository_id,
        expected_ref=approved_ref, expected_manifest_sha256=expected,
        expected_ci_run_id=ci_run_id, expected_audit_id=audit_id,
    )
    terminal = _load_transaction_journal(control_root)
    if _current_approval_reuse_forbidden(terminal, approval):
        raise SafetyError("approval was already bound to a committed/recovered transaction; fresh approval required")
    marker_digest = _approval_marker_digest(approval)
    marker_path = _approval_marker_path(approval_consumption_root, marker_digest)
    if marker_path.exists():
        _validate_consumed_approval_marker(
            control_root=control_root, consumption_root=approval_consumption_root,
            journal={"approval_marker_sha256": marker_digest, "approval_id": str(approval["approval_id"])},
            require_exists=True,
        )
        raise SafetyError("external approval was already consumed")
    if not active_link.is_symlink():
        raise SafetyError("active application path must already be an operator-prepared symlink")
    previous_target = active_link.resolve(strict=True)
    previous_sha = _active_release_sha(active_link)
    _preflight_persistent_sources(persistent_state_root, runtime_entries)
    validate_persistent_bindings(previous_target, persistent_state_root, runtime_entries)

    journal = _write_transaction_journal(control_root, _new_transaction_journal(
        repository_id, approved_ref, sha, previous_sha, expected, prepared, runtime_entries, approval))
    final = releases_root / sha
    try:
        final = _materialize_final_release(prepared_release, releases_root, sha,
                                           persistent_state_root, runtime_entries)
        validate_persistent_bindings(final, persistent_state_root, runtime_entries)
        _verify_final_materialized_release(final, prepared, expected, runtime_entries)
        journal = _transition_transaction(control_root, journal, "MATERIALIZED", materialized_at=utc_now_iso())
    except Exception:
        if final.exists() or final.is_symlink():
            try:
                _force_remove_tree(final)
            except Exception:
                pass
        _best_effort_transaction(control_root, journal, "PREAPPROVAL_ABORTED",
                                 completed_at=utc_now_iso(), approval_reuse_allowed=True)
        raise
    except BaseException:
        raise

    status = {
        "sha": sha, "repository": repository_id, "approved_ref": approved_ref,
        "state": "READY_TO_COMMIT", "release_manifest_sha256": expected,
        "approval_id": str(approval["approval_id"]), "ready_at": utc_now_iso(),
    }
    try:
        write_json_atomic(status_file, status)
        _verify_final_materialized_release(final, prepared, expected, runtime_entries)
        journal = _transition_transaction(control_root, journal, "READY_TO_COMMIT", ready_at=utc_now_iso())
    except Exception as exc:
        quarantine = _quarantine_release(final, releases_root, journal)
        _best_effort_status(status_file, {**status, "state": "PRECOMMIT_FAILED", "completed_at": utc_now_iso()})
        _best_effort_transaction(control_root, journal, "PRECOMMIT_FAILED",
                                 quarantine_name=quarantine.name if quarantine else None,
                                 approval_reuse_allowed=True)
        raise SafetyError("pre-commit deployment checkpoint/integrity verification failed") from exc

    committed = False
    previous = None
    code_backup = state_backup = None
    try:
        consume_external_approval(approval, approval_consumption_root)
        committed = True
        _validate_consumed_approval_marker(control_root=control_root,
            consumption_root=approval_consumption_root, journal=journal, require_exists=True)
        journal = _transition_transaction(control_root, journal, "APPROVAL_COMMITTED",
                                          approval_committed_at=utc_now_iso())
        run_private_hook(quiesce_hook, "quiesce", timeout=90)
        journal = _transition_transaction(control_root, journal, "QUIESCED", quiesced_at=utc_now_iso())
        status.update({"state": "STARTED", "started_at": utc_now_iso()})
        write_json_atomic(status_file, status)
        code_backup = backup_active(active_link, backup_root / "code", sha)
        state_backup = backup_persistent_state(persistent_state_root, backup_root / "state", sha)
        journal = _transition_transaction(control_root, journal, "BACKED_UP", backed_up_at=utc_now_iso())
        _verify_final_materialized_release(final, prepared, expected, runtime_entries)
        previous = atomic_switch_link(active_link, final)
        journal = _transition_transaction(control_root, journal, "SWITCHED", switched_at=utc_now_iso())
        run_private_hook(restart_hook, "restart/reload", timeout=90)
        verify_running_release(identity_hook, sha)
        run_private_hook(unauth_hook, "unauthenticated smoke", timeout=60)
        run_private_hook(auth_hook, "authenticated smoke", timeout=60)
        run_private_hook(resume_hook, "resume/unquiesce", timeout=90)
        journal = _transition_transaction(control_root, journal, "VERIFIED", verified_at=utc_now_iso())
        removed_releases = apply_retention(
            [p for p in releases_root.iterdir() if p.is_dir() and not p.name.startswith(".")],
            active=final, last_known_good=previous, keep_newest=5)
        removed_code = apply_backup_retention(backup_root / "code", last_known_good=code_backup, keep_newest=5)
        removed_state = apply_backup_retention(backup_root / "state", last_known_good=state_backup, keep_newest=5)
        cleanup_stale_staging(releases_root, older_than_seconds=86400)
        status.update({
            "state": "DEPLOYED", "completed_at": utc_now_iso(), "release_root": str(final),
            "persistent_state_mode": "shared_external",
            "retention_removed_release_count": len(removed_releases),
            "retention_removed_code_backup_count": len(removed_code),
            "retention_removed_state_backup_count": len(removed_state),
        })
        write_json_atomic(status_file, status)
        _transition_transaction(control_root, journal, "DEPLOYED", completed_at=utc_now_iso())
        return 0
    except Exception as exc:
        if not committed:
            try:
                committed = _validate_consumed_approval_marker(
                    control_root=control_root, consumption_root=approval_consumption_root,
                    journal=journal, require_exists=False)
            except Exception:
                committed = False
        if previous is not None:
            try:
                restore_link(active_link, previous)
                _recover_previous_release(previous_sha, restart_hook, identity_hook, unauth_hook,
                                          auth_hook, resume_hook, "rollback")
                quarantine = _quarantine_release(final, releases_root, journal)
                if str(journal.get("state", "")) in {"SWITCHED", "VERIFIED"}:
                    _best_effort_transaction(
                        control_root, journal, "ROLLED_BACK",
                        quarantine_name=quarantine.name if quarantine else None,
                        completed_at=utc_now_iso(),
                    )
                else:
                    _best_effort_transaction(
                        control_root, journal, "PRELIVE_RECOVERED",
                        approval_reuse_allowed=False,
                        quarantine_name=quarantine.name if quarantine else None,
                        completed_at=utc_now_iso(),
                        recovery_mode="switched_journal_persist_failed",
                    )
                _best_effort_status(status_file, {**status, "state": "ROLLED_BACK", "completed_at": utc_now_iso()})
                return 20
            except Exception as rollback_exc:
                if str(journal.get("state", "")) in {"SWITCHED", "VERIFIED"}:
                    _best_effort_transaction(control_root, journal, "CRITICAL_ROLLBACK_FAILED",
                                             rollback_failure_type=type(rollback_exc).__name__)
                else:
                    _best_effort_transaction(control_root, journal, "CRITICAL_PRELIVE_RECOVERY_FAILED",
                                             recovery_failure_type=type(rollback_exc).__name__)
                return 70
        if committed:
            try:
                _recover_previous_release(previous_sha, restart_hook, identity_hook, unauth_hook,
                                          auth_hook, resume_hook, "prelive recovery")
                quarantine = _quarantine_release(final, releases_root, journal)
                _best_effort_transaction(control_root, journal, "PRELIVE_RECOVERED",
                    approval_reuse_allowed=False, quarantine_name=quarantine.name if quarantine else None,
                    completed_at=utc_now_iso())
                _best_effort_status(status_file, {**status, "state": "PRELIVE_FAILED",
                    "completed_at": utc_now_iso(), "approval_reuse_allowed": False})
                return 10
            except Exception as recovery_exc:
                _best_effort_transaction(control_root, journal, "CRITICAL_PRELIVE_RECOVERY_FAILED",
                                         recovery_failure_type=type(recovery_exc).__name__)
                return 71
        try:
            quarantine = _quarantine_release(final, releases_root, journal)
        except Exception:
            quarantine = None
        _best_effort_transaction(control_root, journal, "APPROVAL_COMMIT_FAILED",
                                 quarantine_name=quarantine.name if quarantine else None,
                                 approval_reuse_allowed=True)
        raise exc


def execute_prepared_release(*, repo: Path, prepared_release: Path, repository_id: str,
                             approved_ref: str, ci_run_id: str, audit_id: str,
                             active_link: Path, releases_root: Path, backup_root: Path,
                             persistent_state_root: Path, runtime_manifest: Path,
                             control_root: Path, approval_file: Path,
                             approval_consumption_root: Path, quiesce_hook: Path,
                             resume_hook: Path, restart_hook: Path, identity_hook: Path,
                             unauth_hook: Path, auth_hook: Path, status_file: Path,
                             public_root: Path | None = None) -> int:
    topology = validate_deployment_topology(
        repo=repo, active_link=active_link, releases_root=releases_root,
        backup_root=backup_root, persistent_state_root=persistent_state_root,
        control_root=control_root, public_root=public_root)
    repo = topology["repo"]
    releases_root = topology["releases_root"]
    backup_root = topology["backup_root"]
    persistent_state_root = topology["persistent_state_root"]
    control_root = topology["control_root"]
    active_link = topology["active_link"]
    _validate_control_plane(
        control_root=control_root, runtime_manifest=runtime_manifest, approval_file=approval_file,
        approval_consumption_root=approval_consumption_root, quiesce_hook=quiesce_hook,
        resume_hook=resume_hook, restart_hook=restart_hook, identity_hook=identity_hook,
        unauth_hook=unauth_hook, auth_hook=auth_hook, status_file=status_file)
    with _deployment_lock(control_root):
        return _execute_prepared_release_locked(
            repo=repo, prepared_release=prepared_release, repository_id=repository_id,
            approved_ref=approved_ref, ci_run_id=ci_run_id, audit_id=audit_id,
            active_link=active_link, releases_root=releases_root, backup_root=backup_root,
            persistent_state_root=persistent_state_root, runtime_manifest=runtime_manifest,
            control_root=control_root, approval_file=approval_file,
            approval_consumption_root=approval_consumption_root, quiesce_hook=quiesce_hook,
            resume_hook=resume_hook, restart_hook=restart_hook, identity_hook=identity_hook,
            unauth_hook=unauth_hook, auth_hook=auth_hook, status_file=status_file)


def _supported_deploy_entrypoint() -> str:
    return "ops.deploy_release"


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("prepare", "execute"))
    for name in ("repo", "repository-id", "approved-ref", "releases-root", "runtime-manifest", "control-root"):
        parser.add_argument("--" + name, required=True)
    for name in (
        "sha", "python-executable", "prepared-release", "ci-run-id", "audit-id", "active-link",
        "backup-root", "persistent-state-root", "approval-file", "approval-consumption-root",
        "quiesce-hook", "resume-hook", "restart-hook", "identity-hook", "unauth-smoke-hook",
        "auth-smoke-hook", "status-file", "public-root",
    ):
        parser.add_argument("--" + name)
    args = parser.parse_args(argv)
    try:
        control = Path(args.control_root)
        validate_private_control_root(control)
        runtime = Path(args.runtime_manifest)
        validate_private_control_file(runtime, control, "runtime manifest")
        entries = load_runtime_manifest(runtime)
        if args.mode == "prepare":
            if not args.sha or not args.python_executable:
                raise SafetyError("prepare requires sha and python executable")
            path, meta, digest = prepare_versioned_release(
                repo=Path(args.repo), sha=args.sha, approved_ref=args.approved_ref,
                repository_id=args.repository_id, releases_root=Path(args.releases_root),
                python_executable=args.python_executable, runtime_entries=entries)
            print(json.dumps({"state": "PREPARED_FOR_AUDIT", "prepared_release": str(path),
                              "release_manifest_sha256": digest, "sha": meta["sha"]}, sort_keys=True))
            return 0
        required = (
            "prepared_release", "ci_run_id", "audit_id", "active_link", "backup_root",
            "persistent_state_root", "approval_file", "approval_consumption_root", "quiesce_hook",
            "resume_hook", "restart_hook", "identity_hook", "unauth_smoke_hook", "auth_smoke_hook",
            "status_file",
        )
        if any(not getattr(args, name) for name in required):
            raise SafetyError("execute is missing required private deployment arguments")
        return execute_prepared_release(
            repo=Path(args.repo), prepared_release=Path(args.prepared_release),
            repository_id=args.repository_id, approved_ref=args.approved_ref,
            ci_run_id=args.ci_run_id, audit_id=args.audit_id, active_link=Path(args.active_link),
            releases_root=Path(args.releases_root), backup_root=Path(args.backup_root),
            persistent_state_root=Path(args.persistent_state_root), runtime_manifest=runtime,
            control_root=control, approval_file=Path(args.approval_file),
            approval_consumption_root=Path(args.approval_consumption_root),
            quiesce_hook=Path(args.quiesce_hook), resume_hook=Path(args.resume_hook),
            restart_hook=Path(args.restart_hook), identity_hook=Path(args.identity_hook),
            unauth_hook=Path(args.unauth_smoke_hook), auth_hook=Path(args.auth_smoke_hook),
            status_file=Path(args.status_file), public_root=Path(args.public_root) if args.public_root else None)
    except SafetyError as exc:
        print(f"DEPLOYMENT_BLOCKED: {type(exc).__name__}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())