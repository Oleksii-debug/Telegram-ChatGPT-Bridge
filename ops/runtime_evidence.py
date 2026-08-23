# -*- coding: utf-8 -*-
"""Collect bounded non-secret Python/Passenger runtime evidence.

The collector deliberately cannot emit STRONG Passenger proof.  It records only
candidate/process facts.  Strong evidence is a later transformation performed by
the challenged WSGI serving-request path after the request challenge has been
verified.  Consequently a CLI/manual caller cannot obtain STRONG merely by
passing a boolean or setting a Passenger-named environment variable.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib
import importlib.metadata
import os
import platform
import stat
import sys
from pathlib import Path

try:
    from ops.release_guard import SafetyError
except ImportError:
    class SafetyError(RuntimeError):
        pass

from ops.private_control import write_private_json_no_clobber
from ops.private_evidence import canonical_json_sha256, validate_runtime_report

APP_IMPORT_TARGET = "bridge.app.application"
REVIEWED_PACKAGES = ("Telethon", "pypdf")


def _sha256_file(path: Path) -> str:
    if not path.is_file() or path.is_symlink():
        raise SafetyError("runtime evidence target must be a regular non-symlink file")
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _hash_path(path: Path) -> str:
    return hashlib.sha256(str(path).encode("utf-8")).hexdigest()


def _owner_mode_nlink(path: Path) -> tuple[int, int, int]:
    st = path.stat()
    if not stat.S_ISREG(st.st_mode):
        raise SafetyError("interpreter target is not a regular file")
    return st.st_uid, stat.S_IMODE(st.st_mode), st.st_nlink


def _cwd_inside(app_root: Path) -> bool:
    try:
        Path.cwd().resolve().relative_to(app_root)
        return True
    except ValueError:
        return False


def _package_evidence() -> list[dict]:
    rows = []
    for name in REVIEWED_PACKAGES:
        try:
            version = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            rows.append({"name": name.casefold(), "present": False, "version": "NOT_INSTALLED", "metadata_sha256": "0" * 64})
            continue
        try:
            dist = importlib.metadata.distribution(name)
            metadata_text = str(dist.metadata)
            digest = hashlib.sha256(metadata_text.encode("utf-8", errors="replace")).hexdigest()
        except Exception:
            digest = hashlib.sha256((name + "==" + version).encode("utf-8")).hexdigest()
        rows.append({"name": name.casefold(), "present": True, "version": version[:64], "metadata_sha256": digest})
    return rows


def collect_runtime_evidence(
    *,
    app_root: Path,
    wsgi_file: Path,
    application_module: str = "bridge.app",
    application_name: str = "application",
    application_process: bool = False,
) -> dict:
    """Collect process facts without any ability to self-promote to STRONG."""
    app_root = app_root.resolve(strict=True)
    wsgi_file = wsgi_file.resolve(strict=True)
    try:
        rel_wsgi = wsgi_file.relative_to(app_root).as_posix()
    except ValueError as exc:
        raise SafetyError("WSGI file must be inside application root") from exc
    if rel_wsgi != "passenger_wsgi.py":
        raise SafetyError("unexpected WSGI startup path")
    if f"{application_module}.{application_name}" != APP_IMPORT_TARGET:
        raise SafetyError("unexpected application import target")

    import_ok = False
    try:
        module = importlib.import_module(application_module)
        getattr(module, application_name)
        import_ok = True
    except Exception:
        import_ok = False

    executable = Path(sys.executable).resolve(strict=True)
    uid, mode, nlink = _owner_mode_nlink(executable)
    prefix = Path(sys.prefix).resolve()
    base_prefix = Path(getattr(sys, "base_prefix", sys.prefix)).resolve()
    py311 = sys.version_info[:2] == (3, 11)

    # Presence only; values are never read or serialized.  This remains advisory
    # and, by design, can never itself produce STRONG evidence.
    passenger_context_present = any(
        key in os.environ for key in ("PASSENGER_APP_ENV", "PASSENGER_SPAWN_WORK_DIR")
    )
    compliance = (
        "PYTHON_3_11_CANDIDATE_CONTEXT"
        if py311
        else "NONCOMPLIANT_NOT_PYTHON_3_11"
    )

    report = {
        "schema_version": 3,
        "collector_context": "APPLICATION_PROCESS" if application_process else "PRIVATE_CLI_CANDIDATE",
        "python_version": platform.python_version()[:32],
        "python_major_minor": f"{sys.version_info.major}.{sys.version_info.minor}",
        "python_implementation": platform.python_implementation()[:32],
        "runtime_compliance": compliance,
        "python_executable_sha256": _sha256_file(executable),
        "python_executable_owner_uid": uid,
        "python_executable_mode": mode,
        "python_executable_nlink": nlink,
        "sys_prefix_sha256": _hash_path(prefix),
        "sys_base_prefix_sha256": _hash_path(base_prefix),
        "virtual_environment_active": prefix != base_prefix,
        "wsgi_relative_path": rel_wsgi,
        "wsgi_sha256": _sha256_file(wsgi_file),
        "application_import_target": APP_IMPORT_TARGET,
        "application_import_ok": import_ok,
        "process_cwd_inside_app_root": _cwd_inside(app_root),
        "passenger_context_present": passenger_context_present,
        "serving_request_verified": False,
        "package_evidence": _package_evidence(),
        "environment_values_recorded": False,
        "request_data_recorded": False,
        "secret_values_recorded": False,
    }
    report["payload_sha256"] = canonical_json_sha256(report)
    validate_runtime_report(report)
    return report


def system_shell_cannot_prove_passenger(report: dict) -> bool:
    """Return true unless a separately promoted serving report is STRONG."""
    validate_runtime_report(report)
    return (
        report["collector_context"] != "APPLICATION_PROCESS"
        or report["runtime_compliance"] != "PYTHON_3_11_APPLICATION_CONTEXT_CONFIRMED"
        or report["serving_request_verified"] is not True
    )


def write_private_report(path: Path, evidence: dict) -> None:
    validate_runtime_report(evidence)
    path = path.expanduser()
    write_private_json_no_clobber(path.parent, path, evidence)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--app-root", required=True)
    parser.add_argument("--wsgi-file", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    try:
        evidence = collect_runtime_evidence(
            app_root=Path(args.app_root),
            wsgi_file=Path(args.wsgi_file),
            application_process=False,
        )
        write_private_report(Path(args.output), evidence)
    except (SafetyError, OSError):
        print("RUNTIME_EVIDENCE_BLOCKED")
        return 2
    print(evidence["runtime_compliance"])
    # Exit 0 means bounded collection succeeded, never Passenger proof.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
