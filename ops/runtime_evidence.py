# -*- coding: utf-8 -*-
"""Collect non-secret Python/Passenger runtime evidence from the application runtime.

This module is intentionally read-only. It never serializes environment values,
Telegram configuration, cookies, sessions, request bodies, or credentials.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import os
import platform
import sys
from pathlib import Path

from ops.release_guard import SafetyError, write_json_atomic


def _sha256_file(path: Path) -> str | None:
    if not path.is_file() or path.is_symlink():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def collect_runtime_evidence(*, app_root: Path, wsgi_file: Path, application_module: str = "bridge.app", application_name: str = "application") -> dict:
    app_root = app_root.resolve(strict=True)
    wsgi_file = wsgi_file.resolve(strict=True)
    try:
        wsgi_file.relative_to(app_root)
    except ValueError as exc:
        raise SafetyError("WSGI file must be inside application root") from exc
    if sys.version_info[:2] != (3, 11):
        runtime_compliance = "NONCOMPLIANT_NOT_PYTHON_3_11"
    else:
        runtime_compliance = "PYTHON_3_11_CONFIRMED"
    import_ok = False
    application_type = None
    application_object_module = None
    try:
        module = importlib.import_module(application_module)
        application = getattr(module, application_name)
        import_ok = True
        application_type = type(application).__name__
        application_object_module = getattr(application, "__module__", type(application).__module__)
    except Exception:
        # Deliberately do not serialize exception messages because they may contain paths or config details.
        import_ok = False
    executable = str(Path(sys.executable).resolve())
    prefix = str(Path(sys.prefix).resolve())
    base_prefix = str(Path(getattr(sys, "base_prefix", sys.prefix)).resolve())
    return {
        "schema_version": 1,
        "python_version": platform.python_version(),
        "python_major_minor": f"{sys.version_info.major}.{sys.version_info.minor}",
        "python_implementation": platform.python_implementation(),
        "python_executable": executable,
        "sys_prefix": prefix,
        "sys_base_prefix": base_prefix,
        "virtual_environment_active": prefix != base_prefix,
        "runtime_compliance": runtime_compliance,
        "wsgi_relative_path": wsgi_file.relative_to(app_root).as_posix(),
        "wsgi_sha256": _sha256_file(wsgi_file),
        "application_import_target": f"{application_module}.{application_name}",
        "application_import_ok": import_ok,
        "application_type": application_type,
        "application_object_module": application_object_module,
        "process_cwd_inside_app_root": _cwd_inside(app_root),
        "environment_values_recorded": False,
        "request_data_recorded": False,
        "secret_values_recorded": False,
    }


def _cwd_inside(app_root: Path) -> bool:
    try:
        Path.cwd().resolve().relative_to(app_root)
        return True
    except ValueError:
        return False


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--app-root", required=True)
    parser.add_argument("--wsgi-file", required=True)
    parser.add_argument("--application-module", default="bridge.app")
    parser.add_argument("--application-name", default="application")
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    try:
        evidence = collect_runtime_evidence(
            app_root=Path(args.app_root),
            wsgi_file=Path(args.wsgi_file),
            application_module=args.application_module,
            application_name=args.application_name,
        )
        write_json_atomic(Path(args.output), evidence, mode=0o600)
    except (SafetyError, OSError) as exc:
        print(f"RUNTIME_EVIDENCE_BLOCKED: {type(exc).__name__}")
        return 2
    print(evidence["runtime_compliance"])
    return 0 if evidence["runtime_compliance"] == "PYTHON_3_11_CONFIRMED" and evidence["application_import_ok"] else 3


if __name__ == "__main__":
    raise SystemExit(main())
