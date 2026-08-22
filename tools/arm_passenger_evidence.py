# -*- coding: utf-8 -*-
"""Create the one-time Passenger evidence marker from validated package preflight."""
from __future__ import annotations

import argparse
import json
import os
import stat
from pathlib import Path

from ops.passenger_evidence_hook import ARM_MARKER_NAME, build_arm_marker
from ops.release_guard import SafetyError, write_json_atomic

_EXPECTED_PREFLIGHT_KEYS = {
    "schema_version", "candidate_sha", "wsgi_sha256", "requirements_sha256",
    "requirements_lock_sha256", "direct_package_count", "locked_package_count",
    "required_packages_present", "startup_import_contract_ok", "fully_hash_locked",
    "test_dependencies", "private_runtime_payload_present", "preflight_pass",
    "promotion_authorized",
}


def _private_file_json(path: Path) -> dict:
    st = path.lstat()
    mode = stat.S_IMODE(st.st_mode)
    if path.is_symlink() or not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
        raise SafetyError("preflight evidence topology unsafe")
    if hasattr(os, "getuid") and st.st_uid != os.getuid():
        raise SafetyError("preflight evidence owner unsafe")
    if mode & 0o077 or st.st_size <= 0 or st.st_size > 64 * 1024:
        raise SafetyError("preflight evidence permissions/size unsafe")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise SafetyError("preflight evidence JSON invalid") from exc
    if not isinstance(payload, dict) or set(payload) != _EXPECTED_PREFLIGHT_KEYS:
        raise SafetyError("preflight evidence schema mismatch")
    if payload.get("schema_version") != 2:
        raise SafetyError("preflight evidence version mismatch")
    for key in ("required_packages_present", "startup_import_contract_ok", "fully_hash_locked", "preflight_pass"):
        if payload.get(key) is not True:
            raise SafetyError("candidate package preflight is not a positive exact result")
    if payload.get("private_runtime_payload_present") is not False or payload.get("promotion_authorized") is not False:
        raise SafetyError("candidate preflight safety invariant violated")
    return payload


def _private_control_root(path: Path) -> Path:
    path = path.expanduser()
    st = path.lstat()
    if path.is_symlink() or not stat.S_ISDIR(st.st_mode):
        raise SafetyError("private control root topology unsafe")
    if hasattr(os, "getuid") and st.st_uid != os.getuid():
        raise SafetyError("private control root owner unsafe")
    if stat.S_IMODE(st.st_mode) & 0o077:
        raise SafetyError("private control root permissions unsafe")
    return path


def arm_from_preflight(*, preflight_path: Path, control_root: Path) -> Path:
    preflight = _private_file_json(preflight_path)
    control = _private_control_root(control_root)
    marker = control / ARM_MARKER_NAME
    if marker.exists() or marker.is_symlink():
        raise SafetyError("Passenger evidence marker already exists")
    payload = build_arm_marker(preflight["candidate_sha"], preflight["wsgi_sha256"])
    write_json_atomic(marker, payload, mode=0o600)
    st = marker.lstat()
    if marker.is_symlink() or not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or stat.S_IMODE(st.st_mode) & 0o077:
        raise SafetyError("Passenger evidence marker write validation failed")
    return marker


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--preflight", required=True)
    parser.add_argument(
        "--control-root",
        default=str(Path.home() / ".telegram_bridge_private_control"),
    )
    args = parser.parse_args(argv)
    try:
        arm_from_preflight(
            preflight_path=Path(args.preflight),
            control_root=Path(args.control_root),
        )
    except (SafetyError, OSError, ValueError):
        print("PASSENGER_EVIDENCE_ARM_BLOCKED")
        return 2
    print("PASSENGER_EVIDENCE_ARMED_FOR_EXACT_CANDIDATE")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
