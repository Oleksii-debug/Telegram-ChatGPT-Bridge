# -*- coding: utf-8 -*-
"""Create the one-time Passenger evidence marker from validated package preflight."""
from __future__ import annotations

import argparse
import json
import os
import stat
import sys
from pathlib import Path

# HOSTiQ/support may launch this documented tool outside the repository cwd.
# Resolve imports from the script's repository, never from ambient cwd/PYTHONPATH.
_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
if str(_REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPOSITORY_ROOT))

from ops.passenger_evidence_hook import ARM_MARKER_NAME, build_arm_marker
from ops.private_control import read_private_text
from ops.release_guard import SafetyError

_EXPECTED_PREFLIGHT_KEYS = {
    "schema_version", "candidate_sha", "wsgi_sha256", "requirements_sha256",
    "requirements_lock_sha256", "direct_package_count", "locked_package_count",
    "required_packages_present", "startup_import_contract_ok", "fully_hash_locked",
    "test_dependencies", "private_runtime_payload_present", "preflight_pass",
    "promotion_authorized",
}


def _private_file_json(path: Path) -> dict:
    path = path.expanduser()
    raw = read_private_text(path.parent, path, max_bytes=4096)
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
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


def _private_control_root(path: Path) -> tuple[Path, os.stat_result]:
    path = path.expanduser()
    st = path.lstat()
    if path.is_symlink() or not stat.S_ISDIR(st.st_mode):
        raise SafetyError("private control root topology unsafe")
    if hasattr(os, "getuid") and st.st_uid != os.getuid():
        raise SafetyError("private control root owner unsafe")
    if stat.S_IMODE(st.st_mode) & 0o077:
        raise SafetyError("private control root permissions unsafe")
    return path, st


def _write_marker_no_clobber(control: Path, expected_root: os.stat_result, payload: dict) -> Path:
    if os.name != "posix" or not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        raise SafetyError("required POSIX arming primitives unavailable")
    nofollow = int(getattr(os, "O_NOFOLLOW"))
    directory = int(getattr(os, "O_DIRECTORY"))
    cloexec = int(getattr(os, "O_CLOEXEC", 0))
    root_fd = os.open(control, os.O_RDONLY | directory | nofollow | cloexec)
    marker_created = False
    try:
        root_after = os.fstat(root_fd)
        if (
            not stat.S_ISDIR(root_after.st_mode)
            or root_after.st_dev != expected_root.st_dev
            or root_after.st_ino != expected_root.st_ino
            or (hasattr(os, "getuid") and root_after.st_uid != os.getuid())
            or stat.S_IMODE(root_after.st_mode) & 0o077
        ):
            raise SafetyError("private control root changed during arming")
        raw = (json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode("ascii")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | nofollow | cloexec
        try:
            fd = os.open(ARM_MARKER_NAME, flags, 0o600, dir_fd=root_fd)
        except FileExistsError as exc:
            raise SafetyError("Passenger evidence marker already exists") from exc
        marker_created = True
        try:
            offset = 0
            while offset < len(raw):
                written = os.write(fd, raw[offset:])
                if written <= 0:
                    raise SafetyError("Passenger evidence marker write failed")
                offset += written
            os.fsync(fd)
            st = os.fstat(fd)
            if (
                not stat.S_ISREG(st.st_mode)
                or st.st_nlink != 1
                or (hasattr(os, "getuid") and st.st_uid != os.getuid())
                or stat.S_IMODE(st.st_mode) & 0o077
                or st.st_size != len(raw)
            ):
                raise SafetyError("Passenger evidence marker write validation failed")
        finally:
            os.close(fd)
        os.fsync(root_fd)
        return control / ARM_MARKER_NAME
    except Exception:
        if marker_created:
            try:
                os.unlink(ARM_MARKER_NAME, dir_fd=root_fd)
                os.fsync(root_fd)
            except OSError:
                pass
        raise
    finally:
        os.close(root_fd)


def arm_from_preflight(*, preflight_path: Path, control_root: Path) -> Path:
    preflight = _private_file_json(preflight_path)
    control, root_stat = _private_control_root(control_root)
    payload = build_arm_marker(preflight["candidate_sha"], preflight["wsgi_sha256"])
    return _write_marker_no_clobber(control, root_stat, payload)


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
