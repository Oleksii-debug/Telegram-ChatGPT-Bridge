# -*- coding: utf-8 -*-
"""Create one challenge-bound Passenger evidence cycle from validated preflight."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import stat
import sys
from pathlib import Path

# HOSTiQ/support may launch this documented tool outside the repository cwd.
# Resolve imports from the script's repository, never from ambient cwd/PYTHONPATH.
_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
if str(_REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPOSITORY_ROOT))

from ops.passenger_evidence_hook import (
    ARM_MARKER_NAME,
    CONSUMED_RECEIPT_NAME,
    PROBE_CHALLENGE_NAME,
    build_arm_marker,
)
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


def _validate_open_control(root_fd: int, expected_root: os.stat_result) -> None:
    current = os.fstat(root_fd)
    if (
        not stat.S_ISDIR(current.st_mode)
        or current.st_dev != expected_root.st_dev
        or current.st_ino != expected_root.st_ino
        or (hasattr(os, "getuid") and current.st_uid != os.getuid())
        or stat.S_IMODE(current.st_mode) & 0o077
    ):
        raise SafetyError("private control root changed during arming")


def _artifact_exists(root_fd: int, name: str) -> bool:
    try:
        os.stat(name, dir_fd=root_fd, follow_symlinks=False)
        return True
    except FileNotFoundError:
        return False


def _write_exclusive(root_fd: int, name: str, raw: bytes) -> None:
    nofollow = int(getattr(os, "O_NOFOLLOW"))
    cloexec = int(getattr(os, "O_CLOEXEC", 0))
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | nofollow | cloexec
    try:
        fd = os.open(name, flags, 0o600, dir_fd=root_fd)
    except FileExistsError as exc:
        raise SafetyError("Passenger evidence control artifact already exists") from exc
    try:
        offset = 0
        while offset < len(raw):
            written = os.write(fd, raw[offset:])
            if written <= 0:
                raise SafetyError("Passenger evidence control write failed")
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
            raise SafetyError("Passenger evidence control write validation failed")
    finally:
        os.close(fd)


def _write_arm_bundle_no_clobber(
    control: Path,
    expected_root: os.stat_result,
    *,
    challenge: str,
    marker_payload: dict,
) -> Path:
    if os.name != "posix" or not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        raise SafetyError("required POSIX arming primitives unavailable")
    if len(challenge) != 64 or any(ch not in "0123456789abcdef" for ch in challenge):
        raise SafetyError("Passenger evidence challenge generation invalid")

    nofollow = int(getattr(os, "O_NOFOLLOW"))
    directory = int(getattr(os, "O_DIRECTORY"))
    cloexec = int(getattr(os, "O_CLOEXEC", 0))
    root_fd = os.open(control, os.O_RDONLY | directory | nofollow | cloexec)
    created: list[str] = []
    try:
        _validate_open_control(root_fd, expected_root)
        for name in (ARM_MARKER_NAME, PROBE_CHALLENGE_NAME, CONSUMED_RECEIPT_NAME):
            if _artifact_exists(root_fd, name):
                raise SafetyError("Passenger evidence cycle already exists")

        challenge_raw = (challenge + "\n").encode("ascii")
        marker_raw = (
            json.dumps(marker_payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n"
        ).encode("ascii")
        _write_exclusive(root_fd, PROBE_CHALLENGE_NAME, challenge_raw)
        created.append(PROBE_CHALLENGE_NAME)
        _write_exclusive(root_fd, ARM_MARKER_NAME, marker_raw)
        created.append(ARM_MARKER_NAME)
        os.fsync(root_fd)
        return control / ARM_MARKER_NAME
    except Exception:
        for name in reversed(created):
            try:
                os.unlink(name, dir_fd=root_fd)
            except OSError:
                pass
        try:
            os.fsync(root_fd)
        except OSError:
            pass
        raise
    finally:
        os.close(root_fd)


def arm_from_preflight(*, preflight_path: Path, control_root: Path) -> Path:
    preflight = _private_file_json(preflight_path)
    control, root_stat = _private_control_root(control_root)
    challenge = secrets.token_hex(32)
    challenge_sha256 = hashlib.sha256(challenge.encode("ascii")).hexdigest()
    payload = build_arm_marker(
        preflight["candidate_sha"],
        preflight["wsgi_sha256"],
        challenge_sha256,
    )
    return _write_arm_bundle_no_clobber(
        control,
        root_stat,
        challenge=challenge,
        marker_payload=payload,
    )


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
    # Never emit the raw challenge, its path, or any private value.
    print("PASSENGER_EVIDENCE_ARMED_FOR_EXACT_CANDIDATE")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
