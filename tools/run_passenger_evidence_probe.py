#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Run one bounded challenged Passenger evidence probe after Auditor approval.

This tool is mechanism only. Public Git cannot schedule or auto-run it. The raw
256-bit challenge exists only in this process and the HTTPS request header; only
its SHA-256 digest is placed in the owner-private marker/evidence. A successful
HTTP health response is NOT enough: the same request must synchronously create a
valid runtime binding and consumed receipt that match the exact challenge and
candidate.

Deterministic local transport validation happens before arming. Once any network
request may have been dispatched, failure is treated as ambiguous and the marker
is deliberately retained; it is never blindly deleted/re-armed. If terminal
private artifacts already prove that the challenged request was consumed but the
HTTP response was not confirmed, that state is reported separately and remains
non-authorizing.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import secrets
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ops.passenger_evidence_hook import (
    ARM_MARKER_NAME,
    BINDING_REPORT_NAME,
    CONSUMED_RECEIPT_NAME,
    REPORT_NAME,
    STRONG_STATUS,
    validate_arm_marker,
    validate_binding_report,
    validate_consumed_receipt,
)
from ops.passenger_probe import (
    PRODUCTION_HOST,
    dispatch_challenged_health_probe,
    validate_probe_transport,
)
from ops.private_control import (
    private_identity_sha256,
    read_private_text,
    read_private_text_with_identity,
)
from ops.private_evidence import canonical_json_sha256, validate_runtime_report
from ops.release_guard import SafetyError
from tools.arm_passenger_evidence import arm_from_preflight

MAX_PRIVATE_JSON = 4096
DEFAULT_ENDPOINT = f"https://{PRODUCTION_HOST}/health"


def _decode_private_json(raw: str) -> dict:
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SafetyError("Passenger private evidence JSON invalid") from exc
    if not isinstance(value, dict):
        raise SafetyError("Passenger private evidence root invalid")
    return value


def _private_json(root: Path, path: Path, *, max_bytes: int = MAX_PRIVATE_JSON) -> dict:
    return _decode_private_json(read_private_text(root, path, max_bytes=max_bytes))


def _private_json_with_identity(root: Path, path: Path, *, max_bytes: int = MAX_PRIVATE_JSON):
    raw, identity = read_private_text_with_identity(root, path, max_bytes=max_bytes)
    return _decode_private_json(raw), identity


def _verify_terminal_artifacts(
    *,
    control_root: Path,
    evidence_root: Path,
    challenge_sha256: str,
) -> None:
    marker_path = control_root / ARM_MARKER_NAME
    report_path = evidence_root / REPORT_NAME
    binding_path = evidence_root / BINDING_REPORT_NAME
    receipt_path = control_root / CONSUMED_RECEIPT_NAME

    marker_raw, marker_identity = _private_json_with_identity(control_root, marker_path)
    marker = validate_arm_marker(marker_raw)
    runtime = validate_runtime_report(_private_json(evidence_root, report_path))
    binding = validate_binding_report(_private_json(evidence_root, binding_path))
    receipt = validate_consumed_receipt(_private_json(control_root, receipt_path))

    if marker["request_challenge_sha256"] != challenge_sha256:
        raise SafetyError("Passenger marker challenge binding mismatch")
    if binding["request_challenge_sha256"] != challenge_sha256:
        raise SafetyError("Passenger terminal challenge binding mismatch")
    if not (
        marker["candidate_sha"] == binding["candidate_sha"] == receipt["candidate_sha"]
    ):
        raise SafetyError("Passenger terminal candidate binding mismatch")
    if not (
        marker["expected_wsgi_sha256"]
        == binding["expected_wsgi_sha256"]
        == binding["actual_wsgi_sha256"]
        == receipt["expected_wsgi_sha256"]
        == runtime["wsgi_sha256"]
    ):
        raise SafetyError("Passenger terminal WSGI binding mismatch")
    if runtime["runtime_compliance"] != STRONG_STATUS or runtime["serving_request_verified"] is not True:
        raise SafetyError("Passenger terminal runtime is not strong serving evidence")
    if not (
        runtime["payload_sha256"]
        == binding["runtime_payload_sha256"]
        == receipt["runtime_payload_sha256"]
    ):
        raise SafetyError("Passenger terminal runtime binding mismatch")
    if binding["payload_sha256"] != receipt["binding_payload_sha256"]:
        raise SafetyError("Passenger terminal binding payload mismatch")
    if binding["serving_probe_sha256"] != receipt["serving_probe_sha256"]:
        raise SafetyError("Passenger terminal serving probe mismatch")
    if receipt["marker_payload_sha256"] != canonical_json_sha256(marker):
        raise SafetyError("Passenger terminal marker payload mismatch")
    if receipt["marker_identity_sha256"] != private_identity_sha256(marker_identity):
        raise SafetyError("Passenger terminal marker identity mismatch")


def _terminal_artifact_state(
    *,
    control_root: Path,
    evidence_root: Path,
    challenge_sha256: str,
) -> str:
    paths = (
        evidence_root / REPORT_NAME,
        evidence_root / BINDING_REPORT_NAME,
        control_root / CONSUMED_RECEIPT_NAME,
    )
    present = []
    for path in paths:
        try:
            path.lstat()
        except FileNotFoundError:
            present.append(False)
        except OSError as exc:
            raise SafetyError("Passenger terminal artifact state unavailable") from exc
        else:
            present.append(True)
    if not any(present):
        return "ABSENT"
    if not all(present):
        raise SafetyError("Passenger terminal artifact state partial")
    _verify_terminal_artifacts(
        control_root=control_root,
        evidence_root=evidence_root,
        challenge_sha256=challenge_sha256,
    )
    return "VALID"


def inspect_existing_evidence_state(*, control_root: Path, evidence_root: Path) -> str:
    """Inspect an already armed attempt without mutating or reopening it."""
    marker_path = control_root / ARM_MARKER_NAME
    try:
        marker = validate_arm_marker(_private_json(control_root, marker_path))
    except FileNotFoundError:
        dangling = (
            evidence_root / REPORT_NAME,
            evidence_root / BINDING_REPORT_NAME,
            control_root / CONSUMED_RECEIPT_NAME,
        )
        if any(path.exists() for path in dangling):
            raise SafetyError("Passenger terminal artifacts exist without marker")
        return "PASSENGER_EVIDENCE_EXISTING_NOT_ARMED"
    state = _terminal_artifact_state(
        control_root=control_root,
        evidence_root=evidence_root,
        challenge_sha256=marker["request_challenge_sha256"],
    )
    if state == "VALID":
        return "PASSENGER_EVIDENCE_EXISTING_TERMINAL_VALID_NONAUTHORIZING"
    return "PASSENGER_EVIDENCE_EXISTING_ARMED_AMBIGUOUS"


def run_one_shot_probe(
    *,
    preflight_path: Path,
    control_root: Path,
    evidence_root: Path,
    endpoint: str = DEFAULT_ENDPOINT,
    attempts: int = 2,
    timeout: float = 5.0,
) -> str:
    if not isinstance(attempts, int) or isinstance(attempts, bool) or not 1 <= attempts <= 3:
        raise SafetyError("Passenger probe attempts invalid")

    # Critical ordering: deterministic local failures occur before a persistent
    # one-shot marker exists. After dispatch begins, automatic cleanup/re-arm is
    # forbidden because a timeout/reset may hide an already processed request.
    endpoint, timeout_value = validate_probe_transport(endpoint, timeout)

    raw_challenge = secrets.token_hex(32)
    challenge_sha256 = hashlib.sha256(raw_challenge.encode("ascii")).hexdigest()
    try:
        arm_from_preflight(
            preflight_path=preflight_path,
            control_root=control_root,
            request_challenge_sha256=challenge_sha256,
        )
        for _ in range(attempts):
            result = dispatch_challenged_health_probe(endpoint, raw_challenge, timeout=timeout_value)
            if result.status != "PASS":
                continue
            _verify_terminal_artifacts(
                control_root=control_root,
                evidence_root=evidence_root,
                challenge_sha256=challenge_sha256,
            )
            return "PASSENGER_EVIDENCE_ONE_SHOT_CONFIRMED"

        terminal = _terminal_artifact_state(
            control_root=control_root,
            evidence_root=evidence_root,
            challenge_sha256=challenge_sha256,
        )
        if terminal == "VALID":
            return "PASSENGER_EVIDENCE_TERMINAL_CONFIRMED_HTTP_NOT_CONFIRMED"
        return "PASSENGER_EVIDENCE_ONE_SHOT_AMBIGUOUS_RETAINED"
    finally:
        # Python offers no guaranteed memory zeroization; dropping the reference
        # is the only claim made. The raw value is never serialized or printed.
        raw_challenge = ""


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--preflight")
    parser.add_argument("--control-root", required=True)
    parser.add_argument("--evidence-root", required=True)
    parser.add_argument("--endpoint", default=DEFAULT_ENDPOINT)
    parser.add_argument("--attempts", type=int, default=2)
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("--inspect-existing", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.inspect_existing:
            if args.preflight is not None:
                raise SafetyError("Passenger inspection must not accept a preflight mutation input")
            status = inspect_existing_evidence_state(
                control_root=Path(args.control_root),
                evidence_root=Path(args.evidence_root),
            )
            print(status)
            return 0
        if args.preflight is None:
            raise SafetyError("Passenger probe preflight required")
        status = run_one_shot_probe(
            preflight_path=Path(args.preflight),
            control_root=Path(args.control_root),
            evidence_root=Path(args.evidence_root),
            endpoint=args.endpoint,
            attempts=args.attempts,
            timeout=args.timeout,
        )
    except (SafetyError, OSError, ValueError):
        print("PASSENGER_EVIDENCE_PROBE_BLOCKED")
        return 2
    print(status)
    return 0 if status == "PASSENGER_EVIDENCE_ONE_SHOT_CONFIRMED" else 2


if __name__ == "__main__":
    raise SystemExit(main())
