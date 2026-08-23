#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Run one bounded challenged Passenger evidence probe after Auditor approval.

This tool is mechanism only. Public Git cannot schedule or auto-run it. The raw
256-bit challenge exists only in this process and the HTTPS request header; only
its SHA-256 digest is placed in the owner-private marker/evidence. A successful
HTTP health response is NOT enough: the same request must synchronously create a
valid runtime binding and consumed receipt that match the exact challenge and
candidate.
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
    BINDING_REPORT_NAME,
    CONSUMED_RECEIPT_NAME,
    EVIDENCE_DIR_NAME,
    validate_binding_report,
    validate_consumed_receipt,
)
from ops.passenger_probe import PRODUCTION_HOST, dispatch_challenged_health_probe
from ops.private_control import read_private_text
from ops.release_guard import SafetyError
from tools.arm_passenger_evidence import arm_from_preflight

MAX_PRIVATE_JSON = 4096
DEFAULT_ENDPOINT = f"https://{PRODUCTION_HOST}/health"


def _private_json(root: Path, path: Path, *, max_bytes: int = MAX_PRIVATE_JSON) -> dict:
    raw = read_private_text(root, path, max_bytes=max_bytes)
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SafetyError("Passenger private evidence JSON invalid") from exc
    if not isinstance(value, dict):
        raise SafetyError("Passenger private evidence root invalid")
    return value


def _verify_terminal_artifacts(
    *,
    control_root: Path,
    evidence_root: Path,
    challenge_sha256: str,
) -> None:
    binding_path = evidence_root / BINDING_REPORT_NAME
    receipt_path = control_root / CONSUMED_RECEIPT_NAME
    binding = validate_binding_report(_private_json(evidence_root, binding_path))
    receipt = validate_consumed_receipt(_private_json(control_root, receipt_path))
    if binding["request_challenge_sha256"] != challenge_sha256:
        raise SafetyError("Passenger terminal challenge binding mismatch")
    if binding["candidate_sha"] != receipt["candidate_sha"]:
        raise SafetyError("Passenger terminal candidate binding mismatch")
    if binding["expected_wsgi_sha256"] != receipt["expected_wsgi_sha256"]:
        raise SafetyError("Passenger terminal WSGI binding mismatch")
    if binding["runtime_payload_sha256"] != receipt["runtime_payload_sha256"]:
        raise SafetyError("Passenger terminal runtime binding mismatch")
    if binding["payload_sha256"] != receipt["binding_payload_sha256"]:
        raise SafetyError("Passenger terminal binding payload mismatch")
    if binding["serving_probe_sha256"] != receipt["serving_probe_sha256"]:
        raise SafetyError("Passenger terminal serving probe mismatch")


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
    raw_challenge = secrets.token_hex(32)
    challenge_sha256 = hashlib.sha256(raw_challenge.encode("ascii")).hexdigest()
    try:
        arm_from_preflight(
            preflight_path=preflight_path,
            control_root=control_root,
            request_challenge_sha256=challenge_sha256,
        )
        for _ in range(attempts):
            result = dispatch_challenged_health_probe(endpoint, raw_challenge, timeout=timeout)
            if result.status != "PASS":
                continue
            _verify_terminal_artifacts(
                control_root=control_root,
                evidence_root=evidence_root,
                challenge_sha256=challenge_sha256,
            )
            return "PASSENGER_EVIDENCE_ONE_SHOT_CONFIRMED"
        return "PASSENGER_EVIDENCE_ONE_SHOT_NOT_CONFIRMED"
    finally:
        # Python offers no guaranteed memory zeroization; dropping the reference
        # is the only claim made. The raw value is never serialized or printed.
        raw_challenge = ""


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--preflight", required=True)
    parser.add_argument("--control-root", required=True)
    parser.add_argument("--evidence-root", required=True)
    parser.add_argument("--endpoint", default=DEFAULT_ENDPOINT)
    parser.add_argument("--attempts", type=int, default=2)
    parser.add_argument("--timeout", type=float, default=5.0)
    args = parser.parse_args(argv)
    try:
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
