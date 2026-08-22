# -*- coding: utf-8 -*-
"""Validate a one-time HOSTiQ support-return package without echoing private data."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from ops.production_readiness import build_deployment_readiness, validate_public_readiness, validate_support_return
from ops.release_guard import SafetyError, write_json_atomic

MAX_INPUT_BYTES = 64 * 1024


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    try:
        source = Path(args.input).resolve(strict=True)
        raw = source.read_bytes()
        if len(raw) > MAX_INPUT_BYTES:
            raise SafetyError("support return exceeds bounded size")
        payload = json.loads(raw.decode("utf-8"))
        if not isinstance(payload, dict):
            raise SafetyError("support return root invalid")
        validate_support_return(payload)
        readiness = build_deployment_readiness(payload)
        validate_public_readiness(readiness)
        write_json_atomic(Path(args.output), readiness, mode=0o600)
    except (OSError, UnicodeError, json.JSONDecodeError, SafetyError):
        print("HOSTIQ_SUPPORT_RETURN_BLOCKED")
        return 2
    print("HOSTIQ_SUPPORT_RETURN_READY_FOR_AUDITOR")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
