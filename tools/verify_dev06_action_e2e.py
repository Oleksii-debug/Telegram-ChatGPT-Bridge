#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Offline DEV06 H2 read-only Action evidence binding CLI.

Inputs are already-sanitized H1/H2 evidence files. The command performs no
network call and never consumes a private Telegram response body.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ops.dev06_action_e2e_evidence import (
    ActionE2EEvidenceError,
    load_h1_summary,
    load_h2_capture,
    summarize_h2_candidate,
)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidate-sha", required=True)
    parser.add_argument("--h1-summary", required=True)
    parser.add_argument("--h2-capture", required=True)
    args = parser.parse_args(argv)
    try:
        h1 = load_h1_summary(args.h1_summary)
        capture = load_h2_capture(args.h2_capture)
        summary = summarize_h2_candidate(args.candidate_sha, h1, capture)
    except ActionE2EEvidenceError as exc:
        print(json.dumps({
            "schema_version": 1,
            "status": str(exc),
            "live_evidence_candidate": False,
            "product_h2_pass": False,
            "auditor_adjudication_required": True,
            "deployment_authorized": False,
            "production_mutated": False,
            "private_values_recorded": False,
        }, sort_keys=True, separators=(",", ":")))
        return 2
    print(json.dumps(summary, sort_keys=True, separators=(",", ":")))
    # A SOURCE_MOCK run is a valid protocol exercise, not an H2 PASS.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
