#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Verify one exact canonical SHA against the reviewed DEV02 runtime protocol."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ops.dev02_canonical_sync import (
    CanonicalSyncError,
    validate_sync_summary,
    verify_candidate_runtime_sync,
)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", default=".")
    parser.add_argument("--candidate-sha", required=True)
    args = parser.parse_args(argv)
    try:
        summary = validate_sync_summary(
            verify_candidate_runtime_sync(Path(args.repo), args.candidate_sha)
        )
    except (CanonicalSyncError, OSError, ValueError):
        print("DEV02_CANONICAL_RUNTIME_SYNC_BLOCKED")
        return 2
    print(json.dumps(summary, sort_keys=True, separators=(",", ":")))
    return 0 if summary["status"] == "READY_FOR_CANONICAL_REVALIDATION" else 2


if __name__ == "__main__":
    raise SystemExit(main())
