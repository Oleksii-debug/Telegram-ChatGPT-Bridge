# -*- coding: utf-8 -*-
"""Checkout-only, read-only H2 capture verifier; performs no live operation."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ops.dev06_deployed_action_evidence import (  # noqa: E402
    DeployedActionEvidenceError,
    summarize_h2_capture_file,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate a sanitized read-only Action H2 capture against the exact executing checkout")
    parser.add_argument("--source-checkout", required=True)
    parser.add_argument("--capture", required=True)
    args = parser.parse_args(argv)
    try:
        result = summarize_h2_capture_file(args.source_checkout, args.capture)
    except DeployedActionEvidenceError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
