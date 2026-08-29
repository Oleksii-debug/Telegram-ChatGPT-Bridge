# -*- coding: utf-8 -*-
"""Checkout-only H1 verifier; candidate SHA is always derived, never input."""
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
    compare_deployed_action_schema_file,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify a sanitized deployed Action schema against the exact executing checkout")
    parser.add_argument("--source-checkout", required=True)
    parser.add_argument("--observed-schema", required=True)
    parser.add_argument("--source-classification", choices=("SOURCE_MOCK", "DEPLOYED_CAPTURE"), default="SOURCE_MOCK")
    args = parser.parse_args(argv)
    try:
        result = compare_deployed_action_schema_file(
            args.source_checkout,
            args.observed_schema,
            source_classification=args.source_classification,
        )
    except DeployedActionEvidenceError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result["schema_match"] else 3


if __name__ == "__main__":
    raise SystemExit(main())
