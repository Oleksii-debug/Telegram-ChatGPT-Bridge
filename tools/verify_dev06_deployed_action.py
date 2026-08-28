#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Offline DEV06 deployed-Action comparison CLI.

The command never fetches production itself.  A future audited live process may
supply a sanitized captured schema file.  Output is bounded hash/count evidence
only and never self-authorizes H1 or deployment.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ops.dev06_deployed_action_evidence import (
    PRODUCTION_BASE_URL,
    DeployedActionEvidenceError,
    compare_deployed_action_schema,
    load_observed_schema,
)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidate-sha", required=True)
    parser.add_argument("--observed-schema", required=True)
    parser.add_argument("--base-url", default=PRODUCTION_BASE_URL)
    parser.add_argument(
        "--source-classification",
        choices=("SOURCE_MOCK", "DEPLOYED_CAPTURE"),
        default="SOURCE_MOCK",
    )
    args = parser.parse_args(argv)
    try:
        observed = load_observed_schema(args.observed_schema)
        summary = compare_deployed_action_schema(
            args.candidate_sha,
            observed,
            base_url=args.base_url,
            source_classification=args.source_classification,
        )
    except DeployedActionEvidenceError as exc:
        print(json.dumps({
            "schema_version": 1,
            "status": str(exc),
            "schema_match": False,
            "product_h1_pass": False,
            "deployment_authorized": False,
            "production_mutated": False,
            "private_values_recorded": False,
        }, sort_keys=True, separators=(",", ":")))
        return 2
    print(json.dumps(summary, sort_keys=True, separators=(",", ":")))
    return 0 if summary["schema_match"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
