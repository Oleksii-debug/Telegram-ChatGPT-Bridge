#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Build/validate the canonical ChatGPT Action schema without production I/O.

The DEV06 contract layer is authoritative for runtime response/error semantics.
The legacy registry remains an input for mature request schemas only; publishing
its older response envelope would silently diverge from the WSGI API.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ops.dev06_runtime_conformance import (
    build_compatible_chatgpt_action_openapi,
    validate_action_compatibility,
)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="https://tg-api.rukadopomogy.org.ua")
    parser.add_argument("--validate-only", action="store_true")
    args = parser.parse_args(argv)

    schema = build_compatible_chatgpt_action_openapi(args.base_url)
    errors = validate_action_compatibility(schema)
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 2
    if args.validate_only:
        # Preserve the existing CI marker while making the implementation
        # authoritative for the integrated DEV06 runtime contract.
        print("DEV4_OPENAPI_CONTRACT_PASS")
    else:
        print(json.dumps(schema, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
