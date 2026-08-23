#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Build/validate the canonical DEV06 ChatGPT Action schema offline."""
from __future__ import annotations

import argparse
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ops.dev06_api_contracts import (
    build_chatgpt_action_openapi,
    serialized_chatgpt_action_openapi,
    validate_chatgpt_action_schema,
)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="https://tg-api.rukadopomogy.org.ua")
    parser.add_argument("--validate-only", action="store_true")
    args = parser.parse_args(argv)

    schema = build_chatgpt_action_openapi(args.base_url)
    errors = validate_chatgpt_action_schema(schema)
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 2
    if args.validate_only:
        # Preserve the historical marker so older CI consumers do not break.
        print("DEV4_OPENAPI_CONTRACT_PASS")
    else:
        print(serialized_chatgpt_action_openapi(args.base_url))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
