#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Build/validate the canonical ChatGPT Action schema without contacting production."""
from __future__ import annotations
import argparse
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path: sys.path.insert(0,str(ROOT))
from ops.openapi_registry import build_action_openapi, serialized_action_openapi, validate_action_openapi


def main(argv=None)->int:
    p=argparse.ArgumentParser()
    p.add_argument('--base-url',default='https://tg-api.rukadopomogy.org.ua')
    p.add_argument('--validate-only',action='store_true')
    ns=p.parse_args(argv)
    schema=build_action_openapi(ns.base_url)
    errors=validate_action_openapi(schema)
    if errors:
        for error in errors: print(error,file=sys.stderr)
        return 2
    if ns.validate_only:
        print('DEV4_OPENAPI_CONTRACT_PASS')
    else:
        print(serialized_action_openapi(ns.base_url))
    return 0

if __name__=='__main__': raise SystemExit(main())
