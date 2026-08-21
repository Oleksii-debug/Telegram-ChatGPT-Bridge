# -*- coding: utf-8 -*-
"""Machine-readable overlap report for isolated Developer branches.
Input JSON: {"DEV2": ["path", ...], ...}. No Git mutation/network access.
"""
from __future__ import annotations
import json, sys
from collections import defaultdict

def build_report(lanes:dict[str,list[str]])->dict:
    normalized={lane:sorted(set(paths)) for lane,paths in lanes.items() if lane in {"DEV2","DEV3","DEV4","DEV5"}}
    owners=defaultdict(list)
    for lane,paths in normalized.items():
        for path in paths:
            if not isinstance(path,str) or not path or path.startswith("/") or ".." in path.split("/"): raise ValueError("unsafe path")
            owners[path].append(lane)
    overlaps={p:sorted(v) for p,v in sorted(owners.items()) if len(v)>1}
    dev1_sensitive={p:sorted(v) for p,v in sorted(owners.items()) if p in {"ops/evidence_privacy.py","ops/acceptance_harness.py","ops/acceptance_contracts.py","ops/deploy_release.py",".github/workflows/ci.yml"}}
    return {"schema_version":1,"lanes":normalized,"cross_lane_overlaps":overlaps,"dev1_sensitive_overlaps":dev1_sensitive}

def main()->int:
    data=json.load(sys.stdin); print(json.dumps(build_report(data),sort_keys=True,separators=(",",":")));return 0
if __name__=="__main__": raise SystemExit(main())