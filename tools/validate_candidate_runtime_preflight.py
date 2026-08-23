# -*- coding: utf-8 -*-
"""One-command non-live validator for the exact canonical release package."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# The documented support command may be launched from any working directory.
# Bootstrap imports from this script's immutable repository location rather than
# relying on cwd/PYTHONPATH, which is not a valid production-readiness proof.
_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
if str(_REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPOSITORY_ROOT))

from ops.candidate_runtime_preflight import validate_candidate_release_envelope
from ops.release_guard import SafetyError, write_json_atomic


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidate-root", required=True)
    parser.add_argument("--candidate-sha", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    try:
        result = validate_candidate_release_envelope(
            Path(args.candidate_root), candidate_sha=args.candidate_sha
        )
        # Hash/count/boolean-only output; still write owner-private because it is
        # release evidence and should not become an accidental public authority.
        write_json_atomic(Path(args.output), result, mode=0o600)
    except (SafetyError, OSError, ValueError, json.JSONDecodeError):
        print("CANDIDATE_RUNTIME_PREFLIGHT_BLOCKED")
        return 2
    print("CANDIDATE_RUNTIME_PREFLIGHT_PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
