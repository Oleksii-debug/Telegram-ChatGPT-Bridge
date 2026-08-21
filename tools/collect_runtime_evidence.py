# -*- coding: utf-8 -*-
"""One-command private runtime evidence collector for HOSTiQ/support.

No secret values are accepted as CLI arguments.  The report is written outside
the Git checkout under the account home directory with 0700/0600 permissions.
CLI output only states a stable status code.
"""
from __future__ import annotations
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ops.runtime_evidence import collect_runtime_evidence, write_private_report


def main() -> int:
    app_root = ROOT
    wsgi = app_root / "passenger_wsgi.py"
    out = Path.home() / ".telegram_bridge_private_evidence" / "runtime_evidence.json"
    try:
        report = collect_runtime_evidence(app_root=app_root, wsgi_file=wsgi, application_process=False)
        write_private_report(out, report)
    except Exception as exc:
        # Never print message/path; class name only.
        print("RUNTIME_EVIDENCE_BLOCKED:" + type(exc).__name__)
        return 2
    print("RUNTIME_EVIDENCE_PRIVATE_REPORT_WRITTEN")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
