# -*- coding: utf-8 -*-
"""Privately armed in-application Passenger runtime evidence hook.

Public Git cannot activate this collector. HOSTiQ/support creates one empty
owner-private marker under the account's private control root, restarts the
approved Passenger application, and the real application process writes one
bounded private report only if Python 3.11 + Passenger context + application
import are genuinely confirmed.
"""
from __future__ import annotations

import os
from pathlib import Path

from ops.private_control import validate_private_file
from ops.runtime_evidence import collect_runtime_evidence, write_private_report

CONTROL_DIR_NAME = ".telegram_bridge_private_control"
EVIDENCE_DIR_NAME = ".telegram_bridge_private_evidence"
ARM_MARKER_NAME = "collect_passenger_runtime_evidence.once"
REPORT_NAME = "passenger_runtime_evidence.json"
STRONG_STATUS = "PYTHON_3_11_APPLICATION_CONTEXT_CONFIRMED"


def _paths(home: Path | None = None) -> tuple[Path, Path, Path]:
    home = (home or Path.home()).expanduser()
    control = home / CONTROL_DIR_NAME
    marker = control / ARM_MARKER_NAME
    report = home / EVIDENCE_DIR_NAME / REPORT_NAME
    return control, marker, report


def collect_if_armed(*, app_root: Path, wsgi_file: Path, home: Path | None = None) -> str:
    """Return a stable non-secret code and never expose evidence values."""
    control, marker, report = _paths(home)
    if not marker.exists():
        return "PASSENGER_EVIDENCE_NOT_ARMED"
    try:
        validate_private_file(control, marker, allow_empty=True)
        evidence = collect_runtime_evidence(
            app_root=app_root,
            wsgi_file=wsgi_file,
            application_process=True,
        )
        if evidence["runtime_compliance"] != STRONG_STATUS:
            return "PASSENGER_EVIDENCE_CONTEXT_NOT_CONFIRMED"
        write_private_report(report, evidence)
        # Consumption occurs only after the strong report is durably written.
        marker_stat = os.lstat(marker)
        if marker_stat.st_nlink != 1 or marker_stat.st_uid != os.getuid():
            return "PASSENGER_EVIDENCE_MARKER_CHANGED"
        marker.unlink()
        return "PASSENGER_EVIDENCE_PRIVATE_REPORT_WRITTEN"
    except Exception:
        # Application availability is not coupled to evidence collection.
        # No exception text/path/value is logged or returned.
        return "PASSENGER_EVIDENCE_BLOCKED"
