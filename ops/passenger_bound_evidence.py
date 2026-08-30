# -*- coding: utf-8 -*-
"""Descriptor-bound Passenger evidence adapter for the deployed release."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from ops.deployed_release_identity import bound_deployed_release_root
from ops.passenger_evidence_hook import (
    CONSUMED_RECEIPT_NAME,
    _finalize_strong_evidence,
    _paths,
    _read_arm_marker,
    _receipt_state,
    _verified_serving_request,
)
from ops.release_guard import SafetyError


def collect_bound_if_armed_from_bridge_app(
    app_module_file: str | Path,
    *,
    environ: dict[str, Any] | None = None,
    home: Path | None = None,
) -> str:
    """Finalize STRONG evidence only for the descriptor-bound deployed SHA.

    Candidate identity is derived from the exact-SHA release root and
    PREPARED_RELEASE.json before any runtime collection or report/binding/receipt
    write. The validated root fd stays open through finalization, so a same-name
    release-directory replacement cannot redirect subsequent WSGI/runtime reads.
    """
    try:
        app_file = Path(app_module_file).expanduser().resolve(strict=True)
        if app_file.name != "app.py" or app_file.parent.name != "bridge":
            return "PASSENGER_EVIDENCE_APP_TOPOLOGY_BLOCKED"
        app_root = app_file.parent.parent
        wsgi_file = app_root / "passenger_wsgi.py"
        wsgi_stat = os.lstat(wsgi_file)
        if wsgi_file.is_symlink() or not wsgi_file.is_file() or wsgi_stat.st_nlink != 1:
            return "PASSENGER_EVIDENCE_APP_TOPOLOGY_BLOCKED"
        if environ is None:
            return "PASSENGER_EVIDENCE_SERVING_REQUEST_REQUIRED"

        control, marker_path, report, binding = _paths(home)
        receipt = control / CONSUMED_RECEIPT_NAME
        if receipt.exists():
            return "PASSENGER_EVIDENCE_ALREADY_CONSUMED" if _receipt_state(control, receipt) else "PASSENGER_EVIDENCE_BLOCKED"
        if not marker_path.exists():
            return "PASSENGER_EVIDENCE_NOT_ARMED"
        marker, marker_identity = _read_arm_marker(control, marker_path)
        if not _verified_serving_request(environ, marker):
            return "PASSENGER_EVIDENCE_SERVING_REQUEST_NOT_VERIFIED"

        # This is the pre-artifact authority boundary.  No runtime collection or
        # evidence write happens unless the armed SHA equals the actual deployed
        # versioned release identity.  Keep the release fd alive through the
        # finalizer to close the replacement race after validation.
        with bound_deployed_release_root(app_root, marker["candidate_sha"]) as (bound_root, _deployed_sha):
            return _finalize_strong_evidence(
                app_root=bound_root,
                wsgi_file=bound_root / "passenger_wsgi.py",
                control=control,
                marker_path=marker_path,
                report=report,
                binding_path=binding,
                marker=marker,
                marker_identity=marker_identity,
            )
    except (SafetyError, OSError, ValueError):
        return "PASSENGER_EVIDENCE_BLOCKED"
    except Exception:
        # Evidence collection remains fail-isolated from application availability.
        return "PASSENGER_EVIDENCE_BLOCKED"
