# -*- coding: utf-8 -*-
"""Descriptor-bound Passenger evidence adapter for the deployed release."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from ops.deployed_release_identity import bound_deployed_release_root
from ops.passenger_evidence_hook import (
    CONSUMED_RECEIPT_NAME,
    MAX_RECEIPT_BYTES,
    _paths,
    _promote_runtime_for_verified_request,
    _read_arm_marker,
    _receipt_state,
    _verified_serving_request,
    _write_binding_report,
    build_binding_report,
    build_consumed_receipt,
)
from ops.private_control import verify_private_file_identity, write_private_json_no_clobber
from ops.release_guard import SafetyError
from ops.runtime_evidence import collect_runtime_evidence, write_private_report


def _finalize_bound_strong_evidence(
    *,
    bound,
    control: Path,
    marker_path: Path,
    report: Path,
    binding_path: Path,
    marker: dict,
    marker_identity,
) -> str:
    """Collect process facts, then reprove the same bound release before writes."""
    verify_private_file_identity(control, marker_path, marker_identity)
    bound.revalidate()
    candidate = collect_runtime_evidence(
        app_root=bound.proc_path,
        wsgi_file=bound.proc_path / "passenger_wsgi.py",
        application_process=True,
    )

    # collect_runtime_evidence resolves its Path inputs. Re-bind its critical WSGI
    # identity to the still-open release descriptor before any durable artifact.
    bound.revalidate()
    descriptor_wsgi_sha = bound.regular_leaf_sha256("passenger_wsgi.py")
    if candidate.get("wsgi_sha256") != descriptor_wsgi_sha:
        raise SafetyError("Passenger runtime WSGI does not match bound deployed release")

    evidence = _promote_runtime_for_verified_request(candidate)
    bound_report = build_binding_report(marker, evidence)

    verify_private_file_identity(control, marker_path, marker_identity)
    bound.revalidate()
    write_private_report(report, evidence)
    verify_private_file_identity(control, marker_path, marker_identity)
    bound.revalidate()
    _write_binding_report(binding_path, bound_report)
    verify_private_file_identity(control, marker_path, marker_identity)
    bound.revalidate()

    receipt = build_consumed_receipt(marker, marker_identity, evidence, bound_report)
    receipt_path = control / CONSUMED_RECEIPT_NAME
    write_private_json_no_clobber(control, receipt_path, receipt, max_bytes=MAX_RECEIPT_BYTES)
    verify_private_file_identity(control, marker_path, marker_identity)
    bound.revalidate()
    return "PASSENGER_EVIDENCE_PRIVATE_REPORT_WRITTEN"


def collect_bound_if_armed_from_bridge_app(
    app_module_file: str | Path,
    *,
    environ: dict[str, Any] | None = None,
    home: Path | None = None,
) -> str:
    """Finalize STRONG evidence only for the descriptor-bound deployed SHA.

    Candidate identity is derived from the exact-SHA release root and
    PREPARED_RELEASE.json before runtime collection or report/binding/receipt
    writes. The validated root fd stays open through finalization and is
    revalidated before every durable evidence transition.
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

        # Pre-artifact authority boundary: mismatch fails before process evidence
        # collection and the descriptor remains authoritative through finalization.
        with bound_deployed_release_root(app_root, marker["candidate_sha"]) as bound:
            return _finalize_bound_strong_evidence(
                bound=bound,
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
