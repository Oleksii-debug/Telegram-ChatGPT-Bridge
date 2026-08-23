# -*- coding: utf-8 -*-
"""Machine-verifiable DEV02 runtime protocol compatibility with a canonical SHA.

This verifier is deliberately non-authorizing.  It proves only that an exact
candidate contains the reviewed DEV02 runtime protocol ancestry and byte-exact
critical runtime/evidence files, then reports whether the canonical release
ledger has caught up with that fact.
"""
from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

FULL_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
RUNTIME_PROTOCOL_SHA = "8f2044d7bca9487815f754d614ab781555671a4b"
LEDGER_PATH = "integration/release_to_live_v1.json"
MAX_GIT_TEXT = 256 * 1024

CRITICAL_RUNTIME_PATHS = (
    "ops/candidate_runtime_preflight.py",
    "ops/passenger_evidence_hook.py",
    "ops/passenger_probe.py",
    "ops/private_control.py",
    "ops/private_evidence.py",
    "ops/production_readiness.py",
    "tools/arm_passenger_evidence.py",
    "tools/run_passenger_evidence_probe.py",
    "tools/validate_candidate_runtime_preflight.py",
    "tools/validate_hostiq_support_return.py",
)


class CanonicalSyncError(RuntimeError):
    """Bounded compatibility failure; never includes subprocess output."""


def _repo(repo: Path) -> Path:
    root = Path(repo).resolve()
    if not (root / ".git").exists():
        raise CanonicalSyncError("repository checkout required")
    return root


def _git(root: Path, args: list[str], *, text_limit: int = MAX_GIT_TEXT) -> str:
    try:
        cp = subprocess.run(
            ["git", *args],
            cwd=root,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise CanonicalSyncError("Git verification unavailable") from exc
    if cp.returncode != 0 or len(cp.stdout) > text_limit:
        raise CanonicalSyncError("Git verification failed")
    try:
        return cp.stdout.decode("utf-8", "strict").strip()
    except UnicodeError as exc:
        raise CanonicalSyncError("Git verification output invalid") from exc


def _exact_commit(root: Path, sha: str, label: str) -> str:
    if not isinstance(sha, str) or not FULL_SHA_RE.fullmatch(sha):
        raise CanonicalSyncError(f"{label} SHA invalid")
    resolved = _git(root, ["rev-parse", "--verify", f"{sha}^{{commit}}"])
    if resolved != sha:
        raise CanonicalSyncError(f"{label} SHA is not exact")
    return sha


def _is_ancestor(root: Path, ancestor: str, descendant: str) -> bool:
    try:
        cp = subprocess.run(
            ["git", "merge-base", "--is-ancestor", ancestor, descendant],
            cwd=root,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise CanonicalSyncError("Git ancestry verification unavailable") from exc
    if cp.returncode == 0:
        return True
    if cp.returncode == 1:
        return False
    raise CanonicalSyncError("Git ancestry verification failed")


def _blob_sha(root: Path, sha: str, path: str) -> str:
    value = _git(root, ["rev-parse", "--verify", f"{sha}:{path}"])
    if not FULL_SHA_RE.fullmatch(value):
        raise CanonicalSyncError("runtime path identity invalid")
    return value


def _show_json(root: Path, sha: str, path: str) -> dict:
    raw = _git(root, ["show", f"{sha}:{path}"])
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise CanonicalSyncError("canonical release ledger invalid") from exc
    if not isinstance(value, dict):
        raise CanonicalSyncError("canonical release ledger root invalid")
    return value


def _ledger_runtime_sha(ledger: dict) -> str | None:
    # Current canonical name is dev_b_terminal_sync.  A future DEV02-specific
    # spelling may supersede it; the older round2 section remains legacy-only.
    for key in ("dev02_runtime_sync", "dev_b_terminal_sync", "dev_b_round2_sync"):
        section = ledger.get(key)
        if section is None:
            continue
        if not isinstance(section, dict):
            return None
        value = section.get("sha")
        return value if isinstance(value, str) and FULL_SHA_RE.fullmatch(value) else None
    return None


def _ledger_accounts_paths(ledger: dict) -> bool:
    paths = ledger.get("paths")
    if not isinstance(paths, list) or any(not isinstance(item, str) for item in paths):
        return False
    return set(CRITICAL_RUNTIME_PATHS).issubset(paths)


def verify_candidate_runtime_sync(
    repo: Path,
    candidate_sha: str,
    *,
    protocol_sha: str = RUNTIME_PROTOCOL_SHA,
) -> dict:
    """Return a bounded source-level compatibility summary.

    `READY_FOR_CANONICAL_REVALIDATION` means only that ancestry, critical bytes,
    and ledger accounting agree.  It never means deploy/merge/Passenger restart
    or live evidence is authorized.
    """
    root = _repo(repo)
    candidate = _exact_commit(root, candidate_sha, "candidate")
    protocol = _exact_commit(root, protocol_sha, "DEV02 protocol")

    if not _is_ancestor(root, protocol, candidate):
        return {
            "schema_version": 1,
            "candidate_sha": candidate,
            "protocol_sha": protocol,
            "protocol_ancestry": "FAIL",
            "critical_blob_identity": "NOT_CHECKED",
            "critical_path_count": len(CRITICAL_RUNTIME_PATHS),
            "ledger_binding": "NOT_CHECKED",
            "ledger_path_accounting": "NOT_CHECKED",
            "status": "BLOCKED_PROTOCOL_ANCESTRY",
            "promotion_authorized": False,
        }

    for path in CRITICAL_RUNTIME_PATHS:
        try:
            protocol_blob = _blob_sha(root, protocol, path)
            candidate_blob = _blob_sha(root, candidate, path)
        except CanonicalSyncError:
            protocol_blob = None
            candidate_blob = None
        if protocol_blob is None or candidate_blob is None or protocol_blob != candidate_blob:
            return {
                "schema_version": 1,
                "candidate_sha": candidate,
                "protocol_sha": protocol,
                "protocol_ancestry": "PASS",
                "critical_blob_identity": "FAIL",
                "critical_path_count": len(CRITICAL_RUNTIME_PATHS),
                "ledger_binding": "NOT_CHECKED",
                "ledger_path_accounting": "NOT_CHECKED",
                "status": "BLOCKED_RUNTIME_DRIFT",
                "promotion_authorized": False,
            }

    ledger = _show_json(root, candidate, LEDGER_PATH)
    ledger_binding = "PASS" if _ledger_runtime_sha(ledger) == protocol else "STALE"
    ledger_paths = "PASS" if _ledger_accounts_paths(ledger) else "STALE"
    status = (
        "READY_FOR_CANONICAL_REVALIDATION"
        if ledger_binding == "PASS" and ledger_paths == "PASS"
        else "BLOCKED_LEDGER_STALE"
    )
    return {
        "schema_version": 1,
        "candidate_sha": candidate,
        "protocol_sha": protocol,
        "protocol_ancestry": "PASS",
        "critical_blob_identity": "PASS",
        "critical_path_count": len(CRITICAL_RUNTIME_PATHS),
        "ledger_binding": ledger_binding,
        "ledger_path_accounting": ledger_paths,
        "status": status,
        "promotion_authorized": False,
    }


def validate_sync_summary(summary: dict) -> dict:
    expected = {
        "schema_version", "candidate_sha", "protocol_sha", "protocol_ancestry",
        "critical_blob_identity", "critical_path_count", "ledger_binding",
        "ledger_path_accounting", "status", "promotion_authorized",
    }
    if not isinstance(summary, dict) or set(summary) != expected or summary.get("schema_version") != 1:
        raise CanonicalSyncError("sync summary schema invalid")
    if not FULL_SHA_RE.fullmatch(str(summary["candidate_sha"])) or not FULL_SHA_RE.fullmatch(str(summary["protocol_sha"])):
        raise CanonicalSyncError("sync summary identity invalid")
    if summary["protocol_ancestry"] not in {"PASS", "FAIL"}:
        raise CanonicalSyncError("sync ancestry status invalid")
    if summary["critical_blob_identity"] not in {"PASS", "FAIL", "NOT_CHECKED"}:
        raise CanonicalSyncError("sync blob status invalid")
    if summary["ledger_binding"] not in {"PASS", "STALE", "NOT_CHECKED"}:
        raise CanonicalSyncError("sync ledger status invalid")
    if summary["ledger_path_accounting"] not in {"PASS", "STALE", "NOT_CHECKED"}:
        raise CanonicalSyncError("sync path accounting invalid")
    if summary["status"] not in {
        "READY_FOR_CANONICAL_REVALIDATION", "BLOCKED_PROTOCOL_ANCESTRY",
        "BLOCKED_RUNTIME_DRIFT", "BLOCKED_LEDGER_STALE",
    }:
        raise CanonicalSyncError("sync status invalid")
    if summary["critical_path_count"] != len(CRITICAL_RUNTIME_PATHS):
        raise CanonicalSyncError("sync path count invalid")
    if summary["promotion_authorized"] is not False:
        raise CanonicalSyncError("sync summary cannot authorize promotion")
    return json.loads(json.dumps(summary, sort_keys=True, separators=(",", ":")))
