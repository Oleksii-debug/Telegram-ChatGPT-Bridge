# -*- coding: utf-8 -*-
"""Fail-closed exact-blob adjudication for historical synthetic secret findings.

This module does not alter current-tree scanning and does not auto-approve any
history object.  An entry can suppress only assignment findings for one exact
historical Git blob when path, Git object id, SHA-256, and the complete observed
variable set all match a reviewed ledger entry.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path, PurePosixPath

ADJUDICATION_FILE = ".secret-history-adjudications.json"
_SHA1_RE = re.compile(r"^[0-9a-f]{40}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_VARIABLE_RE = re.compile(r"^[A-Z][A-Z0-9_]{1,63}$")
_ASSIGNMENT_FINDING_RE = re.compile(
    r"^history-blob:([0-9a-f]{40}): secret-like assignment ([A-Z][A-Z0-9_]{1,63}) in (.+)$"
)


def _normalise_path(value: str) -> str:
    path = str(PurePosixPath(value.replace("\\", "/")))
    parsed = PurePosixPath(path)
    if not path or parsed.is_absolute() or ".." in parsed.parts:
        raise ValueError("unsafe adjudication path")
    return path


def load_adjudications(repo: Path) -> dict[tuple[str, str, str], frozenset[str]]:
    """Load a strict history-only adjudication ledger.

    Malformed or ambiguous entries fail closed by raising ValueError rather than
    silently disappearing.  Reasons are intentionally required so an exact-blob
    exception cannot be added without a human-readable review record.
    """
    path = repo / ADJUDICATION_FILE
    if not path.exists():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("invalid history adjudication ledger") from exc
    if not isinstance(payload, dict) or set(payload) != {"entries"} or not isinstance(payload["entries"], list):
        raise ValueError("invalid history adjudication ledger schema")

    result: dict[tuple[str, str, str], frozenset[str]] = {}
    for item in payload["entries"]:
        if not isinstance(item, dict) or set(item) != {"path", "git_blob_sha", "sha256", "variables", "reason"}:
            raise ValueError("invalid history adjudication entry schema")
        rel = _normalise_path(str(item["path"]).strip())
        git_blob_sha = str(item["git_blob_sha"]).strip().casefold()
        digest = str(item["sha256"]).strip().casefold()
        reason = str(item["reason"]).strip()
        variables = item["variables"]
        if not _SHA1_RE.fullmatch(git_blob_sha) or not _SHA256_RE.fullmatch(digest):
            raise ValueError("invalid history adjudication digest")
        if len(reason) < 24:
            raise ValueError("history adjudication reason is too short")
        if not isinstance(variables, list) or not variables:
            raise ValueError("history adjudication variables must be non-empty")
        canonical = []
        for variable in variables:
            name = str(variable).strip().upper()
            if not _VARIABLE_RE.fullmatch(name):
                raise ValueError("invalid history adjudication variable")
            canonical.append(name)
        variable_set = frozenset(canonical)
        if len(variable_set) != len(canonical):
            raise ValueError("duplicate history adjudication variable")
        key = (rel, git_blob_sha, digest)
        if key in result:
            raise ValueError("duplicate history adjudication entry")
        result[key] = variable_set
    return result


def filter_exact_history_assignment_findings(
    *,
    repo: Path,
    git_blob_sha: str,
    rel_path: str,
    blob: bytes,
    findings: list[str],
) -> list[str]:
    """Return unresolved findings after exact history-only adjudication.

    Only the exact set of ``secret-like assignment`` findings may be reviewed.
    Private-key markers, setup routes, forbidden files, archive errors, binary
    inspection failures, commit-message findings, current-tree findings, or any
    new variable remain failures.  A modified blob also fails because both Git
    object id and SHA-256 are bound.
    """
    if not findings:
        return []
    sha = git_blob_sha.strip().casefold()
    if not _SHA1_RE.fullmatch(sha):
        return list(findings)
    try:
        rel = _normalise_path(rel_path)
        ledger = load_adjudications(repo)
    except ValueError:
        return list(findings)

    observed: set[str] = set()
    for finding in findings:
        match = _ASSIGNMENT_FINDING_RE.fullmatch(finding)
        if match is None:
            return list(findings)
        finding_sha, variable, finding_path = match.groups()
        try:
            normalised_finding_path = _normalise_path(finding_path)
        except ValueError:
            return list(findings)
        if finding_sha != sha or normalised_finding_path != rel:
            return list(findings)
        observed.add(variable.upper())

    digest = hashlib.sha256(blob).hexdigest()
    approved = ledger.get((rel, sha, digest))
    if approved is None or approved != frozenset(observed):
        return list(findings)
    return []
