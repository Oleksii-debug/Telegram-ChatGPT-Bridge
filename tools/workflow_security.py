# -*- coding: utf-8 -*-
"""Fail-closed GitHub Actions policy guard for the public bridge repository.

The repository is public and CI evidence/logs/artifacts are treated as public.
This guard deliberately supports the small workflow subset used by this project
and rejects privilege-expanding, externally mutable, or cross-run state-sharing
constructs unless they receive a separate explicit security design review.
"""
from __future__ import annotations

import argparse
import os
import re
import stat
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_DIR = Path(".github/workflows")
MAX_WORKFLOW_BYTES = 2_000_000

_SECRET_CONTEXT_RE = re.compile(
    r"\$\{\{[^}\r\n]*\bsecrets\b",
    re.IGNORECASE,
)
_GITHUB_TOKEN_CONTEXT_RE = re.compile(
    r"\$\{\{[^}\r\n]*\bgithub\s*(?:\.\s*token|\[\s*['\"]token['\"]\s*\])",
    re.IGNORECASE,
)
_GITHUB_BRACKET_CONTEXT_RE = re.compile(
    r"\$\{\{[^}\r\n]*\bgithub\s*\[",
    re.IGNORECASE,
)
_GITHUB_WHOLE_CONTEXT_RE = re.compile(
    r"\$\{\{[^}\r\n]*\btojson\s*\(\s*github\s*\)",
    re.IGNORECASE,
)
_DANGEROUS_PIPE_RE = re.compile(
    r"(?im)(?:curl|wget)\b[^\r\n|]*\|\s*(?:sudo\s+)?(?:sh|bash|zsh|python(?:3)?)\b"
)
_IMMUTABLE_ACTION_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+@[0-9a-fA-F]{40}$")
_DOCKER_DIGEST_RE = re.compile(r"^docker://[^\s@]+@sha256:[0-9a-fA-F]{64}$")
_HIGH_RISK_TRIGGER_NAMES = (
    "pull_request_target",
    "workflow_run",
    "repository_dispatch",
    "issue_comment",
    "workflow_call",
)
_HIGH_RISK_TRIGGER_TOKEN_RE = re.compile(
    r"(?<![A-Za-z0-9_-])(?:" + "|".join(map(re.escape, _HIGH_RISK_TRIGGER_NAMES)) + r")(?![A-Za-z0-9_-])",
    re.IGNORECASE,
)
_ON_HEADER_RE = re.compile(r"^(?:on|['\"]on['\"])\s*:\s*(.*)$", re.IGNORECASE)
_ENVIRONMENT_RE = re.compile(r"(?im)^\s*['\"]?environment['\"]?\s*:")
_YAML_MERGE_RE = re.compile(r"(?im)^\s*<<\s*:")
_ESCAPED_MAPPING_KEY_RE = re.compile(r"['\"][^'\"\r\n]*\\[^'\"\r\n]*['\"]\s*:")
_GITHUB_HOSTED_RUNNER_RE = re.compile(
    r"^(?:ubuntu-(?:latest|24\.04|22\.04)|windows-(?:latest|2025|2022)|macos-(?:latest|15|14|13))$",
    re.IGNORECASE,
)
_USES_RE = re.compile(
    r"(?:^|\s|[-{,])['\"]?uses['\"]?\s*:\s*(?:\"([^\"]+)\"|'([^']+)'|([^\s#},]+))",
    re.IGNORECASE,
)
_CACHE_ACTION_PREFIXES = (
    "actions/cache@",
    "actions/cache/save@",
    "actions/cache/restore@",
)
_ARTIFACT_ACTION_PREFIXES = (
    "actions/upload-artifact@",
    "actions/download-artifact@",
)


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _step_block(lines: list[str], index: int) -> str:
    """Return the YAML list-item block containing one uses line."""
    uses_indent = _indent(lines[index])
    start = index
    while start > 0:
        line = lines[start - 1]
        if line.strip() and _indent(line) < uses_indent and line.lstrip().startswith("-"):
            start -= 1
            break
        if line.strip() and _indent(line) <= uses_indent and line.lstrip().startswith("- name:"):
            start -= 1
            break
        start -= 1
    end = index + 1
    while end < len(lines):
        line = lines[end]
        if line.strip() and _indent(line) <= uses_indent and line.lstrip().startswith("-"):
            break
        end += 1
    return "".join(lines[start:end])


def _trigger_findings(path: str, lines: list[str]) -> list[str]:
    """Inspect only the top-level ``on`` stanza, including inline/quoted forms."""
    indexes: list[int] = []
    inline_values: dict[int, str] = {}
    for index, line in enumerate(lines):
        if _indent(line) != 0:
            continue
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = _ON_HEADER_RE.fullmatch(stripped.split("#", 1)[0].rstrip())
        if match:
            indexes.append(index)
            inline_values[index] = match.group(1)
    if len(indexes) != 1:
        return [f"workflow: exactly one explicit top-level on stanza is required: {path}"]

    index = indexes[0]
    fragments = [inline_values[index]]
    for line in lines[index + 1 :]:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if _indent(line) <= 0:
            break
        fragments.append(stripped.split("#", 1)[0].rstrip())
    trigger_text = " ".join(fragments)
    findings: list[str] = []
    if re.search(r"(?:^|\s)[&*][A-Za-z0-9_-]+", trigger_text):
        findings.append(f"workflow: trigger YAML anchors/aliases are forbidden: {path}")
    if _HIGH_RISK_TRIGGER_TOKEN_RE.search(trigger_text):
        findings.append(f"workflow: high-risk trigger requires explicit security review: {path}")
    return findings


def _runner_findings(path: str, lines: list[str]) -> list[str]:
    findings: list[str] = []
    for line in lines:
        match = re.match(r"^\s*['\"]?runs-on['\"]?\s*:\s*(.*?)\s*(?:#.*)?$", line)
        if not match:
            continue
        value = match.group(1).strip().strip("'\"")
        if "${{" in value or not _GITHUB_HOSTED_RUNNER_RE.fullmatch(value):
            findings.append(f"workflow: runs-on must be an explicit approved GitHub-hosted runner: {path}")
    return findings


def _permissions_findings(path: str, lines: list[str]) -> list[str]:
    """Require one exact repository-level Contents: read permission stanza.

    GitHub allows job-level overrides and compact permission maps. This project
    does not need them, so both are rejected rather than partially parsed.
    """
    indexes = [
        i
        for i, line in enumerate(lines)
        if re.match(r"^\s*['\"]?permissions['\"]?\s*:", line)
    ]
    if len(indexes) != 1:
        return [f"workflow: exactly one top-level permissions stanza is required: {path}"]
    index = indexes[0]
    header = lines[index]
    if _indent(header) != 0 or header.strip() != "permissions:":
        return [f"workflow: permissions must be an explicit top-level block: {path}"]

    children: list[str] = []
    for line in lines[index + 1 :]:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if _indent(line) <= 0:
            break
        children.append(stripped.split("#", 1)[0].rstrip())
    if children != ["contents: read"]:
        return [f"workflow: GITHUB_TOKEN permissions must be exactly contents: read: {path}"]
    return []


def _checkout_findings(path: str, text: str, block: str) -> list[str]:
    findings: list[str] = []
    required = {
        "persist-credentials": "false",
        "clean": "true",
        "lfs": "false",
        "submodules": "false",
    }
    if "secret_scan.py --mode history" in text:
        required["fetch-depth"] = "0"
    for key, value in required.items():
        if not re.search(
            rf"(?im)^\s*['\"]?{re.escape(key)}['\"]?\s*:\s*{re.escape(value)}\s*(?:#.*)?$",
            block,
        ):
            findings.append(f"workflow: checkout must set {key}: {value}: {path}")

    # These overrides make the bytes executed by CI differ from the reviewed PR
    # merge/current repository and can silently introduce alternate credentials.
    forbidden_keys = ("ref", "repository", "path", "token", "ssh-key", "ssh-known-hosts")
    for key in forbidden_keys:
        if re.search(rf"(?im)^\s*['\"]?{re.escape(key)}['\"]?\s*:", block):
            findings.append(f"workflow: checkout {key} override is forbidden: {path}")
    return findings


def scan_workflow_text(path: str, text: str) -> list[str]:
    findings: list[str] = []
    lines = text.splitlines(keepends=True)

    findings.extend(_trigger_findings(path, lines))
    findings.extend(_runner_findings(path, lines))
    if _YAML_MERGE_RE.search(text):
        findings.append(f"workflow: YAML merge keys are forbidden in tracked public CI: {path}")
    if _ESCAPED_MAPPING_KEY_RE.search(text):
        findings.append(f"workflow: escaped YAML mapping keys are forbidden: {path}")
    if _ENVIRONMENT_RE.search(text):
        findings.append(f"workflow: GitHub environment binding requires explicit security review: {path}")
    if _SECRET_CONTEXT_RE.search(text):
        findings.append(f"workflow: repository/environment secret context is forbidden in tracked public CI: {path}")
    if _GITHUB_TOKEN_CONTEXT_RE.search(text):
        findings.append(f"workflow: explicit github.token exposure is forbidden: {path}")
    if _GITHUB_BRACKET_CONTEXT_RE.search(text):
        findings.append(f"workflow: dynamic github[...] context access is forbidden: {path}")
    if _GITHUB_WHOLE_CONTEXT_RE.search(text):
        findings.append(f"workflow: whole github context serialization is forbidden: {path}")
    if _DANGEROUS_PIPE_RE.search(text):
        findings.append(f"workflow: network pipe-to-interpreter command is forbidden: {path}")
    findings.extend(_permissions_findings(path, lines))

    for index, line in enumerate(lines):
        match = _USES_RE.search(line)
        if not match:
            continue
        target = next(group for group in match.groups() if group is not None).strip()
        target_lower = target.casefold()

        if target.startswith("./"):
            continue
        if target.startswith("docker://"):
            if not _DOCKER_DIGEST_RE.fullmatch(target):
                findings.append(f"workflow: Docker action is not immutable-digest pinned: {path}")
            continue
        if not _IMMUTABLE_ACTION_RE.fullmatch(target):
            findings.append(f"workflow: third-party action is not immutable-SHA pinned: {path}")

        if target_lower.startswith("actions/checkout@"):
            findings.extend(_checkout_findings(path, text, _step_block(lines, index)))
        if target_lower.startswith(_ARTIFACT_ACTION_PREFIXES):
            findings.append(f"workflow: artifact transfer requires an explicit privacy design review: {path}")
        if target_lower.startswith(_CACHE_ACTION_PREFIXES):
            findings.append(f"workflow: cache restore/save requires an explicit poisoning review: {path}")

    return sorted(set(findings))


def _safe_read(path: Path) -> tuple[str | None, str | None]:
    try:
        info = os.lstat(path)
    except OSError:
        return None, "workflow file is unreadable"
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) & 0o022
    ):
        return None, "workflow path has unsafe topology/ownership/permissions"
    if info.st_size > MAX_WORKFLOW_BYTES:
        return None, "workflow file exceeds inspection size limit"
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    else:
        return None, "platform lacks O_NOFOLLOW for workflow inspection"
    try:
        fd = os.open(path, flags)
    except OSError:
        return None, "workflow file cannot be opened safely"
    try:
        opened = os.fstat(fd)
        signature = (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or opened.st_uid != os.getuid()
            or stat.S_IMODE(opened.st_mode) & 0o022
            or (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino)
        ):
            return None, "workflow file changed during inspection"
        data = bytearray()
        while True:
            chunk = os.read(fd, 64 * 1024)
            if not chunk:
                break
            data.extend(chunk)
            if len(data) > MAX_WORKFLOW_BYTES:
                return None, "workflow file exceeds inspection size limit"
        final = os.fstat(fd)
        final_signature = (final.st_dev, final.st_ino, final.st_size, final.st_mtime_ns, final.st_ctime_ns)
        if final_signature != signature:
            return None, "workflow file changed during inspection"
        try:
            return bytes(data).decode("utf-8"), None
        except UnicodeDecodeError:
            return None, "workflow is not valid UTF-8"
    finally:
        os.close(fd)


def _safe_workflow_root(repo: Path) -> tuple[Path | None, str | None]:
    repo = repo.resolve()
    github_dir = repo / ".github"
    workflows = github_dir / "workflows"
    for label, path in ((".github", github_dir), (".github/workflows", workflows)):
        try:
            info = os.lstat(path)
        except OSError:
            return None, f"{label} directory is missing/unreadable"
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
            return None, f"{label} directory has unsafe topology/ownership"
        if stat.S_IMODE(info.st_mode) & 0o022:
            return None, f"{label} directory is group/world writable"
    return workflows, None


def scan_repository(repo: Path = ROOT) -> list[str]:
    repo = repo.resolve()
    root, root_error = _safe_workflow_root(repo)
    if root_error:
        return [f"workflow: {root_error}"]
    assert root is not None
    findings: list[str] = []
    paths = sorted([path for path in root.iterdir() if path.suffix.casefold() in {".yml", ".yaml"}])
    if not paths:
        return ["workflow: no GitHub Actions workflow files found"]
    for path in paths:
        rel = path.relative_to(repo).as_posix()
        text, error = _safe_read(path)
        if error:
            findings.append(f"workflow: {error}: {rel}")
            continue
        assert text is not None
        findings.extend(scan_workflow_text(rel, text))
    return sorted(set(findings))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", default=str(ROOT))
    args = parser.parse_args(argv)
    findings = scan_repository(Path(args.repo).resolve())
    if findings:
        print("WORKFLOW_SECURITY_SCAN_FAIL")
        for finding in findings:
            print("-", finding)
        return 1
    print("WORKFLOW_SECURITY_SCAN_PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
