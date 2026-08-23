# -*- coding: utf-8 -*-
"""Fail-closed GitHub Actions policy guard for the public bridge repository.

The repository is public and CI evidence/logs/artifacts are treated as public.
This guard deliberately supports the small workflow subset used by this project
and rejects privilege-expanding or externally mutable workflow constructs.
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

_USES_RE = re.compile(r"(?m)^\s*-?\s*uses:\s*([^\s#]+)")
_WRITE_PERMISSION_RE = re.compile(r"(?im)^\s*[A-Za-z0-9_-]+\s*:\s*write\s*(?:#.*)?$")
_WRITE_ALL_RE = re.compile(r"(?im)^\s*permissions\s*:\s*write-all\s*(?:#.*)?$")
_SECRET_CONTEXT_RE = re.compile(r"\$\{\{\s*secrets\.[A-Za-z0-9_]+\s*\}\}", re.IGNORECASE)
_DANGEROUS_PIPE_RE = re.compile(
    r"(?im)(?:curl|wget)\b[^\r\n|]*\|\s*(?:sudo\s+)?(?:sh|bash|zsh|python(?:3)?)\b"
)
_IMMUTABLE_ACTION_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+@[0-9a-fA-F]{40}$")
_DOCKER_DIGEST_RE = re.compile(r"^docker://[^\s@]+@sha256:[0-9a-fA-F]{64}$")


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _step_block(lines: list[str], index: int) -> str:
    """Return the YAML list-item block containing one uses line.

    This is intentionally a narrow structural parser. It does not attempt to
    interpret arbitrary YAML; unfamiliar privilege-relevant syntax is rejected
    elsewhere rather than silently trusted.
    """
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


def scan_workflow_text(path: str, text: str) -> list[str]:
    findings: list[str] = []
    lowered = text.casefold()

    if re.search(r"(?m)^\s*pull_request_target\s*:", text):
        findings.append(f"workflow: pull_request_target is forbidden in public repo: {path}")
    if re.search(r"(?m)^\s*workflow_run\s*:", text):
        findings.append(f"workflow: workflow_run requires explicit security review: {path}")
    if _WRITE_ALL_RE.search(text) or _WRITE_PERMISSION_RE.search(text):
        findings.append(f"workflow: write-capable GITHUB_TOKEN permission is forbidden: {path}")
    if "pull_request:" in lowered and _SECRET_CONTEXT_RE.search(text):
        findings.append(f"workflow: PR-triggered workflow may not reference repository secrets: {path}")
    if _DANGEROUS_PIPE_RE.search(text):
        findings.append(f"workflow: network pipe-to-interpreter command is forbidden: {path}")

    lines = text.splitlines(keepends=True)
    for index, line in enumerate(lines):
        match = re.search(r"\buses:\s*([^\s#]+)", line)
        if not match:
            continue
        target = match.group(1).strip().strip('"\'')
        if target.startswith("./"):
            continue
        if target.startswith("docker://"):
            if not _DOCKER_DIGEST_RE.fullmatch(target):
                findings.append(f"workflow: Docker action is not immutable-digest pinned: {path}")
            continue
        if not _IMMUTABLE_ACTION_RE.fullmatch(target):
            findings.append(f"workflow: third-party action is not immutable-SHA pinned: {path}")

        if target.casefold().startswith("actions/checkout@"):
            block = _step_block(lines, index)
            if not re.search(r"(?im)^\s*persist-credentials\s*:\s*false\s*(?:#.*)?$", block):
                findings.append(f"workflow: checkout must set persist-credentials: false: {path}")
            if "secret_scan.py --mode history" in text and not re.search(
                r"(?im)^\s*fetch-depth\s*:\s*0\s*(?:#.*)?$", block
            ):
                findings.append(f"workflow: full-history scan requires checkout fetch-depth: 0: {path}")

        target_lower = target.casefold()
        if target_lower.startswith("actions/upload-artifact@") or target_lower.startswith("actions/download-artifact@"):
            findings.append(f"workflow: artifact transfer requires an explicit privacy design review: {path}")

    return sorted(set(findings))


def _safe_read(path: Path) -> tuple[str | None, str | None]:
    try:
        info = os.lstat(path)
    except OSError:
        return None, "workflow file is unreadable"
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        return None, "workflow path has unsafe topology"
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
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
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
        try:
            return bytes(data).decode("utf-8"), None
        except UnicodeDecodeError:
            return None, "workflow is not valid UTF-8"
    finally:
        os.close(fd)


def scan_repository(repo: Path = ROOT) -> list[str]:
    root = (repo / WORKFLOW_DIR).resolve()
    if not root.exists() or not root.is_dir():
        return ["workflow: .github/workflows directory is missing"]
    findings: list[str] = []
    paths = sorted([*root.glob("*.yml"), *root.glob("*.yaml")])
    if not paths:
        return ["workflow: no GitHub Actions workflow files found"]
    for path in paths:
        rel = path.relative_to(repo.resolve()).as_posix()
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
