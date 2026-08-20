# -*- coding: utf-8 -*-
"""Telegram Bridge repository secret guard.

Scans both the current tracked tree and Git history for project-policy-prohibited
secret artifacts. Findings never print secret values.
"""
from __future__ import annotations

import argparse
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MAX_BLOB_BYTES = 5_000_000

FORBIDDEN_EXACT_NAMES = {
    ".env",
    "credentials.json",
    "token.json",
    "bootstrap.json",
    "setup_state.json",
    "connection_info.txt",
    "private_config.json",
    "OPENAPI_READY.json",
    "BRIDGE_KEYS_SECRET.txt",
    "TG_SESSION_STRING_SECRET.txt",
    "HOSTIQ_CPANEL_PASSWORD.txt",
    "SSH_PRIVATE_KEY",
    "GITHUB_TOKEN.txt",
    "GITHUB_PAT.txt",
    "id_rsa",
    "id_ed25519",
    "id_ecdsa",
    "id_dsa",
}
FORBIDDEN_SUFFIXES = {
    ".session",
    ".session-journal",
    ".sqlite",
    ".sqlite3",
    ".db",
    ".db-journal",
    ".db-wal",
    ".db-shm",
    ".pem",
    ".key",
    ".p12",
    ".pfx",
}
SECRET_VARIABLES = (
    "TG_API_ID",
    "TG_API_HASH",
    "TG_SESSION_STRING",
    "TELEGRAM_2FA_PASSWORD",
    "BRIDGE_TOKEN",
    "BRIDGE_ROUTE_KEY",
    "SETUP_ROUTE",
    "SETUP_KEY",
    "HOSTIQ_CPANEL_PASSWORD",
    "CPANEL_PASSWORD",
    "SSH_PRIVATE_KEY",
    "GITHUB_TOKEN",
    "GH_TOKEN",
    "GITHUB_PAT",
    "GOOGLE_DRIVE_CLIENT_SECRET",
    "GOOGLE_DRIVE_REFRESH_TOKEN",
)
_SECRET_ALT = "|".join(re.escape(name) for name in SECRET_VARIABLES)
ASSIGNMENT_RE = re.compile(
    rf"(?im)^\s*(?:export\s+|set\s+)?({_SECRET_ALT})\s*[:=]\s*"
    r"(?:\"([^\"]*)\"|'([^']*)'|([^\s#;]+))\s*(?:[#;].*)?$"
)
PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"
)
SETUP_ROUTE_RE = re.compile(
    r"(?<![A-Za-z0-9_])/(setup-[A-Za-z0-9_-]{16,})(?![A-Za-z0-9_])"
)

PLACEHOLDER_WORDS = {
    "placeholder",
    "changeme",
    "change-me",
    "example",
    "example-value",
    "replace-me",
    "replace_me",
    "your-value",
    "your_value",
}


def run_git(repo: Path, *args: str, text: bool = True):
    return subprocess.run(
        ["git", *args],
        cwd=repo,
        check=True,
        capture_output=True,
        text=text,
    )


def is_forbidden_path(path: str) -> bool:
    name = Path(path).name
    lower = name.casefold()
    if lower.startswith(".env"):
        return True
    if name in FORBIDDEN_EXACT_NAMES:
        return True
    return any(lower.endswith(suffix.casefold()) for suffix in FORBIDDEN_SUFFIXES)


def is_placeholder(value: str) -> bool:
    value = (value or "").strip().strip('"').strip("'").strip()
    if not value:
        return True
    lower = value.casefold()
    if (value.startswith("<") and value.endswith(">")) or "${{" in value or "${" in value:
        return True
    if lower in PLACEHOLDER_WORDS:
        return True
    return any(lower.startswith(word + "-") for word in PLACEHOLDER_WORDS)


def scan_text(text: str, path: str, scope: str) -> list[str]:
    findings: list[str] = []
    if PRIVATE_KEY_RE.search(text):
        findings.append(f"{scope}: private key marker in {path}")
    if SETUP_ROUTE_RE.search(text):
        findings.append(f"{scope}: concrete setup route in {path}")
    for match in ASSIGNMENT_RE.finditer(text):
        value = next((group for group in match.groups()[1:] if group is not None), "")
        if not is_placeholder(value):
            findings.append(f"{scope}: secret-like assignment {match.group(1)} in {path}")
    return findings


def _tracked_paths(repo: Path) -> list[str]:
    raw = run_git(repo, "ls-files", "-z", text=False).stdout
    return [item.decode("utf-8", errors="surrogateescape") for item in raw.split(b"\0") if item]


def scan_current_tree(repo: Path = ROOT) -> list[str]:
    findings: list[str] = []
    for rel in _tracked_paths(repo):
        if is_forbidden_path(rel):
            findings.append(f"current-tree: forbidden file {rel}")
            continue
        path = repo / rel
        try:
            if path.stat().st_size > MAX_BLOB_BYTES:
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        findings.extend(scan_text(text, rel, "current-tree"))
    return sorted(set(findings))


def _is_shallow(repo: Path) -> bool:
    return run_git(repo, "rev-parse", "--is-shallow-repository").stdout.strip().casefold() == "true"


def _history_objects(repo: Path):
    output = run_git(repo, "rev-list", "--objects", "--all").stdout.splitlines()
    seen: set[tuple[str, str]] = set()
    for line in output:
        parts = line.split(" ", 1)
        if len(parts) != 2:
            continue
        sha, path = parts
        key = (sha, path)
        if key in seen:
            continue
        seen.add(key)
        try:
            object_type = run_git(repo, "cat-file", "-t", sha).stdout.strip()
        except subprocess.CalledProcessError:
            continue
        if object_type != "blob":
            continue
        yield sha, path


def scan_history(repo: Path = ROOT) -> list[str]:
    findings: list[str] = []
    if _is_shallow(repo):
        findings.append("history: repository checkout is shallow; full-history scan is not proven")
        return findings

    for sha, rel in _history_objects(repo):
        label = f"history:{sha[:12]}"
        if is_forbidden_path(rel):
            findings.append(f"{label}: forbidden file {rel}")
            continue
        try:
            size = int(run_git(repo, "cat-file", "-s", sha).stdout.strip())
        except (ValueError, subprocess.CalledProcessError):
            continue
        if size > MAX_BLOB_BYTES:
            continue
        try:
            blob = run_git(repo, "cat-file", "blob", sha, text=False).stdout
        except subprocess.CalledProcessError:
            continue
        text = blob.decode("utf-8", errors="ignore")
        findings.extend(scan_text(text, rel, label))
    return sorted(set(findings))


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--mode",
        choices=("current", "history", "all"),
        default="all",
        help="Scan current tracked tree, Git history, or both.",
    )
    args = parser.parse_args(argv)

    findings: list[str] = []
    if args.mode in {"current", "all"}:
        findings.extend(scan_current_tree(ROOT))
    if args.mode in {"history", "all"}:
        findings.extend(scan_history(ROOT))

    findings = sorted(set(findings))
    if findings:
        print("SECRET_SCAN_FAIL")
        for item in findings:
            print("-", item)
        return 1

    print("SECRET_SCAN_PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
