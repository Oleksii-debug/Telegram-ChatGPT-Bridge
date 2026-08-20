# -*- coding: utf-8 -*-
"""Fail CI when public-repository files contain forbidden private artifacts.

This is intentionally conservative. It does not replace provider-side secret
scanning; it prevents the most important Telegram Bridge-specific leaks before
merge/push review.
"""
from __future__ import annotations

import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKIP_DIRS = {".git", "__pycache__", ".pytest_cache", ".mypy_cache"}
FORBIDDEN_NAMES = {
    ".env", "credentials.json", "token.json", "bootstrap.json",
    "setup_state.json", "connection_info.txt", "private_config.json",
    "OPENAPI_READY.json",
}
FORBIDDEN_SUFFIXES = {
    ".session", ".session-journal", ".sqlite", ".sqlite3", ".db",
    ".db-journal", ".db-wal", ".db-shm", ".pem", ".p12", ".pfx",
}
PRIVATE_KEY_RE = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")
SETUP_ROUTE_RE = re.compile(r"(?<![A-Za-z0-9_])/(setup-[A-Za-z0-9_-]{16,})(?![A-Za-z0-9_])")
ASSIGNMENT_PATTERNS = [
    re.compile(r"(?im)^\s*(TG_API_HASH|TG_SESSION_STRING|BRIDGE_TOKEN|BRIDGE_ROUTE_KEY|TELEGRAM_2FA_PASSWORD)\s*=\s*[\"']([^\"'\r\n]{12,})[\"']\s*$"),
]


def iter_files():
    git_dir = ROOT / ".git"
    if git_dir.exists():
        proc = subprocess.run(["git", "ls-files", "-z"], cwd=ROOT, check=True, capture_output=True)
        for raw in proc.stdout.decode("utf-8").split("\0"):
            if raw:
                path = ROOT / raw
                if path.is_file():
                    yield path
        return
    for path in ROOT.rglob("*"):
        if not path.is_file() or any(part in SKIP_DIRS for part in path.parts):
            continue
        yield path


def main() -> int:
    findings: list[str] = []
    for path in iter_files():
        rel = path.relative_to(ROOT)
        name = path.name
        if name in FORBIDDEN_NAMES or any(name.endswith(s) for s in FORBIDDEN_SUFFIXES):
            findings.append(f"forbidden file: {rel}")
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        if PRIVATE_KEY_RE.search(text):
            findings.append(f"private key marker: {rel}")
        if SETUP_ROUTE_RE.search(text):
            findings.append(f"concrete setup route: {rel}")
        for pattern in ASSIGNMENT_PATTERNS:
            for match in pattern.finditer(text):
                value = match.group(2).strip()
                if not value or value.startswith("<") or value.lower() in {"placeholder", "changeme", "example"}:
                    continue
                findings.append(f"secret-like assignment {match.group(1)}: {rel}")
    if findings:
        print("SECRET_SCAN_FAIL")
        for item in findings:
            print("-", item)
        return 1
    print("SECRET_SCAN_PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
