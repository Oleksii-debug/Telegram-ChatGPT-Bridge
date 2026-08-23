# -*- coding: utf-8 -*-
"""Fail-closed secret guard for the public Telegram Bridge repository."""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import stat
import subprocess
import tarfile
import zipfile
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
ALLOWLIST_FILE = ".secret-scan-allowlist.json"

MAX_TEXT_BYTES = 50_000_000
MAX_ARCHIVE_DEPTH = 3
MAX_ARCHIVE_MEMBERS = 500
MAX_ARCHIVE_MEMBER_BYTES = 25_000_000
MAX_ARCHIVE_TOTAL_BYTES = 100_000_000
MAX_ALLOWLIST_BYTES = 1_000_000

FORBIDDEN_EXACT_NAMES_CASEFOLD = {
    x.casefold()
    for x in {
        ".env",
        "credentials.json",
        "token.json",
        "bootstrap.json",
        "setup_state.json",
        "connection_info.txt",
        "private_config.json",
        "openapi_ready.json",
        "bridge_keys_secret.txt",
        "tg_session_string_secret.txt",
        "hostiq_cpanel_password.txt",
        "ssh_private_key",
        "github_token.txt",
        "github_pat.txt",
        "cookies.txt",
        "cookies.json",
        "id_rsa",
        "id_ed25519",
        "id_ecdsa",
        "id_dsa",
    }
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
    ".log",
    ".cookie",
    ".cookies",
}
SUPPORTED_ARCHIVE_SUFFIXES = (
    ".zip",
    ".tar",
    ".tgz",
    ".tbz",
    ".tbz2",
    ".txz",
    ".tar.gz",
    ".tar.bz2",
    ".tar.xz",
)
UNSUPPORTED_ARCHIVE_SUFFIXES = (".7z", ".rar", ".gz", ".bz2", ".xz")

PROJECT_SECRET_VARIABLES = (
    "TG_API_ID",
    "TG_API_HASH",
    "TG_SESSION_STRING",
    "TELEGRAM_API_ID",
    "TELEGRAM_API_HASH",
    "TELEGRAM_SESSION",
    "TELETHON_SESSION",
    "STRINGSESSION",
    "SESSION_FILE",
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
GENERIC_CREDENTIAL_ALIASES = (
    "API_ID",
    "API_HASH",
    "API_KEY",
    "SESSION",
    "SESSION_STRING",
    "STRING_SESSION",
    "TWO_FACTOR_PASSWORD",
    "2FA_PASSWORD",
    "PASSWORD",
    "PASSWD",
    "BEARER_TOKEN",
    "ACCESS_TOKEN",
    "REFRESH_TOKEN",
    "CLIENT_SECRET",
)
SECRET_VARIABLES = PROJECT_SECRET_VARIABLES + GENERIC_CREDENTIAL_ALIASES
_SECRET_ALT = "|".join(re.escape(x) for x in SECRET_VARIABLES)

ASSIGNMENT_RE = re.compile(
    rf"""(?im)^\s*(?:export\s+|set\s+)?[\"']?({_SECRET_ALT})[\"']?\s*[:=]\s*
        (?:\"([^\"]*)\"|'([^']*)'|([^#;\r\n]+?))\s*(?:[#;].*)?$""",
    re.IGNORECASE | re.VERBOSE,
)
STRUCTURED_ASSIGNMENT_RE = re.compile(
    rf"""(?im)[\"']({_SECRET_ALT})[\"']\s*[:=]\s*
        (?:\"([^\"]*)\"|'([^']*)'|([^\s,\}}\]]+))""",
    re.IGNORECASE | re.VERBOSE,
)
PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", re.IGNORECASE
)
SETUP_ROUTE_RE = re.compile(
    r"(?<![A-Za-z0-9_])/(setup-[A-Za-z0-9_-]{16,})(?![A-Za-z0-9_])",
    re.IGNORECASE,
)
ANGLE_PLACEHOLDER_RE = re.compile(r"^<[A-Z0-9_.:-]+>$", re.IGNORECASE)
GH_SECRET_PLACEHOLDER_RE = re.compile(
    r"^\$\{\{\s*secrets\.[A-Z0-9_]+\s*\}\}$", re.IGNORECASE
)
ENV_PLACEHOLDER_RE = re.compile(r"^\$\{[A-Z_][A-Z0-9_]*\}$", re.IGNORECASE)
DOLLAR_PLACEHOLDER_RE = re.compile(r"^\$[A-Z_][A-Z0-9_]*$", re.IGNORECASE)
SAFE_REFERENCE_RE = re.compile(
    r"^(?:os\.(?:getenv\([^\r\n]+\)|environ\[[^\r\n]+\])|"
    r"env\([^\r\n]+\)|config\.get\([^\r\n]+\)|settings\.[A-Z0-9_]+)$",
    re.IGNORECASE,
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

SEVEN_Z_SIGNATURE = bytes((0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C))
RAR_SIGNATURES = (
    bytes((0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00)),
    bytes((0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00)),
)
GZIP_SIGNATURE = bytes((0x1F, 0x8B, 0x08))
BZIP2_HEADER = bytes((0x42, 0x5A, 0x68))
BZIP2_BLOCK_MAGIC = bytes((0x31, 0x41, 0x59, 0x26, 0x53, 0x59))
BZIP2_SIGNATURE = BZIP2_HEADER + bytes((0x39,)) + BZIP2_BLOCK_MAGIC
XZ_SIGNATURE = bytes((0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00))
UNSUPPORTED_SIGNATURES = (
    SEVEN_Z_SIGNATURE,
    *RAR_SIGNATURES,
    GZIP_SIGNATURE,
    XZ_SIGNATURE,
)
_LFS_VERSION_LINE = "version https://" + "git-lfs.github.com/spec/v1"
_LFS_OID_RE = re.compile(r"^oid sha256:[0-9a-f]{64}$")
_LFS_SIZE_RE = re.compile(r"^size [0-9]{1,20}$")


def run_git(repo: Path, *args: str, text: bool = True):
    return subprocess.run(
        ["git", *args],
        cwd=repo,
        check=True,
        capture_output=True,
        text=text,
    )


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _normalise_rel(path: str) -> str:
    return str(PurePosixPath(path.replace("\\", "/")))


def _unsafe(path: str) -> bool:
    p = PurePosixPath(path.replace("\\", "/"))
    return p.is_absolute() or ".." in p.parts


def is_forbidden_path(path: str) -> bool:
    name = PurePosixPath(path.replace("\\", "/")).name.casefold()
    return (
        name.startswith(".env")
        or name in FORBIDDEN_EXACT_NAMES_CASEFOLD
        or any(name.endswith(s.casefold()) for s in FORBIDDEN_SUFFIXES)
    )


def _extension_archive_kind(path: str) -> str | None:
    lower = path.casefold()
    if lower.endswith(".zip"):
        return "zip"
    if any(lower.endswith(s) for s in SUPPORTED_ARCHIVE_SUFFIXES if s != ".zip"):
        return "tar"
    if any(lower.endswith(s) for s in UNSUPPORTED_ARCHIVE_SUFFIXES):
        return "unsupported"
    return None


def _probe_zip(data: bytes) -> bool:
    try:
        if not zipfile.is_zipfile(io.BytesIO(data)):
            return False
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            archive.infolist()
        return True
    except (zipfile.BadZipFile, OSError, EOFError, ValueError):
        return False


def _probe_tar(data: bytes) -> bool:
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as archive:
            archive.getmembers()
        return True
    except (tarfile.TarError, OSError, EOFError, ValueError):
        return False


def _contains_bzip2_stream_header(data: bytes) -> bool:
    start = 0
    levels = tuple(bytes((n,)) for n in range(0x31, 0x3A))
    while True:
        index = data.find(BZIP2_HEADER, start)
        if index < 0:
            return False
        if (
            index + 10 <= len(data)
            and data[index + 3 : index + 4] in levels
            and data[index + 4 : index + 10] == BZIP2_BLOCK_MAGIC
        ):
            return True
        start = index + 1


def _contains_unsupported_signature(data: bytes) -> bool:
    return any(data.find(sig) >= 0 for sig in UNSUPPORTED_SIGNATURES) or _contains_bzip2_stream_header(data)


def _magic_archive_kind(data: bytes) -> str | None:
    is_zip = _probe_zip(data)
    is_tar = _probe_tar(data)
    if is_zip and is_tar:
        return "ambiguous"
    if is_zip:
        return "zip"
    if is_tar:
        return "tar"
    if _contains_unsupported_signature(data):
        return "unsupported"
    return None


def _resolved_archive_kind(path: str, data: bytes) -> tuple[str | None, str | None]:
    ext = _extension_archive_kind(path)
    magic = _magic_archive_kind(data)
    if magic == "ambiguous":
        return None, "ambiguous/polyglot archive/container"
    if ext == "unsupported":
        return None, "unsupported archive/container"
    if magic == "unsupported":
        return None, "unsupported compressed/archive signature"
    if ext is not None and magic is None:
        return None, "archive/container extension does not match inspectable content"
    if ext in {"zip", "tar"} and magic in {"zip", "tar"} and ext != magic:
        return None, "archive/container extension-signature mismatch"
    if magic in {"zip", "tar"}:
        return magic, None
    return None, None


def is_placeholder(value: str) -> bool:
    value = (value or "").strip().strip('"').strip("'").strip()
    return (
        not value
        or value.casefold() in PLACEHOLDER_WORDS
        or bool(
            ANGLE_PLACEHOLDER_RE.fullmatch(value)
            or GH_SECRET_PLACEHOLDER_RE.fullmatch(value)
            or ENV_PLACEHOLDER_RE.fullmatch(value)
            or DOLLAR_PLACEHOLDER_RE.fullmatch(value)
        )
    )


def is_safe_reference(value: str) -> bool:
    return bool(
        SAFE_REFERENCE_RE.fullmatch(
            (value or "").strip().strip('"').strip("'").strip()
        )
    )


def _assignment_is_finding(name: str, value: str) -> bool:
    if is_placeholder(value) or is_safe_reference(value):
        return False
    if name.upper() in PROJECT_SECRET_VARIABLES:
        return True
    stripped = value.strip()
    if stripped.casefold() in {"none", "null", "false", "true"} or stripped in {
        "0",
        "1",
        "[]",
        "{}",
    }:
        return False
    if name.upper() == "API_ID" and re.fullmatch(r"\d{5,15}", stripped):
        return True
    return len(stripped) >= 6


def scan_text(text: str, path: str, scope: str) -> list[str]:
    out: list[str] = []
    if PRIVATE_KEY_RE.search(text):
        out.append(f"{scope}: private key marker in {path}")
    if SETUP_ROUTE_RE.search(text):
        out.append(f"{scope}: concrete setup route in {path}")
    for pattern in (ASSIGNMENT_RE, STRUCTURED_ASSIGNMENT_RE):
        for match in pattern.finditer(text):
            value = next((g for g in match.groups()[1:] if g is not None), "")
            if _assignment_is_finding(match.group(1), value):
                out.append(
                    f"{scope}: secret-like assignment {match.group(1).upper()} in {path}"
                )
    return sorted(set(out))


def _read_regular_file(
    path: Path,
    *,
    max_bytes: int | None = None,
) -> tuple[bytes | None, str | None]:
    """Read one file without following symlinks/hardlinks or racing an inode swap."""
    try:
        before = os.lstat(path)
    except OSError:
        return None, "unreadable file"
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        return None, "non-regular/symlink path"
    if before.st_nlink != 1:
        return None, "hardlinked path"
    if hasattr(os, "getuid") and before.st_uid != os.getuid():
        return None, "wrong-owner path"
    if max_bytes is not None and before.st_size > max_bytes:
        return None, "file exceeds inspection size limit"
    if not hasattr(os, "O_NOFOLLOW"):
        return None, "platform lacks O_NOFOLLOW"
    flags = os.O_RDONLY | os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    try:
        fd = os.open(path, flags)
    except OSError:
        return None, "file cannot be opened safely"
    try:
        opened = os.fstat(fd)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
        ):
            return None, "file changed during safe open"
        data = bytearray()
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            data.extend(chunk)
            if max_bytes is not None and len(data) > max_bytes:
                return None, "file exceeds inspection size limit"
        after = os.fstat(fd)
        if (
            (after.st_dev, after.st_ino) != (opened.st_dev, opened.st_ino)
            or after.st_size != opened.st_size
        ):
            return None, "file changed during inspection"
        return bytes(data), None
    finally:
        os.close(fd)


def _load_allowlist(repo: Path) -> dict[tuple[str, str], str]:
    path = repo / ALLOWLIST_FILE
    if not path.exists() and not path.is_symlink():
        return {}
    data, error = _read_regular_file(path, max_bytes=MAX_ALLOWLIST_BYTES)
    if error or data is None:
        return {}
    try:
        payload = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return {}
    result: dict[tuple[str, str], str] = {}
    for item in payload.get("entries", []) if isinstance(payload, dict) else []:
        if not isinstance(item, dict):
            continue
        rel = _normalise_rel(str(item.get("path", "")).strip())
        digest = str(item.get("sha256", "")).strip().casefold()
        reason = str(item.get("reason", "")).strip()
        if (
            rel
            and not _unsafe(rel)
            and re.fullmatch(r"[0-9a-f]{64}", digest)
            and len(reason) >= 12
        ):
            result[(rel, digest)] = reason
    return result


def _zip_member_is_special(info: zipfile.ZipInfo) -> bool:
    if info.is_dir() or info.create_system != 3:
        return False
    mode = (info.external_attr >> 16) & 0xFFFF
    return stat.S_IFMT(mode) not in {0, stat.S_IFREG}


def _scan_archive(
    data: bytes,
    path: str,
    scope: str,
    allowlist: dict[tuple[str, str], str],
    depth: int,
    kind: str,
) -> list[str]:
    if depth > MAX_ARCHIVE_DEPTH:
        return [f"{scope}: archive nesting limit exceeded in {path}"]
    findings: list[str] = []
    members: list[tuple[str, bytes]] = []
    total = 0
    try:
        if kind == "zip":
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                infos = archive.infolist()
                if len(infos) > MAX_ARCHIVE_MEMBERS:
                    return [f"{scope}: archive member-count limit exceeded in {path}"]
                for info in infos:
                    if info.is_dir():
                        continue
                    rel = info.filename
                    if _zip_member_is_special(info):
                        findings.append(
                            f"{scope}: zip special member rejected in {path}!{rel}"
                        )
                        continue
                    if _unsafe(rel):
                        findings.append(f"{scope}: unsafe archive member path in {path}")
                        continue
                    if info.file_size > MAX_ARCHIVE_MEMBER_BYTES:
                        findings.append(
                            f"{scope}: archive member too large in {path}!{rel}"
                        )
                        continue
                    total += info.file_size
                    if total > MAX_ARCHIVE_TOTAL_BYTES:
                        findings.append(
                            f"{scope}: archive expanded-size limit exceeded in {path}"
                        )
                        break
                    members.append((rel, archive.read(info)))
        elif kind == "tar":
            with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as archive:
                infos = archive.getmembers()
                if len(infos) > MAX_ARCHIVE_MEMBERS:
                    return [f"{scope}: archive member-count limit exceeded in {path}"]
                for info in infos:
                    if info.isdir():
                        continue
                    if not info.isfile():
                        findings.append(
                            f"{scope}: tar special member rejected in {path}!{info.name}"
                        )
                        continue
                    rel = info.name
                    if _unsafe(rel):
                        findings.append(f"{scope}: unsafe archive member path in {path}")
                        continue
                    if info.size > MAX_ARCHIVE_MEMBER_BYTES:
                        findings.append(
                            f"{scope}: archive member too large in {path}!{rel}"
                        )
                        continue
                    total += info.size
                    if total > MAX_ARCHIVE_TOTAL_BYTES:
                        findings.append(
                            f"{scope}: archive expanded-size limit exceeded in {path}"
                        )
                        break
                    handle = archive.extractfile(info)
                    if handle is None:
                        findings.append(
                            f"{scope}: archive member unreadable in {path}!{rel}"
                        )
                        continue
                    members.append((rel, handle.read()))
        else:
            return [f"{scope}: archive/container format not safely inspectable: {path}"]
    except (
        zipfile.BadZipFile,
        tarfile.TarError,
        OSError,
        EOFError,
        RuntimeError,
        ValueError,
    ):
        return [f"{scope}: corrupt/uninspectable archive/container: {path}"]
    for rel, blob in members:
        findings.extend(
            _scan_bytes(
                blob,
                rel,
                scope,
                allowlist,
                display=f"{path}!{rel}",
                depth=depth + 1,
            )
        )
    return sorted(set(findings))


def _is_git_lfs_pointer(data: bytes) -> bool:
    if len(data) > 4096:
        return False
    try:
        lines = data.decode("ascii").splitlines()
    except UnicodeDecodeError:
        return False
    if len(lines) < 3:
        return False
    return (
        lines[0].strip() == _LFS_VERSION_LINE
        and bool(_LFS_OID_RE.fullmatch(lines[1].strip()))
        and bool(_LFS_SIZE_RE.fullmatch(lines[2].strip()))
    )


def _scan_bytes(
    data: bytes,
    path: str,
    scope: str,
    allowlist: dict[tuple[str, str], str],
    display: str | None = None,
    depth: int = 0,
) -> list[str]:
    shown = display or path
    if is_forbidden_path(path):
        return [f"{scope}: forbidden file {shown}"]
    if _is_git_lfs_pointer(data):
        return [
            f"{scope}: Git LFS pointer rejected; external object content is not scanned: {shown}"
        ]
    raw = scan_text(data.decode("latin-1", errors="ignore"), shown, scope)
    if raw:
        return raw
    kind, error = _resolved_archive_kind(path, data)
    if error:
        return [f"{scope}: {error}: {shown}"]
    if kind is not None:
        return _scan_archive(data, shown, scope, allowlist, depth, kind)
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        if (_normalise_rel(path), _sha256(data)) in allowlist:
            return []
        return [
            f"{scope}: binary/uninspectable object requires reviewed path+SHA256 allowlist: {shown}"
        ]
    if len(data) > MAX_TEXT_BYTES:
        return [f"{scope}: text object exceeds safe inspection policy limit: {shown}"]
    return scan_text(text, shown, scope)


def _tracked_entries(repo: Path) -> list[tuple[str, str, int, str]]:
    raw = run_git(repo, "ls-files", "--stage", "-z", text=False).stdout
    entries: list[tuple[str, str, int, str]] = []
    for record in raw.split(b"\0"):
        if not record:
            continue
        try:
            metadata, raw_path = record.split(b"\t", 1)
            raw_mode, raw_sha, raw_stage = metadata.split(b" ", 2)
            mode = raw_mode.decode("ascii")
            sha = raw_sha.decode("ascii")
            stage = int(raw_stage.decode("ascii"))
            rel = raw_path.decode("utf-8", errors="surrogateescape")
        except (ValueError, UnicodeError):
            entries.append(("invalid", "", -1, "<unparseable-index-entry>"))
            continue
        entries.append((mode, sha, stage, rel))
    return entries


def _tracked(repo: Path) -> list[str]:
    return [entry[3] for entry in _tracked_entries(repo)]


def scan_directory(
    root: Path,
    allowlist_repo: Path | None = None,
    scope: str = "directory",
) -> list[str]:
    out: list[str] = []
    allow = _load_allowlist(allowlist_repo or root)
    for path in sorted(root.rglob("*")):
        rel = path.relative_to(root).as_posix()
        if path.is_symlink():
            out.append(f"{scope}: symlink/uninspectable path: {rel}")
            continue
        if not path.is_file():
            continue
        data, error = _read_regular_file(path)
        if error or data is None:
            out.append(f"{scope}: unsafe/unreadable file topology: {rel}")
            continue
        out.extend(_scan_bytes(data, rel, scope, allow))
    return sorted(set(out))


def scan_current_tree(repo: Path = ROOT) -> list[str]:
    out: list[str] = []
    allow = _load_allowlist(repo)
    for mode, _sha, stage, rel in _tracked_entries(repo):
        if stage != 0:
            out.append(f"current-tree: unresolved Git index stage rejected: {rel}")
            continue
        if mode == "120000":
            out.append(f"current-tree: tracked symlink rejected: {rel}")
            continue
        if mode == "160000":
            out.append(f"current-tree: tracked gitlink/submodule rejected: {rel}")
            continue
        if mode not in {"100644", "100755"}:
            out.append(f"current-tree: unsupported tracked Git mode rejected: {rel}")
            continue
        path = repo / rel
        data, error = _read_regular_file(path)
        if error or data is None:
            out.append(f"current-tree: tracked file unsafe/unreadable: {rel}")
            continue
        out.extend(_scan_bytes(data, rel, "current-tree", allow))
    return sorted(set(out))


def _is_shallow(repo: Path) -> bool:
    return (
        run_git(repo, "rev-parse", "--is-shallow-repository")
        .stdout.strip()
        .casefold()
        == "true"
    )


def _history_objects(repo: Path):
    seen: set[tuple[str, str]] = set()
    for line in run_git(repo, "rev-list", "--objects", "--all").stdout.splitlines():
        parts = line.split(" ", 1)
        if len(parts) != 2:
            continue
        sha, path = parts
        if (sha, path) in seen:
            continue
        seen.add((sha, path))
        try:
            object_type = run_git(repo, "cat-file", "-t", sha).stdout.strip()
        except subprocess.CalledProcessError:
            continue
        if object_type == "blob":
            yield sha, path


def _commit_messages(repo: Path) -> list[str]:
    out: list[str] = []
    raw = run_git(repo, "log", "--all", "--format=%H%x00%B%x00", text=False).stdout
    parts = raw.split(b"\0")
    for index in range(0, len(parts) - 1, 2):
        sha = parts[index].decode("ascii", errors="ignore").strip()
        if sha:
            out.extend(
                scan_text(
                    parts[index + 1].decode("utf-8", errors="replace"),
                    "<commit-message>",
                    f"history-commit:{sha[:12]}",
                )
            )
    return out


def scan_history(repo: Path = ROOT) -> list[str]:
    if _is_shallow(repo):
        return ["history: repository checkout is shallow; full-history scan is not proven"]
    out = _commit_messages(repo)
    allow = _load_allowlist(repo)
    for sha, rel in _history_objects(repo):
        try:
            blob = run_git(repo, "cat-file", "blob", sha, text=False).stdout
        except subprocess.CalledProcessError:
            out.append(f"history-blob:{sha[:12]}: Git blob unreadable: {rel}")
            continue
        out.extend(_scan_bytes(blob, rel, f"history-blob:{sha[:12]}", allow))
    return sorted(set(out))


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("current", "history", "all"), default="all")
    args = parser.parse_args(argv)
    out: list[str] = []
    if args.mode in {"current", "all"}:
        out.extend(scan_current_tree(ROOT))
    if args.mode in {"history", "all"}:
        out.extend(scan_history(ROOT))
    out = sorted(set(out))
    if out:
        print("SECRET_SCAN_FAIL")
        for finding in out:
            print("-", finding)
        return 1
    print("SECRET_SCAN_PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
