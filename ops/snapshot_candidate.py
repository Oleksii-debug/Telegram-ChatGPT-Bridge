# -*- coding: utf-8 -*-
"""Fail-closed validation and classification for sanitized HOSTiQ reference snapshots.

This module never treats a reference archive as deployment authority.  Its only
purpose is to prove package integrity, produce non-secret path/hash metadata and
select a reviewable source-import candidate.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import tempfile
import unicodedata
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Iterable

try:
    from ops.release_guard import SafetyError, write_json_atomic
except ImportError:  # local isolated tests only
    class SafetyError(RuntimeError):
        pass
    def write_json_atomic(path: Path, payload: dict, mode: int = 0o600) -> None:
        path.write_text(json.dumps(payload, sort_keys=True, indent=2), encoding="utf-8")
        os.chmod(path, mode)

try:
    from tools import secret_scan
except ImportError:  # pragma: no cover - repository CI always has the scanner
    secret_scan = None

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
MAX_ARCHIVE_FILES = 500
MAX_ARCHIVE_MEMBER_BYTES = 25_000_000
MAX_ARCHIVE_TOTAL_BYTES = 100_000_000
MANIFEST_NAME = "MANIFEST_SANITIZED_SHA256.txt"
REFERENCE_MARKER = "REFERENCE_ONLY_NOT_DEPLOY_AUTHORITY"

SOURCE_CATEGORIES = frozenset({
    "application_source", "wsgi_startup", "tests", "tooling",
    "dependency_input", "empty_extra",
})

SERVER_CANDIDATE_EXCLUDES = frozenset({
    "requirements-drive-tools-windows.txt",
    "tools/AUTHORIZE_GOOGLE_DRIVE_WINDOWS.cmd",
    "tools/BUILD_OPENAPI_WINDOWS.cmd",
    "tools/google_drive_authorize_windows.py",
})

def is_server_candidate_path(entry: ManifestEntry) -> bool:
    return entry.category in SOURCE_CATEGORIES and entry.path not in SERVER_CANDIDATE_EXCLUDES

@dataclass(frozen=True)
class ManifestEntry:
    path: str
    sha256: str
    size: int
    category: str


def canonical_path(value: str) -> str:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise SafetyError("non-canonical package path")
    if value != unicodedata.normalize("NFC", value):
        raise SafetyError("package path is not Unicode NFC")
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or any(part in {"", "."} for part in path.parts):
        raise SafetyError("unsafe package path")
    canonical = path.as_posix()
    if canonical != value:
        raise SafetyError("non-canonical package path")
    return canonical


def classify_path(path: str) -> str:
    path = canonical_path(path)
    if path == MANIFEST_NAME:
        return "sanitized_metadata"
    if path == "passenger_wsgi.py":
        return "wsgi_startup"
    if path == "install_server.sh":
        return "empty_extra"
    if path == "cron_worker.py" or (path.startswith("bridge/") and path.endswith(".py")):
        return "application_source"
    if path.startswith("tests/"):
        return "tests"
    if path.startswith("tools/"):
        return "tooling"
    if path.startswith("requirements") and path.endswith(".txt"):
        return "dependency_input"
    if path == ".gitignore":
        return "tooling_metadata"
    if path.startswith("docs/") or path.endswith((".md", ".txt")) or path == "VERSION":
        return "documentation_metadata"
    return "unclassified"


def _zip_mode(info: zipfile.ZipInfo) -> int:
    return (info.external_attr >> 16) & 0xFFFF


def inspect_zip_members(archive: zipfile.ZipFile) -> list[zipfile.ZipInfo]:
    infos = archive.infolist()
    if not infos or len(infos) > MAX_ARCHIVE_FILES:
        raise SafetyError("reference archive file-count policy failed")
    seen: set[str] = set()
    folded: set[str] = set()
    normalized: set[str] = set()
    total = 0
    output: list[zipfile.ZipInfo] = []
    for info in infos:
        if info.is_dir():
            continue
        path = canonical_path(info.filename)
        if path in seen:
            raise SafetyError("duplicate reference archive path")
        cf = path.casefold()
        if cf in folded:
            raise SafetyError("case-colliding reference archive path")
        nfc = unicodedata.normalize("NFC", path)
        if nfc in normalized:
            raise SafetyError("Unicode-normalization-colliding archive path")
        seen.add(path); folded.add(cf); normalized.add(nfc)
        mode = _zip_mode(info)
        if info.create_system == 3 and mode:
            kind = stat.S_IFMT(mode)
            if kind not in {0, stat.S_IFREG}:
                raise SafetyError("symlink/special reference archive member")
        if info.file_size < 0 or info.file_size > MAX_ARCHIVE_MEMBER_BYTES:
            raise SafetyError("reference archive member size policy failed")
        total += info.file_size
        if total > MAX_ARCHIVE_TOTAL_BYTES:
            raise SafetyError("reference archive expanded-size policy failed")
        output.append(info)
    return output


def parse_manifest(text: str) -> list[tuple[str, str]]:
    rows: list[tuple[str, str]] = []
    seen_paths: set[str] = set()
    folded: set[str] = set()
    normalized: set[str] = set()
    for lineno, raw in enumerate(text.splitlines(), 1):
        if not raw.strip():
            continue
        if "  " not in raw:
            raise SafetyError(f"manifest format error at line {lineno}")
        digest, path = raw.split("  ", 1)
        digest = digest.strip().casefold()
        if not SHA256_RE.fullmatch(digest):
            raise SafetyError(f"manifest hash format error at line {lineno}")
        path = canonical_path(path)
        if path == MANIFEST_NAME:
            raise SafetyError("manifest must not self-reference")
        if path in seen_paths or path.casefold() in folded or unicodedata.normalize("NFC", path) in normalized:
            raise SafetyError("duplicate/colliding manifest path")
        seen_paths.add(path); folded.add(path.casefold()); normalized.add(unicodedata.normalize("NFC", path))
        rows.append((digest, path))
    if not rows:
        raise SafetyError("empty sanitized manifest")
    return rows


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def validate_reference_zip(path: Path, *, run_secret_scan: bool = True) -> dict:
    path = path.resolve(strict=True)
    archive_sha = _sha256_bytes(path.read_bytes())
    with zipfile.ZipFile(path, "r") as archive:
        infos = inspect_zip_members(archive)
        member_map = {canonical_path(info.filename): info for info in infos}
        if MANIFEST_NAME not in member_map:
            raise SafetyError("sanitized manifest missing from reference archive")
        manifest_bytes = archive.read(member_map[MANIFEST_NAME])
        try:
            manifest_text = manifest_bytes.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise SafetyError("sanitized manifest is not UTF-8") from exc
        manifest_rows = parse_manifest(manifest_text)
        manifest_paths = {p for _, p in manifest_rows}
        package_paths = set(member_map)
        if package_paths - manifest_paths != {MANIFEST_NAME}:
            raise SafetyError("archive contains unmanifested package files")
        if manifest_paths - package_paths:
            raise SafetyError("manifest references missing package files")
        entries: list[ManifestEntry] = []
        for expected, rel in manifest_rows:
            payload = archive.read(member_map[rel])
            actual = _sha256_bytes(payload)
            if actual != expected:
                raise SafetyError("reference archive manifest hash mismatch")
            category = classify_path(rel)
            if category == "unclassified":
                raise SafetyError("unclassified package path")
            if rel == "install_server.sh" and payload != b"":
                raise SafetyError("install_server.sh must remain an empty extra")
            entries.append(ManifestEntry(rel, actual, len(payload), category))
        # Validate known startup semantics without executing snapshot code.
        startup = archive.read(member_map["passenger_wsgi.py"]).decode("utf-8") if "passenger_wsgi.py" in member_map else ""
        if "from bridge.app import application" not in startup:
            raise SafetyError("Passenger startup import target mismatch")
        if run_secret_scan:
            if secret_scan is None:
                raise SafetyError("repository secret scanner unavailable")
            with tempfile.TemporaryDirectory() as td:
                root = Path(td)
                for info in infos:
                    rel = canonical_path(info.filename)
                    dest = root / rel
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    dest.write_bytes(archive.read(info))
                findings = secret_scan.scan_directory(
                    root,
                    allowlist_repo=Path("/__no_public_allowlist__"),
                    scope="reference-snapshot",
                )
                if findings:
                    raise SafetyError("reference archive failed secret/private-content scan")
    categories: dict[str, int] = {}
    for entry in entries:
        categories[entry.category] = categories.get(entry.category, 0) + 1
    categories["sanitized_metadata"] = categories.get("sanitized_metadata", 0) + 1
    candidate_entries = [e for e in entries if is_server_candidate_path(e)]
    return {
        "schema_version": 1,
        "reference_marker": REFERENCE_MARKER,
        "snapshot_sha256": archive_sha,
        "package_file_count": len(infos),
        "manifest_entry_count": len(manifest_rows),
        "manifest_sha256": _sha256_bytes(manifest_bytes),
        "categories": dict(sorted(categories.items())),
        "candidate_file_count": len(candidate_entries),
        "candidate_files": [e.__dict__ for e in candidate_entries],
        "live_server_file_count_from_drive": 42,
        "old_manifest_exact_match_count_from_drive": 39,
        "known_changed_startup": "passenger_wsgi.py",
        "known_empty_extra": "install_server.sh",
        "package_vs_live_count_delta": len(infos) - 42,
        "exact_live_path_bijection_proven": False,
        "deploy_authority": False,
        "secret_values_recorded": False,
        "raw_private_content_recorded": False,
    }


def emit_candidate_tree(zip_path: Path, destination: Path, report: dict | None = None) -> dict:
    report = report or validate_reference_zip(zip_path)
    destination.mkdir(parents=True, exist_ok=True)
    wanted = {item["path"]: item for item in report["candidate_files"]}
    with zipfile.ZipFile(zip_path, "r") as archive:
        for rel, meta in sorted(wanted.items()):
            target = destination / canonical_path(rel)
            target.parent.mkdir(parents=True, exist_ok=True)
            data = archive.read(rel)
            if _sha256_bytes(data) != meta["sha256"]:
                raise SafetyError("candidate extraction hash mismatch")
            target.write_bytes(data)
    marker = {
        "schema_version": 1,
        "reference_marker": REFERENCE_MARKER,
        "snapshot_sha256": report["snapshot_sha256"],
        "package_file_count": report["package_file_count"],
        "candidate_file_count": report["candidate_file_count"],
        "candidate_files": report["candidate_files"],
        "deploy_authority": False,
        "exact_live_path_bijection_proven": False,
        "raw_source_public_commit_authorized": False,
    }
    (destination / "CANDIDATE_PROVENANCE.json").write_text(
        json.dumps(marker, sort_keys=True, indent=2) + "\n", encoding="utf-8"
    )
    return marker


def validate_candidate_provenance(payload: dict) -> dict:
    required = {
        "schema_version", "reference_marker", "snapshot_sha256", "package_file_count",
        "candidate_file_count", "candidate_files", "deploy_authority",
        "exact_live_path_bijection_proven", "raw_source_public_commit_authorized",
    }
    if not isinstance(payload, dict) or set(payload) != required or payload.get("schema_version") != 1:
        raise SafetyError("candidate provenance schema mismatch")
    if payload["reference_marker"] != REFERENCE_MARKER or payload["deploy_authority"] is not False:
        raise SafetyError("candidate provenance authority marker invalid")
    if payload["exact_live_path_bijection_proven"] is not False or payload["raw_source_public_commit_authorized"] is not False:
        raise SafetyError("candidate provenance must remain non-authoritative")
    digest = payload["snapshot_sha256"]
    if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
        raise SafetyError("candidate snapshot hash invalid")
    files = payload["candidate_files"]
    if not isinstance(files, list) or payload["candidate_file_count"] != len(files) or not 0 < len(files) <= MAX_ARCHIVE_FILES:
        raise SafetyError("candidate provenance file count invalid")
    if not isinstance(payload["package_file_count"], int) or payload["package_file_count"] < len(files):
        raise SafetyError("candidate package count invalid")
    seen=set(); folded=set()
    for item in files:
        if not isinstance(item, dict) or set(item) != {"path", "sha256", "size", "category"}:
            raise SafetyError("candidate provenance entry schema mismatch")
        path=canonical_path(item["path"]); cf=path.casefold()
        if path in seen or cf in folded:
            raise SafetyError("candidate provenance duplicate/case collision")
        seen.add(path); folded.add(cf)
        if not isinstance(item["sha256"], str) or not SHA256_RE.fullmatch(item["sha256"]):
            raise SafetyError("candidate provenance hash invalid")
        if not isinstance(item["size"], int) or isinstance(item["size"], bool) or item["size"] < 0 or item["size"] > MAX_ARCHIVE_MEMBER_BYTES:
            raise SafetyError("candidate provenance size invalid")
        if item["category"] not in SOURCE_CATEGORIES or item["path"] in SERVER_CANDIDATE_EXCLUDES:
            raise SafetyError("candidate provenance category/path invalid")
    return dict(payload)


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--zip", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--emit-candidate")
    args = parser.parse_args(argv)
    try:
        report = validate_reference_zip(Path(args.zip))
        write_json_atomic(Path(args.output), report, mode=0o600)
        if args.emit_candidate:
            emit_candidate_tree(Path(args.zip), Path(args.emit_candidate), report)
    except (SafetyError, OSError, zipfile.BadZipFile) as exc:
        print(f"REFERENCE_SNAPSHOT_BLOCKED: {type(exc).__name__}")
        return 2
    print(REFERENCE_MARKER)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
