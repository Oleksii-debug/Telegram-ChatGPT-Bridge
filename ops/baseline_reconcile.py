# -*- coding: utf-8 -*-
"""Fail-closed non-secret HOSTiQ baseline/source reconciliation.

Two inputs are supported:
1. a reviewed sanitized directory versus an exact Git ref (legacy API retained);
2. two non-secret path/hash/size/category manifests for factual server->candidate
   accounting without copying raw server content into public evidence.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import tempfile
import unicodedata
from collections import Counter
from pathlib import Path, PurePosixPath

try:
    from ops.release_guard import SafetyError, build_manifest, sha256_json, write_json_atomic
except ImportError:  # isolated local tests
    import hashlib
    class SafetyError(RuntimeError):
        pass
    def sha256_json(value):
        raw=json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=True).encode()
        return hashlib.sha256(raw).hexdigest()
    def write_json_atomic(path, payload, mode=0o600):
        path.write_text(json.dumps(payload,sort_keys=True,indent=2)+"\n",encoding="utf-8")
    def build_manifest(root):
        files=[]
        for p in sorted(root.rglob("*")):
            if p.is_file() and not p.is_symlink():
                data=p.read_bytes(); rel=p.relative_to(root).as_posix()
                files.append({"path":rel,"sha256":hashlib.sha256(data).hexdigest(),"size":len(data)})
        return {"files":files}

try:
    from tools import secret_scan
except ImportError:
    secret_scan = None

SAFE_CATEGORIES = frozenset({
    "application_source", "wsgi_startup", "tests", "tooling",
    "dependency_input", "empty_extra", "documentation_metadata",
    "tooling_metadata", "sanitized_metadata", "other_nonsecret",
})
PRIVATE_RUNTIME_PARTS = frozenset({
    "var", "runtime", "sessions", "session", "private", "cache", "tmp", "temp",
})


def canonical_posix_path(value: str) -> str:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise SafetyError("manifest path is not canonical POSIX")
    if value != unicodedata.normalize("NFC", value):
        raise SafetyError("manifest path is not Unicode NFC")
    p = PurePosixPath(value)
    if p.is_absolute() or ".." in p.parts or any(x in {"", "."} for x in p.parts):
        raise SafetyError("unsafe manifest path")
    if p.as_posix() != value:
        raise SafetyError("manifest path normalization mismatch")
    return value


def _private_runtime_path(path: str) -> bool:
    p = PurePosixPath(path)
    folded_parts = {part.casefold() for part in p.parts}
    if folded_parts & PRIVATE_RUNTIME_PARTS:
        return True
    if secret_scan is not None and secret_scan.is_forbidden_path(path):
        return True
    name = p.name.casefold()
    forbidden_names = {"private_config.json", "connection_info.txt", "setup_state.json", "bootstrap.json", "credentials.json", "token.json"}
    return name in forbidden_names or name.startswith(".env") or name.endswith((".session", ".session-journal", ".sqlite", ".sqlite3", ".db", ".log", ".pem", ".key"))


def normalize_nonsecret_manifest(payload: dict, *, require_category: bool = True) -> dict:
    if not isinstance(payload, dict) or payload.get("schema_version") != 1 or set(payload) != {"schema_version", "files"}:
        raise SafetyError("manifest schema mismatch")
    files = payload.get("files")
    if not isinstance(files, list) or len(files) > 500:
        raise SafetyError("manifest file-count policy failed")
    seen=set(); folded=set(); normalized=set(); output=[]
    for item in files:
        expected = {"path", "sha256", "size", "category"} if require_category else {"path", "sha256", "size"}
        if not isinstance(item, dict) or set(item) != expected:
            raise SafetyError("manifest entry schema mismatch")
        path=canonical_posix_path(item["path"])
        if path in seen or path.casefold() in folded or unicodedata.normalize("NFC", path) in normalized:
            raise SafetyError("manifest duplicate/case/Unicode collision")
        seen.add(path); folded.add(path.casefold()); normalized.add(unicodedata.normalize("NFC", path))
        digest=item["sha256"]
        if not isinstance(digest,str) or len(digest)!=64 or any(ch not in "0123456789abcdef" for ch in digest):
            raise SafetyError("manifest digest invalid")
        size=item["size"]
        if not isinstance(size,int) or isinstance(size,bool) or size<0 or size>100_000_000:
            raise SafetyError("manifest size invalid")
        category=item.get("category", "other_nonsecret")
        if category not in SAFE_CATEGORIES:
            raise SafetyError("manifest category invalid")
        if _private_runtime_path(path):
            raise SafetyError("private/runtime candidate path rejected")
        output.append({"path":path,"sha256":digest,"size":size,"category":category})
    output.sort(key=lambda row: row["path"])
    return {"schema_version":1,"files":output}


def reconcile_manifests(server_manifest: dict, candidate_manifest: dict) -> dict:
    server=normalize_nonsecret_manifest(server_manifest)
    candidate=normalize_nonsecret_manifest(candidate_manifest)
    left={x["path"]:x for x in server["files"]}; right={x["path"]:x for x in candidate["files"]}
    lp=set(left); rp=set(right)
    only_server=sorted(lp-rp); only_candidate=sorted(rp-lp)
    changed=[]; category_changed=[]; exact=[]
    for path in sorted(lp & rp):
        l=left[path]; r=right[path]
        if l["sha256"] != r["sha256"] or l["size"] != r["size"]:
            changed.append(path)
        elif l["category"] != r["category"]:
            category_changed.append(path)
        else:
            exact.append(path)
    startup = {
        "path": "passenger_wsgi.py",
        "server_present": "passenger_wsgi.py" in left,
        "candidate_present": "passenger_wsgi.py" in right,
        "exact_hash_match": "passenger_wsgi.py" in left and "passenger_wsgi.py" in right and left["passenger_wsgi.py"]["sha256"] == right["passenger_wsgi.py"]["sha256"],
    }
    return {
        "schema_version": 2,
        "server_manifest_sha256": sha256_json(server),
        "candidate_manifest_sha256": sha256_json(candidate),
        "server_file_count": len(left),
        "candidate_file_count": len(right),
        "server_category_counts": dict(sorted(Counter(x["category"] for x in left.values()).items())),
        "candidate_category_counts": dict(sorted(Counter(x["category"] for x in right.values()).items())),
        "exact_count": len(exact),
        "only_server_paths": only_server,
        "only_candidate_paths": only_candidate,
        "changed_paths": changed,
        "category_changed_paths": category_changed,
        "startup": startup,
        "full_bijection": not only_server and not only_candidate and not changed and not category_changed,
        "raw_file_content_recorded": False,
        "secret_values_recorded": False,
    }


def _git_export(repo: Path, ref: str, destination: Path) -> str:
    try:
        sha = subprocess.check_output(["git", "rev-parse", "--verify", f"{ref}^{{commit}}"], cwd=repo, text=True).strip()
    except subprocess.SubprocessError as exc:
        raise SafetyError("Git reconciliation ref cannot be resolved") from exc
    archive = subprocess.Popen(["git", "archive", sha], cwd=repo, stdout=subprocess.PIPE)
    extract = subprocess.run(["tar", "-x", "-C", str(destination)], stdin=archive.stdout, check=False)
    if archive.stdout:
        archive.stdout.close()
    if archive.wait() != 0 or extract.returncode != 0:
        raise SafetyError("Git reconciliation export failed")
    return sha


def _manifest_map(manifest: dict) -> dict[str, dict]:
    return {item["path"]: item for item in manifest.get("files", [])}


def reconcile(recovered_root: Path, repo: Path, git_ref: str) -> dict:
    """Legacy directory-vs-Git reconciliation retained for prior callers/tests."""
    recovered_root = recovered_root.resolve(strict=True); repo = repo.resolve(strict=True)
    if secret_scan is not None:
        findings = secret_scan.scan_directory(recovered_root, allowlist_repo=Path("/__no_public_allowlist__"), scope="production-reconciliation")
        if findings:
            raise SafetyError("sanitized recovered baseline failed secret/private-content scan")
    recovered_manifest = build_manifest(recovered_root)
    with tempfile.TemporaryDirectory() as td:
        exported = Path(td) / "git"; exported.mkdir()
        git_sha = _git_export(repo, git_ref, exported); git_manifest = build_manifest(exported)
    left=_manifest_map(recovered_manifest); right=_manifest_map(git_manifest)
    rp=set(left); gp=set(right); added=sorted(rp-gp); removed=sorted(gp-rp)
    changed=sorted(path for path in rp & gp if left[path]["sha256"]!=right[path]["sha256"] or left[path]["size"]!=right[path]["size"])
    same=sorted((rp & gp)-set(changed))
    return {"schema_version":1,"git_ref":git_ref,"git_sha":git_sha,
            "recovered_manifest_sha256":sha256_json(recovered_manifest),"git_manifest_sha256":sha256_json(git_manifest),
            "recovered_file_count":len(left),"git_file_count":len(right),"same_count":len(same),
            "added_paths":added,"removed_paths":removed,"changed_paths":changed,
            "startup_file_changed":"passenger_wsgi.py" in changed or "passenger_wsgi.py" in added or "passenger_wsgi.py" in removed,
            "secret_values_recorded":False,"raw_file_content_recorded":False}


def main(argv=None) -> int:
    parser=argparse.ArgumentParser(); parser.add_argument("--server-manifest"); parser.add_argument("--candidate-manifest")
    parser.add_argument("--recovered-root"); parser.add_argument("--repo"); parser.add_argument("--git-ref"); parser.add_argument("--output",required=True)
    args=parser.parse_args(argv)
    try:
        if args.server_manifest or args.candidate_manifest:
            if not (args.server_manifest and args.candidate_manifest):
                raise SafetyError("both manifests are required")
            server=json.loads(Path(args.server_manifest).read_text(encoding="utf-8")); candidate=json.loads(Path(args.candidate_manifest).read_text(encoding="utf-8"))
            result=reconcile_manifests(server,candidate)
        else:
            if not (args.recovered_root and args.repo and args.git_ref):
                raise SafetyError("directory reconciliation arguments incomplete")
            result=reconcile(Path(args.recovered_root),Path(args.repo),args.git_ref)
        write_json_atomic(Path(args.output),result,mode=0o600)
    except (SafetyError,OSError,json.JSONDecodeError):
        # Public/support stdout intentionally exposes only one stable result code.
        print("RECONCILIATION_BLOCKED"); return 2
    print("RECONCILIATION_READY_FOR_AUDIT"); return 0

if __name__=="__main__":
    raise SystemExit(main())