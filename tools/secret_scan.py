# -*- coding: utf-8 -*-
"""Fail-closed secret guard for the public Telegram Bridge repository."""
from __future__ import annotations
import argparse, hashlib, io, json, re, subprocess, tarfile, zipfile
from pathlib import Path, PurePosixPath
ROOT=Path(__file__).resolve().parents[1]; ALLOWLIST_FILE=".secret-scan-allowlist.json"
MAX_TEXT_BYTES=50_000_000; MAX_ARCHIVE_DEPTH=3; MAX_ARCHIVE_MEMBERS=500; MAX_ARCHIVE_MEMBER_BYTES=25_000_000; MAX_ARCHIVE_TOTAL_BYTES=100_000_000
FORBIDDEN_EXACT_NAMES_CASEFOLD={x.casefold() for x in {".env","credentials.json","token.json","bootstrap.json","setup_state.json","connection_info.txt","private_config.json","openapi_ready.json","bridge_keys_secret.txt","tg_session_string_secret.txt","hostiq_cpanel_password.txt","ssh_private_key","github_token.txt","github_pat.txt","id_rsa","id_ed25519","id_ecdsa","id_dsa"}}
FORBIDDEN_SUFFIXES={".session",".session-journal",".sqlite",".sqlite3",".db",".db-journal",".db-wal",".db-shm",".pem",".key",".p12",".pfx"}
SUPPORTED_ARCHIVE_SUFFIXES=(".zip",".tar",".tgz",".tbz",".tbz2",".txz",".tar.gz",".tar.bz2",".tar.xz"); UNSUPPORTED_ARCHIVE_SUFFIXES=(".7z",".rar",".gz",".bz2",".xz")
SECRET_VARIABLES=("TG_API_ID","TG_API_HASH","TG_SESSION_STRING","TELEGRAM_2FA_PASSWORD","BRIDGE_TOKEN","BRIDGE_ROUTE_KEY","SETUP_ROUTE","SETUP_KEY","HOSTIQ_CPANEL_PASSWORD","CPANEL_PASSWORD","SSH_PRIVATE_KEY","GITHUB_TOKEN","GH_TOKEN","GITHUB_PAT","GOOGLE_DRIVE_CLIENT_SECRET","GOOGLE_DRIVE_REFRESH_TOKEN"); _SECRET_ALT="|".join(re.escape(x) for x in SECRET_VARIABLES)
ASSIGNMENT_RE=re.compile(rf"(?im)^\s*(?:export\s+|set\s+)?[\"']?({_SECRET_ALT})[\"']?\s*[:=]\s*(?:\"([^\"]*)\"|'([^']*)'|([^#;\r\n]+?))\s*(?:[#;].*)?$",re.IGNORECASE)
STRUCTURED_ASSIGNMENT_RE=re.compile(rf"(?im)[\"']({_SECRET_ALT})[\"']\s*[:=]\s*(?:\"([^\"]*)\"|'([^']*)'|([^\s,\}}\]]+))",re.IGNORECASE)
PRIVATE_KEY_RE=re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",re.IGNORECASE); SETUP_ROUTE_RE=re.compile(r"(?<![A-Za-z0-9_])/(setup-[A-Za-z0-9_-]{16,})(?![A-Za-z0-9_])",re.IGNORECASE)
ANGLE_PLACEHOLDER_RE=re.compile(r"^<[A-Z0-9_.:-]+>$",re.IGNORECASE); GH_SECRET_PLACEHOLDER_RE=re.compile(r"^\$\{\{\s*secrets\.[A-Z0-9_]+\s*\}\}$",re.IGNORECASE); ENV_PLACEHOLDER_RE=re.compile(r"^\$\{[A-Z_][A-Z0-9_]*\}$",re.IGNORECASE); DOLLAR_PLACEHOLDER_RE=re.compile(r"^\$[A-Z_][A-Z0-9_]*$",re.IGNORECASE); PLACEHOLDER_WORDS={"placeholder","changeme","change-me","example","example-value","replace-me","replace_me","your-value","your_value"}
def run_git(repo,*args,text=True): return subprocess.run(["git",*args],cwd=repo,check=True,capture_output=True,text=text)
def _sha256(data): return hashlib.sha256(data).hexdigest()
def _normalise_rel(path): return str(PurePosixPath(path.replace("\\","/")))
def _unsafe(path): p=PurePosixPath(path.replace("\\","/")); return p.is_absolute() or ".." in p.parts
def is_forbidden_path(path):
    name=PurePosixPath(path.replace("\\","/")).name.casefold(); return name.startswith(".env") or name in FORBIDDEN_EXACT_NAMES_CASEFOLD or any(name.endswith(s.casefold()) for s in FORBIDDEN_SUFFIXES)
def _archive_kind(path):
    lower=path.casefold()
    if lower.endswith(".zip"): return "zip"
    if any(lower.endswith(s) for s in SUPPORTED_ARCHIVE_SUFFIXES if s!=".zip"): return "tar"
    if any(lower.endswith(s) for s in UNSUPPORTED_ARCHIVE_SUFFIXES): return "unsupported"
    return None
def is_placeholder(value):
    value=(value or "").strip().strip('"').strip("'").strip(); lower=value.casefold()
    if not value: return True
    if lower in PLACEHOLDER_WORDS: return True
    return bool(ANGLE_PLACEHOLDER_RE.fullmatch(value) or GH_SECRET_PLACEHOLDER_RE.fullmatch(value) or ENV_PLACEHOLDER_RE.fullmatch(value) or DOLLAR_PLACEHOLDER_RE.fullmatch(value))
def scan_text(text,path,scope):
    out=[]
    if PRIVATE_KEY_RE.search(text): out.append(f"{scope}: private key marker in {path}")
    if SETUP_ROUTE_RE.search(text): out.append(f"{scope}: concrete setup route in {path}")
    for pattern in (ASSIGNMENT_RE,STRUCTURED_ASSIGNMENT_RE):
        for m in pattern.finditer(text):
            value=next((g for g in m.groups()[1:] if g is not None),"")
            if not is_placeholder(value): out.append(f"{scope}: secret-like assignment {m.group(1).upper()} in {path}")
    return sorted(set(out))
def _load_allowlist(repo):
    p=repo/ALLOWLIST_FILE
    if not p.exists(): return {}
    try: payload=json.loads(p.read_text(encoding="utf-8"))
    except (OSError,json.JSONDecodeError): return {}
    result={}
    for item in payload.get("entries",[]) if isinstance(payload,dict) else []:
        if not isinstance(item,dict): continue
        rel=_normalise_rel(str(item.get("path","")).strip()); digest=str(item.get("sha256","")).strip().casefold(); reason=str(item.get("reason","")).strip()
        if rel and not _unsafe(rel) and re.fullmatch(r"[0-9a-f]{64}",digest) and len(reason)>=12: result[(rel,digest)]=reason
    return result
def _scan_archive(data,path,scope,allowlist,depth):
    if depth>MAX_ARCHIVE_DEPTH: return [f"{scope}: archive nesting limit exceeded in {path}"]
    kind=_archive_kind(path); findings=[]; members=[]; total=0
    if kind=="unsupported": return [f"{scope}: unsupported archive/container requires manual private review: {path}"]
    try:
        if kind=="zip":
            with zipfile.ZipFile(io.BytesIO(data)) as arc:
                infos=[i for i in arc.infolist() if not i.is_dir()]
                if len(infos)>MAX_ARCHIVE_MEMBERS: return [f"{scope}: archive member-count limit exceeded in {path}"]
                for info in infos:
                    rel=info.filename
                    if _unsafe(rel): findings.append(f"{scope}: unsafe archive member path in {path}"); continue
                    if info.file_size>MAX_ARCHIVE_MEMBER_BYTES: findings.append(f"{scope}: archive member too large in {path}!{rel}"); continue
                    total+=info.file_size
                    if total>MAX_ARCHIVE_TOTAL_BYTES: findings.append(f"{scope}: archive expanded-size limit exceeded in {path}"); break
                    members.append((rel,arc.read(info)))
        elif kind=="tar":
            with tarfile.open(fileobj=io.BytesIO(data),mode="r:*") as arc:
                infos=[i for i in arc.getmembers() if i.isfile()]
                if len(infos)>MAX_ARCHIVE_MEMBERS: return [f"{scope}: archive member-count limit exceeded in {path}"]
                for info in infos:
                    rel=info.name
                    if _unsafe(rel): findings.append(f"{scope}: unsafe archive member path in {path}"); continue
                    if info.size>MAX_ARCHIVE_MEMBER_BYTES: findings.append(f"{scope}: archive member too large in {path}!{rel}"); continue
                    total+=info.size
                    if total>MAX_ARCHIVE_TOTAL_BYTES: findings.append(f"{scope}: archive expanded-size limit exceeded in {path}"); break
                    f=arc.extractfile(info)
                    if f is None: findings.append(f"{scope}: archive member unreadable in {path}!{rel}"); continue
                    members.append((rel,f.read()))
        else: return [f"{scope}: archive/container format not safely inspectable: {path}"]
    except (zipfile.BadZipFile,tarfile.TarError,OSError,EOFError): return [f"{scope}: corrupt/uninspectable archive/container: {path}"]
    for rel,blob in members: findings.extend(_scan_bytes(blob,rel,scope,allowlist,display=f"{path}!{rel}",depth=depth+1))
    return sorted(set(findings))
def _scan_bytes(data,path,scope,allowlist,display=None,depth=0):
    shown=display or path
    if is_forbidden_path(path): return [f"{scope}: forbidden file {shown}"]
    raw=scan_text(data.decode("latin-1",errors="ignore"),shown,scope)
    if raw: return raw
    kind=_archive_kind(path)
    if kind is not None: return _scan_archive(data,shown,scope,allowlist,depth)
    try: text=data.decode("utf-8")
    except UnicodeDecodeError:
        if (_normalise_rel(path),_sha256(data)) in allowlist: return []
        return [f"{scope}: binary/uninspectable object requires reviewed path+SHA256 allowlist: {shown}"]
    if len(data)>MAX_TEXT_BYTES: return [f"{scope}: text object exceeds safe inspection policy limit: {shown}"]
    return scan_text(text,shown,scope)
def _tracked(repo):
    raw=run_git(repo,"ls-files","-z",text=False).stdout; return [x.decode("utf-8",errors="surrogateescape") for x in raw.split(b"\0") if x]
def scan_directory(root,allowlist_repo=None,scope="directory"):
    out=[]; allow=_load_allowlist(allowlist_repo or root)
    for p in sorted(root.rglob("*")):
        if p.is_symlink(): out.append(f"{scope}: symlink/uninspectable path: {p.relative_to(root).as_posix()}"); continue
        if not p.is_file(): continue
        rel=p.relative_to(root).as_posix()
        try: data=p.read_bytes()
        except OSError: out.append(f"{scope}: unreadable file: {rel}"); continue
        out.extend(_scan_bytes(data,rel,scope,allow))
    return sorted(set(out))
def scan_current_tree(repo=ROOT):
    out=[]; allow=_load_allowlist(repo)
    for rel in _tracked(repo):
        try: data=(repo/rel).read_bytes()
        except OSError: out.append(f"current-tree: tracked file unreadable: {rel}"); continue
        out.extend(_scan_bytes(data,rel,"current-tree",allow))
    return sorted(set(out))
def _is_shallow(repo): return run_git(repo,"rev-parse","--is-shallow-repository").stdout.strip().casefold()=="true"
def _history_objects(repo):
    seen=set()
    for line in run_git(repo,"rev-list","--objects","--all").stdout.splitlines():
        parts=line.split(" ",1)
        if len(parts)!=2: continue
        sha,path=parts
        if (sha,path) in seen: continue
        seen.add((sha,path))
        try: typ=run_git(repo,"cat-file","-t",sha).stdout.strip()
        except subprocess.CalledProcessError: continue
        if typ=="blob": yield sha,path
def _commit_messages(repo):
    out=[]; raw=run_git(repo,"log","--all","--format=%H%x00%B%x00",text=False).stdout; parts=raw.split(b"\0")
    for i in range(0,len(parts)-1,2):
        sha=parts[i].decode("ascii",errors="ignore").strip()
        if sha: out.extend(scan_text(parts[i+1].decode("utf-8",errors="replace"),"<commit-message>",f"history-commit:{sha[:12]}"))
    return out
def scan_history(repo=ROOT):
    if _is_shallow(repo): return ["history: repository checkout is shallow; full-history scan is not proven"]
    out=_commit_messages(repo); allow=_load_allowlist(repo)
    for sha,rel in _history_objects(repo):
        try: blob=run_git(repo,"cat-file","blob",sha,text=False).stdout
        except subprocess.CalledProcessError: out.append(f"history-blob:{sha[:12]}: Git blob unreadable: {rel}"); continue
        out.extend(_scan_bytes(blob,rel,f"history-blob:{sha[:12]}",allow))
    return sorted(set(out))
def main(argv=None):
    p=argparse.ArgumentParser(); p.add_argument("--mode",choices=("current","history","all"),default="all"); a=p.parse_args(argv); out=[]
    if a.mode in {"current","all"}: out.extend(scan_current_tree(ROOT))
    if a.mode in {"history","all"}: out.extend(scan_history(ROOT))
    out=sorted(set(out))
    if out:
        print("SECRET_SCAN_FAIL")
        for item in out: print("-",item)
        return 1
    print("SECRET_SCAN_PASS"); return 0
if __name__=="__main__": raise SystemExit(main())
