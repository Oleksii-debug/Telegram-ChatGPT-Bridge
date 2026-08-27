# -*- coding: utf-8 -*-
"""Telegram Bridge repository secret guard."""
from __future__ import annotations
import argparse, hashlib, json, re, subprocess
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
MAX_BLOB_BYTES = 5_000_000
ALLOWLIST_FILE = ".secret-scan-allowlist.json"
FORBIDDEN_EXACT_NAMES = {".env","credentials.json","token.json","bootstrap.json","setup_state.json","connection_info.txt","private_config.json","OPENAPI_READY.json","BRIDGE_KEYS_SECRET.txt","TG_SESSION_STRING_SECRET.txt","HOSTIQ_CPANEL_PASSWORD.txt","SSH_PRIVATE_KEY","GITHUB_TOKEN.txt","GITHUB_PAT.txt","id_rsa","id_ed25519","id_ecdsa","id_dsa"}
FORBIDDEN_EXACT_NAMES_CASEFOLD = {x.casefold() for x in FORBIDDEN_EXACT_NAMES}
FORBIDDEN_SUFFIXES = {".session",".session-journal",".sqlite",".sqlite3",".db",".db-journal",".db-wal",".db-shm",".pem",".key",".p12",".pfx"}
ARCHIVE_SUFFIXES = (".zip",".7z",".rar",".tar",".tgz",".tbz",".tbz2",".txz",".tar.gz",".tar.bz2",".tar.xz",".gz",".bz2",".xz")
SECRET_VARIABLES = ("TG_API_ID","TG_API_HASH","TG_SESSION_STRING","TELEGRAM_2FA_PASSWORD","BRIDGE_TOKEN","BRIDGE_ROUTE_KEY","SETUP_ROUTE","SETUP_KEY","HOSTIQ_CPANEL_PASSWORD","CPANEL_PASSWORD","SSH_PRIVATE_KEY","GITHUB_TOKEN","GH_TOKEN","GITHUB_PAT","GOOGLE_DRIVE_CLIENT_SECRET","GOOGLE_DRIVE_REFRESH_TOKEN")
_SECRET_ALT = "|".join(re.escape(x) for x in SECRET_VARIABLES)
ASSIGNMENT_RE = re.compile(rf'''(?imx)^\s*(?:export\s+|set\s+)?["']?({_SECRET_ALT})["']?\s*[:=]\s*(?:"([^"]*)"|'([^']*)'|([^\s,#;\}}]+))\s*[,;\}}]?\s*(?:[#;].*)?$''')
STRUCTURED_ASSIGNMENT_RE = re.compile(rf'''(?imx)["']({_SECRET_ALT})["']\s*[:=]\s*(?:"([^"]*)"|'([^']*)'|([^\s,\}}\]]+))''')
PRIVATE_KEY_RE = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", re.IGNORECASE)
SETUP_ROUTE_RE = re.compile(r"(?<![A-Za-z0-9_])/(setup-[A-Za-z0-9_-]{16,})(?![A-Za-z0-9_])", re.IGNORECASE)
PLACEHOLDER_WORDS = {"placeholder","changeme","change-me","example","example-value","replace-me","replace_me","your-value","your_value"}
def run_git(repo: Path,*args: str,text: bool=True):
    return subprocess.run(["git",*args],cwd=repo,check=True,capture_output=True,text=text)
def is_forbidden_path(path: str)->bool:
    lower=Path(path).name.casefold()
    return lower.startswith('.env') or lower in FORBIDDEN_EXACT_NAMES_CASEFOLD or any(lower.endswith(s.casefold()) for s in FORBIDDEN_SUFFIXES)
def is_archive_path(path: str)->bool:
    lower=path.casefold(); return any(lower.endswith(s) for s in ARCHIVE_SUFFIXES)
def is_placeholder(value: str)->bool:
    value=(value or '').strip().strip('"').strip("'").strip(); lower=value.casefold()
    if not value:return True
    if (value.startswith('<') and value.endswith('>')) or '${{' in value or '${' in value:return True
    if lower in PLACEHOLDER_WORDS:return True
    return any(lower.startswith(w+'-') for w in PLACEHOLDER_WORDS)
def scan_text(text: str,path: str,scope: str)->list[str]:
    out=[]
    if PRIVATE_KEY_RE.search(text): out.append(f"{scope}: private key marker in {path}")
    if SETUP_ROUTE_RE.search(text): out.append(f"{scope}: concrete setup route in {path}")
    for pattern in (ASSIGNMENT_RE, STRUCTURED_ASSIGNMENT_RE):
        for m in pattern.finditer(text):
            value=next((g for g in m.groups()[1:] if g is not None),'')
            if not is_placeholder(value): out.append(f"{scope}: secret-like assignment {m.group(1).upper()} in {path}")
    return sorted(set(out))
def _tracked_paths(repo: Path)->list[str]:
    raw=run_git(repo,'ls-files','-z',text=False).stdout
    return [x.decode('utf-8',errors='surrogateescape') for x in raw.split(b'\0') if x]
def _sha256(data: bytes)->str:return hashlib.sha256(data).hexdigest()
def _load_allowlist(repo: Path)->dict[tuple[str,str],str]:
    p=repo/ALLOWLIST_FILE
    if not p.exists():return {}
    try:data=json.loads(p.read_text(encoding='utf-8'))
    except (OSError,json.JSONDecodeError):return {}
    result={}
    for item in data.get('entries',[]) if isinstance(data,dict) else []:
        if not isinstance(item,dict):continue
        rel=str(item.get('path','')).strip(); digest=str(item.get('sha256','')).strip().casefold(); reason=str(item.get('reason','')).strip()
        if rel and re.fullmatch(r'[0-9a-f]{64}',digest) and reason: result[(rel,digest)]=reason
    return result
def _allowed(path: str,data: bytes,allowlist)->bool:return (path,_sha256(data)) in allowlist
def _classify(path: str,data: bytes)->str|None:
    if len(data)>MAX_BLOB_BYTES:return 'oversized object'
    if is_archive_path(path):return 'archive/container object'
    if b'\x00' in data:return 'binary/uninspectable object'
    try:data.decode('utf-8')
    except UnicodeDecodeError:return 'binary/uninspectable object'
    return None
def _scan_bytes(data: bytes,path: str,scope: str,allowlist)->list[str]:
    if is_forbidden_path(path):return [f"{scope}: forbidden file {path}"]
    c=_classify(path,data)
    if c:
        if _allowed(path,data,allowlist):return []
        return [f"{scope}: {c} requires reviewed path+SHA256 allowlist: {path}"]
    return scan_text(data.decode('utf-8'),path,scope)
def scan_current_tree(repo: Path=ROOT)->list[str]:
    findings=[]; allowlist=_load_allowlist(repo)
    for rel in _tracked_paths(repo):
        try:data=(repo/rel).read_bytes()
        except OSError:
            findings.append(f"current-tree: tracked file unreadable: {rel}"); continue
        findings.extend(_scan_bytes(data,rel,'current-tree',allowlist))
    return sorted(set(findings))
def _is_shallow(repo: Path)->bool:return run_git(repo,'rev-parse','--is-shallow-repository').stdout.strip().casefold()=='true'
def _history_objects(repo: Path):
    seen=set()
    for line in run_git(repo,'rev-list','--objects','--all').stdout.splitlines():
        parts=line.split(' ',1)
        if len(parts)!=2:continue
        sha,path=parts; key=(sha,path)
        if key in seen:continue
        seen.add(key)
        try:t=run_git(repo,'cat-file','-t',sha).stdout.strip()
        except subprocess.CalledProcessError:continue
        if t=='blob':yield sha,path
def _scan_commit_messages(repo: Path)->list[str]:
    findings=[]; raw=run_git(repo,'log','--all','--format=%H%x00%B%x00',text=False).stdout; parts=raw.split(b'\0')
    for i in range(0,len(parts)-1,2):
        sha=parts[i].decode('ascii',errors='ignore').strip()
        if not sha:continue
        msg=parts[i+1].decode('utf-8',errors='replace')
        findings.extend(scan_text(msg,'<commit-message>',f"history-commit:{sha[:12]}"))
    return findings
def scan_history(repo: Path=ROOT)->list[str]:
    if _is_shallow(repo):return ['history: repository checkout is shallow; full-history scan is not proven']
    findings=_scan_commit_messages(repo); allowlist=_load_allowlist(repo)
    for sha,rel in _history_objects(repo):
        label=f"history-blob:{sha[:12]}"
        try:blob=run_git(repo,'cat-file','blob',sha,text=False).stdout
        except subprocess.CalledProcessError:
            findings.append(f"{label}: Git blob unreadable: {rel}"); continue
        findings.extend(_scan_bytes(blob,rel,label,allowlist))
    return sorted(set(findings))
def main(argv=None)->int:
    p=argparse.ArgumentParser(); p.add_argument('--mode',choices=('current','history','all'),default='all'); a=p.parse_args(argv); findings=[]
    if a.mode in {'current','all'}:findings.extend(scan_current_tree(ROOT))
    if a.mode in {'history','all'}:findings.extend(scan_history(ROOT))
    findings=sorted(set(findings))
    if findings:
        print('SECRET_SCAN_FAIL')
        for item in findings:print('-',item)
        return 1
    print('SECRET_SCAN_PASS'); return 0
if __name__=='__main__':raise SystemExit(main())
