# -*- coding: utf-8 -*-
"""Fail-closed secret guard for the public Telegram Bridge repository."""
from __future__ import annotations
import argparse, hashlib, io, json, re, stat, subprocess, tarfile, zipfile
from pathlib import Path, PurePosixPath

if __package__:
    from .history_secret_adjudication import filter_exact_history_assignment_findings
else:
    from history_secret_adjudication import filter_exact_history_assignment_findings

ROOT=Path(__file__).resolve().parents[1]
ALLOWLIST_FILE='.secret-scan-allowlist.json'
MAX_TEXT_BYTES=50_000_000; MAX_ARCHIVE_DEPTH=3; MAX_ARCHIVE_MEMBERS=500; MAX_ARCHIVE_MEMBER_BYTES=25_000_000; MAX_ARCHIVE_TOTAL_BYTES=100_000_000
FORBIDDEN_EXACT_NAMES_CASEFOLD={x.casefold() for x in {'.env','credentials.json','token.json','bootstrap.json','setup_state.json','connection_info.txt','private_config.json','openapi_ready.json','bridge_keys_secret.txt','tg_session_string_secret.txt','hostiq_cpanel_password.txt','ssh_private_key','github_token.txt','github_pat.txt','cookies.txt','cookies.json','id_rsa','id_ed25519','id_ecdsa','id_dsa'}}
FORBIDDEN_SUFFIXES={'.session','.session-journal','.sqlite','.sqlite3','.db','.db-journal','.db-wal','.db-shm','.pem','.key','.p12','.pfx','.log','.cookie','.cookies'}
SUPPORTED_ARCHIVE_SUFFIXES=('.zip','.tar','.tgz','.tbz','.tbz2','.txz','.tar.gz','.tar.bz2','.tar.xz')
UNSUPPORTED_ARCHIVE_SUFFIXES=('.7z','.rar','.gz','.bz2','.xz')
PROJECT_SECRET_VARIABLES=('TG_API_ID','TG_API_HASH','TG_SESSION_STRING','TELEGRAM_2FA_PASSWORD','BRIDGE_TOKEN','BRIDGE_ROUTE_KEY','SETUP_ROUTE','SETUP_KEY','HOSTIQ_CPANEL_PASSWORD','CPANEL_PASSWORD','SSH_PRIVATE_KEY','GITHUB_TOKEN','GH_TOKEN','GITHUB_PAT','GOOGLE_DRIVE_CLIENT_SECRET','GOOGLE_DRIVE_REFRESH_TOKEN')
GENERIC_CREDENTIAL_ALIASES=('API_ID','API_HASH','API_KEY','SESSION','SESSION_STRING','STRING_SESSION','TELEGRAM_SESSION','TWO_FACTOR_PASSWORD','2FA_PASSWORD','PASSWORD','PASSWD','BEARER_TOKEN','ACCESS_TOKEN','REFRESH_TOKEN','CLIENT_SECRET')
SECRET_VARIABLES=PROJECT_SECRET_VARIABLES+GENERIC_CREDENTIAL_ALIASES
_SECRET_ALT='|'.join(re.escape(x) for x in SECRET_VARIABLES)
ASSIGNMENT_RE=re.compile(rf'(?im)^\s*(?:export\s+|set\s+)?[\"\']?({_SECRET_ALT})[\"\']?\s*[:=]\s*(?:\"([^\"]*)\"|\'([^\']*)\'|([^#;\r\n]+?))\s*(?:[#;].*)?$',re.IGNORECASE)
STRUCTURED_ASSIGNMENT_RE=re.compile(rf'(?im)[\"\']({_SECRET_ALT})[\"\']\s*[:=]\s*(?:\"([^\"]*)\"|\'([^\']*)\'|([^\s,\}}\]]+))',re.IGNORECASE)
PRIVATE_KEY_RE=re.compile(r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----',re.IGNORECASE)
SETUP_ROUTE_RE=re.compile(r'(?<![A-Za-z0-9_])/(setup-[A-Za-z0-9_-]{16,})(?![A-Za-z0-9_])',re.IGNORECASE)
ANGLE_PLACEHOLDER_RE=re.compile(r'^<[A-Z0-9_.:-]+>$',re.IGNORECASE); GH_SECRET_PLACEHOLDER_RE=re.compile(r'^\$\{\{\s*secrets\.[A-Z0-9_]+\s*\}\}$',re.IGNORECASE); ENV_PLACEHOLDER_RE=re.compile(r'^\$\{[A-Z_][A-Z0-9_]*\}$',re.IGNORECASE); DOLLAR_PLACEHOLDER_RE=re.compile(r'^\$[A-Z_][A-Z0-9_]*$',re.IGNORECASE)
SAFE_REFERENCE_RE=re.compile(r'^(?:os\.(?:getenv\([^\r\n]+\)|environ\[[^\r\n]+\])|env\([^\r\n]+\)|config\.get\([^\r\n]+\)|settings\.[A-Z0-9_]+)$',re.IGNORECASE)
PLACEHOLDER_WORDS={'placeholder','changeme','change-me','example','example-value','replace-me','replace_me','your-value','your_value'}
SEVEN_Z_SIGNATURE=bytes((0x37,0x7A,0xBC,0xAF,0x27,0x1C))
RAR_SIGNATURES=(bytes((0x52,0x61,0x72,0x21,0x1A,0x07,0x00)),bytes((0x52,0x61,0x72,0x21,0x1A,0x07,0x01,0x00)))
GZIP_SIGNATURE=bytes((0x1F,0x8B,0x08))
BZIP2_HEADER=bytes((0x42,0x5A,0x68)); BZIP2_BLOCK_MAGIC=bytes((0x31,0x41,0x59,0x26,0x53,0x59)); BZIP2_SIGNATURE=BZIP2_HEADER+bytes((0x39,))+BZIP2_BLOCK_MAGIC
XZ_SIGNATURE=bytes((0xFD,0x37,0x7A,0x58,0x5A,0x00))
UNSUPPORTED_SIGNATURES=(SEVEN_Z_SIGNATURE,*RAR_SIGNATURES,GZIP_SIGNATURE,XZ_SIGNATURE)

def run_git(repo:Path,*args:str,text:bool=True): return subprocess.run(['git',*args],cwd=repo,check=True,capture_output=True,text=text)
def _sha256(data:bytes)->str:return hashlib.sha256(data).hexdigest()
def _normalise_rel(path:str)->str:return str(PurePosixPath(path.replace('\\','/')))
def _unsafe(path:str)->bool:
    p=PurePosixPath(path.replace('\\','/')); return p.is_absolute() or '..' in p.parts
def is_forbidden_path(path:str)->bool:
    name=PurePosixPath(path.replace('\\','/')).name.casefold(); return name.startswith('.env') or name in FORBIDDEN_EXACT_NAMES_CASEFOLD or any(name.endswith(s.casefold()) for s in FORBIDDEN_SUFFIXES)
def _extension_archive_kind(path:str)->str|None:
    lower=path.casefold()
    if lower.endswith('.zip'):return 'zip'
    if any(lower.endswith(s) for s in SUPPORTED_ARCHIVE_SUFFIXES if s!='.zip'):return 'tar'
    if any(lower.endswith(s) for s in UNSUPPORTED_ARCHIVE_SUFFIXES):return 'unsupported'
    return None
def _probe_zip(data:bytes)->bool:
    try:
        if not zipfile.is_zipfile(io.BytesIO(data)):return False
        with zipfile.ZipFile(io.BytesIO(data)) as a:a.infolist()
        return True
    except (zipfile.BadZipFile,OSError,EOFError,ValueError):return False
def _probe_tar(data:bytes)->bool:
    try:
        with tarfile.open(fileobj=io.BytesIO(data),mode='r:*') as a:a.getmembers()
        return True
    except (tarfile.TarError,OSError,EOFError,ValueError):return False
def _contains_bzip2_stream_header(data:bytes)->bool:
    start=0
    while True:
        index=data.find(BZIP2_HEADER,start)
        if index<0:return False
        if index+10<=len(data) and data[index+3:index+4] in tuple(bytes((n,)) for n in range(0x31,0x3A)) and data[index+4:index+10]==BZIP2_BLOCK_MAGIC:return True
        start=index+1
def _contains_unsupported_signature(data:bytes)->bool:
    return any(data.find(sig)>=0 for sig in UNSUPPORTED_SIGNATURES) or _contains_bzip2_stream_header(data)
def _magic_archive_kind(data:bytes)->str|None:
    z=_probe_zip(data); t=_probe_tar(data)
    if z and t:return 'ambiguous'
    if z:return 'zip'
    if t:return 'tar'
    if _contains_unsupported_signature(data):return 'unsupported'
    return None
def _resolved_archive_kind(path:str,data:bytes)->tuple[str|None,str|None]:
    ext=_extension_archive_kind(path); magic=_magic_archive_kind(data)
    if magic=='ambiguous':return None,'ambiguous/polyglot archive/container'
    if ext=='unsupported':return None,'unsupported archive/container'
    if magic=='unsupported':return None,'unsupported compressed/archive signature'
    if ext is not None and magic is None:return None,'archive/container extension does not match inspectable content'
    if ext in {'zip','tar'} and magic in {'zip','tar'} and ext!=magic:return None,'archive/container extension-signature mismatch'
    if magic in {'zip','tar'}:return magic,None
    return None,None

def is_placeholder(value:str)->bool:
    value=(value or '').strip().strip('"').strip("'").strip()
    return (not value or value.casefold() in PLACEHOLDER_WORDS or bool(ANGLE_PLACEHOLDER_RE.fullmatch(value) or GH_SECRET_PLACEHOLDER_RE.fullmatch(value) or ENV_PLACEHOLDER_RE.fullmatch(value) or DOLLAR_PLACEHOLDER_RE.fullmatch(value)))
def is_safe_reference(value:str)->bool:return bool(SAFE_REFERENCE_RE.fullmatch((value or '').strip().strip('"').strip("'").strip()))
def _assignment_is_finding(name:str,value:str)->bool:
    if is_placeholder(value) or is_safe_reference(value):return False
    if name.upper() in PROJECT_SECRET_VARIABLES:return True
    s=value.strip()
    if s.casefold() in {'none','null','false','true'} or s in {'0','1','[]','{}'}:return False
    if name.upper()=='API_ID' and re.fullmatch(r'\d{5,15}',s):return True
    return len(s)>=6
def scan_text(text:str,path:str,scope:str)->list[str]:
    out=[]
    if PRIVATE_KEY_RE.search(text):out.append(f'{scope}: private key marker in {path}')
    if SETUP_ROUTE_RE.search(text):out.append(f'{scope}: concrete setup route in {path}')
    for pattern in (ASSIGNMENT_RE,STRUCTURED_ASSIGNMENT_RE):
        for m in pattern.finditer(text):
            value=next((g for g in m.groups()[1:] if g is not None),'')
            if _assignment_is_finding(m.group(1),value):out.append(f'{scope}: secret-like assignment {m.group(1).upper()} in {path}')
    return sorted(set(out))
def _load_allowlist(repo:Path)->dict[tuple[str,str],str]:
    path=repo/ALLOWLIST_FILE
    if not path.exists():return {}
    try:payload=json.loads(path.read_text(encoding='utf-8'))
    except (OSError,json.JSONDecodeError):return {}
    result={}
    for item in payload.get('entries',[]) if isinstance(payload,dict) else []:
        if not isinstance(item,dict):continue
        rel=_normalise_rel(str(item.get('path','')).strip()); digest=str(item.get('sha256','')).strip().casefold(); reason=str(item.get('reason','')).strip()
        if rel and not _unsafe(rel) and re.fullmatch(r'[0-9a-f]{64}',digest) and len(reason)>=12:result[(rel,digest)]=reason
    return result
def _zip_member_is_special(info:zipfile.ZipInfo)->bool:
    if info.is_dir() or info.create_system!=3:return False
    mode=(info.external_attr>>16)&0xFFFF; return stat.S_IFMT(mode) not in {0,stat.S_IFREG}
def _scan_archive(data:bytes,path:str,scope:str,allowlist,depth:int,kind:str)->list[str]:
    if depth>MAX_ARCHIVE_DEPTH:return [f'{scope}: archive nesting limit exceeded in {path}']
    findings=[]; members=[]; total=0
    try:
        if kind=='zip':
            with zipfile.ZipFile(io.BytesIO(data)) as a:
                infos=a.infolist()
                if len(infos)>MAX_ARCHIVE_MEMBERS:return [f'{scope}: archive member-count limit exceeded in {path}']
                for info in infos:
                    if info.is_dir():continue
                    rel=info.filename
                    if _zip_member_is_special(info):findings.append(f'{scope}: zip special member rejected in {path}!{rel}');continue
                    if _unsafe(rel):findings.append(f'{scope}: unsafe archive member path in {path}');continue
                    if info.file_size>MAX_ARCHIVE_MEMBER_BYTES:findings.append(f'{scope}: archive member too large in {path}!{rel}');continue
                    total+=info.file_size
                    if total>MAX_ARCHIVE_TOTAL_BYTES:findings.append(f'{scope}: archive expanded-size limit exceeded in {path}');break
                    members.append((rel,a.read(info)))
        elif kind=='tar':
            with tarfile.open(fileobj=io.BytesIO(data),mode='r:*') as a:
                infos=a.getmembers()
                if len(infos)>MAX_ARCHIVE_MEMBERS:return [f'{scope}: archive member-count limit exceeded in {path}']
                for info in infos:
                    if info.isdir():continue
                    if not info.isfile():findings.append(f'{scope}: tar special member rejected in {path}!{info.name}');continue
                    rel=info.name
                    if _unsafe(rel):findings.append(f'{scope}: unsafe archive member path in {path}');continue
                    if info.size>MAX_ARCHIVE_MEMBER_BYTES:findings.append(f'{scope}: archive member too large in {path}!{rel}');continue
                    total+=info.size
                    if total>MAX_ARCHIVE_TOTAL_BYTES:findings.append(f'{scope}: archive expanded-size limit exceeded in {path}');break
                    h=a.extractfile(info)
                    if h is None:findings.append(f'{scope}: archive member unreadable in {path}!{rel}');continue
                    members.append((rel,h.read()))
        else:return [f'{scope}: archive/container format not safely inspectable: {path}']
    except (zipfile.BadZipFile,tarfile.TarError,OSError,EOFError,RuntimeError,ValueError):return [f'{scope}: corrupt/uninspectable archive/container: {path}']
    for rel,blob in members:findings.extend(_scan_bytes(blob,rel,scope,allowlist,display=f'{path}!{rel}',depth=depth+1))
    return sorted(set(findings))
def _scan_bytes(data:bytes,path:str,scope:str,allowlist,display:str|None=None,depth:int=0)->list[str]:
    shown=display or path
    if is_forbidden_path(path):return [f'{scope}: forbidden file {shown}']
    raw=scan_text(data.decode('latin-1',errors='ignore'),shown,scope)
    if raw:return raw
    kind,error=_resolved_archive_kind(path,data)
    if error:return [f'{scope}: {error}: {shown}']
    if kind is not None:return _scan_archive(data,shown,scope,allowlist,depth,kind)
    try:text=data.decode('utf-8')
    except UnicodeDecodeError:
        if (_normalise_rel(path),_sha256(data)) in allowlist:return []
        return [f'{scope}: binary/uninspectable object requires reviewed path+SHA256 allowlist: {shown}']
    if len(data)>MAX_TEXT_BYTES:return [f'{scope}: text object exceeds safe inspection policy limit: {shown}']
    return scan_text(text,shown,scope)
def _tracked(repo:Path)->list[str]:
    raw=run_git(repo,'ls-files','-z',text=False).stdout; return [x.decode('utf-8',errors='surrogateescape') for x in raw.split(b'\0') if x]
def scan_directory(root:Path,allowlist_repo:Path|None=None,scope:str='directory')->list[str]:
    out=[]; allow=_load_allowlist(allowlist_repo or root)
    for path in sorted(root.rglob('*')):
        if path.is_symlink():out.append(f'{scope}: symlink/uninspectable path: {path.relative_to(root).as_posix()}');continue
        if not path.is_file():continue
        rel=path.relative_to(root).as_posix()
        try:data=path.read_bytes()
        except OSError:out.append(f'{scope}: unreadable file: {rel}');continue
        out.extend(_scan_bytes(data,rel,scope,allow))
    return sorted(set(out))
def scan_current_tree(repo:Path=ROOT)->list[str]:
    out=[]; allow=_load_allowlist(repo)
    for rel in _tracked(repo):
        try:data=(repo/rel).read_bytes()
        except OSError:out.append(f'current-tree: tracked file unreadable: {rel}');continue
        out.extend(_scan_bytes(data,rel,'current-tree',allow))
    return sorted(set(out))
def _is_shallow(repo:Path)->bool:return run_git(repo,'rev-parse','--is-shallow-repository').stdout.strip().casefold()=='true'
def _history_objects(repo:Path):
    seen=set()
    for line in run_git(repo,'rev-list','--objects','--all').stdout.splitlines():
        parts=line.split(' ',1)
        if len(parts)!=2:continue
        sha,path=parts
        if (sha,path) in seen:continue
        seen.add((sha,path))
        try:typ=run_git(repo,'cat-file','-t',sha).stdout.strip()
        except subprocess.CalledProcessError:continue
        if typ=='blob':yield sha,path
def _commit_messages(repo:Path)->list[str]:
    out=[]; raw=run_git(repo,'log','--all','--format=%H%x00%B%x00',text=False).stdout; parts=raw.split(b'\0')
    for i in range(0,len(parts)-1,2):
        sha=parts[i].decode('ascii',errors='ignore').strip()
        if sha:out.extend(scan_text(parts[i+1].decode('utf-8',errors='replace'),'<commit-message>',f'history-commit:{sha[:12]}'))
    return out
def scan_history(repo:Path=ROOT)->list[str]:
    if _is_shallow(repo):return ['history: repository checkout is shallow; full-history scan is not proven']
    out=_commit_messages(repo); allow=_load_allowlist(repo)
    for sha,rel in _history_objects(repo):
        try:blob=run_git(repo,'cat-file','blob',sha,text=False).stdout
        except subprocess.CalledProcessError:out.append(f'history-blob:{sha[:12]}: Git blob unreadable: {rel}');continue
        findings=_scan_bytes(blob,rel,f'history-blob:{sha}',allow)
        out.extend(filter_exact_history_assignment_findings(
            repo=repo,
            git_blob_sha=sha,
            rel_path=rel,
            blob=blob,
            findings=findings,
        ))
    return sorted(set(out))
def main(argv=None)->int:
    p=argparse.ArgumentParser(); p.add_argument('--mode',choices=('current','history','all'),default='all'); a=p.parse_args(argv); out=[]
    if a.mode in {'current','all'}:out.extend(scan_current_tree(ROOT))
    if a.mode in {'history','all'}:out.extend(scan_history(ROOT))
    out=sorted(set(out))
    if out:
        print('SECRET_SCAN_FAIL'); [print('-',x) for x in out]; return 1
    print('SECRET_SCAN_PASS'); return 0
if __name__=='__main__':raise SystemExit(main())
