# -*- coding: utf-8 -*-
"""Reusable deterministic synthetic contracts; never product PASS."""
from __future__ import annotations
import hashlib, io, json, math, threading, zipfile
from html.parser import HTMLParser
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any, Callable, Iterable
from ops.acceptance_harness import CRITERIA

class ContractError(RuntimeError): pass

def _sha256_text(value:str)->str: return hashlib.sha256(value.encode("utf-8")).hexdigest()
def _validate_sha256(value:str,label:str)->str:
    if not isinstance(value,str) or len(value)!=64 or any(c not in "0123456789abcdef" for c in value): raise ContractError(f"{label} must be sha256")
    return value

def safe_relative_path(value:str)->str:
    if not isinstance(value,str) or not value or "\\" in value: raise ContractError("unsafe relative path")
    p=PurePosixPath(value)
    if p.is_absolute() or ".." in p.parts or any(x in {"","."} for x in p.parts): raise ContractError("unsafe relative path")
    return p.as_posix()
def authorization_outcome(*,auth_present:bool,auth_matches:bool)->str:
    return "MISSING_AUTH" if not auth_present else ("WRONG_AUTH" if not auth_matches else "AUTHORIZED")

@dataclass(frozen=True)
class RateLimitDecision:
    allowed: bool; remaining: int; retry_after_seconds: int; window_seconds: int; limit: int
    def __iter__(self):
        yield self.allowed; yield self.remaining
    def __eq__(self, other):
        if isinstance(other, tuple) and len(other)==2: return (self.allowed,self.remaining)==other
        if isinstance(other, RateLimitDecision): return (self.allowed,self.remaining,self.retry_after_seconds,self.window_seconds,self.limit)==(other.allowed,other.remaining,other.retry_after_seconds,other.window_seconds,other.limit)
        return NotImplemented
    def public_metadata(self)->dict[str,int|bool]:
        return {"allowed":self.allowed,"remaining":self.remaining,"retry_after_seconds":self.retry_after_seconds,"window_seconds":self.window_seconds,"limit":self.limit}

class FixedWindowRateLimiter:
    """Thread-safe single-process fixed-window synthetic model.

    It is intentionally not claimed process-safe. B8 therefore remains
    REAL_SOURCE_REQUIRED until the real app implements shared/multi-process state.
    """
    def __init__(self,limit:int,window_seconds:int=60,*,clock:Callable[[],float]|None=None,max_actors:int=10000):
        if isinstance(limit,bool) or not isinstance(limit,int) or limit<=0: raise ValueError("positive integer rate limit required")
        if isinstance(window_seconds,bool) or not isinstance(window_seconds,int) or window_seconds<=0 or window_seconds>86400: raise ValueError("positive bounded window required")
        if max_actors<=0: raise ValueError("positive actor bound required")
        import time
        self.limit=limit; self.window_seconds=window_seconds; self.clock=clock or time.monotonic; self.max_actors=max_actors
        self._counts:dict[str,tuple[int,int]]={}; self._last_now:float|None=None; self._lock=threading.Lock()
    def _actor(self,actor_id:str)->str:
        if not isinstance(actor_id,str) or not (1<=len(actor_id)<=256) or any(ord(ch)<32 or ord(ch)==127 for ch in actor_id): raise ContractError("invalid actor identifier")
        return actor_id if len(actor_id)==64 and all(ch in "0123456789abcdef" for ch in actor_id) else _sha256_text(actor_id)
    def _window(self,now:float)->int:
        if not isinstance(now,(int,float)) or isinstance(now,bool) or not math.isfinite(float(now)) or now<0: raise ContractError("invalid clock value")
        if self._last_now is not None and now<self._last_now: raise ContractError("clock moved backward")
        self._last_now=float(now); return int(float(now)//self.window_seconds)
    def _prune(self,current_window:int)->None:
        stale=[k for k,(w,_) in self._counts.items() if w<current_window]
        for k in stale: self._counts.pop(k,None)
    def consume(self,actor_hash:str)->RateLimitDecision:
        actor=self._actor(actor_hash)
        with self._lock:
            now=float(self.clock()); window=self._window(now); self._prune(window)
            if actor not in self._counts and len(self._counts)>=self.max_actors: raise ContractError("rate limiter actor capacity reached")
            stored_window,count=self._counts.get(actor,(window,0))
            if stored_window!=window: stored_window,count=window,0
            window_end=(window+1)*self.window_seconds
            retry=max(0,int(math.ceil(window_end-now)))
            if count>=self.limit: return RateLimitDecision(False,0,retry,self.window_seconds,self.limit)
            count+=1; self._counts[actor]=(window,count)
            return RateLimitDecision(True,self.limit-count,0 if count<self.limit else retry,self.window_seconds,self.limit)
    @property
    def tracked_actors(self)->int: return len(self._counts)

class FakeTelegramAuthFlow:
    def request_code(self,*,flood_wait:bool=False,rpc_failure:bool=False)->str:
        return "FLOOD_WAIT" if flood_wait else ("RPC_ERROR" if rpc_failure else "CODE_REQUESTED")
    def sign_in(self,*,code_valid:bool,requires_2fa:bool=False,second_factor_valid:bool=True,flood_wait:bool=False,rpc_failure:bool=False)->str:
        if flood_wait:return "FLOOD_WAIT"
        if rpc_failure:return "RPC_ERROR"
        if not code_valid:return "INVALID_CODE"
        if requires_2fa and not second_factor_valid:return "INVALID_2FA"
        return "AUTHORIZED"

@dataclass(frozen=True)
class SyntheticMessage: message_id:int; dialog_id:int; sender_id:int; text:str; timestamp:int
class SyntheticMessageStore:
    def __init__(self,messages:Iterable[SyntheticMessage]): self.messages=sorted(list(messages),key=lambda x:(x.timestamp,x.message_id))
    def list_dialogs(self)->list[int]: return sorted({x.dialog_id for x in self.messages})
    def history(self,dialog_id:int,*,offset:int=0,limit:int=50)->list[SyntheticMessage]:
        if offset<0 or limit<=0 or limit>100: raise ContractError("invalid pagination")
        rows=[x for x in self.messages if x.dialog_id==dialog_id]; return rows[offset:offset+limit]
    def search(self,*,dialog_id:int|None=None,sender_id:int|None=None,text:str|None=None,date_from:int|None=None,date_to:int|None=None)->list[SyntheticMessage]:
        rows=list(self.messages)
        if dialog_id is not None: rows=[x for x in rows if x.dialog_id==dialog_id]
        if sender_id is not None: rows=[x for x in rows if x.sender_id==sender_id]
        if text is not None: q=text.casefold(); rows=[x for x in rows if q in x.text.casefold()]
        if date_from is not None: rows=[x for x in rows if x.timestamp>=date_from]
        if date_to is not None: rows=[x for x in rows if x.timestamp<=date_to]
        return rows

@dataclass(frozen=True)
class SyntheticMedia:
    file_id:str; kind:str; content:bytes
    @property
    def sha256(self)->str:return hashlib.sha256(self.content).hexdigest()
class SyntheticDownloadJob:
    def __init__(self, items: Iterable[SyntheticMedia]):
        self.items = list(items)
        self.completed: dict[str, bytes] = {}
        self.failed = False
    def download_one(self, file_id: str, expected_sha256: str) -> bytes:
        match = next((item for item in self.items if item.file_id == file_id), None)
        if match is None: raise ContractError("file not found")
        if match.sha256 != expected_sha256: raise ContractError("file hash mismatch")
        self.completed.setdefault(file_id, match.content)
        return self.completed[file_id]
    def bulk(self, file_ids: Iterable[str]) -> dict[str, bytes]:
        requested = list(dict.fromkeys(file_ids)); result: dict[str, bytes] = {}
        for file_id in requested:
            match = next((item for item in self.items if item.file_id == file_id), None)
            if match is None: continue
            result[file_id] = self.download_one(file_id, match.sha256)
        return result
    def mark_interrupted(self) -> None:self.failed = True
    def resume(self) -> dict[str, bytes]:
        self.failed = False; return dict(self.completed)

def build_zip(files:dict[str,bytes])->bytes:
    b=io.BytesIO();seen=set()
    with zipfile.ZipFile(b,"w",compression=zipfile.ZIP_DEFLATED) as a:
        for name,content in sorted(files.items()):
            safe=safe_relative_path(name)
            if safe in seen: raise ContractError("duplicate archive entry")
            seen.add(safe);a.writestr(safe,content)
    payload=b.getvalue()
    with zipfile.ZipFile(io.BytesIO(payload),"r") as a:
        if sorted(a.namelist())!=sorted(seen) or a.testzip() is not None: raise ContractError("zip validation failed")
    return payload
def private_file_access(*,authorized:bool)->str:return "PRIVATE_FILE_ALLOWED" if authorized else "PRIVATE_FILE_DENIED"

@dataclass
class PreviewRecord:
    action:str; target_sha256:str; payload_sha256:str; expires_at:int; used:bool=False
    def fingerprint(self,preview_key:str)->str:
        return hashlib.sha256(f"{preview_key}|{self.action}|{self.target_sha256}|{self.payload_sha256}".encode()).hexdigest()
@dataclass
class IdempotencyEntry:
    fingerprint_sha256:str; state:str; result:str|None; reserved_at:int; committed_at:int|None=None

class PreviewCommitStore:
    """Synthetic durable-state model. Raw idempotency keys are never stored/exported."""
    SCHEMA_VERSION=2
    def __init__(self,*,retention_seconds:int=86400):
        if retention_seconds<300: raise ValueError("idempotency retention too short")
        self.retention_seconds=retention_seconds; self._counter=0; self._records:dict[str,PreviewRecord]={}; self._idempotency:dict[str,IdempotencyEntry]={}; self._retired:set[str]=set(); self.external_write_count=0
    def _idem_hash(self,key:str)->str:
        if not isinstance(key,str) or not (1<=len(key)<=256): raise ContractError("invalid idempotency key")
        return _sha256_text(key)
    def create_preview(self,*,action:str,target_sha256:str,payload_sha256:str,now:int,ttl_seconds:int=300)->str:
        if ttl_seconds<=0 or ttl_seconds>3600: raise ContractError("invalid preview TTL")
        _validate_sha256(target_sha256,"target");_validate_sha256(payload_sha256,"payload")
        if action not in {"SEND","REPLY","FORWARD","SEND_FILE"}: raise ContractError("unsupported preview action")
        self._counter+=1;opaque=_sha256_text(f"{self._counter}|{action}|{target_sha256}|{payload_sha256}|{now}")
        self._records[opaque]=PreviewRecord(action,target_sha256,payload_sha256,now+ttl_seconds);return opaque
    def begin_commit(self,preview_key:str,*,now:int,idempotency_key:str)->str:
        record=self._records.get(preview_key)
        if record is None:return "INVALID_PREVIEW"
        idem=self._idem_hash(idempotency_key);fp=record.fingerprint(preview_key)
        if idem in self._retired:return "IDEMPOTENCY_RETIRED"
        existing=self._idempotency.get(idem)
        if existing:
            if existing.fingerprint_sha256!=fp:return "IDEMPOTENCY_CONFLICT"
            if existing.state=="COMMITTED":return existing.result or "COMMITTED"
            return "RECONCILE_REQUIRED"
        if now>record.expires_at:return "EXPIRED_PREVIEW"
        if record.used:return "USED_PREVIEW"
        self._idempotency[idem]=IdempotencyEntry(fp,"RESERVED",None,now,None)
        return "READY_TO_WRITE"
    def record_external_result(self,preview_key:str,*,now:int,idempotency_key:str,result:str="COMMITTED")->str:
        record=self._records.get(preview_key)
        if record is None:return "INVALID_PREVIEW"
        idem=self._idem_hash(idempotency_key);fp=record.fingerprint(preview_key);entry=self._idempotency.get(idem)
        if entry is None or entry.fingerprint_sha256!=fp:return "IDEMPOTENCY_CONFLICT"
        if entry.state=="COMMITTED":return entry.result or "COMMITTED"
        if entry.state!="RESERVED":return "RECONCILE_REQUIRED"
        entry.state="COMMITTED";entry.result=result;entry.committed_at=now;record.used=True;self.external_write_count+=1;return result
    def commit(self,preview_key:str,*,now:int,idempotency_key:str)->str:
        decision=self.begin_commit(preview_key,now=now,idempotency_key=idempotency_key)
        if decision!="READY_TO_WRITE":return decision
        return self.record_external_result(preview_key,now=now,idempotency_key=idempotency_key)
    def prune(self,*,now:int)->None:
        for idem,entry in list(self._idempotency.items()):
            anchor=entry.committed_at if entry.committed_at is not None else entry.reserved_at
            if now-anchor>self.retention_seconds:
                self._retired.add(idem);self._idempotency.pop(idem,None)
        # Retired hashed keys intentionally remain tombstones: retention must not re-enable writes.
    def export_state(self)->dict[str,Any]:
        return {"schema_version":self.SCHEMA_VERSION,"counter":self._counter,"retention_seconds":self.retention_seconds,
            "records":{k:{"action":v.action,"target_sha256":v.target_sha256,"payload_sha256":v.payload_sha256,"expires_at":v.expires_at,"used":v.used} for k,v in self._records.items()},
            "idempotency":{k:{"fingerprint_sha256":v.fingerprint_sha256,"state":v.state,"result":v.result,"reserved_at":v.reserved_at,"committed_at":v.committed_at} for k,v in self._idempotency.items()},
            "retired":sorted(self._retired),"external_write_count":self.external_write_count}
    @classmethod
    def restore_state(cls,state:dict[str,Any])->"PreviewCommitStore":
        if not isinstance(state,dict) or state.get("schema_version")!=cls.SCHEMA_VERSION: raise ContractError("unsupported idempotency state")
        obj=cls(retention_seconds=int(state["retention_seconds"]));obj._counter=int(state["counter"]);obj.external_write_count=int(state.get("external_write_count",0))
        for k,v in state.get("records",{}).items():
            _validate_sha256(k,"preview key");obj._records[k]=PreviewRecord(v["action"],_validate_sha256(v["target_sha256"],"target"),_validate_sha256(v["payload_sha256"],"payload"),int(v["expires_at"]),bool(v["used"]))
        for k,v in state.get("idempotency",{}).items():
            _validate_sha256(k,"idempotency hash");obj._idempotency[k]=IdempotencyEntry(_validate_sha256(v["fingerprint_sha256"],"fingerprint"),v["state"],v.get("result"),int(v["reserved_at"]),None if v.get("committed_at") is None else int(v["committed_at"]))
        obj._retired={_validate_sha256(x,"retired idempotency hash") for x in state.get("retired",[])};return obj
    def audit_metadata(self,preview_key:str)->dict[str,Any]:
        r=self._records[preview_key];return {"operation_kind":r.action,"target_sha256":r.target_sha256,"payload_sha256":r.payload_sha256,"used":r.used,"operation_sha256":r.fingerprint(preview_key)}

class ResumableJob:
    def __init__(self,*,timeout_ms:int):
        if timeout_ms<=0:raise ValueError("timeout required")
        self.timeout_ms=timeout_ms;self.checkpoint=0;self.state="READY"
    def advance(self,checkpoint:int)->None:
        if checkpoint<self.checkpoint:raise ContractError("job checkpoint cannot move backward")
        self.checkpoint=checkpoint;self.state="RUNNING"
    def fail(self)->None:self.state="RETRYABLE"
    def resume(self)->int:
        if self.state not in {"RETRYABLE","RUNNING","READY"}:raise ContractError("job is not resumable")
        self.state="RUNNING";return self.checkpoint
    def complete(self)->None:self.state="COMPLETED"

# Keep OpenAPI/accessibility checks intentionally synthetic; DEV4/DEV5 own deeper implementation.
def validate_openapi_contract(schema:dict[str,Any])->list[str]:
    errors=[]
    if not isinstance(schema,dict) or not str(schema.get("openapi","")).startswith("3."):return ["OPENAPI_VERSION"]
    paths=schema.get("paths")
    if not isinstance(paths,dict) or not paths:return ["PATHS_MISSING"]
    if any("setup" in str(p).casefold() for p in paths):errors.append("PRIVATE_SETUP_ROUTE_EXPOSED")
    for _,item in paths.items():
        if not isinstance(item,dict):errors.append("INVALID_PATH_ITEM");continue
        for method,op in item.items():
            if method.lower() not in {"get","post","put","patch","delete"}:continue
            if not isinstance(op,dict):errors.append("INVALID_OPERATION");continue
            if op.get("x-protected") is True and not op.get("security"):errors.append("PROTECTED_WITHOUT_SECURITY")
            if op.get("x-write-operation") is True and op.get("x-preview-commit") is not True:errors.append("WRITE_WITHOUT_PREVIEW_COMMIT")
            if "responses" not in op:errors.append("RESPONSES_MISSING")
    return sorted(set(errors))

class _AccessibilityParser(HTMLParser):
    def __init__(self):
        super().__init__(); self.inputs=[]; self.label_fors=set(); self.buttons=[]; self.headings=[]; self.mouse_only=False; self._button_text=[]; self._in_button=False
    def handle_starttag(self,tag,attrs):
        data=dict(attrs)
        if tag in {"input","select","textarea"}: self.inputs.append(data)
        elif tag=="label" and data.get("for"): self.label_fors.add(str(data["for"]))
        elif tag=="button": self.buttons.append(data); self._button_text.append(""); self._in_button=True
        elif tag in {"h1","h2","h3","h4","h5","h6"}: self.headings.append(int(tag[1]))
        if "onclick" in data and not any(k in data for k in ("onkeydown","onkeyup","onkeypress")) and tag not in {"button","a","input"}: self.mouse_only=True
    def handle_data(self,data):
        if self._in_button and self._button_text: self._button_text[-1]+=data
    def handle_endtag(self,tag):
        if tag=="button": self._in_button=False

def analyze_accessibility(html:str)->dict[str,bool]:
    p=_AccessibilityParser();p.feed(html)
    labels=all(bool(x.get("aria-label")) or bool(x.get("id") and x.get("id") in p.label_fors) for x in p.inputs)
    names=all(bool(x.get("aria-label")) or bool(text.strip()) for x,text in zip(p.buttons,p._button_text))
    heading=True
    for prev,cur in zip(p.headings,p.headings[1:]):
        if cur-prev>1: heading=False;break
    return {"keyboard_operable":not p.mouse_only,"labels_present":labels,"accessible_names_present":names,"heading_order_valid":heading,"mouse_only_absent":not p.mouse_only}

SYNTHETIC_EXECUTABLE={"B1","B2","B5","B7","C3","C4","C6","D1","D2","D3","D4","D5","D6","E1","E2","E3","E4","E5","E6","F1","F2","F3","F4","F5","F6","F7","F8","G1","G2","G3","G4","G5","H1","H3","H4","H5","I1","I2","I3","I4","I5","I6","I7","J2","J3","J5"}
LIVE_EXTERNAL={"H2","J1","J4","J6","K1","K2","K3","K4","K5"}
def coverage_report()->list[dict[str,str]]:
    out=[]
    for c in sorted(CRITERIA,key=lambda x:(x[0],int(x[1:]))):out.append({"criterion":c,"coverage":"SYNTHETIC_EXECUTABLE" if c in SYNTHETIC_EXECUTABLE else ("LIVE_EXTERNAL_REQUIRED" if c in LIVE_EXTERNAL else "REAL_SOURCE_REQUIRED")})
    return out
def final_scenario_definition(criterion:str)->dict[str,Any]:
    if criterion not in {"K1","K2","K3","K4","K5"}:raise ValueError("not a final user scenario")
    return {"criterion":criterion,"requires_live_telegram":True,"requires_audited_deployed_sha":True,"requires_explicit_write_approval":criterion=="K5","synthetic_pass_allowed":False}