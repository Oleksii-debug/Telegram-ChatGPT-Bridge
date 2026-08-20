# -*- coding: utf-8 -*-
"""Restart-safe deployment transaction hardening layered over the audited round-7 core."""
from __future__ import annotations
import hashlib, json, os, re, shutil, stat
from pathlib import Path, PurePosixPath
from types import ModuleType

CORE: ModuleType | None = None
LEGACY_PREPARE = LEGACY_VERIFY = None
TRANSACTION_JOURNAL = "DEPLOYMENT_TRANSACTION.json"
IMMUTABLE_PERMISSION_POLICY = "no-write-bits-v1"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
FULL_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
SAFE_REF_RE = re.compile(r"^(?:refs/heads/)?[A-Za-z0-9._/-]+$")
INCOMPLETE = {"READY_TO_COMMIT","APPROVAL_COMMITTED","QUIESCED","BACKED_UP","SWITCHED","VERIFIED"}
TERMINAL = {"PREAPPROVAL_ABORTED","PRELIVE_RECOVERED","DEPLOYED","ROLLED_BACK",
            "APPROVAL_COMMIT_FAILED","PRECOMMIT_FAILED","CRITICAL_PRELIVE_RECOVERY_FAILED",
            "CRITICAL_ROLLBACK_FAILED","CRITICAL_TRANSACTION_AMBIGUOUS"}

def C():
    if CORE is None: raise RuntimeError("deployment hardening is not installed")
    return CORE

def fail(msg):
    return C().SafetyError(msg)

def excluded(rel, items):
    p=PurePosixPath(rel)
    return any(p==PurePosixPath(x) or PurePosixPath(x) in p.parents for x in items)

def seal(root: Path, skip=()):
    uid=os.getuid() if hasattr(os,"getuid") else None
    for p in [root,*sorted(root.rglob("*"))]:
        rel="" if p==root else p.relative_to(root).as_posix()
        if rel and excluded(rel,set(skip)): continue
        try: st=p.lstat()
        except OSError as e: raise fail("immutable release path unreadable while sealing") from e
        if uid is not None and st.st_uid!=uid: raise fail("immutable release owner mismatch")
        if not p.is_symlink():
            try: os.chmod(p,stat.S_IMODE(st.st_mode)&~0o222)
            except OSError as e: raise fail("immutable release could not be sealed") from e

def validate_readonly(root: Path, skip=()):
    uid=os.getuid() if hasattr(os,"getuid") else None
    for p in [root,*sorted(root.rglob("*"))]:
        rel="" if p==root else p.relative_to(root).as_posix()
        if rel and excluded(rel,set(skip)): continue
        st=p.lstat()
        if uid is not None and st.st_uid!=uid: raise fail("immutable release owner mismatch")
        if not p.is_symlink() and stat.S_IMODE(st.st_mode)&0o222:
            raise fail("immutable release retains write permission")

def open_dirs(root: Path):
    uid=os.getuid() if hasattr(os,"getuid") else None
    for p in [root,*sorted(root.rglob("*"))]:
        if p.is_symlink() or not p.is_dir(): continue
        st=p.stat()
        if uid is not None and st.st_uid!=uid: raise fail("staging owner mismatch")
        os.chmod(p,stat.S_IMODE(st.st_mode)|stat.S_IWUSR)

def remove_tree(path: Path):
    if not path.exists() and not path.is_symlink(): return
    if path.is_symlink(): path.unlink(); return
    for p in sorted(path.rglob("*"),key=lambda x:len(x.parts),reverse=True):
        if p.is_symlink(): continue
        try:
            m=stat.S_IMODE(p.lstat().st_mode)
            os.chmod(p,m|stat.S_IWUSR|(stat.S_IXUSR if p.is_dir() else 0))
        except OSError: pass
    try:
        m=stat.S_IMODE(path.lstat().st_mode); os.chmod(path,m|stat.S_IWUSR|stat.S_IXUSR)
    except OSError: pass
    try: shutil.rmtree(path)
    except OSError as e: raise fail("controlled release cleanup failed") from e

def prepare_versioned_release(**kw):
    prepared,meta,_=LEGACY_PREPARE(**kw)
    updated=dict(meta); updated["immutable_permission_policy"]=IMMUTABLE_PERMISSION_POLICY
    digest=C().sha256_json(updated); mp=prepared/C().PREPARED_META
    try:
        C().write_json_atomic(mp,updated,mode=0o444)
        ident=C()._validated_python_identity(updated.get("approved_python_identity")) if updated.get("approved_python_identity") else None
        if C().sha256_json(C()._payload_manifest_without_meta(prepared,ident))!=updated.get("payload_manifest_sha256"):
            raise fail("prepared payload changed during immutable policy upgrade")
        seal(prepared); validate_readonly(prepared)
        if C().sha256_json(C()._payload_manifest_without_meta(prepared,ident))!=updated.get("payload_manifest_sha256"):
            raise fail("permission sealing changed prepared payload bytes")
        dst=prepared.parent/f"{updated['sha']}-{digest[:16]}"
        if dst!=prepared:
            if dst.exists() or dst.is_symlink(): raise fail("strict prepared release already exists")
            os.replace(prepared,dst); prepared=dst
        return prepared,updated,digest
    except Exception:
        if prepared.exists() or prepared.is_symlink(): remove_tree(prepared)
        raise

def verify_prepared_release(prepared: Path, expected: str):
    mp=prepared/C().PREPARED_META
    try: meta=json.loads(mp.read_text(encoding="utf-8"))
    except (OSError,json.JSONDecodeError): return LEGACY_VERIFY(prepared,expected)
    if meta.get("immutable_permission_policy")!=IMMUTABLE_PERMISSION_POLICY:
        return LEGACY_VERIFY(prepared,expected)
    if C().sha256_json(meta)!=expected: raise fail("prepared release manifest hash mismatch")
    ident=C()._validated_python_identity(meta.get("approved_python_identity")) if meta.get("approved_python_identity") else None
    validate_readonly(prepared)
    if C().sha256_json(C()._payload_manifest_without_meta(prepared,ident))!=meta.get("payload_manifest_sha256"):
        raise fail("prepared release payload changed after approval")
    return meta

def materialize(prepared: Path,releases: Path,sha: str,state: Path,entries: list[str]):
    final=releases/sha; stage=releases/(".finalize_"+sha)
    if final.exists() or final.is_symlink(): raise fail("target release already exists")
    if stage.exists() or stage.is_symlink(): raise fail("finalization staging already exists")
    try:
        shutil.copytree(prepared,stage,symlinks=True); open_dirs(stage)
        C().attach_persistent_state(stage,state,entries); C().validate_persistent_bindings(stage,state,entries)
        seal(stage,entries); validate_readonly(stage,entries); os.replace(stage,final); return final
    except Exception:
        if stage.exists() or stage.is_symlink(): remove_tree(stage)
        raise

def verify_final(final: Path,meta: dict,expected: str,entries: list[str]):
    try: fm=json.loads((final/C().PREPARED_META).read_text(encoding="utf-8"))
    except (OSError,json.JSONDecodeError) as e: raise fail("final release metadata invalid") from e
    if fm!=meta or C().sha256_json(fm)!=expected: raise fail("final release metadata mismatch")
    ident=C()._validated_python_identity(meta.get("approved_python_identity")) if meta.get("approved_python_identity") else None
    validate_readonly(final,entries)
    if C().sha256_json(C()._payload_manifest_without_meta(final,ident,entries))!=meta.get("payload_manifest_sha256"):
        raise fail("final immutable payload mismatch")

def jpath(control): return control/TRANSACTION_JOURNAL
def marker_digest(a): return hashlib.sha256((str(a["approval_id"])+"\0"+str(a["nonce"])).encode()).hexdigest()
def marker_exists(root,d):
    if not SHA256_RE.fullmatch(d): raise fail("approval marker digest invalid")
    p=root/(d+".consumed.json")
    if p.is_symlink(): raise fail("approval marker unsafe")
    return p.is_file()
def txn_id(repo,sha,d): return C().sha256_json({"repository":repo,"sha":sha,"approval_marker_sha256":d})
def new_journal(repo,ref,sha,previous,manifest,a):
    d=marker_digest(a); now=C().utc_now_iso()
    return {"schema_version":1,"transaction_id":txn_id(repo,sha,d),"repository":repo,"approved_ref":ref,
            "sha":sha,"previous_sha":previous,"release_manifest_sha256":manifest,
            "approval_id":str(a["approval_id"]),"approval_marker_sha256":d,
            "state":"READY_TO_COMMIT","created_at":now,"updated_at":now}
def valid_journal(j):
    if not isinstance(j,dict) or j.get("schema_version")!=1 or str(j.get("state")) not in INCOMPLETE|TERMINAL:
        raise fail("deployment transaction journal invalid")
    for k,rx in (("sha",FULL_SHA_RE),("previous_sha",FULL_SHA_RE),("release_manifest_sha256",SHA256_RE),
                 ("approval_marker_sha256",SHA256_RE),("transaction_id",SHA256_RE)):
        if not rx.fullmatch(str(j.get(k,""))): raise fail("deployment transaction journal provenance invalid")
    if not str(j.get("repository","")) or not SAFE_REF_RE.fullmatch(str(j.get("approved_ref",""))):
        raise fail("deployment transaction journal provenance invalid")
    return dict(j)
def load_journal(control):
    p=jpath(control)
    if not p.exists(): return None
    C().validate_private_control_file(p,control,"deployment transaction journal")
    try: return valid_journal(json.loads(p.read_text(encoding="utf-8")))
    except (OSError,json.JSONDecodeError) as e: raise fail("deployment transaction journal unreadable") from e
def write_journal(control,j):
    j=dict(j); j["updated_at"]=C().utc_now_iso(); valid_journal(j)
    C().write_json_atomic(jpath(control),j,mode=0o600); return j
def transition(control,j,state,**extra):
    if state not in INCOMPLETE|TERMINAL: raise fail("invalid deployment transaction transition")
    n=dict(j); n["state"]=state; n.update(extra); return write_journal(control,n)
def best_txn(control,j,state,**extra):
    n=dict(j); n["state"]=state; n.update(extra)
    try: return write_journal(control,n)
    except Exception: return n
def best_status(path,payload):
    try: C().write_json_atomic(path,payload)
    except Exception: pass

def quarantine(final,releases,j):
    if not final.exists() and not final.is_symlink(): return None
    if final!=releases/str(j["sha"]) or final.is_symlink() or not final.is_dir(): raise fail("unsafe release quarantine target")
    qroot=releases/".quarantine"
    if qroot.is_symlink(): raise fail("release quarantine root unsafe")
    qroot.mkdir(mode=0o700,exist_ok=True); os.chmod(qroot,0o700)
    base=f"{j['sha']}-{str(j['transaction_id'])[:16]}"; dst=qroot/base; i=0
    while dst.exists() or dst.is_symlink(): i+=1; dst=qroot/f"{base}-{i}"
    # Linux may require owner-write on the moved directory itself when changing its parent.
    # Open only the candidate root for the rename, then restore its exact mode at destination.
    source_mode=stat.S_IMODE(final.lstat().st_mode)
    try:
        os.chmod(final,source_mode|stat.S_IWUSR)
        os.replace(final,dst)
        os.chmod(dst,source_mode)
    except OSError as e:
        if final.exists() and not final.is_symlink():
            try: os.chmod(final,source_mode)
            except OSError: pass
        raise fail("release quarantine move failed") from e
    return dst

def recover_previous(previous_sha,restart,identity,unauth,auth,resume,prefix):
    C().run_private_hook(restart,f"{prefix} restart/reload",timeout=90); C().verify_running_release(identity,previous_sha)
    C().run_private_hook(unauth,f"{prefix} unauthenticated smoke",timeout=60)
    C().run_private_hook(auth,f"{prefix} authenticated smoke",timeout=60)
    C().run_private_hook(resume,f"{prefix} resume/unquiesce",timeout=90)

def reconcile(*,control_root,releases_root,persistent_state_root,runtime_entries,active_link,
              approval_consumption_root,restart_hook,identity_hook,unauth_hook,auth_hook,resume_hook,status_file):
    j=load_journal(control_root)
    if j is None or j["state"] in TERMINAL: return j
    sha,prev=str(j["sha"]),str(j["previous_sha"]); final=releases_root/sha; old=releases_root/prev
    if not active_link.is_symlink(): raise fail("active path unsafe during transaction recovery")
    try: active=active_link.resolve(strict=True); previous=old.resolve(strict=True)
    except OSError as e: raise fail("transaction recovery target missing") from e
    consumed=marker_exists(approval_consumption_root,str(j["approval_marker_sha256"]))
    if not consumed:
        if j["state"]!="READY_TO_COMMIT" or active!=previous:
            best_txn(control_root,j,"CRITICAL_TRANSACTION_AMBIGUOUS",reason_code="unconsumed_state_mismatch")
            raise fail("incomplete transaction ambiguous")
        q=quarantine(final,releases_root,j)
        return transition(control_root,j,"PREAPPROVAL_ABORTED",completed_at=C().utc_now_iso(),
                          quarantine_name=q.name if q else None)
    ft=None
    if final.exists() and not final.is_symlink():
        try: ft=final.resolve(strict=True)
        except OSError: pass
    if ft is not None and active==ft:
        try:
            fm=json.loads((final/C().PREPARED_META).read_text(encoding="utf-8"))
            if C().sha256_json(fm)!=str(j["release_manifest_sha256"]): raise fail("recovery final metadata mismatch")
            C().validate_persistent_bindings(final,persistent_state_root,runtime_entries)
            verify_final(final,fm,str(j["release_manifest_sha256"]),runtime_entries)
            C().run_private_hook(restart_hook,"transaction recovery restart/reload",timeout=90)
            C().verify_running_release(identity_hook,sha)
            C().run_private_hook(unauth_hook,"transaction recovery unauthenticated smoke",timeout=60)
            C().run_private_hook(auth_hook,"transaction recovery authenticated smoke",timeout=60)
            C().run_private_hook(resume_hook,"transaction recovery resume/unquiesce",timeout=90)
            j=transition(control_root,j,"VERIFIED",recovered_at=C().utc_now_iso())
            return transition(control_root,j,"DEPLOYED",completed_at=C().utc_now_iso(),recovery_mode="resumed_after_switch")
        except Exception as e:
            try:
                C().restore_link(active_link,previous)
                recover_previous(prev,restart_hook,identity_hook,unauth_hook,auth_hook,resume_hook,"transaction rollback")
                q=quarantine(final,releases_root,j)
                return best_txn(control_root,j,"ROLLED_BACK",completed_at=C().utc_now_iso(),
                                quarantine_name=q.name if q else None,failure_type=type(e).__name__)
            except Exception as r:
                best_txn(control_root,j,"CRITICAL_ROLLBACK_FAILED",rollback_failure_type=type(r).__name__)
                raise fail("interrupted switched deployment recovery failed") from r
    if active==previous:
        try:
            C().validate_persistent_bindings(previous,persistent_state_root,runtime_entries)
            recover_previous(prev,restart_hook,identity_hook,unauth_hook,auth_hook,resume_hook,"pre-switch transaction recovery")
            q=quarantine(final,releases_root,j)
            best_status(status_file,{"state":"PRELIVE_RECOVERED","sha":sha,"completed_at":C().utc_now_iso(),
                                     "approval_reuse_allowed":False})
            return transition(control_root,j,"PRELIVE_RECOVERED",completed_at=C().utc_now_iso(),
                              approval_reuse_allowed=False,quarantine_name=q.name if q else None)
        except Exception as e:
            best_txn(control_root,j,"CRITICAL_PRELIVE_RECOVERY_FAILED",recovery_failure_type=type(e).__name__)
            raise fail("interrupted pre-switch deployment recovery failed") from e
    best_txn(control_root,j,"CRITICAL_TRANSACTION_AMBIGUOUS",reason_code="active_target_mismatch")
    raise fail("incomplete transaction active target ambiguous")

def execute_prepared_release(*,repo:Path,prepared_release:Path,repository_id:str,approved_ref:str,ci_run_id:str,
                             audit_id:str,active_link:Path,releases_root:Path,backup_root:Path,persistent_state_root:Path,
                             runtime_manifest:Path,control_root:Path,approval_file:Path,approval_consumption_root:Path,
                             quiesce_hook:Path,resume_hook:Path,restart_hook:Path,identity_hook:Path,unauth_hook:Path,
                             auth_hook:Path,status_file:Path,public_root:Path|None=None)->int:
    c=C(); t=c.validate_deployment_topology(repo=repo,active_link=active_link,releases_root=releases_root,
        backup_root=backup_root,persistent_state_root=persistent_state_root,control_root=control_root,public_root=public_root)
    repo,releases_root,backup_root,persistent_state_root,control_root,active_link=(t[x] for x in
        ("repo","releases_root","backup_root","persistent_state_root","control_root","active_link"))
    c._validate_control_plane(control_root=control_root,runtime_manifest=runtime_manifest,approval_file=approval_file,
        approval_consumption_root=approval_consumption_root,quiesce_hook=quiesce_hook,resume_hook=resume_hook,
        restart_hook=restart_hook,identity_hook=identity_hook,unauth_hook=unauth_hook,auth_hook=auth_hook,status_file=status_file)
    entries=c.load_runtime_manifest(runtime_manifest)
    reconcile(control_root=control_root,releases_root=releases_root,persistent_state_root=persistent_state_root,
        runtime_entries=entries,active_link=active_link,approval_consumption_root=approval_consumption_root,
        restart_hook=restart_hook,identity_hook=identity_hook,unauth_hook=unauth_hook,auth_hook=auth_hook,
        resume_hook=resume_hook,status_file=status_file)
    try: raw=json.loads(approval_file.read_text(encoding="utf-8"))
    except Exception as e: raise fail("external approval invalid") from e
    expected=str(raw.get("release_manifest_sha256",""))
    if not SHA256_RE.fullmatch(expected): raise fail("approval manifest hash invalid")
    prepared=c.verify_prepared_release(prepared_release,expected); sha=str(prepared.get("sha",""))
    c.verify_approved_ref_policy(repo,sha,approved_ref)
    if prepared.get("repository")!=repository_id or prepared.get("approved_ref")!=approved_ref: raise fail("prepared provenance mismatch")
    if sorted(entries)!=prepared.get("runtime_entries"): raise fail("runtime binding manifest changed")
    a=c.load_external_approval(approval_file,expected_sha=sha,expected_repository=repository_id,expected_ref=approved_ref,
        expected_manifest_sha256=expected,expected_ci_run_id=ci_run_id,expected_audit_id=audit_id)
    md=marker_digest(a)
    if marker_exists(approval_consumption_root,md): raise fail("external approval was already consumed")
    if not active_link.is_symlink(): raise fail("active application path must be a symlink")
    previous_target=active_link.resolve(strict=True); previous_sha=c._active_release_sha(active_link)
    c._preflight_persistent_sources(persistent_state_root,entries); c.validate_persistent_bindings(previous_target,persistent_state_root,entries)
    final=c._materialize_final_release(prepared_release,releases_root,sha,persistent_state_root,entries)
    j=new_journal(repository_id,approved_ref,sha,previous_sha,expected,a)
    try:
        c.validate_persistent_bindings(final,persistent_state_root,entries); c._verify_final_materialized_release(final,prepared,expected,entries)
        j=write_journal(control_root,j)
    except Exception:
        try: quarantine(final,releases_root,j)
        finally: raise
    status={"sha":sha,"repository":repository_id,"approved_ref":approved_ref,"state":"READY_TO_COMMIT",
            "release_manifest_sha256":expected,"approval_id":str(a["approval_id"]),"ready_at":c.utc_now_iso()}
    try:
        c.write_json_atomic(status_file,status); c._verify_final_materialized_release(final,prepared,expected,entries)
    except Exception as e:
        q=quarantine(final,releases_root,j); best_status(status_file,{**status,"state":"PRECOMMIT_FAILED","completed_at":c.utc_now_iso()})
        best_txn(control_root,j,"PRECOMMIT_FAILED",quarantine_name=q.name if q else None)
        raise fail("pre-commit checkpoint failed") from e
    committed=False; previous=None; cb=sb=None
    try:
        c.consume_external_approval(a,approval_consumption_root); committed=True
        j=transition(control_root,j,"APPROVAL_COMMITTED",approval_committed_at=c.utc_now_iso())
        c.run_private_hook(quiesce_hook,"quiesce",timeout=90); j=transition(control_root,j,"QUIESCED",quiesced_at=c.utc_now_iso())
        status.update({"state":"STARTED","started_at":c.utc_now_iso()}); c.write_json_atomic(status_file,status)
        cb=c.backup_active(active_link,backup_root/"code",sha); sb=c.backup_persistent_state(persistent_state_root,backup_root/"state",sha)
        j=transition(control_root,j,"BACKED_UP",backed_up_at=c.utc_now_iso())
        # Read-only POSIX modes are defense in depth; same owning UID can chmod.
        # Exact approved bytes are therefore checked at the last possible pre-switch point.
        c._verify_final_materialized_release(final,prepared,expected,entries)
        previous=c.atomic_switch_link(active_link,final); j=transition(control_root,j,"SWITCHED",switched_at=c.utc_now_iso())
        c.run_private_hook(restart_hook,"restart/reload",timeout=90); c.verify_running_release(identity_hook,sha)
        c.run_private_hook(unauth_hook,"unauthenticated smoke",timeout=60); c.run_private_hook(auth_hook,"authenticated smoke",timeout=60)
        c.run_private_hook(resume_hook,"resume/unquiesce",timeout=90); j=transition(control_root,j,"VERIFIED",verified_at=c.utc_now_iso())
        rr=c.apply_retention([p for p in releases_root.iterdir() if p.is_dir() and not p.name.startswith(".")],
                             active=final,last_known_good=previous,keep_newest=5)
        rc=c.apply_backup_retention(backup_root/"code",last_known_good=cb,keep_newest=5)
        rs=c.apply_backup_retention(backup_root/"state",last_known_good=sb,keep_newest=5); c.cleanup_stale_staging(releases_root,older_than_seconds=86400)
        status.update({"state":"DEPLOYED","completed_at":c.utc_now_iso(),"release_root":str(final),"persistent_state_mode":"shared_external",
                       "retention_removed_release_count":len(rr),"retention_removed_code_backup_count":len(rc),"retention_removed_state_backup_count":len(rs)})
        c.write_json_atomic(status_file,status); transition(control_root,j,"DEPLOYED",completed_at=c.utc_now_iso()); return 0
    except Exception as e:
        if not committed:
            try: committed=marker_exists(approval_consumption_root,md)
            except Exception: committed=False
        if previous is not None:
            try:
                c.restore_link(active_link,previous); recover_previous(previous_sha,restart_hook,identity_hook,unauth_hook,auth_hook,resume_hook,"rollback")
                q=quarantine(final,releases_root,j); best_txn(control_root,j,"ROLLED_BACK",quarantine_name=q.name if q else None)
                best_status(status_file,{**status,"state":"ROLLED_BACK","completed_at":c.utc_now_iso()}); return 20
            except Exception as r:
                best_txn(control_root,j,"CRITICAL_ROLLBACK_FAILED",rollback_failure_type=type(r).__name__); return 70
        if committed:
            try:
                recover_previous(previous_sha,restart_hook,identity_hook,unauth_hook,auth_hook,resume_hook,"prelive recovery")
                q=quarantine(final,releases_root,j); best_txn(control_root,j,"PRELIVE_RECOVERED",approval_reuse_allowed=False,
                    quarantine_name=q.name if q else None,completed_at=c.utc_now_iso())
                best_status(status_file,{**status,"state":"PRELIVE_FAILED","completed_at":c.utc_now_iso(),"approval_reuse_allowed":False}); return 10
            except Exception as r:
                best_txn(control_root,j,"CRITICAL_PRELIVE_RECOVERY_FAILED",recovery_failure_type=type(r).__name__); return 71
        try: q=quarantine(final,releases_root,j)
        except Exception: q=None
        best_txn(control_root,j,"APPROVAL_COMMIT_FAILED",quarantine_name=q.name if q else None); raise

def install(core: ModuleType):
    global CORE,LEGACY_PREPARE,LEGACY_VERIFY
    CORE=core
    if not hasattr(core,"_round7_prepare_versioned_release"): core._round7_prepare_versioned_release=core.prepare_versioned_release
    if not hasattr(core,"_round7_verify_prepared_release"): core._round7_verify_prepared_release=core.verify_prepared_release
    LEGACY_PREPARE,LEGACY_VERIFY=core._round7_prepare_versioned_release,core._round7_verify_prepared_release
    core.TRANSACTION_JOURNAL=TRANSACTION_JOURNAL; core.IMMUTABLE_PERMISSION_POLICY=IMMUTABLE_PERMISSION_POLICY
    core._strict_seal_immutable_tree=seal; core._strict_validate_immutable_tree=validate_readonly; core._force_remove_tree=remove_tree
    core._approval_marker_digest=marker_digest; core._approval_marker_exists=marker_exists; core._load_transaction_journal=load_journal
    core._write_transaction_journal=write_journal; core._transition_transaction=transition; core._quarantine_release=quarantine
    core._reconcile_incomplete_transaction=reconcile
    core.prepare_versioned_release=prepare_versioned_release; core.verify_prepared_release=verify_prepared_release
    core._materialize_final_release=materialize; core._verify_final_materialized_release=verify_final
    core.execute_prepared_release=execute_prepared_release
    return core
