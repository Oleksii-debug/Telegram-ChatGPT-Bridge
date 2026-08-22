# -*- coding: utf-8 -*-
"""Acceptance planning, typed public evidence and Telegram-auth gate helpers."""
from __future__ import annotations
import json, re
from typing import Any
from ops import evidence_privacy as privacy

PLAN_STATUSES = {"IMPLEMENTED_TEST", "READY_FOR_REAL_SOURCE", "EXTERNALLY_BLOCKED", "NOT_IMPLEMENTED"}
RESULT_STATUSES = {"PASS", "FAIL", "BLOCKED"}
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
AUTH_NOT_YET_REQUIRED = "USER_TELEGRAM_AUTH_NOT_YET_REQUIRED"
AUTH_REQUIRED = "USER_TELEGRAM_AUTH_REQUIRED"

# Exact 67 Drive criteria. Planning state is never product PASS.
_ROWS = [
("A1","Python 3.11 compile/import checks pass.","READY_FOR_REAL_SOURCE"),("A2","WSGI application imports successfully.","READY_FOR_REAL_SOURCE"),("A3","Health endpoint responds within timeout.","READY_FOR_REAL_SOURCE"),("A4","Invalid route does not leak stack traces/secrets.","READY_FOR_REAL_SOURCE"),("A5","Restart preserves private session/config.","READY_FOR_REAL_SOURCE"),
("B1","Protected endpoints reject missing bearer/auth.","READY_FOR_REAL_SOURCE"),("B2","Wrong token cannot retrieve Telegram content.","READY_FOR_REAL_SOURCE"),("B3","Logs do not contain private material.","READY_FOR_REAL_SOURCE"),("B4","Repository/history/PR/Actions artifacts contain no secrets.","IMPLEMENTED_TEST"),("B5","Path traversal attempts are rejected.","READY_FOR_REAL_SOURCE"),("B6","File IDs cannot read arbitrary server files.","READY_FOR_REAL_SOURCE"),("B7","Malformed input returns controlled errors.","READY_FOR_REAL_SOURCE"),("B8","Rate limits prevent obvious abuse.","READY_FOR_REAL_SOURCE"),
("C1","One-time setup is keyboard/NVDA accessible.","READY_FOR_REAL_SOURCE"),("C2","Setup route is protected/rotated.","READY_FOR_REAL_SOURCE"),("C3","Code request/auth errors handled safely.","READY_FOR_REAL_SOURCE"),("C4","2FA works when required.","READY_FOR_REAL_SOURCE"),("C5","Restart preserves session.","READY_FOR_REAL_SOURCE"),("C6","FloodWait/RPC failures safe.","READY_FOR_REAL_SOURCE"),
("D1","List dialogs works.","READY_FOR_REAL_SOURCE"),("D2","History ordering/pagination correct.","READY_FOR_REAL_SOURCE"),("D3","Search works.","READY_FOR_REAL_SOURCE"),("D4","Filters correct.","READY_FOR_REAL_SOURCE"),("D5","Unicode/Cyrillic intact.","READY_FOR_REAL_SOURCE"),("D6","Empty/no-result controlled.","READY_FOR_REAL_SOURCE"),
("E1","Media metadata listing works.","READY_FOR_REAL_SOURCE"),("E2","Single download validates expected file.","READY_FOR_REAL_SOURCE"),("E3","Bulk download filters/deduplicates.","READY_FOR_REAL_SOURCE"),("E4","ZIP valid.","READY_FOR_REAL_SOURCE"),("E5","Interrupted download recoverable.","READY_FOR_REAL_SOURCE"),("E6","Private files not public.","READY_FOR_REAL_SOURCE"),
("F1","Send preview.","READY_FOR_REAL_SOURCE"),("F2","Reply preview and target.","READY_FOR_REAL_SOURCE"),("F3","Forward preview.","READY_FOR_REAL_SOURCE"),("F4","Send-files preview.","READY_FOR_REAL_SOURCE"),("F5","Commit uses single-use preview.","READY_FOR_REAL_SOURCE"),("F6","Repeated commit no duplicate.","READY_FOR_REAL_SOURCE"),("F7","Expired/used/invalid preview safe.","READY_FOR_REAL_SOURCE"),("F8","Audit metadata body-free.","READY_FOR_REAL_SOURCE"),
("G1","Idempotency retry correct.","READY_FOR_REAL_SOURCE"),("G2","Duplicate protection survives restart/retry.","READY_FOR_REAL_SOURCE"),("G3","Timeouts explicit.","READY_FOR_REAL_SOURCE"),("G4","Errors preserve state.","READY_FOR_REAL_SOURCE"),("G5","Jobs resumable/retryable.","READY_FOR_REAL_SOURCE"),
("H1","OpenAPI matches deployed endpoints.","READY_FOR_REAL_SOURCE"),("H2","Read-only Action E2E.","EXTERNALLY_BLOCKED"),("H3","Unauthorized Action no leak.","READY_FOR_REAL_SOURCE"),("H4","Writes preserve preview/commit.","READY_FOR_REAL_SOURCE"),("H5","Structured Action errors.","READY_FOR_REAL_SOURCE"),
("I1","Setup fully keyboard operable.","READY_FOR_REAL_SOURCE"),("I2","Inputs labeled.","READY_FOR_REAL_SOURCE"),("I3","Buttons named.","READY_FOR_REAL_SOURCE"),("I4","Logical Tab order.","READY_FOR_REAL_SOURCE"),("I5","Heading structure meaningful.","READY_FOR_REAL_SOURCE"),("I6","NVDA-readable status/errors.","READY_FOR_REAL_SOURCE"),("I7","No mouse-only control.","READY_FOR_REAL_SOURCE"),
("J1","Deployed SHA known.","EXTERNALLY_BLOCKED"),("J2","Backup before change.","IMPLEMENTED_TEST"),("J3","Runtime secrets/session preserved.","IMPLEMENTED_TEST"),("J4","Post-deploy health/smoke.","EXTERNALLY_BLOCKED"),("J5","Rollback works.","IMPLEMENTED_TEST"),("J6","Main/production traceable.","EXTERNALLY_BLOCKED"),
("K1","List chats final scenario.","EXTERNALLY_BLOCKED"),("K2","Recent person messages final scenario.","EXTERNALLY_BLOCKED"),("K3","Files package final scenario.","EXTERNALLY_BLOCKED"),("K4","Preview reply no send before commit.","EXTERNALLY_BLOCKED"),("K5","Explicit one-send final scenario.","EXTERNALLY_BLOCKED")]
ACCEPTANCE_MATRIX=[{"criterion":c,"description":d,"plan_status":s} for c,d,s in _ROWS]
CRITERIA={i["criterion"]:i for i in ACCEPTANCE_MATRIX}

COMMON_FACT_KEYS={"success","count","duration_ms","timeout_ms","retry_count","attempt","return_code","http_status","status_code","state","reason_code","reason_codes","checks","contract_status","error_type","error_present"}
GROUP_FACT_KEYS={
"A":{"observed_sha","restart_safe","state_preserved"},
"B":{"authorized","findings_count","tree_scan_passed","history_scan_passed","artifact_count","rate_limit_remaining","retry_after_seconds","window_seconds","file_count","scan_scope"},
"C":{"auth_state","state_preserved","restart_safe","recoverable"},"D":{"result_count","page_count","identifier_hashes"},
"E":{"file_count","file_hashes","file_sha256","deduplicated","recoverable","private_serving_enforced","media_kind"},
"F":{"preview_only","commit_single_use","audit_recorded","operation_kind","payload_sha256","identifier_sha256","operation_sha256","idempotency_sha256","preview_state","commit_state","deduplicated"},
"G":{"state_preserved","restart_safe","recoverable","job_state","job_checkpoint","deduplicated","idempotency_sha256"},
"H":{"schema_valid","authorized","preview_only","commit_single_use","operation_kind"},
"I":{"keyboard_operable","labels_present","accessible_names_present","heading_order_valid","tab_order_valid","mouse_only_absent"},
"J":{"backup_created","backup_sha256","state_preserved","persistent_state_preserved","persistent_entries_count","previous_sha","candidate_sha","deployed_sha","observed_sha","rollback_state","quiesced","resumed","manifest_sha256"},
"K":{"result_count","file_count","preview_only","commit_single_use","operation_kind","identifier_sha256","success"}}
CRITERION_FACT_KEYS={c:COMMON_FACT_KEYS|GROUP_FACT_KEYS[c[0]] for c in CRITERIA}
RESULT_KEYS={"schema_version","criterion","code_sha","environment_class","result","evidence_ref","facts"}


def validate_matrix()->None:
    expected=set("ABCDEFGHIJK"); seen=set()
    for item in ACCEPTANCE_MATRIX:
        c=item["criterion"]
        if c in seen: raise ValueError("duplicate criterion")
        seen.add(c)
        if c[0] not in expected or not c[1:].isdigit(): raise ValueError("invalid criterion id")
        if item["plan_status"] not in PLAN_STATUSES: raise ValueError("invalid planning status")
        if not item["description"].strip(): raise ValueError("missing criterion description")
    if {i["criterion"][0] for i in ACCEPTANCE_MATRIX}!=expected: raise ValueError("A-K groups incomplete")


def validate_result_payload(payload:Any)->dict[str,Any]:
    if not isinstance(payload,dict) or set(payload)!=RESULT_KEYS: raise ValueError("acceptance result schema mismatch")
    if payload.get("schema_version")!=2: raise ValueError("acceptance result schema version unsupported")
    criterion=payload.get("criterion")
    if criterion not in CRITERIA: raise ValueError("unknown acceptance criterion")
    sha=payload.get("code_sha")
    if not isinstance(sha,str) or not SHA_RE.fullmatch(sha): raise ValueError("exact 40-character code SHA required")
    payload["environment_class"]=privacy.validate_environment_class(payload.get("environment_class"))
    if payload.get("result") not in RESULT_STATUSES: raise ValueError("invalid result status")
    payload["evidence_ref"]=privacy.validate_evidence_ref(payload.get("evidence_ref"))
    payload["facts"]=privacy.validate_facts(payload.get("facts"),allowed_keys=CRITERION_FACT_KEYS[criterion])
    privacy.validate_aggregate_payload(payload)
    return payload


def build_result(*,criterion:str,code_sha:str,environment_class:str,result:str,evidence_ref:dict[str,Any],facts:dict[str,Any]|None=None)->dict[str,Any]:
    return validate_result_payload({"schema_version":2,"criterion":criterion,"code_sha":code_sha,"environment_class":environment_class,"result":result,"evidence_ref":evidence_ref,"facts":facts or {}})


def serialize_result(payload:dict[str,Any])->str:
    # Deep JSON-safe copy prevents alias/shared-object mutation from bypassing revalidation.
    try: copied=json.loads(json.dumps(payload,ensure_ascii=False))
    except (TypeError,ValueError) as exc: raise ValueError("unsafe prebuilt acceptance result") from exc
    validated=validate_result_payload(copied)
    return json.dumps(validated,ensure_ascii=False,sort_keys=True,separators=(",",":"))


def evaluate_telegram_auth_gate(*,sanitized_application_source_ready:bool,passenger_runtime_verified:bool,server_setup_ready:bool,setup_session_is_first_human_blocker:bool,synthetic_only:bool=False)->dict[str,Any]:
    inputs=(sanitized_application_source_ready,passenger_runtime_verified,server_setup_ready,setup_session_is_first_human_blocker,synthetic_only)
    if any(not isinstance(x,bool) for x in inputs): raise ValueError("Telegram auth gate inputs must be booleans")
    reasons=[]
    if synthetic_only: reasons.append("SYNTHETIC_TEST_ONLY")
    if not sanitized_application_source_ready: reasons.append("SANITIZED_SOURCE_PENDING")
    if not passenger_runtime_verified: reasons.append("PASSENGER_RUNTIME_PENDING")
    if not server_setup_ready: reasons.append("SERVER_SETUP_NOT_READY")
    if not setup_session_is_first_human_blocker: reasons.append("HUMAN_INPUT_NOT_FIRST_BLOCKER")
    return {"state":AUTH_NOT_YET_REQUIRED,"reason_codes":reasons} if reasons else {"state":AUTH_REQUIRED,"reason_codes":["SERVER_SETUP_FIRST_HUMAN_BLOCKER"]}


def current_planning_auth_gate()->dict[str,Any]:
    return evaluate_telegram_auth_gate(sanitized_application_source_ready=False,passenger_runtime_verified=False,server_setup_ready=False,setup_session_is_first_human_blocker=False,synthetic_only=False)

validate_matrix()