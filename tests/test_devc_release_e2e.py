# -*- coding: utf-8 -*-
"""Deterministic packaged-candidate WSGI QA; no live external I/O."""
from __future__ import annotations
import io, json, tempfile, threading, unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from bridge.app import BridgeApplication, ReadAppConfig
from bridge.audit import AuditLog
from bridge.integrated_app import UnifiedBridgeApplication, validate_unified_registry
from bridge.models import DialogRecord, EntityRef, MediaRecord, MessageRecord, Page
from bridge.security import RateLimitDecision
from ops import openapi_registry
from ops.openapi_registry import OperationClass
from ops.telegram_write_adapter import DeterministicFakeTelegramClient, TelegramRuntimeConfig, TelegramWriteAdapter
from ops.write_endpoint_policy import FixedWindowEndpointLimiter

AUTH="devc-release-placeholder-auth-0001"; SIGNING="devc-release-placeholder-signing-0001"

class AllowRead:
    def check(self,_actor): return RateLimitDecision(True,remaining=999)

class Backend:
    def __init__(self):
        self.lock=threading.Lock(); self.download_count=0; self.bytes=b"devc-release-synthetic-media"; self.ref="tg_2_0123456789abcdefabcd"
        self.private_title="DEV_C_PRIVATE_CHAT_LABEL"; self.private_sender="DEV_C_PRIVATE_PERSON_LABEL"; self.private_body="DEV_C_PRIVATE_MESSAGE_BODY"
        media=MediaRecord("document",self.ref,"devc-private-file.bin","application/octet-stream",len(self.bytes))
        self.dialogs=(DialogRecord("2","group",self.private_title,None,1,False,"2026-08-23T07:00:00+00:00"),)
        self.messages=(MessageRecord(2,"2","2026-08-23T07:00:00+00:00",self.private_body,EntityRef("20","user",self.private_sender),media=(media,)),)
    def list_dialogs(self,**_): return Page(self.dialogs,None,1)
    def history(self,**_): return Page(self.messages,None,1)
    def search(self,**_): return Page(self.messages,None,1)
    def get_message(self,**_): return self.messages[0]
    def download_media(self,**kw):
        Path(kw["destination"]).write_bytes(self.bytes)
        with self.lock: self.download_count+=1
        return {"path":str(kw["destination"])}

def request(app,path,body=None,method="POST",auth=True):
    raw=json.dumps(body or {},ensure_ascii=False,separators=(",",":")).encode()
    env={"REQUEST_METHOD":method,"PATH_INFO":path,"QUERY_STRING":"","wsgi.input":io.BytesIO(raw),"CONTENT_TYPE":"application/json","CONTENT_LENGTH":str(len(raw))}
    if auth: env["HTTP_AUTHORIZATION"]=f"Bearer {AUTH}"
    seen={}
    def start(status,headers): seen.update(status=status,headers=dict(headers))
    payload=b"".join(app(env,start)); seen["raw"]=payload
    if seen["headers"].get("Content-Type","").startswith("application/json"): seen["payload"]=json.loads(payload.decode())
    return seen

def make_app(root,backend,fake,audit=None):
    read=BridgeApplication(config=ReadAppConfig(auth_secret=AUTH,file_signing_secret=SIGNING,private_root=root,public_base_url="https://bridge.example.invalid"),backend=backend,rate_limiter=AllowRead(),audit=audit or AuditLog())
    adapter=TelegramWriteAdapter(TelegramRuntimeConfig(application_id_ref=12345,application_hash_ref="synthetic-hash-reference",session_reference="synthetic-session-reference",synthetic_test_mode=True),lambda:fake)
    return UnifiedBridgeApplication(read_app=read,write_adapter=adapter,write_limiter=FixedWindowEndpointLimiter(limit=1000,window_seconds=60,clock=lambda:300.0))

class RouteAndSchemaTests(unittest.TestCase):
    def test_17_action_operations_resolve_and_schema_is_strict(self):
        with tempfile.TemporaryDirectory() as t:
            app=make_app(Path(t),Backend(),DeterministicFakeTelegramClient())
            unresolved=[]
            for s in openapi_registry.OPERATIONS:
                r=app._operation_for_request(str(s.method).upper(),str(s.path))
                if r is None or r.operation_id!=s.operation_id: unresolved.append(s.operation_id)
            self.assertEqual([],unresolved); self.assertEqual(17,len(openapi_registry.OPERATIONS))
            self.assertEqual({(str(s.method).upper(),str(s.path)) for s in openapi_registry.OPERATIONS if s.operation_class is OperationClass.READ},set(validate_unified_registry()))
            first=openapi_registry.build_action_openapi("https://bridge.example.invalid"); self.assertEqual(first,openapi_registry.build_action_openapi("https://bridge.example.invalid")); self.assertNotIn("setup"," ".join(first["paths"]).casefold())
            for s in openapi_registry.OPERATIONS:
                if s.operation_class is OperationClass.WRITE_COMMIT:
                    op=first["paths"][s.path][str(s.method).lower()]; schema=op["requestBody"]["content"]["application/json"]["schema"]
                    self.assertFalse(schema.get("additionalProperties",True)); self.assertEqual({"preview_token","idempotency_key","explicit_user_command"},set(schema["required"])); self.assertIs(schema["properties"]["explicit_user_command"].get("const"),True); self.assertIs(op.get("x-openai-isConsequential"),True)

class ContinuousFlowTests(unittest.TestCase):
    def test_full_mocked_flow_privacy_exactly_once_and_restart(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t); audit=AuditLog(); backend=Backend(); fake=DeterministicFakeTelegramClient(); app=make_app(root,backend,fake,audit)
            for path,body in (("/api/v1/dialogs/list",{"limit":10}),("/api/v1/history/read",{"chat":"2","limit":10}),("/api/v1/search",{"chat":"2","text":"synthetic"}),("/api/v1/search",{"text":"synthetic"}),("/api/v1/media/metadata",{"chat":"2","message_id":2})):
                self.assertTrue(request(app,path,body)["status"].startswith("200"),path)
            item={"chat":"2","message_id":2,"file_ref":backend.ref,"name":"scenario.bin","mime_type":"application/octet-stream","expected_size":len(backend.bytes)}
            single=request(app,"/api/v1/downloads/single",item); self.assertTrue(single["status"].startswith("200")); f=single["payload"]["data"]
            bulk=request(app,"/api/v1/downloads/bulk",{"items":[item]}); b=bulk["payload"]["data"]; self.assertEqual("complete",b["status"]); n=backend.download_count
            self.assertEqual("complete",request(app,"/api/v1/downloads/resume",{"job_id":b["job_id"]})["payload"]["data"]["status"]); self.assertEqual(n,backend.download_count)
            self.assertTrue(request(app,"/api/v1/archives/create",{"file_refs":[f["file_ref"]],"name":"scenario.zip"})["status"].startswith("200")); self.assertTrue(request(app,"/api/v1/files/get",{"file_ref":f["file_ref"]})["status"].startswith("200")); self.assertEqual(backend.bytes,request(app,f"/api/v1/files/{f['file_ref']}",method="GET")["raw"])
            previews=[]
            cases=(("/api/v1/messages/send/preview",{"chat":"100","text":backend.private_body}),("/api/v1/messages/reply/preview",{"chat":"100","reply_to_message_id":1,"text":backend.private_body}),("/api/v1/messages/forward/preview",{"from_chat":"200","to_chat":"100","message_ids":[1]}),("/api/v1/files/send/preview",{"chat":"100","files":[{"file_ref":f["file_ref"],"sha256":f["sha256"],"size":f["size"]}],"caption":"","voice_note":False}))
            for path,body in cases:
                r=request(app,path,body); self.assertTrue(r["status"].startswith("200")); previews.append(r["payload"]["data"])
            self.assertEqual([],fake.external_writes); self.assertEqual(0,fake.connect_count)
            commit={"preview_token":previews[0]["preview_token"],"idempotency_key":"devc-release-idem-0001","explicit_user_command":False}
            self.assertTrue(request(app,"/api/v1/messages/send/commit",commit)["status"].startswith("409")); self.assertEqual([],fake.external_writes)
            commit["explicit_user_command"]=True; first=request(app,"/api/v1/messages/send/commit",commit); replay=request(app,"/api/v1/messages/send/commit",commit)
            self.assertFalse(first["payload"]["data"]["idempotent_replay"]); self.assertTrue(replay["payload"]["data"]["idempotent_replay"]); self.assertEqual(1,len(fake.external_writes))
            text=json.dumps(audit.events,ensure_ascii=False,sort_keys=True)
            for private in (backend.private_title,backend.private_sender,backend.private_body,"devc-private-file.bin",AUTH,SIGNING,str(root)): self.assertNotIn(private,text)
            restarted_fake=DeterministicFakeTelegramClient(); restarted=make_app(root,Backend(),restarted_fake,AuditLog())
            self.assertTrue(request(restarted,"/api/v1/files/get",{"file_ref":f["file_ref"]})["status"].startswith("200")); self.assertEqual("complete",request(restarted,"/api/v1/downloads/resume",{"job_id":b["job_id"]})["payload"]["data"]["status"]); rr=request(restarted,"/api/v1/messages/send/commit",commit); self.assertTrue(rr["payload"]["data"]["idempotent_replay"]); self.assertEqual([],restarted_fake.external_writes)

    def test_unauth_write_hidden_before_body_processing(self):
        with tempfile.TemporaryDirectory() as t:
            fake=DeterministicFakeTelegramClient(); app=make_app(Path(t),Backend(),fake); r=request(app,"/api/v1/messages/send/preview",{"chat":"100","text":"PRIVATE"},auth=False); self.assertTrue(r["status"].startswith("404")); self.assertEqual([],fake.external_writes)

class ContentionTests(unittest.TestCase):
    def test_read_resume_duplicate_commit_exactly_one_effect(self):
        with tempfile.TemporaryDirectory() as t:
            backend=Backend(); fake=DeterministicFakeTelegramClient(); app=make_app(Path(t),backend,fake)
            item={"chat":"2","message_id":2,"file_ref":backend.ref,"name":"c.bin","mime_type":"application/octet-stream","expected_size":len(backend.bytes)}; bulk=request(app,"/api/v1/downloads/bulk",{"items":[item]})["payload"]["data"]; job=bulk["job_id"]; downloads=backend.download_count
            preview=request(app,"/api/v1/messages/send/preview",{"chat":"100","text":"contention"})["payload"]["data"]; commit={"preview_token":preview["preview_token"],"idempotency_key":"devc-release-concurrent-idem-0001","explicit_user_command":True}
            barrier=threading.Barrier(18)
            def read(): barrier.wait(10); return "read",request(app,"/api/v1/dialogs/list",{"limit":5})
            def resume(): barrier.wait(10); return "resume",request(app,"/api/v1/downloads/resume",{"job_id":job})
            def write(): barrier.wait(10); return "write",request(app,"/api/v1/messages/send/commit",commit)
            with ThreadPoolExecutor(max_workers=18) as pool: results=[f.result(20) for f in [pool.submit(fn) for fn in [read]*6+[resume]*6+[write]*6]]
            flags=[]; busy_resumes=0; write_in_progress=0
            for kind,r in results:
                if kind=="resume" and r["status"].startswith("409"):
                    error=r.get("payload",{}).get("error",{})
                    self.assertEqual("job_busy",error.get("code"),(kind,r)); self.assertIs(error.get("details",{}).get("retryable"),True,(kind,r)); busy_resumes+=1; continue
                if kind=="write" and r["status"].startswith("409"):
                    error=r.get("payload",{}).get("error",{})
                    self.assertEqual("write_in_progress",error.get("code"),(kind,r)); write_in_progress+=1; continue
                self.assertTrue(r["status"].startswith("200"),(kind,r))
                if kind=="resume": self.assertEqual("complete",r["payload"]["data"]["status"])
                elif kind=="write": flags.append(bool(r["payload"]["data"]["idempotent_replay"]))
            self.assertGreaterEqual(busy_resumes,0)
            self.assertLessEqual(write_in_progress,5)
            self.assertEqual(downloads,backend.download_count); self.assertEqual(1,len(fake.external_writes)); self.assertEqual(1,flags.count(False)); self.assertEqual(5-write_in_progress,flags.count(True))
            settled=request(app,"/api/v1/messages/send/commit",commit)
            self.assertTrue(settled["status"].startswith("200"),settled); self.assertTrue(settled["payload"]["data"]["idempotent_replay"]); self.assertEqual(1,len(fake.external_writes))

if __name__=="__main__": unittest.main()
