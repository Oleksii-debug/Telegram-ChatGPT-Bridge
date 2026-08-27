from __future__ import annotations

import io
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from bridge.app import BridgeApplication, ReadAppConfig
from bridge.audit import AuditLog
from bridge.errors import BridgeError
from bridge.models import DialogRecord, EntityRef, MediaRecord, MessageRecord, Page
from bridge.security import RateLimitDecision
from bridge.validation import DateRange

TOKEN = "dummy-test-bearer-token-000000000001"
SIGN = "dummy-test-signing-secret-000000001"


class AllowLimiter:
    def check(self, actor):
        self.actor = actor
        return RateLimitDecision(True, remaining=9)


class DenyLimiter:
    def check(self, actor):
        return RateLimitDecision(False, retry_after_seconds=7, remaining=0)


class FakeBackend:
    def __init__(self):
        self.calls=[]
        self.dialogs = [
            DialogRecord("2", "group", "Привіт 🌍", "hello", 1, False, "2026-08-21T09:00:00+00:00"),
            DialogRecord("1", "user", "Іван", None, 0, False, "2026-08-20T09:00:00+00:00"),
        ]
        self.messages = [
            MessageRecord(2,"2","2026-08-21T09:00:00+00:00","Їжак 🦔 e\u0301",EntityRef("20","user","Олена"),media=(MediaRecord("document","tg_2_0123456789abcdefabcd","résumé.pdf","application/pdf",3),)),
            MessageRecord(1,"2","2026-08-20T09:00:00+00:00","старе",EntityRef("21","user","Петро")),
        ]
    def list_dialogs(self, **kw): self.calls.append(("dialogs",kw)); return Page(tuple(self.dialogs[:kw['limit']]), None, len(self.dialogs))
    def history(self, **kw): self.calls.append(("history",kw)); return Page(tuple(self.messages[:kw['limit']]), None, len(self.messages))
    def search(self, **kw): self.calls.append(("search",kw)); return Page((self.messages[0],), None, 2)
    def get_message(self, **kw): self.calls.append(("message",kw)); return self.messages[0]
    def download_media(self, **kw):
        self.calls.append(("download",kw)); p=Path(kw['destination']); p.write_bytes(b"abc"); return {"path":str(p)}


def request(app, path, body=None, method="POST", token=TOKEN, content_type="application/json", raw=None, length=None, query=""):
    payload = raw if raw is not None else json.dumps(body or {}, ensure_ascii=False).encode("utf-8")
    env={"REQUEST_METHOD":method,"PATH_INFO":path,"QUERY_STRING":query,"wsgi.input":io.BytesIO(payload),"CONTENT_TYPE":content_type,"CONTENT_LENGTH":str(len(payload) if length is None else length)}
    if token is not None: env["HTTP_AUTHORIZATION"]="Bearer "+token
    seen={}
    def start(status, headers): seen["status"]=status; seen["headers"]=dict(headers)
    chunks=app(env,start)
    rawout=b"".join(chunks)
    seen["raw"]=rawout
    if seen["headers"].get("Content-Type","").startswith("application/json"):
        seen["json"]=json.loads(rawout.decode("utf-8"))
    return seen


class ReadApplicationTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.backend=FakeBackend(); self.audit=AuditLog()
        self.app=BridgeApplication(config=ReadAppConfig(auth_secret=TOKEN,file_signing_secret=SIGN,private_root=Path(self.tmp.name),public_base_url="https://example.invalid"),backend=self.backend,rate_limiter=AllowLimiter(),audit=self.audit)

    def test_health_public_bounded_and_ready(self):
        r=request(self.app,"/health",method="GET",token=None,raw=b"")
        self.assertTrue(r["status"].startswith("200")); self.assertTrue(r["json"]["ready"]); self.assertNotIn(TOKEN,r["raw"].decode())

    def test_health_without_dependencies_is_not_ready(self):
        app=BridgeApplication(config=ReadAppConfig())
        r=request(app,"/health",method="GET",token=None,raw=b"")
        self.assertFalse(r["json"]["ready"]); self.assertEqual(r["json"]["components"]["backend"],"unconfigured")

    def test_health_wrong_method_controlled(self):
        r=request(self.app,"/health",body={},method="POST")
        self.assertTrue(r["status"].startswith("405")); self.assertEqual(r["json"]["error"]["code"],"method_not_allowed")

    def test_missing_auth_hidden(self):
        r=request(self.app,"/api/v1/dialogs/list",{},token=None)
        self.assertTrue(r["status"].startswith("404")); self.assertFalse(self.backend.calls)

    def test_wrong_auth_hidden(self):
        r=request(self.app,"/api/v1/dialogs/list",{},token="x"*32)
        self.assertTrue(r["status"].startswith("404")); self.assertFalse(self.backend.calls)

    def test_malformed_auth_hidden(self):
        r=request(self.app,"/api/v1/dialogs/list",{},token="")
        self.assertTrue(r["status"].startswith("404"))

    def test_rate_limit_before_body_and_retry_after(self):
        app=BridgeApplication(config=self.app.config,backend=self.backend,rate_limiter=DenyLimiter())
        r=request(app,"/api/v1/dialogs/list",raw=b"not-json")
        self.assertTrue(r["status"].startswith("429")); self.assertEqual(r["headers"]["Retry-After"],"7"); self.assertFalse(self.backend.calls)

    def test_invalid_route_hidden(self): self.assertTrue(request(self.app,"/api/v1/nope",{})["status"].startswith("404"))
    def test_invalid_method_hidden(self): self.assertTrue(request(self.app,"/api/v1/dialogs/list",method="GET",token=TOKEN,raw=b"")["status"].startswith("404"))
    def test_invalid_content_type(self): self.assertEqual(request(self.app,"/api/v1/dialogs/list",{},content_type="text/plain")["json"]["error"]["code"],"invalid_content_type")
    def test_invalid_utf8(self): self.assertEqual(request(self.app,"/api/v1/dialogs/list",raw=b"\xff")["json"]["error"]["code"],"invalid_utf8")
    def test_malformed_json(self): self.assertEqual(request(self.app,"/api/v1/dialogs/list",raw=b"{")["json"]["error"]["code"],"malformed_json")
    def test_json_array_rejected(self): self.assertEqual(request(self.app,"/api/v1/dialogs/list",raw=b"[]")["json"]["error"]["code"],"invalid_json_shape")
    def test_huge_content_length_rejected_without_read(self): self.assertEqual(request(self.app,"/api/v1/dialogs/list",raw=b"{}",length=999999)["json"]["error"]["code"],"request_too_large")
    def test_bad_content_length(self): self.assertEqual(request(self.app,"/api/v1/dialogs/list",raw=b"{}",length=-1)["json"]["error"]["code"],"invalid_content_length")
    def test_missing_content_length(self):
        env={"REQUEST_METHOD":"POST","PATH_INFO":"/api/v1/dialogs/list","wsgi.input":io.BytesIO(b"{}"),"CONTENT_TYPE":"application/json","HTTP_AUTHORIZATION":"Bearer "+TOKEN}; seen={}
        out=self.app(env,lambda status,headers:seen.update(status=status,headers=dict(headers))); payload=json.loads(b"".join(out)); self.assertEqual(payload["error"]["code"],"invalid_content_length")
    def test_incomplete_body(self): self.assertEqual(request(self.app,"/api/v1/dialogs/list",raw=b"{}",length=3)["json"]["error"]["code"],"incomplete_body")
    def test_unknown_field_rejected(self): self.assertEqual(request(self.app,"/api/v1/dialogs/list",{"secret":"x"})["json"]["error"]["code"],"unknown_field")

    def test_dialogs_unicode(self):
        r=request(self.app,"/api/v1/dialogs/list",{"limit":2})
        self.assertEqual(r["json"]["data"]["items"][0]["title"],"Привіт 🌍")
    def test_dialog_limit_bound(self): self.assertEqual(request(self.app,"/api/v1/dialogs/list",{"limit":999})["json"]["error"]["code"],"invalid_range")
    def test_dialog_unread_must_be_bool(self): self.assertEqual(request(self.app,"/api/v1/dialogs/list",{"unread_only":"yes"})["json"]["error"]["code"],"invalid_boolean")

    def test_history_requires_chat(self): self.assertEqual(request(self.app,"/api/v1/history/read",{})["json"]["error"]["code"],"field_required")
    def test_history_preserves_unicode_combining(self):
        r=request(self.app,"/api/v1/history/read",{"chat":"2"}); self.assertEqual(r["json"]["data"]["items"][0]["text"],"Їжак 🦔 e\u0301")
    def test_sender_stable_id_separate_from_name(self):
        r=request(self.app,"/api/v1/history/read",{"chat":"2"}); s=r["json"]["data"]["items"][0]["sender"]; self.assertEqual(s["id"],"20"); self.assertEqual(s["display_name"],"Олена")

    def test_search_requires_filter(self): self.assertEqual(request(self.app,"/api/v1/search",{})["json"]["error"]["code"],"search_filter_required")
    def test_search_timezone_required(self): self.assertEqual(request(self.app,"/api/v1/search",{"text":"x","date_from":"2026-01-01T00:00:00"})["json"]["error"]["code"],"timezone_required")
    def test_search_invalid_range(self): self.assertEqual(request(self.app,"/api/v1/search",{"date_from":"2026-01-02T00:00:00Z","date_to":"2026-01-01T00:00:00Z"})["json"]["error"]["code"],"invalid_date_range")
    def test_search_scan_limit(self): self.assertEqual(request(self.app,"/api/v1/search",{"text":"x","scan_limit":999999})["json"]["error"]["code"],"invalid_range")
    def test_search_calls_backend_with_utc_range(self):
        request(self.app,"/api/v1/search",{"text":"ЇЖАК","date_from":"2026-08-21T11:00:00+02:00","date_to":"2026-08-21T09:00:00Z"})
        _,kw=self.backend.calls[-1]; self.assertEqual(kw["dates"].start,datetime(2026,8,21,9,tzinfo=timezone.utc)); self.assertEqual(kw["dates"].end,datetime(2026,8,21,9,tzinfo=timezone.utc))

    def test_media_metadata_excludes_message_text(self):
        r=request(self.app,"/api/v1/media/metadata",{"chat":"2","message_id":2}); self.assertNotIn("text",r["json"]["data"]); self.assertEqual(r["json"]["data"]["media"][0]["type"],"document")

    def test_download_single_and_private_metadata(self):
        r=request(self.app,"/api/v1/downloads/single",{"chat":"2","message_id":2,"file_ref":"tg_2_0123456789abcdefabcd","name":"résumé.pdf","mime_type":"application/pdf","expected_size":3})
        data=r["json"]["data"]; self.assertNotIn("path",data); self.assertEqual(data["size"],3); self.assertEqual(len(data["sha256"]),64)
    def test_download_path_like_source_ref_rejected(self): self.assertEqual(request(self.app,"/api/v1/downloads/single",{"chat":"2","message_id":2,"file_ref":"../../etc/passwd"})["json"]["error"]["code"],"file_not_found")
    def test_download_hash_validation(self): self.assertEqual(request(self.app,"/api/v1/downloads/single",{"chat":"2","message_id":2,"file_ref":"tg_2_0123456789abcdefabcd","expected_sha256":"0"*64})["json"]["error"]["code"],"file_hash_mismatch")
    def test_bulk_items_bound(self): self.assertEqual(request(self.app,"/api/v1/downloads/bulk",{"items":[{}]*101})["json"]["error"]["code"],"invalid_list")

    def _downloaded_ref(self):
        r=request(self.app,"/api/v1/downloads/single",{"chat":"2","message_id":2,"file_ref":"tg_2_0123456789abcdefabcd","name":"a.txt","expected_size":3})
        return r["json"]["data"]["file_ref"]

    def test_private_file_metadata_and_signed_url(self):
        ref=self._downloaded_ref(); r=request(self.app,"/api/v1/files/get",{"file_ref":ref}); data=r["json"]["data"]; self.assertNotIn("path",data); self.assertIn("signed_url",data); self.assertIn(ref,data["download_path"])

    def test_private_file_unauthorized_get_hidden(self):
        ref=self._downloaded_ref(); r=request(self.app,f"/api/v1/files/{ref}",method="GET",token=None,raw=b""); self.assertTrue(r["status"].startswith("404"))

    def test_private_file_bearer_get(self):
        ref=self._downloaded_ref(); r=request(self.app,f"/api/v1/files/{ref}",method="GET",token=TOKEN,raw=b""); self.assertTrue(r["status"].startswith("200")); self.assertEqual(r["raw"],b"abc"); self.assertEqual(r["headers"]["Cache-Control"],"private, no-store")

    def test_private_file_signed_get_and_tamper(self):
        ref=self._downloaded_ref(); meta=request(self.app,"/api/v1/files/get",{"file_ref":ref})["json"]["data"]; query=meta["signed_url"].split("?",1)[1]
        good=request(self.app,f"/api/v1/files/{ref}",method="GET",token=None,raw=b"",query=query); self.assertEqual(good["raw"],b"abc")
        bad=request(self.app,f"/api/v1/files/{ref}",method="GET",token=None,raw=b"",query=query.replace("sig=","sig=0")); self.assertTrue(bad["status"].startswith("404"))

    def test_private_file_ref_swap_signed_link_fails(self):
        ref=self._downloaded_ref(); ref2=self._downloaded_ref(); meta=request(self.app,"/api/v1/files/get",{"file_ref":ref})["json"]["data"]; query=meta["signed_url"].split("?",1)[1]
        bad=request(self.app,f"/api/v1/files/{ref2}",method="GET",token=None,raw=b"",query=query); self.assertTrue(bad["status"].startswith("404"))

    def test_archive_endpoint_collision_and_private_metadata(self):
        a=self._downloaded_ref(); b=self._downloaded_ref(); r=request(self.app,"/api/v1/archives/create",{"file_refs":[a,b],"name":"пакет.zip"}); data=r["json"]["data"]; self.assertEqual(data["mime_type"],"application/zip"); self.assertNotIn("path",data)

    def test_audit_does_not_capture_private_body(self):
        secret_text="VERY_PRIVATE_MESSAGE_ABC"
        request(self.app,"/api/v1/search",{"text":secret_text})
        encoded=json.dumps(self.audit.events,ensure_ascii=False); self.assertNotIn(secret_text,encoded); self.assertNotIn("Привіт",encoded); self.assertNotIn(TOKEN,encoded)

    def test_internal_exception_text_not_leaked(self):
        class Boom(FakeBackend):
            def list_dialogs(self,**kw): raise RuntimeError("PRIVATE_CHAT_TITLE_should_not_leak")
        app=BridgeApplication(config=self.app.config,backend=Boom(),rate_limiter=AllowLimiter(),audit=self.audit)
        r=request(app,"/api/v1/dialogs/list",{}); self.assertTrue(r["status"].startswith("500")); self.assertNotIn("PRIVATE_CHAT_TITLE",r["raw"].decode())

    def test_security_headers(self):
        r=request(self.app,"/health",method="GET",token=None,raw=b""); self.assertEqual(r["headers"]["Cache-Control"],"no-store"); self.assertEqual(r["headers"]["X-Content-Type-Options"],"nosniff")

if __name__ == "__main__": unittest.main()
