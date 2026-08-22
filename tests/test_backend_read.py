from __future__ import annotations
import unittest
from datetime import datetime, timezone
from types import SimpleNamespace

from bridge.backend import TelethonReadBackend, TelethonReadConfig
from bridge.errors import BridgeError
from bridge.validation import DateRange

class Entity:
    def __init__(self,id,title=None,first_name=None,username=None): self.id=id; self.title=title; self.first_name=first_name; self.username=username
class User(Entity): pass
class Chat(Entity): pass
class File:
    def __init__(self,name="a.txt",mime_type="text/plain",size=3,id=99): self.name=name; self.mime_type=mime_type; self.size=size; self.id=id; self.duration=None; self.width=None; self.height=None
class Msg:
    def __init__(self,id,text,date,sender_id=7,media=False):
        self.id=id; self.message=text; self.date=date; self.sender_id=sender_id; self.out=False; self.reply_to=None
        self.media=object() if media else None; self.file=File() if media else None; self.document=SimpleNamespace(id=123) if media else None
        self.voice=None; self.video_note=None; self.photo=None; self.video=None; self.audio=None; self.sticker=None
    async def get_sender(self): return User(self.sender_id,first_name="Ім'я",username="name")
class Dialog:
    def __init__(self,id,title,date,unread=0): self.entity=Chat(id,title=title); self.message=SimpleNamespace(date=date); self.unread_count=unread; self.pinned=False
class Client:
    def __init__(self):
        z=timezone.utc
        self.dialogs=[Dialog(1,"Україна",datetime(2026,8,21,10,tzinfo=z),1),Dialog(2,"Other",datetime(2026,8,20,10,tzinfo=z),0)]
        self.messages=[Msg(3,"ЇЖАК",datetime(2026,8,21,10,tzinfo=z),7,True),Msg(2,"їжак",datetime(2026,8,21,10,tzinfo=z),8),Msg(1,"old",datetime(2026,8,20,10,tzinfo=z),7)]
    def iter_dialogs(self,limit): return self.dialogs[:limit]
    def get_entity(self,target): return Chat(int(target) if str(target).lstrip('-').isdigit() else 1,title="x")
    def iter_messages(self,entity,limit): return self.messages[:limit]
    def get_messages(self,entity,ids): return next((m for m in self.messages if m.id==ids),None)
    def download_media(self,msg,file): open(file,"wb").write(b"abc"); return file

class BackendTests(unittest.TestCase):
    def setUp(self): self.client=Client(); self.b=TelethonReadBackend(client_factory=lambda:self.client,config=TelethonReadConfig(request_timeout_seconds=2,dialog_scan_limit=100,search_scan_limit=100))
    def test_no_client_factory_at_construction(self):
        calls=[]; TelethonReadBackend(client_factory=lambda:calls.append(1)); self.assertEqual(calls,[])
    def test_dialog_order(self): self.assertEqual([x.id for x in self.b.list_dialogs(limit=10,cursor=None,query="",unread_only=False).items],["1","2"])
    def test_dialog_unicode_casefold_query(self): self.assertEqual(len(self.b.list_dialogs(limit=10,cursor=None,query="уКРАЇНА",unread_only=False).items),1)
    def test_dialog_unread_filter(self): self.assertEqual(len(self.b.list_dialogs(limit=10,cursor=None,query="",unread_only=True).items),1)
    def test_dialog_cursor_is_opaque(self): self.assertNotEqual(self.b.list_dialogs(limit=1,cursor=None,query="",unread_only=False).next_cursor,"1")
    def test_dialog_cursor_scope_swap_rejected(self):
        c=self.b.list_dialogs(limit=1,cursor=None,query="",unread_only=False).next_cursor
        with self.assertRaises(BridgeError) as cm: self.b.history(chat="1",limit=1,cursor=c)
        self.assertEqual(cm.exception.code,"invalid_cursor")
    def test_history_equal_timestamp_tiebreak_id(self): self.assertEqual([m.id for m in self.b.history(chat="1",limit=3,cursor=None).items],[3,2,1])
    def test_history_pagination_no_duplicate(self):
        p1=self.b.history(chat="1",limit=1,cursor=None); p2=self.b.history(chat="1",limit=1,cursor=p1.next_cursor); self.assertNotEqual(p1.items[0].id,p2.items[0].id)
    def test_sender_id_not_name_identifier(self): self.assertEqual(self.b.history(chat="1",limit=1,cursor=None).items[0].sender.id,"7")
    def test_media_ref_deterministic_across_instances(self):
        m=self.client.messages[0]; a=self.b._media_records(m)[0].file_ref; b=TelethonReadBackend(client_factory=lambda:self.client)._media_records(m)[0].file_ref; self.assertEqual(a,b); self.assertTrue(a.startswith("tg_3_"))
    def test_search_casefold(self):
        d=DateRange(None,None); self.assertEqual(len(self.b.search(chat="1",sender=None,text="їжак",dates=d,limit=10,cursor=None,scan_limit=10).items),2)
    def test_search_sender_stable_id(self): self.assertEqual(len(self.b.search(chat="1",sender="7",text="",dates=DateRange(None,None),limit=10,cursor=None,scan_limit=10).items),2)
    def test_date_start_inclusive(self):
        d=DateRange(datetime(2026,8,21,10,tzinfo=timezone.utc),None); self.assertEqual(len(self.b.search(chat="1",sender=None,text="",dates=d,limit=10,cursor=None,scan_limit=10).items),2)
    def test_date_end_inclusive(self):
        d=DateRange(None,datetime(2026,8,20,10,tzinfo=timezone.utc)); self.assertEqual(len(self.b.search(chat="1",sender=None,text="",dates=d,limit=10,cursor=None,scan_limit=10).items),1)
    def test_get_message_not_found(self):
        with self.assertRaises(BridgeError) as cm: self.b.get_message(chat="1",message_id=999)
        self.assertEqual(cm.exception.code,"message_not_found")
    def test_download_ref_mismatch_no_write(self):
        with self.assertRaises(BridgeError) as cm: self.b.download_media(chat="1",message_id=3,file_ref="bad",destination="/tmp/should-not-exist")
        self.assertEqual(cm.exception.code,"file_not_found")
    def test_backend_exception_text_hidden(self):
        class Bad(Client):
            def iter_dialogs(self,limit): raise RuntimeError("PRIVATE title")
        b=TelethonReadBackend(client_factory=Bad)
        with self.assertRaises(BridgeError) as cm: b.list_dialogs(limit=1,cursor=None,query="",unread_only=False)
        self.assertEqual(cm.exception.code,"telegram_rpc_error"); self.assertNotIn("PRIVATE",cm.exception.message)
    def test_floodwait_capped(self):
        class FloodWaitError(Exception):
            seconds=999
        class Bad(Client):
            def iter_dialogs(self,limit): raise FloodWaitError()
        b=TelethonReadBackend(client_factory=Bad,config=TelethonReadConfig(flood_wait_cap_seconds=30))
        with self.assertRaises(BridgeError) as cm: b.list_dialogs(limit=1,cursor=None,query="",unread_only=False)
        self.assertEqual(cm.exception.code,"telegram_flood_wait"); self.assertEqual(cm.exception.retry_after_seconds,30)

if __name__ == '__main__': unittest.main()
