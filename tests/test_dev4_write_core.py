import copy, tempfile, threading, unittest
from pathlib import Path
from ops.openapi_registry import build_action_openapi, canonical_operation, validate_action_openapi, OpenAPIContractError
from ops.telegram_write_adapter import DeterministicFakeTelegramClient, TelegramContractError, TelegramRuntimeConfig, TelegramWriteAdapter, normalize_entity_ref
from ops.write_safety import PersistentWriteStore, ReconciliationRequired, SafeNoSideEffectFailure, TransactionState, WriteSafetyError

H='a'*64

def cfg(**kw):
    d=dict(application_id_ref=1,application_hash_ref='dummy',session_reference='dummy-ref',synthetic_test_mode=True,request_timeout_seconds=.2,max_flood_wait_seconds=60); d.update(kw); return TelegramRuntimeConfig(**d)

def payload(text='draft'): return {'target':'@target_user','text':text}

class AdapterCoreTests(unittest.TestCase):
    def test_numeric_target(self): self.assertEqual(normalize_entity_ref('123').value,123)
    def test_username_target(self): self.assertEqual(normalize_entity_ref('@target_user').value,'target_user')
    def test_tme_target(self): self.assertEqual(normalize_entity_ref('https://t.me/target_user').value,'target_user')
    def test_other_url_rejected(self):
        with self.assertRaises(TelegramContractError): normalize_entity_ref('https://example.com/x')
    def test_send_disconnects(self):
        c=DeterministicFakeTelegramClient(); r=TelegramWriteAdapter(cfg(),lambda:c).send('@target_user','x'); self.assertEqual(r.operation,'SEND'); self.assertEqual(c.disconnect_count,1); self.assertEqual(len(c.external_writes),1)
    def test_reply_is_distinct_and_exact(self):
        c=DeterministicFakeTelegramClient(); r=TelegramWriteAdapter(cfg(),lambda:c).reply('@target_user',10,'x'); self.assertEqual(r.operation,'REPLY'); self.assertEqual(c.external_writes[0]['reply_to'],10)
    def test_cross_chat_reply_rejected_no_write(self):
        from ops.telegram_write_adapter import FakeMessage
        c=DeterministicFakeTelegramClient(messages={(100,10):FakeMessage(10,200)}); a=TelegramWriteAdapter(cfg(),lambda:c)
        with self.assertRaisesRegex(TelegramContractError,'chat_mismatch'): a.reply('@target_user',10,'x')
        self.assertEqual(c.external_writes,[])
    def test_forward_order_and_count(self):
        c=DeterministicFakeTelegramClient(); r=TelegramWriteAdapter(cfg(),lambda:c).forward('@source_user','@target_user',[20,21]); self.assertEqual(r.count,2); self.assertEqual(c.external_writes[0]['count'],2)
    def test_duplicate_forward_ids_rejected(self):
        c=DeterministicFakeTelegramClient(); a=TelegramWriteAdapter(cfg(),lambda:c)
        with self.assertRaises(TelegramContractError): a.forward('@source_user','@target_user',[20,20])
        self.assertEqual(c.external_writes,[])
    def test_files_cap_preconnect(self):
        c=DeterministicFakeTelegramClient(); a=TelegramWriteAdapter(cfg(max_send_files=1),lambda:c)
        with self.assertRaises(TelegramContractError): a.send_files('@target_user',['a','b'])
        self.assertEqual(c.connect_count,0)
    def test_voice_multiple_rejected(self):
        c=DeterministicFakeTelegramClient(); a=TelegramWriteAdapter(cfg(),lambda:c)
        with self.assertRaises(TelegramContractError): a.send_files('@target_user',['a','b'],voice_note=True)
    def test_floodwait_redacted_and_bounded(self):
        class FloodWaitError(Exception): seconds=999
        c=DeterministicFakeTelegramClient(operation_error=FloodWaitError('private body')); a=TelegramWriteAdapter(cfg(),lambda:c)
        with self.assertRaises(TelegramContractError) as cm: a.send('@target_user','x')
        self.assertEqual(cm.exception.code,'telegram_flood_wait'); self.assertEqual(cm.exception.retry_after,60); self.assertNotIn('private body',str(cm.exception))
    def test_rpc_redacted(self):
        class RPCError(Exception): pass
        c=DeterministicFakeTelegramClient(operation_error=RPCError('/secret/path')); a=TelegramWriteAdapter(cfg(),lambda:c)
        with self.assertRaises(TelegramContractError) as cm: a.send('@target_user','x')
        self.assertEqual(cm.exception.code,'telegram_rpc_error'); self.assertNotIn('/secret/path',str(cm.exception)); self.assertEqual(c.disconnect_count,1)
    def test_timeout_disconnects(self):
        c=DeterministicFakeTelegramClient(operation_delay=.05); a=TelegramWriteAdapter(cfg(request_timeout_seconds=.01),lambda:c)
        with self.assertRaisesRegex(TelegramContractError,'telegram_timeout'): a.send('@target_user','x')
        self.assertEqual(c.disconnect_count,1); self.assertEqual(c.external_writes,[])

class WriteStoreTests(unittest.TestCase):
    def setUp(self): self.td=tempfile.TemporaryDirectory(); self.path=Path(self.td.name)/'w.db'; self.s=PersistentWriteStore(self.path,preview_ttl_seconds=5)
    def tearDown(self): self.td.cleanup()
    def p(self,text='draft'): return self.s.create_preview('SEND',payload(text),now=100)
    def test_preview_bound(self):
        p=self.p(); self.assertEqual(len(p.request_fingerprint),64); self.assertEqual(p.expires_at,105)
    def test_wrong_commit_type_no_effect(self):
        p=self.p(); calls=[]
        with self.assertRaisesRegex(WriteSafetyError,'preview_action_mismatch'): self.s.commit(p.token,expected_action='REPLY',idempotency_key='idem-key-1',external_write=lambda x:(calls.append(1) or {'id':1}),now=101)
        self.assertEqual(calls,[])
    def test_never_committed_expired_rejected(self):
        p=self.p()
        with self.assertRaisesRegex(WriteSafetyError,'expired_preview'): self.s.commit(p.token,expected_action='SEND',idempotency_key='idem-key-1',external_write=lambda x:{'id':1},now=106)
    def test_replay_exactly_once(self):
        p=self.p(); calls=[]; self.s.commit(p.token,expected_action='SEND',idempotency_key='idem-key-1',external_write=lambda x:(calls.append(1) or {'id':1}),now=101); r=self.s.commit(p.token,expected_action='SEND',idempotency_key='idem-key-1',external_write=lambda x:(calls.append(2) or {'id':2}),now=102); self.assertTrue(r.idempotent_replay); self.assertEqual(calls,[1])
    def test_replay_after_expiry(self):
        p=self.p(); self.s.commit(p.token,expected_action='SEND',idempotency_key='idem-key-1',external_write=lambda x:{'id':1},now=101); r=self.s.commit(p.token,expected_action='SEND',idempotency_key='idem-key-1',external_write=lambda x:{'id':2},now=999); self.assertTrue(r.idempotent_replay); self.assertEqual(r.result,{'id':1})
    def test_idempotency_conflict_different_preview(self):
        p1=self.p('a'); p2=self.p('b'); self.s.commit(p1.token,expected_action='SEND',idempotency_key='idem-key-1',external_write=lambda x:{'id':1},now=101)
        with self.assertRaisesRegex(WriteSafetyError,'idempotency_key_conflict'): self.s.commit(p2.token,expected_action='SEND',idempotency_key='idem-key-1',external_write=lambda x:{'id':2},now=101)
    def test_safe_failure_not_ambiguous(self):
        p=self.p()
        with self.assertRaises(WriteSafetyError): self.s.commit(p.token,expected_action='SEND',idempotency_key='idem-key-1',external_write=lambda x:(_ for _ in ()).throw(SafeNoSideEffectFailure()),now=101)
        self.assertEqual(self.s.transaction_state('idem-key-1'),TransactionState.FAILED_SAFE.value)
    def test_unknown_external_outcome_ambiguous(self):
        p=self.p()
        with self.assertRaises(ReconciliationRequired): self.s.commit(p.token,expected_action='SEND',idempotency_key='idem-key-1',external_write=lambda x:(_ for _ in ()).throw(RuntimeError('unknown')),now=101)
        self.assertEqual(self.s.transaction_state('idem-key-1'),TransactionState.AMBIGUOUS.value)
    def test_ambiguous_never_blind_resends(self):
        p=self.p(); calls=[]
        with self.assertRaises(ReconciliationRequired): self.s.commit(p.token,expected_action='SEND',idempotency_key='idem-key-1',external_write=lambda x:(_ for _ in ()).throw(RuntimeError()),now=101)
        with self.assertRaises(ReconciliationRequired): self.s.commit(p.token,expected_action='SEND',idempotency_key='idem-key-1',external_write=lambda x:(calls.append(1) or {'id':2}),now=102)
        self.assertEqual(calls,[])
    def test_reserved_crash_resumes(self):
        p=self.p(); self.s.simulate_reserved_crash_for_test(p.token,expected_action='SEND',idempotency_key='idem-key-1',now=101); r=self.s.commit(p.token,expected_action='SEND',idempotency_key='idem-key-1',external_write=lambda x:{'id':1},now=102); self.assertEqual(r.state,'COMMITTED')
    def test_calling_crash_recovery_ambiguous(self):
        p=self.p(); self.s.simulate_calling_crash_for_test(p.token,expected_action='SEND',idempotency_key='idem-key-1',now=101); self.assertEqual(self.s.mark_calling_transaction_ambiguous_on_recovery(now=102),1); self.assertEqual(self.s.transaction_state('idem-key-1'),'AMBIGUOUS')
    def test_restart_preserves_commit(self):
        p=self.p(); self.s.commit(p.token,expected_action='SEND',idempotency_key='idem-key-1',external_write=lambda x:{'id':1},now=101); s2=PersistentWriteStore(self.path,preview_ttl_seconds=5); calls=[]; r=s2.commit(p.token,expected_action='SEND',idempotency_key='idem-key-1',external_write=lambda x:(calls.append(1) or {'id':2}),now=999); self.assertTrue(r.idempotent_replay); self.assertEqual(calls,[])
    def test_audit_drops_body_target_token(self):
        p=self.s.create_preview('SEND',{'target':'Private Chat','text':'Private Body'},now=100); meta=str(self.s.audit_metadata(p.token,idempotency_key='idem-key-1')); self.assertNotIn('Private Chat',meta); self.assertNotIn('Private Body',meta); self.assertNotIn(p.token,meta)
    def test_cleanup_keeps_committed_tombstone(self):
        p=self.p(); self.s.commit(p.token,expected_action='SEND',idempotency_key='idem-key-1',external_write=lambda x:{'id':1},now=101); self.s.cleanup(now=999,expired_preview_grace_seconds=0); self.assertEqual(self.s.transaction_state('idem-key-1'),'COMMITTED')
    def test_concurrent_commit_one_external(self):
        p=self.p(); entered=threading.Event(); release=threading.Event(); calls=[]
        def external(x): calls.append(1); entered.set(); release.wait(2); return {'id':1}
        def first(): self.s.commit(p.token,expected_action='SEND',idempotency_key='idem-key-1',external_write=external,now=101)
        t=threading.Thread(target=first); t.start(); self.assertTrue(entered.wait(2))
        try:
            with self.assertRaisesRegex(WriteSafetyError,'write_in_progress'): self.s.commit(p.token,expected_action='SEND',idempotency_key='idem-key-1',external_write=lambda x:{'id':2},now=101)
            self.assertEqual(self.s.transaction_state('idem-key-1'),'CALLING')
        finally: release.set(); t.join(2)
        self.assertEqual(calls,[1]); self.assertEqual(self.s.transaction_state('idem-key-1'),'COMMITTED')

class OpenAPICoreTests(unittest.TestCase):
    def setUp(self): self.s=build_action_openapi('https://tg-api.rukadopomogy.org.ua')
    def test_generated_valid(self): self.assertEqual(validate_action_openapi(self.s),[])
    def test_unknown_registry_operation_fail_closed(self):
        with self.assertRaises(OpenAPIContractError): canonical_operation('/api/v1/not-real','post')
    def test_dev3_read_media_paths_are_canonical(self):
        expected={'/api/v1/dialogs/list','/api/v1/history/read','/api/v1/search','/api/v1/media/metadata','/api/v1/downloads/single','/api/v1/downloads/bulk','/api/v1/downloads/resume','/api/v1/archives/create','/api/v1/files/get'}
        self.assertTrue(expected.issubset(self.s['paths']))
    def test_read_and_send_files_use_file_ref(self):
        get_body=self.s['paths']['/api/v1/files/get']['post']['requestBody']['content']['application/json']['schema']; self.assertIn('file_ref',get_body['properties']); self.assertNotIn('file_id',get_body['properties'])
        send_body=self.s['paths']['/api/v1/files/send/preview']['post']['requestBody']['content']['application/json']['schema']; item=send_body['properties']['files']['items']; self.assertIn('file_ref',item['properties']); self.assertNotIn('file_id',item['properties'])
    def test_all_ops_bearer(self):
        for item in self.s['paths'].values():
            for op in item.values(): self.assertEqual(op['security'],[{'BearerAuth':[]}])
    def test_remove_self_markers_does_not_remove_security_requirement(self):
        s=copy.deepcopy(self.s); op=s['paths']['/api/v1/messages/send/commit']['post']; op.pop('x-bridge-operation-class',None); op.pop('x-bridge-write-action',None); op.pop('security'); self.assertIn('PROTECTED_WITHOUT_BEARER:commitTelegramSend',validate_action_openapi(s))
    def test_commit_requires_explicit_user_command(self):
        body=self.s['paths']['/api/v1/messages/send/commit']['post']['requestBody']['content']['application/json']['schema']; self.assertIn('explicit_user_command',body['required']); self.assertIs(body['properties']['explicit_user_command']['const'],True)
    def test_preview_nonconsequential(self): self.assertFalse(self.s['paths']['/api/v1/messages/send/preview']['post']['x-openai-isConsequential'])
    def test_commit_consequential(self): self.assertTrue(self.s['paths']['/api/v1/messages/send/commit']['post']['x-openai-isConsequential'])
    def test_private_setup_not_in_paths(self): self.assertFalse(any('setup' in p.lower() for p in self.s['paths']))
    def test_private_setup_added_rejected(self):
        s=copy.deepcopy(self.s); s['paths']['/setup/private']={'post':copy.deepcopy(s['paths']['/api/v1/dialogs/list']['post'])}; self.assertTrue(any('PRIVATE_SETUP_ROUTE' in x for x in validate_action_openapi(s)))
    def test_unknown_schema_route_rejected(self):
        s=copy.deepcopy(self.s); s['paths']['/api/v1/not-real']={'post':copy.deepcopy(s['paths']['/api/v1/dialogs/list']['post'])}; self.assertTrue(any('UNKNOWN_SCHEMA_OPERATION' in x for x in validate_action_openapi(s)))
    def test_k5_safe_destination_component(self): self.assertIn('K5TestSafeDestination',self.s['components']['schemas'])

if __name__=='__main__': unittest.main()