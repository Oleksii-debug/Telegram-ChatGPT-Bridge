import tempfile
import unittest
from pathlib import Path
from ops.telegram_write_adapter import TelegramContractError
from ops.write_endpoint_policy import (
    EndpointContext, EndpointPolicyError, FixedWindowEndpointLimiter,
    WriteCoordinator, WriteEndpointPolicy, structured_write_error,
)
from ops.write_safety import PersistentWriteStore, WriteSafetyError

A='a'*64; B='b'*64
class Clock:
    def __init__(self,v=0): self.v=v
    def __call__(self): return self.v

class LimiterTests(unittest.TestCase):
    def test_first_request_allowed(self): self.assertEqual(FixedWindowEndpointLimiter(limit=2,window_seconds=10,clock=Clock()).consume(A,'op')[0],1)
    def test_limit_enforced(self):
        l=FixedWindowEndpointLimiter(limit=1,window_seconds=10,clock=Clock()); l.consume(A,'op')
        with self.assertRaises(EndpointPolicyError) as cm: l.consume(A,'op')
        self.assertEqual(cm.exception.status,429)
    def test_retry_after_bounded_to_window(self):
        c=Clock(3); l=FixedWindowEndpointLimiter(limit=1,window_seconds=10,clock=c); l.consume(A,'op')
        with self.assertRaises(EndpointPolicyError) as cm: l.consume(A,'op')
        self.assertEqual(cm.exception.retry_after_seconds,7)
    def test_window_resets_at_boundary(self):
        c=Clock(9); l=FixedWindowEndpointLimiter(limit=1,window_seconds=10,clock=c); l.consume(A,'op'); c.v=10; self.assertEqual(l.consume(A,'op')[0],0)
    def test_actors_isolated(self):
        l=FixedWindowEndpointLimiter(limit=1,window_seconds=10,clock=Clock()); l.consume(A,'op'); self.assertEqual(l.consume(B,'op')[0],0)
    def test_operations_isolated(self):
        l=FixedWindowEndpointLimiter(limit=1,window_seconds=10,clock=Clock()); l.consume(A,'op1'); self.assertEqual(l.consume(A,'op2')[0],0)
    def test_invalid_actor_hash(self):
        with self.assertRaisesRegex(EndpointPolicyError,'invalid_actor_identity'): FixedWindowEndpointLimiter(clock=Clock()).consume('private-user-name','op')
    def test_limit_bound(self):
        with self.assertRaises(ValueError): FixedWindowEndpointLimiter(limit=0)
    def test_window_bound(self):
        with self.assertRaises(ValueError): FixedWindowEndpointLimiter(window_seconds=0)

class PolicyTests(unittest.TestCase):
    def setUp(self): self.p=WriteEndpointPolicy(FixedWindowEndpointLimiter(limit=100,clock=Clock()))
    def ctx(self,auth=True,explicit=False): return EndpointContext(auth,A,explicit)
    def test_preview_requires_auth(self):
        with self.assertRaisesRegex(EndpointPolicyError,'authentication_required'): self.p.authorize('previewTelegramSend',self.ctx(False),expected_class=__import__('ops.openapi_registry',fromlist=['OperationClass']).OperationClass.WRITE_PREVIEW)
    def test_commit_requires_auth(self):
        from ops.openapi_registry import OperationClass
        with self.assertRaisesRegex(EndpointPolicyError,'authentication_required'): self.p.authorize('commitTelegramSend',self.ctx(False,True),expected_class=OperationClass.WRITE_COMMIT)
    def test_commit_requires_explicit_current_command(self):
        from ops.openapi_registry import OperationClass
        with self.assertRaisesRegex(EndpointPolicyError,'explicit_user_commit_required'): self.p.authorize('commitTelegramSend',self.ctx(True,False),expected_class=OperationClass.WRITE_COMMIT)
    def test_commit_explicit_allowed(self):
        from ops.openapi_registry import OperationClass
        self.assertEqual(self.p.authorize('commitTelegramSend',self.ctx(True,True),expected_class=OperationClass.WRITE_COMMIT).action,'SEND')
    def test_wrong_operation_class_rejected(self):
        from ops.openapi_registry import OperationClass
        with self.assertRaisesRegex(EndpointPolicyError,'operation_class_mismatch'): self.p.authorize('commitTelegramSend',self.ctx(True,True),expected_class=OperationClass.WRITE_PREVIEW)
    def test_unknown_operation_fails_closed(self):
        from ops.openapi_registry import OperationClass
        with self.assertRaisesRegex(EndpointPolicyError,'unknown_operation'): self.p.authorize('notReal',self.ctx(),expected_class=OperationClass.WRITE_PREVIEW)

class CoordinatorTests(unittest.TestCase):
    def setUp(self):
        self.td=tempfile.TemporaryDirectory(); store=PersistentWriteStore(Path(self.td.name)/'w.db'); self.c=WriteCoordinator(store,WriteEndpointPolicy(FixedWindowEndpointLimiter(limit=100,clock=Clock()))); self.ctx=EndpointContext(True,A,False); self.commit_ctx=EndpointContext(True,A,True)
    def tearDown(self): self.td.cleanup()
    def test_preview_does_not_call_external_write(self):
        p=self.c.preview('previewTelegramSend',self.ctx,{'target':'@target_user','text':'draft'},now=100); self.assertEqual(p.action.value,'SEND')
    def test_send_commit_exact_action(self):
        p=self.c.preview('previewTelegramSend',self.ctx,{'target':'@target_user','text':'draft'},now=100); calls=[]; r=self.c.commit('commitTelegramSend',self.commit_ctx,preview_token=p.token,idempotency_key='idem-key-001',external_write=lambda x:(calls.append(x) or {'id':1}),now=101); self.assertEqual(r.state,'COMMITTED'); self.assertEqual(len(calls),1)
    def test_reply_preview_cannot_commit_at_send_endpoint(self):
        p=self.c.preview('previewTelegramReply',self.ctx,{'target':'@target_user','text':'r','reply_to_message_id':10},now=100)
        with self.assertRaisesRegex(WriteSafetyError,'preview_action_mismatch'): self.c.commit('commitTelegramSend',self.commit_ctx,preview_token=p.token,idempotency_key='idem-key-001',external_write=lambda x:{'id':1},now=101)
    def test_send_preview_cannot_commit_at_reply_endpoint(self):
        p=self.c.preview('previewTelegramSend',self.ctx,{'target':'@target_user','text':'s'},now=100)
        with self.assertRaisesRegex(WriteSafetyError,'preview_action_mismatch'): self.c.commit('commitTelegramReply',self.commit_ctx,preview_token=p.token,idempotency_key='idem-key-001',external_write=lambda x:{'id':1},now=101)
    def test_forward_bound_exactly(self):
        p=self.c.preview('previewTelegramForward',self.ctx,{'source':'@source_user','target':'@target_user','message_ids':[20,21]},now=100); self.assertEqual(p.payload['message_ids'],[20,21])
    def test_files_public_file_ref_maps_to_opaque_store_key(self):
        p=self.c.preview('previewTelegramFiles',self.ctx,{'target':'@target_user','files':[{'file_ref':'opaque','sha256':'a'*64,'size':1}]},now=100); self.assertEqual(p.payload['files'][0]['file_id'],'opaque'); self.assertNotIn('file_ref',p.payload['files'][0])
    def test_commit_without_explicit_command_never_calls_external(self):
        p=self.c.preview('previewTelegramSend',self.ctx,{'target':'@target_user','text':'draft'},now=100); calls=[]
        with self.assertRaisesRegex(EndpointPolicyError,'explicit_user_commit_required'): self.c.commit('commitTelegramSend',self.ctx,preview_token=p.token,idempotency_key='idem-key-001',external_write=lambda x:(calls.append(1) or {'id':1}),now=101)
        self.assertEqual(calls,[])
    def test_unauth_preview_does_not_create_preview(self):
        with self.assertRaises(EndpointPolicyError): self.c.preview('previewTelegramSend',EndpointContext(False,A),{'target':'x','text':'y'},now=100)
    def test_idempotent_retry_via_coordinator(self):
        p=self.c.preview('previewTelegramSend',self.ctx,{'target':'@target_user','text':'draft'},now=100); calls=[]; self.c.commit('commitTelegramSend',self.commit_ctx,preview_token=p.token,idempotency_key='idem-key-001',external_write=lambda x:(calls.append(1) or {'id':1}),now=101); r=self.c.commit('commitTelegramSend',self.commit_ctx,preview_token=p.token,idempotency_key='idem-key-001',external_write=lambda x:(calls.append(2) or {'id':2}),now=999); self.assertTrue(r.idempotent_replay); self.assertEqual(calls,[1])

class StructuredErrorTests(unittest.TestCase):
    def test_policy_error_no_message(self):
        e=EndpointPolicyError('rate_limited',status=429,retry_after_seconds=3); self.assertEqual(structured_write_error(e),{'error':'rate_limited','status':429,'retry_after_seconds':3})
    def test_write_error_no_raw_text(self): self.assertEqual(structured_write_error(WriteSafetyError('expired_preview',status=409)),{'error':'expired_preview','status':409})
    def test_unknown_error_redacted(self): self.assertEqual(structured_write_error(RuntimeError('/home/private/session PRIVATE BODY')),{'error':'internal_bridge_error','status':500})
    def test_foreign_error_cannot_spoof_retry_metadata(self):
        class X(Exception): code='telegram_flood_wait'; status=429; retry_after=9999
        self.assertEqual(structured_write_error(X()),{'error':'internal_bridge_error','status':500})
    def test_reviewed_telegram_retry_metadata_is_bounded(self):
        self.assertEqual(
            structured_write_error(TelegramContractError('telegram_flood_wait',status=429,retry_after=600)),
            {'error':'telegram_flood_wait','status':429,'retry_after_seconds':600},
        )
        self.assertEqual(
            structured_write_error(TelegramContractError('telegram_flood_wait',status=429,retry_after=601)),
            {'error':'telegram_flood_wait','status':429},
        )

if __name__=='__main__': unittest.main()
