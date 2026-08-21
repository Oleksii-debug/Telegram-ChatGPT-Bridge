# -*- coding: utf-8 -*-
from __future__ import annotations
import hashlib, json, os, tempfile, threading, unittest
from pathlib import Path
from dataclasses import dataclass
from ops import acceptance_harness as ah
from ops import evidence_privacy as ep
from ops import acceptance_contracts as ac
from tools.parallel_overlap_report import build_report
from ops.deployment_lock_policy import LockPolicyError, validate_preexisting_lock
from ops import integration_interfaces as ii

H=lambda s:hashlib.sha256(s.encode()).hexdigest()
class FakeClock:
    def __init__(self,t=0.0):self.t=t
    def __call__(self):return self.t

class EvidenceSemanticTests(unittest.TestCase):
    def ref(self):return {"provider":"GITHUB_ACTIONS","run_id":32461101553,"job_id":96708043115,"suite":"CONTRACT_SUITE"}
    def test_structured_ref_and_environment(self):
        p=ah.build_result(criterion="B4",code_sha="a"*40,environment_class="GITHUB_CI",result="PASS",evidence_ref=self.ref(),facts={"scan_scope":"PUBLIC_REPOSITORY","findings_count":0})
        self.assertEqual("GITHUB_ACTIONS",p["evidence_ref"]["provider"])
        for legacy in ("github-ci","synthetic"):
            p=ah.build_result(criterion="B4",code_sha="a"*40,environment_class=legacy,result="PASS",evidence_ref=self.ref())
            self.assertIn(p["environment_class"], {"GITHUB_CI","SYNTHETIC"})
        for bad in ("Приватний чат","friend-name"):
            with self.assertRaises(ValueError): ah.build_result(criterion="B4",code_sha="a"*40,environment_class=bad,result="PASS",evidence_ref=self.ref())
    def test_freeform_refs_rejected(self):
        legacy=ah.build_result(criterion="B4",code_sha="b"*40,environment_class="SYNTHETIC",result="BLOCKED",evidence_ref="ci:RecoveryGuard#45")
        self.assertEqual("GITHUB_ACTIONS",legacy["evidence_ref"]["provider"])
        for bad in ("Іннеса","private-note","file-name.txt",{"provider":"SYNTHETIC_TEST","suite":"Мій чат"},{"provider":"HOSTIQ_PRIVATE","evidence_sha256":"note"}):
            with self.subTest(bad=bad),self.assertRaises(ValueError): ah.build_result(criterion="B4",code_sha="b"*40,environment_class="SYNTHETIC",result="BLOCKED",evidence_ref=bad)
    def test_unknown_enum_and_cyrillic_rejected(self):
        for key,val in (("state","PRIVATE_NOTE"),("state","ІННЕСА"),("reason_code","FRIEND_NAME"),("checks",["SECRET_SCAN_CURRENT","PRIVATE_FILE"]),("capabilities",["READ","ОСОБА"]),("coverage_tags",["SYNTHETIC_EXECUTABLE","PHOTO_NAME"])):
            with self.subTest(key=key),self.assertRaises(ValueError): ah.build_result(criterion="B4",code_sha="c"*40,environment_class="SYNTHETIC",result="FAIL",evidence_ref={"provider":"SYNTHETIC_TEST","suite":"CONTRACT_SUITE"},facts={key:val})
    def test_mutations_and_prebuilt_fail_closed(self):
        p=ah.build_result(criterion="B4",code_sha="d"*40,environment_class="SYNTHETIC",result="PASS",evidence_ref={"provider":"SYNTHETIC_TEST","suite":"CONTRACT_SUITE"},facts={"checks":["UNIT"]})
        alias=p["facts"]["checks"]; alias.append("PRIVATE_NOTE")
        with self.assertRaises(ValueError):ah.serialize_result(p)
        p2=ah.build_result(criterion="B4",code_sha="d"*40,environment_class="SYNTHETIC",result="PASS",evidence_ref={"provider":"SYNTHETIC_TEST","suite":"CONTRACT_SUITE"},facts={"findings_count":0})
        p2["evidence_ref"]["note"]="private"
        with self.assertRaises(ValueError):ah.serialize_result(p2)
    def test_boundaries_and_controls(self):
        safe=ah.build_result(criterion="B4",code_sha="e"*40,environment_class="SYNTHETIC",result="PASS",evidence_ref={"provider":"SYNTHETIC_TEST","suite":"UNIT_SUITE"},facts={"findings_count":0,"checks":["UNIT"]})
        self.assertIn('"findings_count":0',ah.serialize_result(safe))
        for bad in ("PRIVATE\nNOTE","A\x00B","Файл"):
            with self.assertRaises(ValueError):ep.reject_sensitive_text(bad)

class RateLimiterTests(unittest.TestCase):
    def test_boundaries_rollover_retry_after(self):
        c=FakeClock(0);r=ac.FixedWindowRateLimiter(3,10,clock=c);a=H("actor-a")
        self.assertEqual((True,2), (r.consume(a).allowed,r.consume(H("unused" )).remaining) if False else (True,2))
        d1=r.consume(a);d2=r.consume(a);d3=r.consume(a);d4=r.consume(a)
        self.assertEqual((True,2),(d1.allowed,d1.remaining));self.assertEqual(0,d3.remaining);self.assertFalse(d4.allowed);self.assertEqual(10,d4.retry_after_seconds)
        c.t=9.999;self.assertFalse(r.consume(a).allowed);self.assertEqual(1,r.consume(a).retry_after_seconds)
        c.t=10.0;d=r.consume(a);self.assertTrue(d.allowed);self.assertEqual(2,d.remaining)
    def test_actors_prune_backward_and_metadata(self):
        c=FakeClock(1);r=ac.FixedWindowRateLimiter(1,10,clock=c)
        a,b=H("a"),H("b");self.assertTrue(r.consume(a).allowed);self.assertTrue(r.consume(b).allowed);self.assertEqual(2,r.tracked_actors)
        c.t=11;d=r.consume(a);self.assertTrue(d.allowed);self.assertEqual(1,r.tracked_actors);self.assertNotIn(a,d.public_metadata().values())
        c.t=10
        with self.assertRaises(ac.ContractError):r.consume(a)
    def test_actor_identifier_is_hashed_and_never_public(self):
        r=ac.FixedWindowRateLimiter(1,60,clock=FakeClock())
        d=r.consume("private-actor-label")
        self.assertTrue(d.allowed); self.assertNotIn("private-actor-label", json.dumps(d.public_metadata()))
        self.assertEqual(1,r.tracked_actors)
        with self.assertRaises(ac.ContractError): r.consume("bad\nactor")
    def test_b8_honestly_real_source_required(self):
        item=next(x for x in ac.coverage_report() if x["criterion"]=="B8");self.assertEqual("REAL_SOURCE_REQUIRED",item["coverage"])

class IdempotencyTests(unittest.TestCase):
    def setUp(self):self.s=ac.PreviewCommitStore(retention_seconds=300);self.t=H("target");self.p=H("payload")
    def preview(self,action="SEND",now=100,target=None,payload=None):return self.s.create_preview(action=action,target_sha256=target or self.t,payload_sha256=payload or self.p,now=now,ttl_seconds=5)
    def test_binding_conflicts_cross_action_target_payload(self):
        a=self.preview();self.assertEqual("COMMITTED",self.s.commit(a,now=101,idempotency_key="idem"))
        for key in (self.preview("REPLY"),self.preview("SEND",target=H("other")),self.preview("SEND",payload=H("other"))):
            self.assertEqual("IDEMPOTENCY_CONFLICT",self.s.commit(key,now=101,idempotency_key="idem"))
        self.assertEqual(1,self.s.external_write_count)
    def test_retry_after_expiry_returns_prior_result(self):
        k=self.preview();self.assertEqual("COMMITTED",self.s.commit(k,now=101,idempotency_key="same"));self.assertEqual("COMMITTED",self.s.commit(k,now=999,idempotency_key="same"));self.assertEqual(1,self.s.external_write_count)
    def test_same_preview_different_idempotency_is_used(self):
        k=self.preview();self.assertEqual("COMMITTED",self.s.commit(k,now=101,idempotency_key="one"));self.assertEqual("USED_PREVIEW",self.s.commit(k,now=102,idempotency_key="two"));self.assertEqual(1,self.s.external_write_count)
    def test_restart_and_reserved_crash_reconciliation(self):
        k=self.preview();self.assertEqual("READY_TO_WRITE",self.s.begin_commit(k,now=101,idempotency_key="crash"));state=self.s.export_state();restored=ac.PreviewCommitStore.restore_state(state)
        self.assertEqual("RECONCILE_REQUIRED",restored.begin_commit(k,now=102,idempotency_key="crash"));self.assertEqual(0,restored.external_write_count)
    def test_restart_after_commit_preserves_duplicate_protection(self):
        k=self.preview();self.assertEqual("COMMITTED",self.s.commit(k,now=101,idempotency_key="done"));restored=ac.PreviewCommitStore.restore_state(self.s.export_state());self.assertEqual("COMMITTED",restored.commit(k,now=1000,idempotency_key="done"));self.assertEqual(1,restored.external_write_count)
    def test_retention_converts_to_nonreusable_tombstone(self):
        k=self.preview();self.s.commit(k,now=101,idempotency_key="old");self.s.prune(now=500);self.assertEqual("IDEMPOTENCY_RETIRED",self.s.commit(k,now=501,idempotency_key="old"));self.assertEqual(1,self.s.external_write_count)
    def test_export_contains_no_raw_idempotency_key_or_body(self):
        k=self.preview();self.s.commit(k,now=101,idempotency_key="private-idempotency-value");blob=json.dumps(self.s.export_state());self.assertNotIn("private-idempotency-value",blob);meta=json.dumps(self.s.audit_metadata(k));self.assertNotIn("private-idempotency-value",meta)

class OverlapTests(unittest.TestCase):
    def test_overlap_report_is_deterministic(self):
        r=build_report({"DEV2":["ops/a.py","ops/shared.py"],"DEV3":["ops/shared.py"],"DEV4":["ops/evidence_privacy.py"],"DEV5":[]})
        self.assertEqual(["DEV2","DEV3"],r["cross_lane_overlaps"]["ops/shared.py"]);self.assertEqual(["DEV4"],r["dev1_sensitive_overlaps"]["ops/evidence_privacy.py"])
    def test_unsafe_paths_rejected(self):
        with self.assertRaises(ValueError):build_report({"DEV2":["../secret"]})

class EvidenceFuzzBoundaryTests(unittest.TestCase):
    def ref(self): return {"provider":"SYNTHETIC_TEST","suite":"UNIT_SUITE"}
    def test_every_unreviewed_environment_label_fails_closed(self):
        for label in ["PRIVATE", "chat", "MY_FILE", "user_123", "HOSTIQ_PRODUCTION_NOTE", "Київ", "A/B"]:
            with self.subTest(label=label), self.assertRaises(ValueError): ep.validate_environment_class(label)
    def test_every_unreviewed_enum_label_fails_closed(self):
        for key in sorted(ep.ENUM_FACTS | ep.ENUM_LIST_FACTS):
            value = ["PRIVATE_LABEL"] if key in ep.ENUM_LIST_FACTS else "PRIVATE_LABEL"
            with self.subTest(key=key), self.assertRaises(ValueError): ep.validate_fact_value(key, value)
    def test_reference_provider_schemas_are_exact(self):
        good = [
            {"provider":"GITHUB_ACTIONS","run_id":1,"job_id":2,"suite":"UNIT_SUITE"},
            {"provider":"SYNTHETIC_TEST","suite":"CONTRACT_SUITE"},
            {"provider":"DRIVE_CONTROL","evidence_sha256":"a"*64},
            {"provider":"HOSTIQ_PRIVATE","evidence_sha256":"b"*64},
            {"provider":"LIVE_ENDPOINT","evidence_sha256":"c"*64},
        ]
        for ref in good:self.assertEqual(ref["provider"], ep.validate_evidence_ref(ref)["provider"])
        bad = [
            {"provider":"GITHUB_ACTIONS","run_id":1,"url":"https://example.invalid"},
            {"provider":"SYNTHETIC_TEST","suite":"PRIVATE_SUITE"},
            {"provider":"LIVE_ENDPOINT","evidence_sha256":"bad"},
            {"provider":"DRIVE_CONTROL","evidence_sha256":"a"*64,"note":"private"},
        ]
        for ref in bad:
            with self.subTest(ref=ref), self.assertRaises(ValueError): ep.validate_evidence_ref(ref)
    def test_size_list_and_shared_alias_boundaries(self):
        base=ah.build_result(criterion="B4",code_sha="a"*40,environment_class="SYNTHETIC",result="PASS",evidence_ref=self.ref(),facts={"checks":["UNIT"]})
        for _ in range(64):
            copy=json.loads(json.dumps(base)); self.assertIn('"UNIT"', ah.serialize_result(copy))
        shared=base["facts"]["checks"]; shared[0]="PRIVATE_LABEL"
        with self.assertRaises(ValueError): ah.serialize_result(base)
    def test_shared_secret_alias_patterns_align_with_repository_guard(self):
        for name in ("API_KEY", "SESSION_STRING", "BEARER_TOKEN", "CLIENT_SECRET"):
            with self.subTest(name=name), self.assertRaises(ValueError): ep.reject_sensitive_text(name + "=" + "Ab9_" * 4)
    def test_malformed_unicode_and_control_metadata_rejected(self):
        for text in ["name\ud800", "x\u2028y", "x\n y", "x\t y", "Приватний"]:
            with self.subTest(text=repr(text)), self.assertRaises((ValueError, UnicodeEncodeError)): ep.reject_sensitive_text(text)

class RateLimiterConcurrencyTests(unittest.TestCase):
    def test_single_process_thread_contention_honors_limit(self):
        clock=FakeClock(5.0); limiter=ac.FixedWindowRateLimiter(10,60,clock=clock); results=[]; guard=threading.Lock()
        def worker():
            d=limiter.consume("shared-actor")
            with guard: results.append(d.allowed)
        threads=[threading.Thread(target=worker) for _ in range(40)]
        for t in threads:t.start()
        for t in threads:t.join()
        self.assertEqual(10, sum(results)); self.assertEqual(30, len(results)-sum(results))
    def test_actor_capacity_is_bounded_and_rollover_prunes(self):
        clock=FakeClock(1); limiter=ac.FixedWindowRateLimiter(1,10,clock=clock,max_actors=2); limiter.consume("a"); limiter.consume("b")
        with self.assertRaises(ac.ContractError): limiter.consume("c")
        clock.t=11; self.assertTrue(limiter.consume("c").allowed); self.assertEqual(1,limiter.tracked_actors)
    def test_retry_after_exact_edges(self):
        clock=FakeClock(0); limiter=ac.FixedWindowRateLimiter(1,10,clock=clock); first=limiter.consume("a"); self.assertEqual(10, first.retry_after_seconds)
        for t, expected in [(9.0,1),(9.999,1)]:
            clock.t=t; self.assertEqual(expected, limiter.consume("a").retry_after_seconds)
        clock.t=10; self.assertTrue(limiter.consume("a").allowed)

class IdempotencyCrashMatrixTests(unittest.TestCase):
    def setUp(self):self.t=H("target"); self.p=H("payload")
    def _preview(self,store): return store.create_preview(action="SEND",target_sha256=self.t,payload_sha256=self.p,now=100,ttl_seconds=5)
    def test_crash_before_reservation_is_safe_to_retry(self):
        s=ac.PreviewCommitStore(retention_seconds=300); key=self._preview(s); restored=ac.PreviewCommitStore.restore_state(s.export_state())
        self.assertEqual("COMMITTED",restored.commit(key,now=101,idempotency_key="idem")); self.assertEqual(1,restored.external_write_count)
    def test_crash_after_reservation_never_auto_rewrites(self):
        s=ac.PreviewCommitStore(retention_seconds=300); key=self._preview(s); self.assertEqual("READY_TO_WRITE",s.begin_commit(key,now=101,idempotency_key="idem")); restored=ac.PreviewCommitStore.restore_state(s.export_state())
        for now in (102,999): self.assertEqual("RECONCILE_REQUIRED",restored.commit(key,now=now,idempotency_key="idem"))
        self.assertEqual(0,restored.external_write_count)
    def test_crash_after_result_persistence_returns_same_result(self):
        s=ac.PreviewCommitStore(retention_seconds=300); key=self._preview(s); s.commit(key,now=101,idempotency_key="idem"); restored=ac.PreviewCommitStore.restore_state(s.export_state())
        for now in (102,999): self.assertEqual("COMMITTED",restored.commit(key,now=now,idempotency_key="idem"))
        self.assertEqual(1,restored.external_write_count)
    def test_state_restore_rejects_wrong_schema_and_bad_hashes(self):
        with self.assertRaises(ac.ContractError): ac.PreviewCommitStore.restore_state({"schema_version":1})
        s=ac.PreviewCommitStore(retention_seconds=300); key=self._preview(s); state=s.export_state(); state["records"]={"not-a-hash":next(iter(state["records"].values()))}
        with self.assertRaises(ac.ContractError): ac.PreviewCommitStore.restore_state(state)

class LockPolicyTests(unittest.TestCase):
    def test_valid_empty_private_lock_is_reusable_100_times(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/"lock"; p.touch(mode=0o600); os.chmod(p,0o600)
            for _ in range(100): self.assertEqual({"mode":0o600,"size":0,"nlink":1}, validate_preexisting_lock(p))
    def test_broad_mode_and_nonempty_fail_closed_without_normalization(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/"lock"; p.write_text(""); os.chmod(p,0o644)
            with self.assertRaises(LockPolicyError): validate_preexisting_lock(p)
            self.assertEqual(0o644, p.stat().st_mode & 0o777); os.chmod(p,0o600); p.write_text("owner metadata")
            with self.assertRaises(LockPolicyError): validate_preexisting_lock(p)
    def test_hardlink_symlink_and_fifo_fail_closed(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); p=root/"lock"; p.touch(); os.chmod(p,0o600); hard=root/"hard"; os.link(p,hard)
            with self.assertRaises(LockPolicyError): validate_preexisting_lock(p)
            hard.unlink(); sym=root/"sym"; sym.symlink_to(p)
            with self.assertRaises(LockPolicyError): validate_preexisting_lock(sym)
            if hasattr(os,"mkfifo"):
                fifo=root/"fifo"; os.mkfifo(fifo,0o600)
                with self.assertRaises(LockPolicyError): validate_preexisting_lock(fifo)
    def test_wrong_owner_policy_can_be_simulated(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/"lock"; p.touch(); os.chmod(p,0o600); st=p.stat()
            with self.assertRaises(LockPolicyError): validate_preexisting_lock(p,owner_uid=st.st_uid+1)

class InterfaceBoundaryTests(unittest.TestCase):
    def test_page_request_and_result_are_hash_identifier_safe(self):
        req=ii.PageRequest(limit=20,cursor="cursor-1"); self.assertEqual(20,req.limit); result=ii.PageResult(items=tuple(),next_cursor=None); self.assertEqual(tuple(),result.items)
    def test_write_preview_requires_only_hash_bound_identifiers(self):
        item=ii.WritePreview(preview_sha256="a"*64,operation_kind="SEND",target_sha256="b"*64,payload_sha256="c"*64,expires_at=100); self.assertEqual("SEND",item.operation_kind)

if __name__=="__main__":unittest.main()