# -*- coding: utf-8 -*-
import hashlib
import io
import json
import os
import stat
import tempfile
import types
import unittest
import zipfile
from pathlib import Path
from unittest import mock

from ops import baseline_reconcile, hostiq_lifecycle, private_evidence, runtime_evidence, snapshot_candidate

class LifecycleTests(unittest.TestCase):
    def root(self,td):
        root=Path(td)/"private"; root.mkdir(); os.chmod(root,0o700); return root
    def file(self,root,name="hook",content="#!/bin/sh\nexit 0\n",mode=0o700):
        p=root/name; p.write_text(content,encoding="utf-8"); os.chmod(p,mode); return p
    def test_private_hook_accepts_owner_only(self):
        with tempfile.TemporaryDirectory() as td:
            root=self.root(td); p=self.file(root); self.assertEqual(p,hostiq_lifecycle.validate_private_file(root,p,require_executable=True))
    def test_broad_hook_mode_blocks(self):
        with tempfile.TemporaryDirectory() as td:
            root=self.root(td); p=self.file(root,mode=0o744); self.assertRaises(Exception,hostiq_lifecycle.validate_private_file,root,p,require_executable=True)
    def test_broad_root_mode_blocks(self):
        with tempfile.TemporaryDirectory() as td:
            root=self.root(td); os.chmod(root,0o755); p=self.file(root); self.assertRaises(Exception,hostiq_lifecycle.validate_private_file,root,p)
    def test_symlink_file_blocks(self):
        with tempfile.TemporaryDirectory() as td:
            root=self.root(td); target=self.file(root,"target",mode=0o600); link=root/"link"; link.symlink_to(target)
            self.assertRaises(Exception,hostiq_lifecycle.validate_private_file,root,link)
    def test_hardlink_blocks(self):
        with tempfile.TemporaryDirectory() as td:
            root=self.root(td); p=self.file(root,"x",mode=0o600); os.link(p,root/"y")
            self.assertRaises(Exception,hostiq_lifecycle.validate_private_file,root,p)
    def test_path_escape_blocks(self):
        with tempfile.TemporaryDirectory() as td:
            root=self.root(td); outside=Path(td)/"x"; outside.write_text("x"); os.chmod(outside,0o600)
            self.assertRaises(Exception,hostiq_lifecycle.validate_private_file,root,outside)
    def test_hook_success_nonzero_timeout(self):
        with tempfile.TemporaryDirectory() as td:
            root=self.root(td); ok=self.file(root,"ok","#!/bin/sh\nexit 0\n"); bad=self.file(root,"bad","#!/bin/sh\nexit 7\n")
            self.assertEqual("PASS",hostiq_lifecycle.run_private_hook(root,ok,expected_name="restart").status)
            self.assertEqual("HOOK_NONZERO",hostiq_lifecycle.run_private_hook(root,bad,expected_name="restart").detail_code)
            with mock.patch.object(hostiq_lifecycle.subprocess,"run",side_effect=hostiq_lifecycle.subprocess.TimeoutExpired("x",1)):
                self.assertEqual("HOOK_TIMEOUT",hostiq_lifecycle.run_private_hook(root,ok,expected_name="restart").detail_code)
    def test_endpoint_requires_https_production_host(self):
        self.assertEqual("https://tg-api.rukadopomogy.org.ua/health",hostiq_lifecycle.validate_endpoint_url("https://tg-api.rukadopomogy.org.ua/health"))
        for u in ("http://tg-api.rukadopomogy.org.ua/health","https://evil.example/health","file:///etc/passwd","https://u:p@tg-api.rukadopomogy.org.ua/x","https://tg-api.rukadopomogy.org.ua/setup-abcdefghijklmnop"):
            with self.subTest(url=u), self.assertRaises(Exception): hostiq_lifecycle.validate_endpoint_url(u)
    def test_health_200_alone_is_not_enough(self):
        with mock.patch.object(hostiq_lifecycle,"_request",return_value=(200,b"{}","application/json")):
            self.assertEqual("HEALTH_SHAPE",hostiq_lifecycle.health_check("https://tg-api.rukadopomogy.org.ua/health").detail_code)
    def test_health_valid_shape_passes(self):
        with mock.patch.object(hostiq_lifecycle,"_request",return_value=(200,b'{"status":"ok"}',"application/json")):
            self.assertEqual("PASS",hostiq_lifecycle.health_check("https://tg-api.rukadopomogy.org.ua/health").status)
    def test_unauth_reject_and_leak_signature(self):
        with mock.patch.object(hostiq_lifecycle,"_request",return_value=(401,b'{"error":"unauthorized"}',"application/json")):
            self.assertEqual("PASS",hostiq_lifecycle.unauthenticated_smoke("https://tg-api.rukadopomogy.org.ua/private").status)
        with mock.patch.object(hostiq_lifecycle,"_request",return_value=(401,b'Traceback (most recent call last)',"text/plain")):
            self.assertEqual("UNAUTH_LEAK_SIGNATURE",hostiq_lifecycle.unauthenticated_smoke("https://tg-api.rukadopomogy.org.ua/private").detail_code)
    def test_unauth_200_fails(self):
        with mock.patch.object(hostiq_lifecycle,"_request",return_value=(200,b"{}","application/json")):
            self.assertEqual("UNAUTH_NOT_REJECTED",hostiq_lifecycle.unauthenticated_smoke("https://tg-api.rukadopomogy.org.ua/private").detail_code)
    def test_authenticated_smoke_uses_private_token_file_but_returns_no_token(self):
        with tempfile.TemporaryDirectory() as td:
            root=self.root(td); token=self.file(root,"bearer","x"*32,0o600)
            def fake(url,timeout,token=None): self.assertEqual("x"*32,token); return 200,b'{"status":"ready"}',"application/json"
            with mock.patch.object(hostiq_lifecycle,"_request",side_effect=fake):
                r=hostiq_lifecycle.authenticated_smoke("https://tg-api.rukadopomogy.org.ua/private",private_root=root,token_file=token)
            self.assertEqual("PASS",r.status); self.assertNotIn("x"*32,repr(r))
    def test_short_token_reference_fails_closed(self):
        with tempfile.TemporaryDirectory() as td:
            root=self.root(td); token=self.file(root,"bearer","short",0o600)
            self.assertEqual("AUTH_EXCEPTION",hostiq_lifecycle.authenticated_smoke("https://tg-api.rukadopomogy.org.ua/private",private_root=root,token_file=token).detail_code)
    def test_running_identity_match_mismatch(self):
        with tempfile.TemporaryDirectory() as td:
            root=self.root(td); s="a"*40; p=self.file(root,"sha",s,0o600)
            self.assertEqual("IDENTITY_MATCH",hostiq_lifecycle.running_identity(root,p,s).detail_code)
            self.assertEqual("IDENTITY_MISMATCH",hostiq_lifecycle.running_identity(root,p,"b"*40).detail_code)
    def test_verify_serving_state(self):
        P=lambda n:hostiq_lifecycle.HookResult(n,"PASS",None,"OK"); F=hostiq_lifecycle.HookResult("h","FAIL",None,"BAD")
        self.assertEqual("PASS",hostiq_lifecycle.verify_serving_state(health=P("h"),identity=P("i"),unauth=P("u")).status)
        self.assertEqual("FAIL",hostiq_lifecycle.verify_serving_state(health=F,identity=P("i"),unauth=P("u")).status)
    def test_orchestrator_ready_without_rollback(self):
        P=lambda n:lambda:hostiq_lifecycle.HookResult(n,"PASS",0,"OK")
        r=hostiq_lifecycle.orchestrate_lifecycle(restart=P("r"),identity=P("i"),health=P("h"),unauth=P("u"),auth=P("a"),rollback=P("rb"),rollback_health=P("rbh"))
        self.assertEqual("READY_FOR_AUDIT",r["status"]); self.assertFalse(r["rollback_attempted"])
    def test_orchestrator_failure_rolls_back(self):
        P=lambda n:lambda:hostiq_lifecycle.HookResult(n,"PASS",0,"OK"); F=lambda n:lambda:hostiq_lifecycle.HookResult(n,"FAIL",1,"FAIL")
        r=hostiq_lifecycle.orchestrate_lifecycle(restart=P("r"),identity=F("i"),health=P("h"),unauth=P("u"),auth=None,rollback=P("rb"),rollback_health=P("rbh"))
        self.assertEqual("ROLLED_BACK",r["status"]); self.assertTrue(r["rollback_attempted"])
    def test_orchestrator_unhealthy_rollback_is_critical(self):
        P=lambda n:lambda:hostiq_lifecycle.HookResult(n,"PASS",0,"OK"); F=lambda n:lambda:hostiq_lifecycle.HookResult(n,"FAIL",1,"FAIL")
        r=hostiq_lifecycle.orchestrate_lifecycle(restart=F("r"),identity=P("i"),health=P("h"),unauth=P("u"),auth=None,rollback=P("rb"),rollback_health=F("rbh"))
        self.assertEqual("CRITICAL_ROLLBACK_FAILED",r["status"])
    def test_orchestrator_never_copies_arbitrary_hook_detail(self):
        bad=lambda:hostiq_lifecycle.HookResult("anything","FAIL",1,"PRIVATE_LABEL_SHOULD_NOT_COPY")
        good=lambda:hostiq_lifecycle.HookResult("anything","PASS",0,"PRIVATE_LABEL_SHOULD_NOT_COPY")
        r=hostiq_lifecycle.orchestrate_lifecycle(restart=bad,identity=good,health=good,unauth=good,auth=None,rollback=good,rollback_health=good)
        self.assertNotIn("PRIVATE_LABEL_SHOULD_NOT_COPY",json.dumps(r)); self.assertEqual("restart",r["failed_stage"])
    def test_private_hook_name_is_allowlisted(self):
        with tempfile.TemporaryDirectory() as td:
            root=self.root(td); p=self.file(root)
            self.assertRaises(Exception,hostiq_lifecycle.run_private_hook,root,p,expected_name="private-label")

    def test_failure_matrix_complete(self):
        self.assertEqual({"RESTART_FAILURE","IDENTITY_MISMATCH","HEALTH_FAILURE","UNAUTH_SMOKE_FAILURE","AUTH_SMOKE_FAILURE","RESUME_FAILURE","ROLLBACK_HEALTH_FAILURE"},set(hostiq_lifecycle.lifecycle_failure_matrix()))




if __name__ == "__main__": unittest.main()
