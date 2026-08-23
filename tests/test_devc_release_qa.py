# -*- coding: utf-8 -*-
from __future__ import annotations
import tempfile
import unittest
from pathlib import Path
from ops.devc_release_qa import assess_release_root, keyboard_nvda_protocol, release_live_protocols, remaining_gate_classes, validate_dependency_envelope, validate_passenger_wsgi_source, validate_prepared_release_metadata
from ops.production_readiness import build_deployment_readiness, validate_support_return
from ops.release_guard import SafetyError

ROOT = Path(__file__).resolve().parents[1]
SHA = "a" * 40
HASH = "b" * 64


def prepared_payload():
    return {"schema_version":2,"repository":"Oleksii-debug/Telegram-ChatGPT-Bridge","approved_ref":"refs/heads/work3/integration-release-candidate","sha":SHA,"configured_python_version":"3.11.16","python_version":"3.11.16","approved_python_identity":{"canonical_path":"/opt/python/bin/python3.11","version":"3.11.16","sha256":HASH,"size":1,"uid":1000,"gid":1000,"mode":493},"source_manifest_sha256":HASH,"requirements_lock_sha256":HASH,"requirements_test_lock_sha256":None,"payload_manifest_sha256":HASH,"runtime_entries":["var"],"persistent_state_mode":"shared_external","immutable_permission_policy":"no-write-bits-v1"}


def legacy_live_support_return():
    return {"schema_version":1,"candidate_sha":SHA,"evidence_classes":{"source":"PRIVATE_SERVER_EVIDENCE","runtime":"PRIVATE_SERVER_EVIDENCE","lifecycle":"PRIVATE_SERVER_EVIDENCE"},"server_manifest":{"artifact_sha256":HASH,"manifest_sha256":HASH,"file_count":42},"reconciliation":{"artifact_sha256":HASH,"status":"EXACT_ACCOUNTED","server_file_count":42,"candidate_file_count":100,"unreviewed_difference_count":0,"startup_accounted":True},"runtime":{"artifact_sha256":HASH,"collector_context":"APPLICATION_PROCESS","python_major_minor":"3.11","runtime_compliance":"PYTHON_3_11_APPLICATION_CONTEXT_CONFIRMED","application_import_ok":True,"passenger_context_present":True,"wsgi_sha256":HASH},"lifecycle":{"mode":"LIVE_SERVER","candidate_sha":SHA,"backup":"PASS","restart":"PASS","running_identity":"PASS","health":"PASS","unauth_smoke":"PASS","auth_smoke":"PASS","resume":"PASS","rollback":"PASS"},"privacy":{"private_values_copied":False,"raw_response_copied":False}}


class ReleasePackageIndependentTests(unittest.TestCase):
    def test_current_release_package_contract_ready_for_prepare(self):
        r = assess_release_root(ROOT)
        self.assertEqual("READY_FOR_PREPARE", r.status, r)
        self.assertEqual((), r.defect_codes)
        self.assertEqual((1,4),(r.direct_requirement_count,r.locked_requirement_count))

    def test_actual_wsgi_exact_and_negatives_fail_closed(self):
        source=(ROOT/"passenger_wsgi.py").read_text(encoding="utf-8")
        self.assertEqual([],validate_passenger_wsgi_source(source))
        self.assertIn("PASSENGER_WSGI_STATEMENT_SET_MISMATCH",validate_passenger_wsgi_source('from bridge.app import application\n__all__=["application"]\n'))
        self.assertIn("PASSENGER_WSGI_APPLICATION_IMPORT_MISMATCH",validate_passenger_wsgi_source(source.replace("from bridge.app import application","from bridge.integrated_app import application")))
        self.assertIn("PASSENGER_WSGI_STATEMENT_SET_MISMATCH",validate_passenger_wsgi_source(source+"\napplication()\n"))
        self.assertIn("PASSENGER_WSGI_PRIVATE_MATERIAL",validate_passenger_wsgi_source(source+"\n# TG_API_HASH forbidden marker\n"))
        self.assertIn("PASSENGER_WSGI_EVIDENCE_CALL_MISMATCH",validate_passenger_wsgi_source(source.replace("app_root=_here.parent, wsgi_file=_here","wsgi_file=_here, app_root=_here.parent")))

    def test_dependency_actual_and_negative_matrix(self):
        req=(ROOT/"requirements.txt").read_text(encoding="utf-8"); lock=(ROOT/"requirements.lock").read_text(encoding="utf-8")
        self.assertEqual(([],1,4),validate_dependency_envelope(req,lock))
        h="c"*64
        cases=((None,None,{"REQUIREMENTS_INPUT_MISSING","REQUIREMENTS_LOCK_MISSING"}),("Telethon>=1,<2\n",f"Telethon==1.44.0 --hash=sha256:{h}\n",{"REQUIREMENTS_INPUT_NOT_EXACT_PIN"}),("Telethon==1.44.0\n","Telethon==1.44.0\n",{"REQUIREMENTS_LOCK_NOT_EXACT_HASH_PIN"}),("Telethon==1.43.0\n",f"Telethon==1.44.0 --hash=sha256:{h}\n",{"DIRECT_RUNTIME_SET_MISMATCH","DIRECT_LOCK_VERSION_MISMATCH"}),("Telethon==1.44.0\n",f"Telethon==1.44.0 --hash=sha256:{h}\n",{"LOCKED_RUNTIME_CLOSURE_MISMATCH"}))
        for a,b,expected in cases:
            with self.subTest(expected=expected): self.assertTrue(expected.issubset(set(validate_dependency_envelope(a,b)[0])))

    def test_private_runtime_artifact_detected(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t)
            for n in ("passenger_wsgi.py","requirements.txt","requirements.lock"): (root/n).write_text((ROOT/n).read_text(encoding="utf-8"),encoding="utf-8")
            (root/"private").mkdir(); (root/"private"/"runtime.session").write_text("placeholder",encoding="utf-8")
            self.assertIn("PRIVATE_RUNTIME_ARTIFACT_IN_RELEASE",assess_release_root(root).defect_codes)


class PreparedAndCrossLaneTruthTests(unittest.TestCase):
    def test_prepared_metadata_positive_and_fail_closed(self):
        self.assertEqual([],validate_prepared_release_metadata(prepared_payload(),SHA))
        p=prepared_payload(); p["sha"]="d"*40; p["requirements_lock_sha256"]="bad"; p["python_version"]="3.12.0"; p["immutable_permission_policy"]="mutable"
        d=set(validate_prepared_release_metadata(p,SHA))
        self.assertTrue({"PREPARED_METADATA_STALE_SHA","PREPARED_METADATA_HASH_MISSING_OR_INVALID","PREPARED_METADATA_BUILT_PYTHON_INVALID","PREPARED_METADATA_IMMUTABILITY_POLICY_INVALID"}.issubset(d))
        p=prepared_payload(); p["unexpected"]=True
        self.assertEqual(["PREPARED_METADATA_SCHEMA_MISMATCH"],validate_prepared_release_metadata(p,SHA))

    def test_current_legacy_v1_runtime_gate_lacks_exact_candidate_binding(self):
        payload=legacy_live_support_return(); validated=validate_support_return(payload)
        self.assertEqual(1,validated["schema_version"])
        readiness=build_deployment_readiness(payload)
        self.assertEqual("PASS",readiness["checks"]["passenger_python_311"]["status"])
        self.assertFalse(readiness["promotion_authorized"])
        self.assertEqual("BLOCKED_EXTERNAL",readiness["checks"]["independent_auditor_gate"]["status"])

    def test_newer_v2_shape_is_not_currently_accepted(self):
        p=legacy_live_support_return(); p["schema_version"]=2; p["runtime"]["payload_sha256"]=HASH
        p["candidate_package"]={"identity_artifact_sha256":HASH,"manifest_sha256":HASH,"wsgi_sha256":HASH,"requirements_lock_sha256":HASH,"package_preflight_pass":True}
        p["runtime_binding"]={"artifact_sha256":HASH,"candidate_sha":SHA,"expected_wsgi_sha256":HASH,"actual_wsgi_sha256":HASH,"runtime_payload_sha256":HASH,"binding_valid":True}
        with self.assertRaises(SafetyError): validate_support_return(p)


class ProtocolTruthTests(unittest.TestCase):
    def test_hk_protocols_never_execute_and_k5_stays_locked(self):
        p=release_live_protocols(); self.assertEqual({"H1","H2","H3","H4","H5","K1","K2","K3","K4","K5"},set(p)); self.assertTrue(all(x.execute_now is False for x in p.values()))
        for gate in ("INDEPENDENT_AUDITOR_WRITE_APPROVAL","SAFE_DESTINATION_CONFIRMED","FRESH_EXPLICIT_USER_COMMIT"): self.assertIn(gate,p["K5"].required_gates)

    def test_nvda_is_human_live_only_and_gate_order_exact(self):
        steps=keyboard_nvda_protocol(); self.assertTrue(any("KEYBOARD_ONLY" in s for s in steps)); self.assertTrue(any("NVDA" in s for s in steps)); self.assertTrue(any("WITHOUT_MOUSE" in s for s in steps))
        self.assertEqual(("INTERNAL_RELEASE_BLOCKER","HOSTIQ_LIVE","TELEGRAM_AUTH_E2E","DEPLOYED_ACTION","HUMAN_NVDA","K5"),remaining_gate_classes())

if __name__ == "__main__": unittest.main()
