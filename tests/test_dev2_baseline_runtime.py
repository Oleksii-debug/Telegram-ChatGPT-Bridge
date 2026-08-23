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


class FakeVersionInfo:
    def __init__(self, major, minor):
        self.major=major; self.minor=minor
    def __getitem__(self, key):
        values=(self.major,self.minor,0,"final",0)
        return values[key]


def sha(data=b"x"):
    return hashlib.sha256(data).hexdigest()


def manifest_for(files):
    return "".join(f"{sha(data)}  {name}\n" for name,data in files.items() if name != snapshot_candidate.MANIFEST_NAME)


def make_reference_zip(path: Path, files=None, *, add_unmanifested=None, bad_manifest=None, symlink_name=None):
    files = dict(files or {
        "bridge/app.py": b"application = object()\n",
        "passenger_wsgi.py": b"from bridge.app import application\n",
        "install_server.sh": b"",
        "requirements.txt": b"Telethon==1.44.0\n",
        "tests/test_core.py": b"pass\n",
        "tools/server_selftest.py": b"pass\n",
    })
    manifest=(bad_manifest.encode() if bad_manifest is not None else manifest_for(files).encode())
    with zipfile.ZipFile(path,"w") as z:
        for name,data in files.items(): z.writestr(name,data)
        z.writestr(snapshot_candidate.MANIFEST_NAME, manifest)
        if add_unmanifested: z.writestr(add_unmanifested,b"extra")
        if symlink_name:
            info=zipfile.ZipInfo(symlink_name); info.create_system=3; info.external_attr=(stat.S_IFLNK|0o777)<<16
            z.writestr(info,b"target")
    return path


class SnapshotCandidateTests(unittest.TestCase):
    def test_real_reference_inventory_and_candidate(self):
        z=Path("/mnt/data/Telegram_Bridge_HOSTiQ_CURRENT_SANITIZED_v0.4.zip")
        if not z.exists(): self.skipTest("project reference unavailable")
        r=snapshot_candidate.validate_reference_zip(z,run_secret_scan=False)
        self.assertEqual(44,r["package_file_count"]); self.assertEqual(43,r["manifest_entry_count"])
        self.assertEqual(22,r["candidate_file_count"]); self.assertEqual(2,r["package_vs_live_count_delta"])
        self.assertFalse(r["exact_live_path_bijection_proven"]); self.assertFalse(r["deploy_authority"])
        self.assertEqual("passenger_wsgi.py",r["known_changed_startup"]); self.assertEqual("install_server.sh",r["known_empty_extra"])
        paths={x["path"] for x in r["candidate_files"]}
        self.assertIn("bridge/app.py",paths); self.assertIn("tools/server_selftest.py",paths)
        self.assertNotIn("tools/google_drive_authorize_windows.py",paths)
    def test_manifest_hash_mismatch_blocks(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/"x.zip"; files={"passenger_wsgi.py":b"from bridge.app import application\n","install_server.sh":b""}
            make_reference_zip(p,files,bad_manifest="0"*64+"  passenger_wsgi.py\n"+sha(b"")+"  install_server.sh\n")
            with self.assertRaises(Exception): snapshot_candidate.validate_reference_zip(p,run_secret_scan=False)
    def test_unmanifested_file_blocks(self):
        with tempfile.TemporaryDirectory() as td:
            p=make_reference_zip(Path(td)/"x.zip",add_unmanifested="surprise.py")
            with self.assertRaises(Exception): snapshot_candidate.validate_reference_zip(p,run_secret_scan=False)
    def test_manifest_self_reference_blocks(self):
        with self.assertRaises(Exception): snapshot_candidate.parse_manifest("0"*64+"  MANIFEST_SANITIZED_SHA256.txt\n")
    def test_manifest_duplicate_blocks(self):
        line=sha(b"x")+"  bridge/app.py\n"
        with self.assertRaises(Exception): snapshot_candidate.parse_manifest(line+line)
    def test_manifest_case_collision_blocks(self):
        text=sha(b"x")+"  Bridge/app.py\n"+sha(b"y")+"  bridge/app.py\n"
        with self.assertRaises(Exception): snapshot_candidate.parse_manifest(text)
    def test_path_traversal_blocks(self):
        for value in ("../x","a/../x","/abs","a\\b","a/./b",""):
            with self.subTest(value=value), self.assertRaises(Exception): snapshot_candidate.canonical_path(value)
    def test_non_nfc_path_blocks(self):
        with self.assertRaises(Exception): snapshot_candidate.canonical_path("docs/e\u0301.txt")
    def test_zip_symlink_blocks(self):
        with tempfile.TemporaryDirectory() as td:
            p=make_reference_zip(Path(td)/"x.zip",symlink_name="badlink")
            with self.assertRaises(Exception): snapshot_candidate.validate_reference_zip(p,run_secret_scan=False)
    def test_nonempty_install_server_blocks(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/"x.zip"; make_reference_zip(p,{"passenger_wsgi.py":b"from bridge.app import application\n","install_server.sh":b"echo nope\n"})
            with self.assertRaises(Exception): snapshot_candidate.validate_reference_zip(p,run_secret_scan=False)
    def test_wrong_passenger_import_blocks(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/"x.zip"; make_reference_zip(p,{"passenger_wsgi.py":b"from wrong.app import application\n","install_server.sh":b""})
            with self.assertRaises(Exception): snapshot_candidate.validate_reference_zip(p,run_secret_scan=False)
    def test_secret_scan_finding_blocks(self):
        with tempfile.TemporaryDirectory() as td:
            p=make_reference_zip(Path(td)/"x.zip")
            fake=types.SimpleNamespace(scan_directory=lambda *a,**k:["finding"])
            with mock.patch.object(snapshot_candidate,"secret_scan",fake):
                with self.assertRaises(Exception): snapshot_candidate.validate_reference_zip(p,run_secret_scan=True)
    def test_candidate_provenance_is_reference_only(self):
        with tempfile.TemporaryDirectory() as td:
            p=make_reference_zip(Path(td)/"x.zip"); r=snapshot_candidate.validate_reference_zip(p,run_secret_scan=False)
            out=Path(td)/"candidate"; marker=snapshot_candidate.emit_candidate_tree(p,out,r)
            self.assertFalse(marker["deploy_authority"]); self.assertFalse(marker["exact_live_path_bijection_proven"])
            self.assertEqual(snapshot_candidate.REFERENCE_MARKER,marker["reference_marker"])
            self.assertTrue((out/"CANDIDATE_PROVENANCE.json").is_file())
    def test_windows_drive_tools_excluded_from_server_candidate(self):
        entry=snapshot_candidate.ManifestEntry("tools/google_drive_authorize_windows.py",sha(),1,"tooling")
        self.assertFalse(snapshot_candidate.is_server_candidate_path(entry))
    def test_committed_provenance_is_strictly_non_authoritative(self):
        p=Path(__file__).resolve().parents[1] / "reference_candidate/hostiq_v0_4/CANDIDATE_PROVENANCE.json"
        payload=json.loads(p.read_text(encoding="utf-8")); out=snapshot_candidate.validate_candidate_provenance(payload)
        self.assertFalse(out["raw_source_public_commit_authorized"]); self.assertFalse(out["deploy_authority"])
    def test_provenance_cannot_be_mutated_to_deploy_authority(self):
        p=Path(__file__).resolve().parents[1] / "reference_candidate/hostiq_v0_4/CANDIDATE_PROVENANCE.json"
        payload=json.loads(p.read_text(encoding="utf-8")); payload["deploy_authority"]=True
        self.assertRaises(Exception,snapshot_candidate.validate_candidate_provenance,payload)


class ManifestReconciliationTests(unittest.TestCase):
    def m(self, rows): return {"schema_version":1,"files":rows}
    def row(self,path,data=b"x",category="application_source"): return {"path":path,"sha256":sha(data),"size":len(data),"category":category}
    def test_exact_bijection(self):
        m=self.m([self.row("bridge/app.py"),self.row("passenger_wsgi.py",b"p","wsgi_startup")])
        r=baseline_reconcile.reconcile_manifests(m,m); self.assertTrue(r["full_bijection"]); self.assertEqual(2,r["exact_count"])
    def test_hash_change_reported(self):
        a=self.m([self.row("bridge/app.py",b"a")]); b=self.m([self.row("bridge/app.py",b"b")])
        self.assertEqual(["bridge/app.py"],baseline_reconcile.reconcile_manifests(a,b)["changed_paths"])
    def test_only_server_and_candidate_reported(self):
        a=self.m([self.row("a.py")]); b=self.m([self.row("b.py")]); r=baseline_reconcile.reconcile_manifests(a,b)
        self.assertEqual(["a.py"],r["only_server_paths"]); self.assertEqual(["b.py"],r["only_candidate_paths"])
    def test_category_change_reported(self):
        a=self.m([self.row("x.py",category="application_source")]); b=self.m([self.row("x.py",category="tooling")])
        self.assertEqual(["x.py"],baseline_reconcile.reconcile_manifests(a,b)["category_changed_paths"])
    def test_case_collision_blocks(self):
        m=self.m([self.row("A.py"),self.row("a.py")])
        with self.assertRaises(Exception): baseline_reconcile.normalize_nonsecret_manifest(m)
    def test_traversal_blocks(self):
        with self.assertRaises(Exception): baseline_reconcile.normalize_nonsecret_manifest(self.m([self.row("../x")]))
    def test_private_runtime_path_blocks(self):
        for p in ("var/state.json","sessions/x.txt","private/config.json","x.session","app.log","private_config.json"):
            with self.subTest(path=p), self.assertRaises(Exception): baseline_reconcile.normalize_nonsecret_manifest(self.m([self.row(p)]))
    def test_invalid_category_blocks(self):
        with self.assertRaises(Exception): baseline_reconcile.normalize_nonsecret_manifest(self.m([self.row("x.py",category="private_message")]))
    def test_startup_presence_and_match(self):
        row=self.row("passenger_wsgi.py",b"x","wsgi_startup"); r=baseline_reconcile.reconcile_manifests(self.m([row]),self.m([row]))
        self.assertTrue(r["startup"]["server_present"]); self.assertTrue(r["startup"]["exact_hash_match"])
    def test_output_contains_no_raw_content(self):
        m=self.m([self.row("bridge/app.py")]); r=baseline_reconcile.reconcile_manifests(m,m)
        self.assertFalse(r["raw_file_content_recorded"]); self.assertFalse(r["secret_values_recorded"])


class PrivateEvidenceTests(unittest.TestCase):
    def server(self): return {"schema_version":1,"files":[{"path":"bridge/app.py","sha256":sha(),"size":1,"category":"application_source"}]}
    def test_server_manifest_accepts_hash_only(self): self.assertEqual(1,len(private_evidence.validate_server_manifest(self.server())["files"]))
    def test_server_manifest_bad_hash_blocks(self):
        x=self.server(); x["files"][0]["sha256"]="no"; self.assertRaises(Exception,private_evidence.validate_server_manifest,x)
    def test_server_manifest_case_collision_blocks(self):
        x=self.server(); y=dict(x["files"][0]); y["path"]="BRIDGE/app.py"; x["files"].append(y)
        self.assertRaises(Exception,private_evidence.validate_server_manifest,x)
    def test_private_evidence_shape_rejects_secret_key(self):
        self.assertRaises(Exception,private_evidence._walk_shape,{"token":"abc"})
    def test_private_evidence_shape_rejects_secret_text(self):
        self.assertRaises(Exception,private_evidence._walk_shape,{"safe":"Authorization: Bearer abcdefghijklmnop"})
    def test_private_evidence_depth_limit(self):
        v={"a":{"b":{"c":{"d":{"e":{"f":{"g":1}}}}}}}
        self.assertRaises(Exception,private_evidence._walk_shape,v)
    def test_ingestion_public_summary_omits_paths(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/"m.json"; p.write_text(json.dumps(self.server()),encoding="utf-8")
            r=private_evidence.ingest_private_evidence_file(p,"server_manifest")
            self.assertEqual(1,r["file_count"]); self.assertNotIn("files",r); self.assertFalse(r["private_values_copied"])


class RuntimeEvidenceTests(unittest.TestCase):
    def setup_root(self,td):
        root=Path(td); wsgi=root/"passenger_wsgi.py"; wsgi.write_text("from bridge.app import application\n",encoding="utf-8"); return root,wsgi
    def fake_module(self): return types.SimpleNamespace(application=object())
    def test_cli_on_current_python_is_never_strong_passenger_proof(self):
        with tempfile.TemporaryDirectory() as td, mock.patch.object(runtime_evidence.importlib,"import_module",return_value=self.fake_module()):
            root,wsgi=self.setup_root(td); r=runtime_evidence.collect_runtime_evidence(app_root=root,wsgi_file=wsgi)
            self.assertNotEqual("PYTHON_3_11_APPLICATION_CONTEXT_CONFIRMED",r["runtime_compliance"])
            self.assertTrue(runtime_evidence.system_shell_cannot_prove_passenger(r))
    def test_python_311_cli_is_candidate_only(self):
        with tempfile.TemporaryDirectory() as td, mock.patch.object(runtime_evidence.importlib,"import_module",return_value=self.fake_module()), mock.patch.object(runtime_evidence.sys,"version_info",FakeVersionInfo(3,11)), mock.patch.object(runtime_evidence.platform,"python_version",return_value="3.11.99"):
            root,wsgi=self.setup_root(td); r=runtime_evidence.collect_runtime_evidence(app_root=root,wsgi_file=wsgi,application_process=False)
            self.assertEqual("PYTHON_3_11_CANDIDATE_CONTEXT",r["runtime_compliance"]); self.assertTrue(runtime_evidence.system_shell_cannot_prove_passenger(r))
    def test_application_context_and_fake_passenger_env_are_still_candidate_only(self):
        with tempfile.TemporaryDirectory() as td, mock.patch.object(runtime_evidence.importlib,"import_module",return_value=self.fake_module()), mock.patch.object(runtime_evidence.sys,"version_info",FakeVersionInfo(3,11)), mock.patch.object(runtime_evidence.platform,"python_version",return_value="3.11.99"), mock.patch.dict(os.environ,{"PASSENGER_APP_ENV":"production"},clear=False):
            root,wsgi=self.setup_root(td); r=runtime_evidence.collect_runtime_evidence(app_root=root,wsgi_file=wsgi,application_process=True)
            self.assertEqual("PYTHON_3_11_CANDIDATE_CONTEXT",r["runtime_compliance"]); self.assertFalse(r["serving_request_verified"]); self.assertTrue(runtime_evidence.system_shell_cannot_prove_passenger(r))
    def test_application_boolean_without_passenger_signal_is_not_enough(self):
        with tempfile.TemporaryDirectory() as td, mock.patch.object(runtime_evidence.importlib,"import_module",return_value=self.fake_module()), mock.patch.object(runtime_evidence.sys,"version_info",FakeVersionInfo(3,11)), mock.patch.object(runtime_evidence.platform,"python_version",return_value="3.11.99"), mock.patch.dict(os.environ,{},clear=True):
            root,wsgi=self.setup_root(td); r=runtime_evidence.collect_runtime_evidence(app_root=root,wsgi_file=wsgi,application_process=True)
            self.assertEqual("PYTHON_3_11_CANDIDATE_CONTEXT",r["runtime_compliance"])
    def test_non_311_is_noncompliant(self):
        with tempfile.TemporaryDirectory() as td, mock.patch.object(runtime_evidence.importlib,"import_module",return_value=self.fake_module()), mock.patch.object(runtime_evidence.sys,"version_info",FakeVersionInfo(3,6)), mock.patch.object(runtime_evidence.platform,"python_version",return_value="3.6.8"):
            root,wsgi=self.setup_root(td); r=runtime_evidence.collect_runtime_evidence(app_root=root,wsgi_file=wsgi)
            self.assertEqual("NONCOMPLIANT_NOT_PYTHON_3_11",r["runtime_compliance"])
    def test_wsgi_outside_root_blocks(self):
        with tempfile.TemporaryDirectory() as td:
            base=Path(td); root=base/"app"; root.mkdir(); other=base/"passenger_wsgi.py"; other.write_text("x")
            self.assertRaises(Exception,runtime_evidence.collect_runtime_evidence,app_root=root,wsgi_file=other)
    def test_wrong_wsgi_name_blocks(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); wsgi=root/"wrong.py"; wsgi.write_text("x")
            self.assertRaises(Exception,runtime_evidence.collect_runtime_evidence,app_root=root,wsgi_file=wsgi)
    def test_wrong_import_target_blocks(self):
        with tempfile.TemporaryDirectory() as td:
            root,wsgi=self.setup_root(td)
            self.assertRaises(Exception,runtime_evidence.collect_runtime_evidence,app_root=root,wsgi_file=wsgi,application_module="wrong")
    def test_report_has_integrity_hash_and_no_env_values(self):
        with tempfile.TemporaryDirectory() as td, mock.patch.object(runtime_evidence.importlib,"import_module",return_value=self.fake_module()):
            root,wsgi=self.setup_root(td); r=runtime_evidence.collect_runtime_evidence(app_root=root,wsgi_file=wsgi)
            self.assertEqual(64,len(r["payload_sha256"])); self.assertFalse(r["environment_values_recorded"]); self.assertFalse(r["secret_values_recorded"])
            self.assertNotIn(str(root),json.dumps(r))
    def test_tampered_runtime_report_blocks(self):
        with tempfile.TemporaryDirectory() as td, mock.patch.object(runtime_evidence.importlib,"import_module",return_value=self.fake_module()):
            root,wsgi=self.setup_root(td); r=runtime_evidence.collect_runtime_evidence(app_root=root,wsgi_file=wsgi); r["application_import_ok"]=not r["application_import_ok"]
            self.assertRaises(Exception,private_evidence.validate_runtime_report,r)
    def test_package_schema_cannot_carry_arbitrary_private_field(self):
        with tempfile.TemporaryDirectory() as td, mock.patch.object(runtime_evidence.importlib,"import_module",return_value=self.fake_module()):
            root,wsgi=self.setup_root(td); r=runtime_evidence.collect_runtime_evidence(app_root=root,wsgi_file=wsgi); r["package_evidence"][0]["detail"]="x"; base=dict(r); base.pop("payload_sha256"); r["payload_sha256"]=private_evidence.canonical_json_sha256(base)
            self.assertRaises(Exception,private_evidence.validate_runtime_report,r)
    def test_private_report_permissions(self):
        with tempfile.TemporaryDirectory() as td, mock.patch.object(runtime_evidence.importlib,"import_module",return_value=self.fake_module()):
            root,wsgi=self.setup_root(td); r=runtime_evidence.collect_runtime_evidence(app_root=root,wsgi_file=wsgi); out=root/"private"/"evidence.json"; runtime_evidence.write_private_report(out,r)
            self.assertEqual(0o600,stat.S_IMODE(out.stat().st_mode)); self.assertEqual(0o700,stat.S_IMODE(out.parent.stat().st_mode))




if __name__ == "__main__": unittest.main()
