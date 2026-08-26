# -*- coding: utf-8 -*-
from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path

from ops.release_guard import SafetyError
from ops.release_package import EXPECTED_RUNTIME_LOCK, validate_dependency_contract
from tools.finalwave35_supply_chain import (
    APPROVED_ARTIFACT_KINDS,
    SupplyChainError,
    audit_prepare_residuals,
    is_lfs_pointer,
    parse_ls_files_stage_z,
    parse_ls_tree_z,
    scan_repository,
    validate_artifact_policy,
    validate_no_import_shadowing,
)

ROOT = Path(__file__).resolve().parents[1]
OID = "a" * 40
CHECKOUT_PIN = "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"
SETUP_PYTHON_PIN = "actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97"


class FinalWave35GitTopologyTests(unittest.TestCase):
    def test_regular_blob_modes_are_accepted(self) -> None:
        raw = (
            f"100644 blob {OID}\tbridge/app.py\0"
            f"100755 blob {OID}\ttools/check.py\0"
        ).encode("ascii")
        entries = parse_ls_tree_z(raw)
        self.assertEqual(("bridge/app.py", "tools/check.py"), tuple(item.path for item in entries))

    def test_symlink_and_gitlink_are_rejected_before_archive_extraction(self) -> None:
        for mode, object_type in (("120000", "blob"), ("160000", "commit")):
            with self.subTest(mode=mode):
                raw = f"{mode} {object_type} {OID}\tshadow\0".encode("ascii")
                with self.assertRaises(SupplyChainError):
                    parse_ls_tree_z(raw)

    def test_nonportable_duplicate_and_traversal_paths_fail_closed(self) -> None:
        cases = (
            f"100644 blob {OID}\t../escape.py\0",
            f"100644 blob {OID}\t/pkg.py\0",
            f"100644 blob {OID}\ta\\b.py\0",
            (
                f"100644 blob {OID}\tName.py\0"
                f"100644 blob {OID}\tname.py\0"
            ),
        )
        for raw in cases:
            with self.subTest(raw=raw):
                with self.assertRaises(SupplyChainError):
                    parse_ls_tree_z(raw.encode("ascii"))

    def test_unmerged_stage_and_nonregular_index_modes_fail_closed(self) -> None:
        with self.assertRaises(SupplyChainError):
            parse_ls_files_stage_z(f"100644 {OID} 2\tbridge/app.py\0".encode("ascii"))
        with self.assertRaises(SupplyChainError):
            parse_ls_files_stage_z(f"120000 {OID} 0\tlink\0".encode("ascii"))
        with self.assertRaises(SupplyChainError):
            parse_ls_files_stage_z(f"160000 {OID} 0\tsubmodule\0".encode("ascii"))

    def test_lfs_pointer_is_rejected_as_unmaterialized_dependency_input(self) -> None:
        pointer = (
            b"version https://git-lfs.github.com/spec/v1\n"
            b"oid sha256:" + b"b" * 64 + b"\n"
            b"size 12345\n"
        )
        self.assertTrue(is_lfs_pointer(pointer))
        self.assertFalse(is_lfs_pointer(b"ordinary source\n"))


class FinalWave35DependencyBoundaryTests(unittest.TestCase):
    def _requirements_root(self) -> tuple[tempfile.TemporaryDirectory, Path]:
        temp = tempfile.TemporaryDirectory()
        root = Path(temp.name)
        shutil.copy2(ROOT / "requirements.txt", root / "requirements.txt")
        shutil.copy2(ROOT / "requirements.lock", root / "requirements.lock")
        return temp, root

    def test_exact_reviewed_artifact_policy_is_three_wheels_one_sdist(self) -> None:
        counts = validate_artifact_policy()
        self.assertEqual({"wheel_count": 3, "sdist_count": 1}, counts)
        self.assertEqual(set(EXPECTED_RUNTIME_LOCK), set(APPROVED_ARTIFACT_KINDS))
        self.assertEqual("sdist", APPROVED_ARTIFACT_KINDS["pyaes"])

    def test_local_editable_url_and_unhashed_dependency_forms_are_rejected(self) -> None:
        bad_locks = (
            "-e ./local-package\n",
            "Telethon @ file:///tmp/local.whl --hash=sha256:" + "a" * 64 + "\n",
            "Telethon @ git+https://example.invalid/repo.git@deadbeef --hash=sha256:" + "a" * 64 + "\n",
            "Telethon==1.44.0\n",
        )
        for text in bad_locks:
            with self.subTest(text=text.splitlines()[0]):
                temp, root = self._requirements_root()
                self.addCleanup(temp.cleanup)
                (root / "requirements.lock").write_text(text, encoding="utf-8")
                with self.assertRaises(SafetyError):
                    validate_dependency_contract(root)

    def test_dependency_mismatch_is_rejected_before_it_can_be_reviewed_as_closure(self) -> None:
        temp, root = self._requirements_root()
        self.addCleanup(temp.cleanup)
        lock = (root / "requirements.lock").read_text(encoding="utf-8")
        (root / "requirements.lock").write_text(lock.replace("rsa==4.9.1", "rsa==4.9.0"), encoding="utf-8")
        with self.assertRaises(SafetyError):
            validate_dependency_contract(root)

    def test_dependency_and_build_tool_import_shadowing_fails_closed(self) -> None:
        for path in (
            "telethon/__init__.py",
            "Telethon.py",
            "pyaes.py",
            "rsa/__init__.py",
            "pyasn1.py",
            "pip.py",
            "venv/__init__.py",
            "ensurepip.py",
            "compileall.py",
            "unittest/__init__.py",
            "sitecustomize.py",
            "usercustomize.py",
        ):
            with self.subTest(path=path):
                with self.assertRaises(SupplyChainError):
                    validate_no_import_shadowing(["bridge/app.py", path])
        validate_no_import_shadowing(["bridge/app.py", "ops/release_package.py", "tests/test_ok.py"])


class FinalWave35CanonicalResidualTests(unittest.TestCase):
    def test_current_prepare_residuals_are_explicit_not_silently_green(self) -> None:
        source = (ROOT / "ops" / "deploy_release.py").read_text(encoding="utf-8")
        residuals = set(audit_prepare_residuals(source))
        self.assertIn("PIP_TRANSITIVE_RESOLUTION_NOT_EXPLICITLY_DISABLED", residuals)
        self.assertIn("APPROVED_SDIST_BUILD_ISOLATION_NOT_DISABLED", residuals)
        self.assertIn("PIP_AMBIENT_CONFIG_NOT_EXPLICITLY_ISOLATED", residuals)
        self.assertIn("PYTHON_SAFE_PATH_NOT_ENABLED_FOR_PREPARE_MODULES", residuals)
        self.assertIn("EXTERNAL_TAR_EXTRACTION_RELIES_ON_PREFLIGHT_TOPOLOGY", residuals)

    def test_exact_branch_repository_passes_new_preflight_but_retains_residual_codes(self) -> None:
        result = scan_repository(ROOT, ref="HEAD")
        self.assertGreater(result["tracked_blob_count"], 0)
        self.assertEqual(4, result["runtime_package_count"])
        self.assertEqual(3, result["wheel_count"])
        self.assertEqual(1, result["sdist_count"])
        self.assertTrue(result["residuals"])
        self.assertFalse(result["production_authorized"])
        self.assertFalse(result["private_values_recorded"])

    def test_specialist_workflow_is_read_only_and_uses_reviewed_action_pins(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "finalwave35-supply-chain.yml").read_text(encoding="utf-8")
        self.assertIn("permissions:\n  contents: read", workflow)
        self.assertIn("persist-credentials: false", workflow)
        self.assertIn("fetch-depth: 0", workflow)
        self.assertIn("clean: true", workflow)
        self.assertIn("lfs: false", workflow)
        self.assertIn("submodules: false", workflow)
        uses = [line.split("uses:", 1)[1].strip().split("#", 1)[0].strip() for line in workflow.splitlines() if "uses:" in line]
        self.assertEqual([CHECKOUT_PIN, SETUP_PYTHON_PIN], uses)
        self.assertNotIn("secrets.", workflow)
        self.assertNotIn("github.token", workflow)
        self.assertNotIn("pull_request_target", workflow)


if __name__ == "__main__":
    unittest.main()
