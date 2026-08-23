# -*- coding: utf-8 -*-
"""Explicit compile coverage for DEV_B-owned production-readiness files."""
import py_compile
import unittest
from pathlib import Path


class DevBCompileCoverageTests(unittest.TestCase):
    def test_devb_python_files_compile(self):
        root = Path(__file__).resolve().parents[1]
        for relative in (
            "ops/candidate_runtime_preflight.py",
            "ops/production_readiness.py",
            "ops/private_control.py",
            "ops/server_manifest.py",
            "ops/passenger_evidence_hook.py",
            "ops/passenger_probe.py",
            "ops/devb_run_matrix.py",
            "tools/validate_candidate_runtime_preflight.py",
            "tools/arm_passenger_evidence.py",
            "tools/run_passenger_evidence_probe.py",
            "tools/validate_hostiq_support_return.py",
            "tools/collect_server_manifest.py",
            "tools/strict_history_secret_scan.py",
            "tests/test_candidate_runtime_preflight.py",
            "tests/test_arm_passenger_evidence.py",
            "tests/test_devb_cli_entrypoints.py",
            "tests/test_run_passenger_evidence_probe.py",
            "tests/test_passenger_probe.py",
            "tests/test_devb_run_matrix.py",
            "tests/test_strict_history_secret_scan.py",
            "tests/test_devb_production_readiness.py",
            "tests/test_private_control.py",
            "tests/test_server_manifest.py",
            "tests/test_passenger_evidence_hook.py",
            "tests/test_devb_round2_release.py",
        ):
            with self.subTest(path=relative):
                source = root / relative
                self.assertTrue(source.is_file(), relative)
                py_compile.compile(str(source), doraise=True)


if __name__ == "__main__":
    unittest.main()
