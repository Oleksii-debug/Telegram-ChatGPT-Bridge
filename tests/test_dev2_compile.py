# -*- coding: utf-8 -*-
"""Explicit Python 3.11 compile coverage for DEV2-owned modules."""
from __future__ import annotations

import py_compile
import unittest
from pathlib import Path


class Dev2CompileCoverageTests(unittest.TestCase):
    def test_all_dev2_python_modules_compile(self):
        root = Path(__file__).resolve().parents[1]
        paths = (
            "ops/baseline_reconcile.py",
            "ops/hostiq_lifecycle.py",
            "ops/private_evidence.py",
            "ops/runtime_evidence.py",
            "ops/snapshot_candidate.py",
            "tools/collect_runtime_evidence.py",
            "tests/test_dev2_baseline_runtime.py",
            "tests/test_dev2_lifecycle.py",
            "tests/test_runtime_evidence.py",
        )
        for relative in paths:
            with self.subTest(path=relative):
                source = root / relative
                self.assertTrue(source.is_file(), relative)
                py_compile.compile(str(source), doraise=True)


if __name__ == "__main__":
    unittest.main()
