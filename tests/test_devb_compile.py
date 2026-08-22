# -*- coding: utf-8 -*-
"""Explicit compile coverage for DEV_B-owned production-readiness files."""
import py_compile
import unittest
from pathlib import Path


class DevBCompileCoverageTests(unittest.TestCase):
    def test_devb_python_files_compile(self):
        root = Path(__file__).resolve().parents[1]
        for relative in (
            "ops/production_readiness.py",
            "tools/validate_hostiq_support_return.py",
            "tests/test_devb_production_readiness.py",
        ):
            with self.subTest(path=relative):
                source = root / relative
                self.assertTrue(source.is_file(), relative)
                py_compile.compile(str(source), doraise=True)


if __name__ == "__main__":
    unittest.main()
