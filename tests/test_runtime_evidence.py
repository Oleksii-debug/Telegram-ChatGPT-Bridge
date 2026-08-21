# -*- coding: utf-8 -*-
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from ops import runtime_evidence, release_guard


class RuntimeEvidenceTests(unittest.TestCase):
    def test_evidence_contains_only_nonsecret_runtime_facts(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            wsgi = root / "passenger_wsgi.py"
            wsgi.write_text("from bridge.app import application\n", encoding="utf-8")
            fake_app = type("FakeApp", (), {})()
            fake_module = type("FakeModule", (), {"application": fake_app})
            with mock.patch.object(runtime_evidence.importlib, "import_module", return_value=fake_module):
                evidence = runtime_evidence.collect_runtime_evidence(app_root=root, wsgi_file=wsgi)
            self.assertIn("python_version", evidence)
            self.assertIn("python_executable", evidence)
            self.assertEqual("passenger_wsgi.py", evidence["wsgi_relative_path"])
            self.assertTrue(evidence["application_import_ok"])
            self.assertFalse(evidence["environment_values_recorded"])
            self.assertFalse(evidence["request_data_recorded"])
            self.assertFalse(evidence["secret_values_recorded"])
            forbidden = {"environment", "cookies", "session", "token", "password", "route"}
            for key in evidence:
                self.assertNotIn(key.casefold(), forbidden)

    def test_wsgi_outside_app_root_fails(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); app = root / "app"; app.mkdir(); other = root / "other.py"; other.write_text("x\n")
            with self.assertRaises(release_guard.SafetyError):
                runtime_evidence.collect_runtime_evidence(app_root=app, wsgi_file=other)


if __name__ == "__main__":
    unittest.main()
