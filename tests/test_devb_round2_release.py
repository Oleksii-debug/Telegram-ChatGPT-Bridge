# -*- coding: utf-8 -*-
import hashlib
import tempfile
import unittest
from pathlib import Path

from ops import candidate_runtime_preflight, passenger_evidence_hook, server_manifest
from ops.release_guard import SafetyError


CANONICAL_WSGI = (
    "from pathlib import Path\n"
    "from bridge.app import application\n"
    "from ops.passenger_evidence_hook import collect_if_armed\n"
    "_here = Path(__file__).resolve()\n"
    "collect_if_armed(app_root=_here.parent, wsgi_file=_here)\n"
    "__all__ = ['application']\n"
)


class DevBRound2ReleaseContractsTests(unittest.TestCase):
    SHA = "a" * 40
    HASH = "b" * 64
    CHALLENGE = "c" * 64
    CHALLENGE_SHA = hashlib.sha256(CHALLENGE.encode("ascii")).hexdigest()

    def write(self, root: Path, rel: str, data: str) -> None:
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(data, encoding="utf-8")

    def package(self, root: Path) -> None:
        self.write(root, "passenger_wsgi.py", CANONICAL_WSGI)
        self.write(root, "install_server.sh", "")
        self.write(root, "requirements.txt", "Telethon==1.42.0\n")
        self.write(root, "requirements.lock", f"Telethon==1.42.0 --hash=sha256:{self.HASH}\n")
        self.write(root, "requirements-test.txt", "pytest==9.0.0\n")
        self.write(root, "requirements-test.lock", f"pytest==9.0.0 --hash=sha256:{self.HASH}\n")
        self.write(root, "bridge/app.py", "application = object()\n")
        self.write(root, "tests/test_smoke.py", "import unittest\n")

    def test_preflight_manifest_and_passenger_binding_share_exact_wsgi_identity(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); self.package(root)
            package = candidate_runtime_preflight.validate_candidate_release_envelope(root, candidate_sha=self.SHA)
            manifest = server_manifest.collect_server_manifest(root)
            rows = {row["path"]: row for row in manifest["files"]}
            self.assertEqual("dependency_input", rows["requirements-test.txt"]["category"])
            self.assertEqual("dependency_input", rows["requirements-test.lock"]["category"])
            self.assertEqual(package["wsgi_sha256"], rows["passenger_wsgi.py"]["sha256"])

            marker = passenger_evidence_hook.build_arm_marker(
                self.SHA, package["wsgi_sha256"], self.CHALLENGE_SHA
            )
            evidence = {
                "runtime_compliance": passenger_evidence_hook.STRONG_STATUS,
                "wsgi_sha256": package["wsgi_sha256"],
                "payload_sha256": "d" * 64,
                "serving_request_verified": True,
            }
            binding = passenger_evidence_hook.build_binding_report(marker, evidence)
            passenger_evidence_hook.validate_binding_report(binding)
            self.assertEqual(self.SHA, binding["candidate_sha"])
            self.assertEqual(package["wsgi_sha256"], binding["actual_wsgi_sha256"])
            self.assertTrue(binding["serving_request_verified"])

    def test_passenger_binding_rejects_runtime_from_different_wsgi(self):
        marker = passenger_evidence_hook.build_arm_marker(
            self.SHA, "d" * 64, self.CHALLENGE_SHA
        )
        evidence = {
            "runtime_compliance": passenger_evidence_hook.STRONG_STATUS,
            "wsgi_sha256": "e" * 64,
            "payload_sha256": "f" * 64,
            "serving_request_verified": True,
        }
        with self.assertRaises(SafetyError):
            passenger_evidence_hook.build_binding_report(marker, evidence)

    def test_binding_rejects_unverified_serving_request(self):
        marker = passenger_evidence_hook.build_arm_marker(
            self.SHA, "d" * 64, self.CHALLENGE_SHA
        )
        evidence = {
            "runtime_compliance": "PYTHON_3_11_CANDIDATE_CONTEXT",
            "wsgi_sha256": "d" * 64,
            "payload_sha256": "f" * 64,
            "serving_request_verified": False,
        }
        with self.assertRaises(SafetyError):
            passenger_evidence_hook.build_binding_report(marker, evidence)


if __name__ == "__main__":
    unittest.main()
