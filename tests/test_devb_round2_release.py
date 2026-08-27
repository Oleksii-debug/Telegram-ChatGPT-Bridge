# -*- coding: utf-8 -*-
import tempfile
import unittest
from pathlib import Path

from ops import candidate_runtime_preflight, passenger_evidence_hook, private_evidence, server_manifest
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
    CHALLENGE_SHA = "d" * 64

    def write(self, root: Path, rel: str, data: str) -> None:
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(data, encoding="utf-8")

    def package(self, root: Path) -> None:
        self.write(root, "passenger_wsgi.py", CANONICAL_WSGI)
        self.write(root, "install_server.sh", "")
        self.write(root, "requirements.txt", "Telethon==1.42.0\n")
        self.write(root, "requirements.lock", f"Telethon==1.42.0 --hash=sha256:{self.HASH}\n")
        self.write(root, "bridge/app.py", "application = object()\n")
        self.write(root, "tests/test_smoke.py", "import unittest\n")

    def strong_evidence(self, wsgi_sha: str) -> dict:
        report = {
            "schema_version": 3,
            "collector_context": "APPLICATION_PROCESS",
            "python_version": "3.11.16",
            "python_major_minor": "3.11",
            "python_implementation": "CPython",
            "runtime_compliance": passenger_evidence_hook.STRONG_STATUS,
            "python_executable_sha256": "1" * 64,
            "python_executable_owner_uid": 1000,
            "python_executable_mode": 0o755,
            "python_executable_nlink": 1,
            "sys_prefix_sha256": "2" * 64,
            "sys_base_prefix_sha256": "3" * 64,
            "virtual_environment_active": True,
            "wsgi_relative_path": "passenger_wsgi.py",
            "wsgi_sha256": wsgi_sha,
            "application_import_target": "bridge.app.application",
            "application_import_ok": True,
            "process_cwd_inside_app_root": True,
            "passenger_context_present": True,
            "serving_request_verified": True,
            "package_evidence": [
                {"name": "telethon", "present": True, "version": "1.42.0", "metadata_sha256": "4" * 64},
                {"name": "pypdf", "present": False, "version": "NOT_INSTALLED", "metadata_sha256": "0" * 64},
            ],
            "environment_values_recorded": False,
            "request_data_recorded": False,
            "secret_values_recorded": False,
        }
        report["payload_sha256"] = private_evidence.canonical_json_sha256(report)
        private_evidence.validate_runtime_report(report)
        return report

    def test_preflight_manifest_and_passenger_binding_share_exact_wsgi_identity(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            self.package(root)
            package = candidate_runtime_preflight.validate_candidate_release_envelope(root, candidate_sha=self.SHA)
            self.assertFalse(package["test_dependencies"]["present"])
            manifest = server_manifest.collect_server_manifest(root)
            rows = {row["path"]: row for row in manifest["files"]}
            self.assertEqual(package["wsgi_sha256"], rows["passenger_wsgi.py"]["sha256"])

            marker = passenger_evidence_hook.build_arm_marker(
                self.SHA, package["wsgi_sha256"], self.CHALLENGE_SHA
            )
            binding = passenger_evidence_hook.build_binding_report(
                marker, self.strong_evidence(package["wsgi_sha256"])
            )
            passenger_evidence_hook.validate_binding_report(binding)
            self.assertEqual(self.SHA, binding["candidate_sha"])
            self.assertEqual(package["wsgi_sha256"], binding["actual_wsgi_sha256"])
            self.assertEqual(self.CHALLENGE_SHA, binding["request_challenge_sha256"])
            self.assertRegex(binding["serving_probe_sha256"], r"^[0-9a-f]{64}$")

    def test_passenger_binding_rejects_runtime_from_different_wsgi(self):
        marker = passenger_evidence_hook.build_arm_marker(self.SHA, "d" * 64, self.CHALLENGE_SHA)
        with self.assertRaises(SafetyError):
            passenger_evidence_hook.build_binding_report(marker, self.strong_evidence("e" * 64))


if __name__ == "__main__":
    unittest.main()
