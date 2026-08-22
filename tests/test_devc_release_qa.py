# -*- coding: utf-8 -*-
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from ops.devc_release_qa import (
    assess_release_package_root,
    keyboard_nvda_protocol,
    release_live_protocols,
    validate_dependency_envelope,
    validate_devb_evidence_interface,
    validate_passenger_wsgi_source,
    validate_prepared_release_metadata,
)

H = "a" * 64
SHA = "b" * 40


class PassengerWSGITests(unittest.TestCase):
    def test_canonical_source_is_minimal_and_import_safe(self):
        self.assertEqual([], validate_passenger_wsgi_source("from bridge.app import application\n"))

    def test_missing_wrong_import_side_effect_and_private_material_fail(self):
        self.assertIn("PASSENGER_WSGI_MISSING", validate_passenger_wsgi_source(None))
        self.assertIn(
            "PASSENGER_WSGI_CANONICAL_IMPORT_MISSING",
            validate_passenger_wsgi_source("from bridge.integrated_app import application\n"),
        )
        self.assertIn(
            "PASSENGER_WSGI_IMPORT_SIDE_EFFECT_RISK",
            validate_passenger_wsgi_source("from bridge.app import application\napplication()\n"),
        )
        self.assertIn(
            "PASSENGER_WSGI_PRIVATE_MATERIAL",
            validate_passenger_wsgi_source('"""TG_API_HASH /home/example"""\nfrom bridge.app import application\n'),
        )


class DependencyEnvelopeTests(unittest.TestCase):
    def test_hash_locked_telethon_envelope_passes(self):
        defects, inputs, locked = validate_dependency_envelope(
            "Telethon==1.40.0\n",
            f"Telethon==1.40.0 --hash=sha256:{H}\n",
        )
        self.assertEqual([], defects)
        self.assertEqual((1, 1), (inputs, locked))

    def test_absent_input_lock_and_runtime_dependency_fail(self):
        defects, _, _ = validate_dependency_envelope(None, None)
        self.assertIn("REQUIREMENTS_INPUT_MISSING", defects)
        self.assertIn("REQUIREMENTS_LOCK_MISSING", defects)
        self.assertIn("REQUIRED_RUNTIME_DEPENDENCY_MISSING", defects)

    def test_input_without_lock_and_unhashed_or_bad_hash_fail(self):
        defects, _, _ = validate_dependency_envelope("Telethon\n", None)
        self.assertIn("REQUIREMENTS_LOCK_MISSING", defects)
        self.assertIn("REQUIREMENTS_INPUT_PACKAGE_NOT_LOCKED", defects)
        defects, _, _ = validate_dependency_envelope("Telethon==1.40.0\n", "Telethon==1.40.0\n")
        self.assertIn("REQUIREMENTS_LOCK_MISSING_SHA256", defects)
        defects, _, _ = validate_dependency_envelope(
            "Telethon==1.40.0\n", "Telethon==1.40.0 --hash=sha256:1234\n"
        )
        self.assertIn("REQUIREMENTS_LOCK_MISSING_SHA256", defects)
        self.assertIn("REQUIREMENTS_LOCK_INVALID_HASH", defects)

    def test_unsafe_url_and_missing_telethon_fail(self):
        defects, _, _ = validate_dependency_envelope(
            "pkg @ https://example.invalid/pkg.whl\n",
            f"pkg==1.0 --hash=sha256:{H}\n",
        )
        self.assertIn("REQUIREMENTS_INPUT_UNSAFE_LINE", defects)
        self.assertIn("REQUIRED_RUNTIME_DEPENDENCY_MISSING", defects)


class PackageAssessmentTests(unittest.TestCase):
    def test_missing_package_is_internal_release_blocker(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = assess_release_package_root(Path(tmp))
            self.assertEqual("INTERNAL_RELEASE_BLOCKER", result.status)
            self.assertIn("PASSENGER_WSGI_MISSING", result.defect_codes)
            self.assertIn("REQUIREMENTS_INPUT_MISSING", result.defect_codes)
            self.assertIn("REQUIREMENTS_LOCK_MISSING", result.defect_codes)

    def test_complete_synthetic_package_is_ready_for_prepare(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "passenger_wsgi.py").write_text("from bridge.app import application\n", encoding="utf-8")
            (root / "requirements.txt").write_text("Telethon==1.40.0\n", encoding="utf-8")
            (root / "requirements.lock").write_text(
                f"Telethon==1.40.0 --hash=sha256:{H}\n", encoding="utf-8"
            )
            result = assess_release_package_root(root)
            self.assertEqual("READY_FOR_PREPARE", result.status)
            self.assertEqual((), result.defect_codes)

    def test_private_runtime_file_blocks_package(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "passenger_wsgi.py").write_text("from bridge.app import application\n", encoding="utf-8")
            (root / "requirements.txt").write_text("Telethon==1.40.0\n", encoding="utf-8")
            (root / "requirements.lock").write_text(
                f"Telethon==1.40.0 --hash=sha256:{H}\n", encoding="utf-8"
            )
            (root / ".env").write_text("synthetic=no-secret-value\n", encoding="utf-8")
            self.assertIn("PRIVATE_FILE_IN_RELEASE", assess_release_package_root(root).defect_codes)


class PreparedMetadataTests(unittest.TestCase):
    def _valid(self):
        return {
            "schema_version": 2,
            "approved_ref": "refs/heads/work3/integration-release-candidate",
            "sha": SHA,
            "configured_python_version": "3.11.16",
            "python_version": "3.11.16",
            "source_manifest_sha256": H,
            "requirements_lock_sha256": H,
            "payload_manifest_sha256": H,
            "runtime_entries": ["passenger_wsgi.py"],
            "persistent_state_mode": "shared_external",
            "immutable_permission_policy": "no-write-bits-v1",
        }

    def test_valid_prepare_metadata_passes(self):
        self.assertEqual([], validate_prepared_release_metadata(self._valid(), SHA))

    def test_stale_sha_missing_lock_hash_and_unaccounted_startup_fail(self):
        payload = self._valid()
        payload["sha"] = "c" * 40
        payload["requirements_lock_sha256"] = None
        payload["runtime_entries"] = []
        defects = validate_prepared_release_metadata(payload, SHA)
        self.assertIn("PREPARED_METADATA_STALE_SHA", defects)
        self.assertIn("PREPARED_METADATA_HASH_MISSING_OR_INVALID", defects)
        self.assertIn("PREPARED_METADATA_STARTUP_UNACCOUNTED", defects)


class DevBEvidenceInterfaceTests(unittest.TestCase):
    def _payload(self, *, mode="LIVE_SERVER", lifecycle_class="FIRST_HAND_LIVE"):
        return {
            "schema_version": 1,
            "candidate_sha": SHA,
            "evidence_classes": {
                "source": "FIRST_HAND_LIVE",
                "runtime": "PRIVATE_SERVER_EVIDENCE",
                "lifecycle": lifecycle_class,
            },
            "server_manifest": {"artifact_sha256": H, "manifest_sha256": H, "file_count": 42},
            "reconciliation": {
                "artifact_sha256": H,
                "status": "EXACT_ACCOUNTED",
                "server_file_count": 42,
                "candidate_file_count": 100,
                "unreviewed_difference_count": 0,
                "startup_accounted": True,
            },
            "runtime": {
                "artifact_sha256": H,
                "collector_context": "APPLICATION_PROCESS",
                "python_major_minor": "3.11",
                "runtime_compliance": "PYTHON_3_11_APPLICATION_CONTEXT_CONFIRMED",
                "application_import_ok": True,
                "passenger_context_present": True,
                "wsgi_sha256": H,
            },
            "lifecycle": {
                "mode": mode,
                "candidate_sha": SHA,
                **{step: "PASS" for step in (
                    "backup", "restart", "running_identity", "health",
                    "unauth_smoke", "auth_smoke", "resume", "rollback",
                )},
            },
            "privacy": {"private_values_copied": False, "raw_response_copied": False},
        }

    def test_live_interface_semantics_are_accepted(self):
        self.assertEqual([], validate_devb_evidence_interface(self._payload(), SHA))

    def test_simulation_cannot_self_promote_to_live(self):
        payload = self._payload(mode="TEST_SIMULATION", lifecycle_class="TEST_SIMULATION")
        self.assertIn("DEVB_SIMULATION_CANNOT_SATISFY_LIVE", validate_devb_evidence_interface(payload, SHA))

    def test_runtime_claim_and_privacy_are_fail_closed(self):
        payload = self._payload()
        payload["runtime"]["collector_context"] = "PRIVATE_CLI_CANDIDATE"
        payload["privacy"]["private_values_copied"] = True
        defects = validate_devb_evidence_interface(payload, SHA)
        self.assertIn("DEVB_PASSENGER_CLAIM_UNSUPPORTED", defects)
        self.assertIn("DEVB_PRIVACY_BOUNDARY_VIOLATION", defects)


class PreLiveProtocolTests(unittest.TestCase):
    def test_h1_h5_k1_k5_are_prepared_not_executed(self):
        protocols = release_live_protocols()
        self.assertEqual(
            {"H1", "H2", "H3", "H4", "H5", "K1", "K2", "K3", "K4", "K5"},
            set(protocols),
        )
        self.assertTrue(all(not item.execute_now for item in protocols.values()))
        k5 = set(protocols["K5"].required_gates)
        self.assertTrue({
            "INDEPENDENT_AUDITOR_WRITE_APPROVAL", "SAFE_DESTINATION_CONFIRMED", "EXPLICIT_USER_COMMIT"
        } <= k5)

    def test_keyboard_nvda_protocol_is_machine_readable_and_non_live(self):
        steps = keyboard_nvda_protocol()
        self.assertEqual(7, len(steps))
        self.assertEqual(len({item[0] for item in steps}), len(steps))
        self.assertTrue(all(item[0].startswith("I") for item in steps))


if __name__ == "__main__":
    unittest.main()
