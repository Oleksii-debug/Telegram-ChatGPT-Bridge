# -*- coding: utf-8 -*-
import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path

from ops.passenger_evidence_hook import ARM_MARKER_NAME, CONSUMED_RECEIPT_NAME, validate_arm_marker
from ops.release_guard import SafetyError
from tools.arm_passenger_evidence import arm_from_preflight


class ArmPassengerEvidenceTests(unittest.TestCase):
    SHA = "a" * 40
    WSGI = "b" * 64
    RAW_CHALLENGE = "1" * 64
    CHALLENGE_SHA = hashlib.sha256(RAW_CHALLENGE.encode("ascii")).hexdigest()

    def roots(self, td: str):
        home = Path(td)
        evidence = home / ".telegram_bridge_private_evidence"
        control = home / ".telegram_bridge_private_control"
        evidence.mkdir(mode=0o700); control.mkdir(mode=0o700)
        os.chmod(evidence, 0o700); os.chmod(control, 0o700)
        preflight = evidence / "candidate_runtime_preflight.json"
        return evidence, control, preflight

    def preflight_payload(self):
        return {
            "schema_version": 2,
            "candidate_sha": self.SHA,
            "wsgi_sha256": self.WSGI,
            "requirements_sha256": "c" * 64,
            "requirements_lock_sha256": "d" * 64,
            "direct_package_count": 1,
            "locked_package_count": 3,
            "required_packages_present": True,
            "startup_import_contract_ok": True,
            "fully_hash_locked": True,
            "test_dependencies": {
                "present": False,
                "requirements_sha256": "0" * 64,
                "requirements_lock_sha256": "0" * 64,
                "direct_package_count": 0,
                "locked_package_count": 0,
            },
            "private_runtime_payload_present": False,
            "preflight_pass": True,
            "promotion_authorized": False,
        }

    def write_preflight(self, path: Path, payload=None, mode=0o600):
        path.write_text(json.dumps(payload or self.preflight_payload()), encoding="utf-8")
        os.chmod(path, mode)

    def arm(self, preflight: Path, control: Path):
        return arm_from_preflight(
            preflight_path=preflight,
            control_root=control,
            request_challenge_sha256=self.CHALLENGE_SHA,
        )

    def test_exact_preflight_creates_owner_private_digest_bound_marker(self):
        with tempfile.TemporaryDirectory() as td:
            _, control, preflight = self.roots(td); self.write_preflight(preflight)
            marker = self.arm(preflight, control)
            self.assertEqual(control / ARM_MARKER_NAME, marker)
            st = marker.lstat()
            self.assertEqual(0, st.st_mode & 0o077)
            text = marker.read_text(encoding="utf-8")
            payload = validate_arm_marker(json.loads(text))
            self.assertEqual(self.SHA, payload["candidate_sha"])
            self.assertEqual(self.WSGI, payload["expected_wsgi_sha256"])
            self.assertEqual(self.CHALLENGE_SHA, payload["request_challenge_sha256"])
            self.assertNotIn(self.RAW_CHALLENGE, text)

    def test_existing_marker_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as td:
            _, control, preflight = self.roots(td); self.write_preflight(preflight)
            marker = control / ARM_MARKER_NAME
            marker.write_text("do-not-overwrite", encoding="utf-8"); os.chmod(marker, 0o600)
            with self.assertRaises(SafetyError):
                self.arm(preflight, control)
            self.assertEqual("do-not-overwrite", marker.read_text(encoding="utf-8"))

    def test_consumed_receipt_is_terminal_and_never_overwritten(self):
        with tempfile.TemporaryDirectory() as td:
            _, control, preflight = self.roots(td); self.write_preflight(preflight)
            receipt = control / CONSUMED_RECEIPT_NAME
            receipt.write_text("terminal", encoding="utf-8"); os.chmod(receipt, 0o600)
            with self.assertRaises(SafetyError):
                self.arm(preflight, control)
            self.assertFalse((control / ARM_MARKER_NAME).exists())
            self.assertEqual("terminal", receipt.read_text(encoding="utf-8"))

    def test_invalid_challenge_digest_cannot_arm(self):
        with tempfile.TemporaryDirectory() as td:
            _, control, preflight = self.roots(td); self.write_preflight(preflight)
            with self.assertRaises(SafetyError):
                arm_from_preflight(
                    preflight_path=preflight,
                    control_root=control,
                    request_challenge_sha256="not-a-sha",
                )
            self.assertFalse((control / ARM_MARKER_NAME).exists())

    def test_broad_preflight_or_control_permissions_fail_closed(self):
        with tempfile.TemporaryDirectory() as td:
            _, control, preflight = self.roots(td); self.write_preflight(preflight, mode=0o644)
            with self.assertRaises(SafetyError):
                self.arm(preflight, control)
        with tempfile.TemporaryDirectory() as td:
            _, control, preflight = self.roots(td); self.write_preflight(preflight)
            os.chmod(control, 0o755)
            with self.assertRaises(SafetyError):
                self.arm(preflight, control)

    def test_failed_or_mutated_preflight_cannot_arm(self):
        for key, value in (
            ("preflight_pass", False),
            ("fully_hash_locked", False),
            ("private_runtime_payload_present", True),
            ("promotion_authorized", True),
        ):
            with self.subTest(key=key), tempfile.TemporaryDirectory() as td:
                _, control, preflight = self.roots(td)
                payload = self.preflight_payload(); payload[key] = value
                self.write_preflight(preflight, payload)
                with self.assertRaises(SafetyError):
                    self.arm(preflight, control)
                self.assertFalse((control / ARM_MARKER_NAME).exists())


if __name__ == "__main__":
    unittest.main()
