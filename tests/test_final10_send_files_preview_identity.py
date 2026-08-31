from __future__ import annotations

import unittest
from types import SimpleNamespace

from bridge.errors import BridgeError
from bridge.phase_aware_write_app import PhaseAwareUnifiedBridgeApplication


class Final10SendFilesPreviewIdentityTests(unittest.TestCase):
    SPEC = SimpleNamespace(action="SEND_FILES")

    @staticmethod
    def _body(files: list[dict[str, object]]) -> dict[str, object]:
        return {
            "chat": "target-chat",
            "files": files,
            "caption": "",
            "reply_to_message_id": None,
            "voice_note": False,
        }

    def test_conflicting_hash_for_same_file_ref_rejected_before_preview(self) -> None:
        files = [
            {"file_ref": "file-A", "sha256": "1" * 64, "size": 12},
            {"file_ref": "file-A", "sha256": "2" * 64, "size": 12},
        ]
        with self.assertRaises(BridgeError) as caught:
            PhaseAwareUnifiedBridgeApplication._preview_payload(self.SPEC, self._body(files))
        self.assertEqual(caught.exception.status, 400)
        self.assertEqual(caught.exception.code, "invalid_file_reference")

    def test_conflicting_size_for_same_file_ref_rejected_before_preview(self) -> None:
        files = [
            {"file_ref": "file-A", "sha256": "1" * 64, "size": 12},
            {"file_ref": "file-A", "sha256": "1" * 64, "size": 13},
        ]
        with self.assertRaises(BridgeError) as caught:
            PhaseAwareUnifiedBridgeApplication._preview_payload(self.SPEC, self._body(files))
        self.assertEqual(caught.exception.status, 400)
        self.assertEqual(caught.exception.code, "invalid_file_reference")

    def test_exact_duplicate_identity_is_not_rejected_as_conflict(self) -> None:
        files = [
            {"file_ref": "file-A", "sha256": "1" * 64, "size": 12},
            {"file_ref": "file-A", "sha256": "1" * 64, "size": 12},
        ]
        payload = PhaseAwareUnifiedBridgeApplication._preview_payload(self.SPEC, self._body(files))
        self.assertEqual(payload["files"], files)


if __name__ == "__main__":
    unittest.main()
