from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from bridge.app import BridgeApplication, ReadAppConfig
from bridge.integrated_app import UnifiedBridgeApplication
from ops.write_safety import SafeNoSideEffectFailure


class SnapshotReadingAdapter:
    def __init__(self, original_path: Path, *, replacement: bytes) -> None:
        self.original_path = original_path
        self.replacement = replacement
        self.calls = 0
        self.observed: list[bytes] = []

    def send_files(self, target, paths, **kwargs):
        del target, kwargs
        self.calls += 1
        # Simulate the exact TOCTOU: mutate the registered pathname after the
        # Bridge has validated it but before the Telegram layer opens upload data.
        self.original_path.write_bytes(self.replacement)
        self.observed = [Path(path).read_bytes() for path in paths]
        return {"operation": "SEND_FILES", "message_ids": [7001], "chat_id": 100, "count": 1}


class ShouldNotBeCalledAdapter:
    def __init__(self) -> None:
        self.calls = 0

    def send_files(self, *args, **kwargs):
        self.calls += 1
        raise AssertionError("external adapter must not run when snapshot verification fails")


class SendFilesSnapshotBoundaryTests(unittest.TestCase):
    def setUp(self) -> None:
        if os.name != "posix" or not Path("/proc/self/fd").is_dir():
            self.skipTest("production snapshot upload boundary requires Linux procfs")
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.read_app = BridgeApplication(
            config=ReadAppConfig(private_root=Path(self.tmp.name)),
        )
        assert self.read_app.files is not None
        self.path = self.read_app.files.root / "registered.bin"
        self.original = b"ORIGINAL-VERIFIED-BYTES"
        self.path.write_bytes(self.original)
        os.chmod(self.path, 0o600)
        self.record = self.read_app.files.add(
            self.path,
            name="registered.bin",
            mime_type="application/octet-stream",
        )
        self.payload = {
            "target": "100",
            "files": [
                {
                    "file_id": self.record.file_ref,
                    "sha256": self.record.sha256,
                    "size": self.record.size,
                }
            ],
            "caption": "",
            "voice_note": False,
        }

    def test_send_files_uses_verified_unlinked_snapshot_after_registered_path_mutates(self) -> None:
        adapter = SnapshotReadingAdapter(self.path, replacement=b"ATTACKER-REPLACED-BYTES")
        app = UnifiedBridgeApplication(read_app=self.read_app, write_adapter=adapter)

        receipt = app._execute_external_write("SEND_FILES", self.payload)

        self.assertEqual(adapter.calls, 1)
        self.assertEqual(adapter.observed, [self.original])
        self.assertEqual(self.path.read_bytes(), b"ATTACKER-REPLACED-BYTES")
        self.assertEqual(receipt["operation"], "SEND_FILES")
        self.assertEqual(receipt["message_ids"], [7001])

    def test_preexisting_registered_byte_change_fails_before_external_adapter(self) -> None:
        self.path.write_bytes(b"CHANGED-BEFORE-SNAPSHOT")
        adapter = ShouldNotBeCalledAdapter()
        app = UnifiedBridgeApplication(read_app=self.read_app, write_adapter=adapter)

        with self.assertRaises(SafeNoSideEffectFailure):
            app._execute_external_write("SEND_FILES", self.payload)

        self.assertEqual(adapter.calls, 0)

    def test_symlink_swap_after_snapshot_cannot_redirect_upload_bytes(self) -> None:
        replacement = self.read_app.files.root / "replacement.bin"
        replacement.write_bytes(b"SYMLINK-ATTACK-BYTES")
        os.chmod(replacement, 0o600)

        class SymlinkSwapAdapter(SnapshotReadingAdapter):
            def send_files(inner_self, target, paths, **kwargs):
                del target, kwargs
                inner_self.calls += 1
                self.path.unlink()
                self.path.symlink_to(replacement)
                inner_self.observed = [Path(path).read_bytes() for path in paths]
                return {"operation": "SEND_FILES", "message_ids": [7002], "chat_id": 100, "count": 1}

        adapter = SymlinkSwapAdapter(self.path, replacement=b"")
        app = UnifiedBridgeApplication(read_app=self.read_app, write_adapter=adapter)
        receipt = app._execute_external_write("SEND_FILES", self.payload)

        self.assertEqual(adapter.observed, [self.original])
        self.assertTrue(self.path.is_symlink())
        self.assertEqual(receipt["message_ids"], [7002])


if __name__ == "__main__":
    unittest.main()
