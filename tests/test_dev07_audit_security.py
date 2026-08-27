from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from bridge.audit import AuditLog, AuditSecurityError


class Dev07AuditLogSecurityTests(unittest.TestCase):
    def make_path(self) -> tuple[tempfile.TemporaryDirectory, Path]:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        parent = Path(tmp.name) / "private-audit"
        parent.mkdir(mode=0o700)
        return tmp, parent / "audit.jsonl"

    def test_private_audit_file_is_owner_only_and_metadata_only(self):
        _, path = self.make_path()
        log = AuditLog(path)
        private_text = "synthetic-private-body-not-for-audit"
        log.write(
            "request_error",
            request_id="0123456789abcdef",
            status=400,
            error_code="bad_request",
            message_body=private_text,
            server_path=private_text,
        )
        self.assertEqual(stat_mode(path), 0o600)
        raw = path.read_text(encoding="ascii")
        self.assertNotIn(private_text, raw)
        event = json.loads(raw)
        self.assertEqual(event["error_code"], "bad_request")
        self.assertNotIn("message_body", event)
        self.assertNotIn("server_path", event)

    def test_symlink_leaf_is_rejected_without_touching_target(self):
        if not hasattr(os, "symlink"):
            self.skipTest("symlink unavailable")
        _, path = self.make_path()
        target = path.parent / "target.txt"
        sentinel = "unchanged-target\n"
        target.write_text(sentinel, encoding="utf-8")
        target.chmod(0o600)
        path.symlink_to(target)
        log = AuditLog(path)
        with self.assertRaises(AuditSecurityError):
            log.write("request_error", status=500)
        self.assertEqual(target.read_text(encoding="utf-8"), sentinel)

    def test_hardlink_leaf_is_rejected_without_mutating_peer(self):
        _, path = self.make_path()
        target = path.parent / "target.txt"
        sentinel = "unchanged-hardlink-target\n"
        target.write_text(sentinel, encoding="utf-8")
        target.chmod(0o600)
        os.link(target, path)
        log = AuditLog(path)
        with self.assertRaises(AuditSecurityError):
            log.write("request_error", status=500)
        self.assertEqual(target.read_text(encoding="utf-8"), sentinel)

    def test_broad_mode_existing_leaf_is_rejected(self):
        _, path = self.make_path()
        sentinel = "existing-broad-mode\n"
        path.write_text(sentinel, encoding="utf-8")
        path.chmod(0o644)
        log = AuditLog(path)
        with self.assertRaises(AuditSecurityError):
            log.write("request_error", status=500)
        self.assertEqual(path.read_text(encoding="utf-8"), sentinel)

    def test_fifo_leaf_is_rejected_without_blocking(self):
        if not hasattr(os, "mkfifo"):
            self.skipTest("FIFO unavailable")
        _, path = self.make_path()
        os.mkfifo(path, 0o600)
        log = AuditLog(path)
        with self.assertRaises(AuditSecurityError):
            log.write("request_error", status=500)

    def test_group_writable_parent_is_rejected(self):
        _, path = self.make_path()
        path.parent.chmod(0o770)
        with self.assertRaises(AuditSecurityError):
            AuditLog(path)

    def test_parent_symlink_replacement_after_construction_is_rejected(self):
        if not hasattr(os, "symlink"):
            self.skipTest("symlink unavailable")
        tmp, path = self.make_path()
        log = AuditLog(path)
        original_parent = path.parent
        moved_parent = Path(tmp.name) / "moved-parent"
        original_parent.rename(moved_parent)
        replacement = Path(tmp.name) / "replacement"
        replacement.mkdir(mode=0o700)
        original_parent.symlink_to(replacement, target_is_directory=True)
        with self.assertRaises(AuditSecurityError):
            log.write("request_error", status=500)
        self.assertFalse((replacement / path.name).exists())

    def test_parent_inode_replacement_after_construction_is_rejected(self):
        tmp, path = self.make_path()
        log = AuditLog(path)
        original_parent = path.parent
        moved_parent = Path(tmp.name) / "moved-parent"
        original_parent.rename(moved_parent)
        original_parent.mkdir(mode=0o700)
        with self.assertRaises(AuditSecurityError):
            log.write("request_error", status=500)
        self.assertFalse((original_parent / path.name).exists())

    def test_in_memory_sink_keeps_metadata_filter_without_filesystem(self):
        log = AuditLog()
        private = "synthetic-private-value"
        log.write("request_ok", route="dialogs.list", status=200, message_body=private)
        self.assertEqual(len(log.events), 1)
        self.assertEqual(log.events[0]["route"], "dialogs.list")
        self.assertNotIn(private, json.dumps(log.events[0], sort_keys=True))


def stat_mode(path: Path) -> int:
    return path.stat().st_mode & 0o777


if __name__ == "__main__":
    unittest.main()
