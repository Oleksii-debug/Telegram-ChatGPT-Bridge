from __future__ import annotations

import errno
import json
import multiprocessing
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import bridge.audit as audit_module
from bridge.audit import AuditLog, AuditSecurityError


def worker(path: str, prefix: str, count: int) -> None:
    log = AuditLog(Path(path), max_file_bytes=64 * 1024, retention_files=64)
    for i in range(count):
        log.write("request_ok", request_id=f"{prefix}-{i}", status=200)


def all_records(path: Path):
    files = sorted(path.parent.glob(path.name + ".r*")) + ([path] if path.exists() else [])
    out = []
    for f in files:
        for line in f.read_text(encoding="ascii").splitlines():
            if line:
                out.append(json.loads(line))
    return out


class Finalwave23AuditDurabilityTests(unittest.TestCase):
    def make_path(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        parent = Path(tmp.name) / "audit"
        parent.mkdir(mode=0o700)
        return parent / "audit.jsonl"

    def test_memory_100k_is_bounded(self):
        log = AuditLog(memory_event_limit=64)
        for i in range(100_000):
            log.write("request_ok", request_id=str(i), status=200)
        self.assertEqual(len(log.events), 64)
        self.assertEqual(log.events[0]["request_id"], str(100_000 - 64))

    def test_resource_limits_fail_closed(self):
        for kwargs in (
            {"memory_event_limit": 0},
            {"memory_event_limit": True},
            {"max_file_bytes": 511},
            {"max_file_bytes": AuditLog.MAX_FILE_BYTES + 1},
            {"retention_files": 0},
            {"retention_files": AuditLog.MAX_RETENTION_FILES + 1},
        ):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                AuditLog(**kwargs)

    def test_same_owner_leaf_replacement_is_rejected(self):
        path = self.make_path()
        log = AuditLog(path)
        log.write("request_ok", request_id="one", status=200)
        moved = path.with_name("moved.jsonl")
        path.rename(moved)
        path.write_text("replacement\n", encoding="ascii")
        path.chmod(0o600)
        with self.assertRaises(AuditSecurityError):
            log.write("request_ok", request_id="two", status=200)
        self.assertEqual(path.read_text(encoding="ascii"), "replacement\n")

    def test_metadata_only_event_name_and_values(self):
        log = AuditLog()
        log.write("private message body with spaces", route="dialogs.list", error_code="bad request with spaces", status=400)
        self.assertEqual(log.events[0]["event"], "invalid_event")
        self.assertEqual(log.events[0]["route"], "dialogs.list")
        self.assertNotIn("error_code", log.events[0])

    def test_multiprocess_append_is_line_complete_and_unique(self):
        if "fork" not in multiprocessing.get_all_start_methods():
            self.skipTest("fork unavailable")
        path = self.make_path()
        ctx = multiprocessing.get_context("fork")
        procs = [ctx.Process(target=worker, args=(str(path), f"p{p}", 300)) for p in range(4)]
        for p in procs:
            p.start()
        for p in procs:
            p.join(30)
            self.assertEqual(p.exitcode, 0)
        records = all_records(path)
        ids = [r["request_id"] for r in records]
        self.assertEqual(len(ids), 1200)
        self.assertEqual(len(set(ids)), 1200)

    def test_5000_rotating_restart_events_preserve_all_when_retention_sufficient(self):
        path = self.make_path()
        log = AuditLog(path, max_file_bytes=32 * 1024, retention_files=64)
        for i in range(2500):
            log.write("request_ok", request_id=f"a-{i}", status=200)
        del log
        log = AuditLog(path, max_file_bytes=32 * 1024, retention_files=64)
        for i in range(2500, 5000):
            log.write("request_ok", request_id=f"a-{i}", status=200)
        records = all_records(path)
        ids = [r["request_id"] for r in records]
        self.assertEqual(len(ids), 5000)
        self.assertEqual(len(set(ids)), 5000)

    def test_partial_disk_full_rolls_back_record_and_cache(self):
        path = self.make_path()
        log = AuditLog(path)
        log.write("request_ok", request_id="before", status=200)
        before = path.read_bytes()
        real_write = os.write
        calls = 0
        def broken_write(fd, data):
            nonlocal calls
            calls += 1
            if calls == 1:
                raw = bytes(data)
                return real_write(fd, raw[: max(1, len(raw)//2)])
            raise OSError(errno.ENOSPC, "synthetic disk full")
        with mock.patch.object(audit_module.os, "write", side_effect=broken_write):
            with self.assertRaises(AuditSecurityError):
                log.write("request_ok", request_id="after", status=200)
        self.assertEqual(path.read_bytes(), before)
        self.assertEqual([e["request_id"] for e in log.events], ["before"])

    def test_rotation_create_failure_keeps_old_evidence_and_restart_recovers(self):
        path = self.make_path()
        log = AuditLog(path, max_file_bytes=512, retention_files=8)
        # fill near threshold
        i = 0
        while (path.stat().st_size if path.exists() else 0) < 430:
            log.write("request_ok", request_id=f"x-{i}", status=200)
            i += 1
        before_ids = {r["request_id"] for r in all_records(path)}
        real_open = os.open
        failed = False
        def maybe_fail(name, flags, mode=0o777, *, dir_fd=None):
            nonlocal failed
            if (
                not failed
                and name == path.name
                and flags & os.O_EXCL
                and flags & os.O_CREAT
            ):
                failed = True
                raise OSError(errno.ENOSPC, "synthetic rotation create failure")
            return real_open(name, flags, mode, dir_fd=dir_fd)
        with mock.patch.object(audit_module.os, "open", side_effect=maybe_fail):
            with self.assertRaises(AuditSecurityError):
                log.write("request_ok", request_id="trigger", status=200)
        self.assertTrue(any(path.parent.glob(path.name + ".r*")))
        self.assertTrue(before_ids.issubset({r["request_id"] for r in all_records(path)}))
        # restart can recreate the current leaf; triggering record was not claimed committed
        restarted = AuditLog(path, max_file_bytes=512, retention_files=8)
        restarted.write("request_ok", request_id="after-restart", status=200)
        after = {r["request_id"] for r in all_records(path)}
        self.assertTrue(before_ids.issubset(after))
        self.assertIn("after-restart", after)
        self.assertNotIn("trigger", after)

    def test_fsync_failure_rolls_back_record_and_cache(self):
        path = self.make_path()
        log = AuditLog(path)
        log.write("request_ok", request_id="before-sync", status=200)
        before = path.read_bytes()
        real_fsync = os.fsync
        calls = 0
        def flaky_fsync(fd):
            nonlocal calls
            calls += 1
            if calls == 1:
                raise OSError(errno.EIO, "synthetic fsync failure")
            return real_fsync(fd)
        with mock.patch.object(audit_module.os, "fsync", side_effect=flaky_fsync):
            with self.assertRaises(AuditSecurityError):
                log.write("request_ok", request_id="after-sync", status=200)
        self.assertEqual(path.read_bytes(), before)
        self.assertEqual([e["request_id"] for e in log.events], ["before-sync"])

    def test_same_owner_lock_replacement_is_rejected(self):
        path = self.make_path()
        log = AuditLog(path)
        log.write("request_ok", request_id="before-lock", status=200)
        before = path.read_bytes()
        lock = path.parent / f".{path.name}.lock"
        moved = lock.with_name(lock.name + ".old")
        lock.rename(moved)
        lock.write_bytes(b"")
        lock.chmod(0o600)
        with self.assertRaises(AuditSecurityError):
            log.write("request_ok", request_id="after-lock", status=200)
        self.assertEqual(path.read_bytes(), before)

    def test_invalid_archive_namespace_blocks_rotation_without_losing_current(self):
        path = self.make_path()
        log = AuditLog(path, max_file_bytes=512, retention_files=2)
        while (path.stat().st_size if path.exists() else 0) < 430:
            log.write("request_ok", request_id=f"seed-{len(log.events)}", status=200)
        before = path.read_bytes()
        attack = path.parent / f"{path.name}.r00000000000000000001"
        target = path.parent / "other.txt"
        target.write_text("do-not-touch\n", encoding="ascii")
        target.chmod(0o600)
        attack.symlink_to(target)
        with self.assertRaises(AuditSecurityError):
            log.write("request_ok", request_id="rotation-blocked", status=200)
        self.assertEqual(path.read_bytes(), before)
        self.assertEqual(target.read_text(encoding="ascii"), "do-not-touch\n")
        self.assertNotIn("rotation-blocked", [e.get("request_id") for e in log.events])

    def test_leaf_swap_during_append_is_detected_and_old_fd_rolled_back(self):
        path = self.make_path()
        log = AuditLog(path)
        log.write("request_ok", request_id="before-swap", status=200)
        before = path.read_bytes()
        real_fsync = os.fsync
        swapped = False
        moved = path.with_name("audit-old.jsonl")
        def swap_after_sync(fd):
            nonlocal swapped
            result = real_fsync(fd)
            if not swapped:
                swapped = True
                path.rename(moved)
                path.write_text("replacement\n", encoding="ascii")
                path.chmod(0o600)
            return result
        with mock.patch.object(audit_module.os, "fsync", side_effect=swap_after_sync):
            with self.assertRaises(AuditSecurityError):
                log.write("request_ok", request_id="during-swap", status=200)
        self.assertEqual(moved.read_bytes(), before)
        self.assertEqual(path.read_text(encoding="ascii"), "replacement\n")
        self.assertNotIn("during-swap", [e.get("request_id") for e in log.events])

    def test_retention_prunes_only_old_archives_and_keeps_recent_evidence(self):
        path = self.make_path()
        log = AuditLog(path, max_file_bytes=512, retention_files=2)
        for i in range(120):
            log.write("request_ok", request_id=f"keep-{i}", status=200)
        archives = sorted(path.parent.glob(path.name + ".r*"))
        self.assertLessEqual(len(archives), 2)
        self.assertTrue(path.exists())
        ids = [r["request_id"] for r in all_records(path)]
        self.assertIn("keep-119", ids)
        self.assertEqual(len(ids), len(set(ids)))



if __name__ == "__main__":
    unittest.main(verbosity=2)
