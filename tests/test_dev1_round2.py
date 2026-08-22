# -*- coding: utf-8 -*-
from __future__ import annotations

import os
import stat
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from ops import deploy_release as deploy
from ops.acceptance_contracts import ContractError, FixedWindowRateLimiter, PreviewCommitStore
from ops.integration_interfaces import PageRequest, RateLimitOutcome, RoutePolicy, WritePreview
from ops.release_guard import SafetyError
from tools.parallel_overlap_report import build_report


class ActualDeploymentLockTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.control = Path(self.tmp.name)
        os.chmod(self.control, 0o700)
        self.lock = self.control / deploy.TRANSACTION_LOCK

    def tearDown(self):
        self.tmp.cleanup()

    def _touch_private(self, content: bytes = b"") -> None:
        self.lock.write_bytes(content)
        os.chmod(self.lock, 0o600)

    def test_valid_empty_private_lock_reuses_for_128_cycles(self):
        for _ in range(128):
            with deploy._deployment_lock(self.control) as path:
                self.assertEqual(self.lock, path)
        st = self.lock.lstat()
        self.assertTrue(stat.S_ISREG(st.st_mode))
        self.assertEqual(0o600, stat.S_IMODE(st.st_mode))
        self.assertEqual(0, st.st_size)
        self.assertEqual(1, st.st_nlink)

    def test_broad_mode_fails_without_normalizing_mode(self):
        self._touch_private()
        os.chmod(self.lock, 0o644)
        before = stat.S_IMODE(self.lock.lstat().st_mode)
        with self.assertRaises(SafetyError):
            with deploy._deployment_lock(self.control):
                self.fail("unsafe lock acquired")
        self.assertEqual(before, stat.S_IMODE(self.lock.lstat().st_mode))
        self.assertEqual(0o644, before)

    def test_nonempty_lock_fails_without_truncating_content(self):
        marker = b"synthetic-lock-state"
        self._touch_private(marker)
        with self.assertRaises(SafetyError):
            with deploy._deployment_lock(self.control):
                self.fail("unsafe lock acquired")
        self.assertEqual(marker, self.lock.read_bytes())

    def test_hardlink_symlink_and_fifo_fail_closed(self):
        self._touch_private()
        alias = self.control / "lock-alias"
        os.link(self.lock, alias)
        with self.assertRaises(SafetyError):
            with deploy._deployment_lock(self.control):
                self.fail("hardlinked lock acquired")
        alias.unlink()
        self.lock.unlink()

        target = self.control / "target"
        target.write_bytes(b"")
        os.chmod(target, 0o600)
        self.lock.symlink_to(target)
        with self.assertRaises(SafetyError):
            with deploy._deployment_lock(self.control):
                self.fail("symlink lock acquired")
        self.lock.unlink()
        target.unlink()

        if hasattr(os, "mkfifo"):
            os.mkfifo(self.lock, 0o600)
            with self.assertRaises(SafetyError):
                with deploy._deployment_lock(self.control):
                    self.fail("fifo lock acquired")

    def test_inode_replacement_between_preflight_and_open_fails(self):
        self._touch_private()
        replacement = self.control / "replacement-lock"
        replacement.write_bytes(b"")
        os.chmod(replacement, 0o600)
        original_stat = self.lock.lstat()
        replacement_stat = replacement.lstat()
        self.assertEqual(original_stat.st_dev, replacement_stat.st_dev)
        self.assertNotEqual(original_stat.st_ino, replacement_stat.st_ino)

        real_open = os.open
        swapped = False

        def racing_open(path, flags, mode=0o777):
            nonlocal swapped
            if Path(path) == self.lock and not swapped:
                swapped = True
                os.replace(replacement, self.lock)
            return real_open(path, flags, mode)

        with mock.patch.object(deploy.os, "open", side_effect=racing_open):
            with self.assertRaises(SafetyError):
                with deploy._deployment_lock(self.control):
                    self.fail("raced lock acquired")
        self.assertTrue(swapped)
        self.assertEqual(replacement_stat.st_ino, self.lock.lstat().st_ino)


class RateLimiterRound2Tests(unittest.TestCase):
    def test_window_edges_and_retry_after_are_deterministic(self):
        now = [0.0]
        limiter = FixedWindowRateLimiter(2, 10, clock=lambda: now[0])
        first = limiter.consume("actor-a")
        second = limiter.consume("actor-a")
        denied = limiter.consume("actor-a")
        self.assertTrue(first.allowed)
        self.assertEqual(1, first.remaining)
        self.assertTrue(second.allowed)
        self.assertEqual(0, second.remaining)
        self.assertFalse(denied.allowed)
        self.assertEqual(10, denied.retry_after_seconds)
        now[0] = 9.999
        self.assertFalse(limiter.consume("actor-a").allowed)
        now[0] = 10.0
        reset = limiter.consume("actor-a")
        self.assertTrue(reset.allowed)
        self.assertEqual(1, reset.remaining)

    def test_backward_clock_and_actor_capacity_fail_closed(self):
        now = [20.0]
        limiter = FixedWindowRateLimiter(1, 10, clock=lambda: now[0], max_actors=2)
        limiter.consume("actor-a")
        limiter.consume("actor-b")
        with self.assertRaises(ContractError):
            limiter.consume("actor-c")
        now[0] = 19.0
        with self.assertRaises(ContractError):
            limiter.consume("actor-a")

    def test_single_process_thread_contention_never_exceeds_limit(self):
        limiter = FixedWindowRateLimiter(7, 60, clock=lambda: 1.0)
        decisions = []
        guard = threading.Lock()

        def consume_once():
            value = limiter.consume("shared-actor")
            with guard:
                decisions.append(value.allowed)

        threads = [threading.Thread(target=consume_once) for _ in range(64)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(7, sum(decisions))
        self.assertEqual(64, len(decisions))


class IdempotencyRound2Tests(unittest.TestCase):
    def setUp(self):
        self.store = PreviewCommitStore(retention_seconds=600)
        self.target = "1" * 64
        self.payload = "2" * 64

    def test_cross_action_target_payload_conflicts_are_explicit(self):
        p1 = self.store.create_preview(action="SEND", target_sha256=self.target, payload_sha256=self.payload, now=0)
        self.assertEqual("COMMITTED", self.store.commit(p1, now=1, idempotency_key="safe-key"))
        variations = [
            ("REPLY", self.target, self.payload),
            ("SEND", "3" * 64, self.payload),
            ("SEND", self.target, "4" * 64),
        ]
        for action, target, payload in variations:
            with self.subTest(action=action, target=target[:1], payload=payload[:1]):
                preview = self.store.create_preview(
                    action=action, target_sha256=target, payload_sha256=payload, now=2
                )
                self.assertEqual(
                    "IDEMPOTENCY_CONFLICT",
                    self.store.commit(preview, now=3, idempotency_key="safe-key"),
                )
        self.assertEqual(1, self.store.external_write_count)

    def test_committed_retry_survives_preview_expiry_and_restart(self):
        preview = self.store.create_preview(
            action="FORWARD", target_sha256=self.target, payload_sha256=self.payload, now=10, ttl_seconds=5
        )
        self.assertEqual("COMMITTED", self.store.commit(preview, now=11, idempotency_key="retry-key"))
        restored = PreviewCommitStore.restore_state(self.store.export_state())
        self.assertEqual("COMMITTED", restored.commit(preview, now=999, idempotency_key="retry-key"))
        self.assertEqual(1, restored.external_write_count)

    def test_reserved_crash_requires_reconciliation_after_restart(self):
        preview = self.store.create_preview(
            action="SEND_FILE", target_sha256=self.target, payload_sha256=self.payload, now=10
        )
        self.assertEqual("READY_TO_WRITE", self.store.begin_commit(preview, now=11, idempotency_key="crash-key"))
        restored = PreviewCommitStore.restore_state(self.store.export_state())
        self.assertEqual("RECONCILE_REQUIRED", restored.commit(preview, now=12, idempotency_key="crash-key"))
        self.assertEqual(0, restored.external_write_count)

    def test_retention_tombstone_never_reenables_same_key(self):
        preview = self.store.create_preview(action="SEND", target_sha256=self.target, payload_sha256=self.payload, now=0)
        self.assertEqual("COMMITTED", self.store.commit(preview, now=1, idempotency_key="retained-key"))
        self.store.prune(now=1000)
        second = self.store.create_preview(action="SEND", target_sha256=self.target, payload_sha256=self.payload, now=1001)
        self.assertEqual("IDEMPOTENCY_RETIRED", self.store.commit(second, now=1002, idempotency_key="retained-key"))
        self.assertEqual(1, self.store.external_write_count)


class CrossLaneCompatibilityTests(unittest.TestCase):
    DEV3_FILES = [
        "bridge/__init__.py", "bridge/app.py", "bridge/archive.py", "bridge/audit.py",
        "bridge/backend.py", "bridge/downloads.py", "bridge/errors.py", "bridge/models.py",
        "bridge/security.py", "bridge/storage.py", "bridge/validation.py",
        "docs/APPLICATION_READ_MEDIA.md", "tests/test_archive_security.py",
        "tests/test_backend_read.py", "tests/test_read_app.py", "tests/test_storage_downloads.py",
        "tests/test_validation_security.py",
    ]
    DEV5_FILES = [
        "docs/ACCEPTANCE_CONTRACTS.md", "docs/ACCEPTANCE_HARNESS.md",
        "docs/DEV5_QA_SECURITY_MATRIX.md", "docs/DEV5_ROUND2_QA.md",
        "ops/acceptance_contracts.py", "ops/acceptance_harness.py",
        "ops/dev5_round2_oracles.py", "ops/evidence_privacy.py",
        "tests/test_acceptance_contracts.py", "tests/test_acceptance_harness.py",
        "tests/test_dev5_round2.py", "tests/test_dev5_round2_fuzz.py",
    ]

    def test_overlap_report_marks_dev5_control_plane_overlap_only(self):
        report = build_report({"DEV3": self.DEV3_FILES, "DEV5": self.DEV5_FILES})
        self.assertEqual({}, report["cross_lane_overlaps"])
        self.assertEqual(
            {
                "ops/acceptance_contracts.py": ["DEV5"],
                "ops/acceptance_harness.py": ["DEV5"],
                "ops/evidence_privacy.py": ["DEV5"],
            },
            report["dev1_sensitive_overlaps"],
        )
        self.assertFalse(any(path.startswith("bridge/") for path in report["dev1_sensitive_overlaps"]))

    def test_interface_value_objects_are_fail_closed(self):
        self.assertEqual(50, PageRequest().limit)
        with self.assertRaises(ValueError):
            PageRequest(limit=0)
        with self.assertRaises(ValueError):
            PageRequest(cursor="bad\nvalue")
        outcome = RateLimitOutcome(True, 1, 0, 60, 2)
        self.assertTrue(outcome.allowed)
        route = RoutePolicy("post", "/messages/send", "send_message", "PROTECTED_WRITE", True)
        self.assertEqual("POST", route.method)
        with self.assertRaises(ValueError):
            RoutePolicy("POST", "/messages/send", "send_message", "PROTECTED_WRITE", False)
        preview = WritePreview("a" * 64, "SEND", "b" * 64, "c" * 64, 123)
        self.assertEqual("SEND", preview.operation_kind)


if __name__ == "__main__":
    unittest.main()
