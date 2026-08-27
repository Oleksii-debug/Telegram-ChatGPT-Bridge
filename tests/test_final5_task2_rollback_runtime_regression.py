from __future__ import annotations

import subprocess
import sys
import tempfile
import types
import unittest
from pathlib import Path

from bridge.runtime import SQLiteWriteRateLimiter, _SQLiteFixedWindowStore


PREDECESSOR_EVIDENCE_SHA = "00684e834a523f55ea3b61c1a12cb9dc54cfd947"


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _load_predecessor_runtime():
    root = _repo_root()
    if not (root / ".git").exists():
        raise unittest.SkipTest("full Git history required for exact predecessor evidence")
    try:
        source = subprocess.check_output(
            ["git", "show", f"{PREDECESSOR_EVIDENCE_SHA}:bridge/runtime.py"],
            cwd=root,
            text=True,
            stderr=subprocess.DEVNULL,
        )
    except subprocess.CalledProcessError as exc:
        raise unittest.SkipTest("exact predecessor runtime object unavailable") from exc
    name = "bridge._final5_task2_predecessor_runtime"
    module = types.ModuleType(name)
    module.__package__ = "bridge"
    sys.modules[name] = module
    exec(compile(source, "predecessor_runtime.py", "exec"), module.__dict__)
    return name, module


class _SequenceClock:
    def __init__(self, *values: float):
        self._values = list(values)
        self.calls = 0

    def __call__(self) -> float:
        if not self._values:
            raise AssertionError("unexpected extra clock sample")
        self.calls += 1
        return self._values.pop(0)


class RollbackRuntimeRegressionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.module_name, self.predecessor = _load_predecessor_runtime()
        self.addCleanup(sys.modules.pop, self.module_name, None)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.private = Path(self.temp.name) / "private"
        self.private.mkdir(mode=0o700)
        self.database = self.private / "rate-limit.sqlite3"

    def test_rate_limit_persistent_state_is_cross_version_interoperable(self) -> None:
        predecessor_store = self.predecessor._SQLiteFixedWindowStore(
            self.database, clock=lambda: 100.0
        )
        allowed, remaining, retry = predecessor_store.take(
            namespace="write",
            actor="actor",
            operation="SEND",
            limit=2,
            window_seconds=60,
        )
        self.assertTrue(allowed)
        self.assertEqual(1, remaining)
        self.assertEqual(0, retry)

        current_store = _SQLiteFixedWindowStore(self.database, clock=lambda: 100.0)
        outcome = current_store.take_outcome(
            namespace="write",
            actor="actor",
            operation="SEND",
            limit=2,
            window_seconds=60,
        )
        self.assertTrue(outcome.allowed)
        self.assertEqual(0, outcome.remaining)
        self.assertEqual(120, outcome.reset_at_epoch)

        allowed, remaining, retry = predecessor_store.take(
            namespace="write",
            actor="actor",
            operation="SEND",
            limit=2,
            window_seconds=60,
        )
        self.assertFalse(allowed)
        self.assertEqual(0, remaining)
        self.assertEqual(20, retry)

    def test_exact_predecessor_reset_metadata_is_not_bound_to_atomic_clock_sample(self) -> None:
        predecessor_clock = _SequenceClock(100.0, 1_000.0)
        predecessor_store = self.predecessor._SQLiteFixedWindowStore(
            self.database, clock=predecessor_clock
        )
        predecessor_limiter = self.predecessor.SQLiteWriteRateLimiter(
            predecessor_store, limit=3, window_seconds=60
        )
        remaining, reset_at = predecessor_limiter.consume("actor", "SEND")

        self.assertEqual(2, remaining)
        self.assertEqual(1_060, reset_at)
        self.assertEqual(2, predecessor_clock.calls)
        # The transaction enforced the 60..120 window from the first sample, but
        # the rollback target reports reset metadata from a second, unrelated sample.
        self.assertNotEqual(120, reset_at)

    def test_current_reset_metadata_uses_the_same_atomic_clock_sample(self) -> None:
        current_clock = _SequenceClock(100.0)
        current_store = _SQLiteFixedWindowStore(self.database, clock=current_clock)
        current_limiter = SQLiteWriteRateLimiter(
            current_store, limit=3, window_seconds=60
        )
        remaining, reset_at = current_limiter.consume("actor", "SEND")

        self.assertEqual(2, remaining)
        self.assertEqual(120, reset_at)
        self.assertEqual(1, current_clock.calls)


if __name__ == "__main__":
    unittest.main()
