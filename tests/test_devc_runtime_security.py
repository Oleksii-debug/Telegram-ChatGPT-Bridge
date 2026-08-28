# -*- coding: utf-8 -*-
"""DEV_C security regressions for the actual production runtime bootstrap.

Credential-free and network-free.  These tests exercise only local temporary
state and must never be interpreted as live Telegram or production evidence.
"""
from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from bridge.runtime import RuntimeBootstrapError, _SQLiteFixedWindowStore


class MutableClock:
    def __init__(self, value: float):
        self.value = value

    def __call__(self) -> float:
        return self.value


class RuntimeRateLimitSecurityTests(unittest.TestCase):
    @staticmethod
    def _private_state(root: Path) -> Path:
        state = root / "state"
        state.mkdir(mode=0o700)
        os.chmod(state, 0o700)
        return state

    def test_backward_clock_after_exhaustion_fails_closed_across_store_instances(self):
        """Wall-clock rollback must not reopen an already consumed quota window."""
        with tempfile.TemporaryDirectory() as td:
            state = self._private_state(Path(td))
            database = state / "rate.sqlite3"
            clock = MutableClock(120.0)
            first = _SQLiteFixedWindowStore(database, clock=clock)

            allowed, remaining, retry = first.take(
                namespace="read", actor="actor-a", operation="read-api", limit=1, window_seconds=60
            )
            self.assertTrue(allowed)
            self.assertEqual(0, remaining)
            self.assertEqual(0, retry)
            denied = first.take(
                namespace="read", actor="actor-a", operation="read-api", limit=1, window_seconds=60
            )
            self.assertFalse(denied[0])

            # A one-second rollback crosses the fixed-window boundary.  The
            # previous in-memory DEV1/DEV5 contract rejected backward time; the
            # process-shared production store must preserve that safety property.
            clock.value = 119.0
            with self.assertRaises(RuntimeBootstrapError):
                first.take(
                    namespace="read", actor="actor-a", operation="read-api", limit=1, window_seconds=60
                )

            # Restart/new-worker semantics must not erase the monotonicity fact.
            second = _SQLiteFixedWindowStore(database, clock=clock)
            with self.assertRaises(RuntimeBootstrapError):
                second.take(
                    namespace="read", actor="actor-a", operation="read-api", limit=1, window_seconds=60
                )


if __name__ == "__main__":
    unittest.main()
