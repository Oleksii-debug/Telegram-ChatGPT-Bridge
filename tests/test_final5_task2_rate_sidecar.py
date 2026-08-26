"""FINAL5 Task2 regressions for SQLite rate-limit WAL/SHM lifecycle."""
from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from bridge.runtime import RuntimeBootstrapError, _secure_rate_limit_sidecar


class RateLimitSidecarRaceTests(unittest.TestCase):
    @staticmethod
    def _private_state(base: str) -> Path:
        state = Path(base) / "state"
        state.mkdir(mode=0o700)
        os.chmod(state, 0o700)
        return state

    def test_ephemeral_sidecar_disappearance_is_benign(self):
        with tempfile.TemporaryDirectory() as td:
            missing = self._private_state(td) / "rate.sqlite3-wal"
            _secure_rate_limit_sidecar(missing)
            self.assertFalse(missing.exists())

    def test_existing_sidecar_is_pinned_and_tightened_owner_private(self):
        with tempfile.TemporaryDirectory() as td:
            sidecar = self._private_state(td) / "rate.sqlite3-wal"
            sidecar.write_bytes(b"fixture")
            os.chmod(sidecar, 0o644)
            _secure_rate_limit_sidecar(sidecar)
            self.assertEqual(0o600, sidecar.stat().st_mode & 0o777)
            self.assertEqual(b"fixture", sidecar.read_bytes())

    def test_symlink_sidecar_fails_closed_without_touching_target(self):
        with tempfile.TemporaryDirectory() as td:
            state = self._private_state(td)
            target = state / "target"
            target.write_bytes(b"keep")
            os.chmod(target, 0o600)
            sidecar = state / "rate.sqlite3-wal"
            sidecar.symlink_to(target)
            with self.assertRaises(RuntimeBootstrapError) as caught:
                _secure_rate_limit_sidecar(sidecar)
            self.assertEqual("unsafe_rate_limit_database_sidecar", caught.exception.code)
            self.assertEqual(b"keep", target.read_bytes())

    def test_hardlink_sidecar_fails_closed_without_mutating_peer(self):
        with tempfile.TemporaryDirectory() as td:
            state = self._private_state(td)
            target = state / "target"
            target.write_bytes(b"keep")
            os.chmod(target, 0o600)
            sidecar = state / "rate.sqlite3-wal"
            os.link(target, sidecar)
            with self.assertRaises(RuntimeBootstrapError) as caught:
                _secure_rate_limit_sidecar(sidecar)
            self.assertEqual("unsafe_rate_limit_database_sidecar", caught.exception.code)
            self.assertEqual(b"keep", target.read_bytes())


if __name__ == "__main__":
    unittest.main()
