from __future__ import annotations

import json
import os
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest import mock

from ops.atomic_private_state import (
    PrivateStateError,
    atomic_create_json_once,
    atomic_replace_json,
)


@unittest.skipUnless(os.name == "posix" and hasattr(os, "O_DIRECTORY") and hasattr(os, "O_NOFOLLOW"), "POSIX descriptor security required")
class FinalWave32AtomicPrivateStateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.root = self.base / "private"
        self.root.mkdir(mode=0o700)
        os.chmod(self.root, 0o700)
        self.path = self.root / "state.json"

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _assert_no_generated_temps(self, directory: Path | None = None) -> None:
        directory = directory or self.root
        leftovers = [p.name for p in directory.iterdir() if p.name.startswith(f".{self.path.name}.") and p.name.endswith(".tmp")]
        self.assertEqual(leftovers, [])

    def test_replace_round_trip_is_owner_private_and_complete(self) -> None:
        atomic_replace_json(self.path, {"state": "ONE", "count": 1})
        self.assertEqual(json.loads(self.path.read_text(encoding="utf-8")), {"state": "ONE", "count": 1})
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)
        atomic_replace_json(self.path, {"state": "TWO", "count": 2})
        self.assertEqual(json.loads(self.path.read_text(encoding="utf-8")), {"state": "TWO", "count": 2})
        self._assert_no_generated_temps()

    def test_predictable_stale_temp_symlink_is_ignored_not_followed(self) -> None:
        outside = self.base / "outside.txt"
        outside.write_text("unchanged", encoding="utf-8")
        stale = self.root / f"{self.path.name}.tmp"
        stale.symlink_to(outside)
        atomic_replace_json(self.path, {"state": "SAFE"})
        self.assertEqual(outside.read_text(encoding="utf-8"), "unchanged")
        self.assertTrue(stale.is_symlink())
        self.assertEqual(json.loads(self.path.read_text(encoding="utf-8"))["state"], "SAFE")

    def test_symlink_parent_is_rejected_without_redirected_write(self) -> None:
        target = self.base / "target"
        target.mkdir(mode=0o700)
        os.chmod(target, 0o700)
        alias = self.base / "alias"
        alias.symlink_to(target, target_is_directory=True)
        with self.assertRaisesRegex(PrivateStateError, "parent_topology_unsafe"):
            atomic_replace_json(alias / "state.json", {"state": "NO"})
        self.assertFalse((target / "state.json").exists())

    def test_existing_symlink_hardlink_fifo_and_broad_mode_fail_closed(self) -> None:
        outside = self.base / "outside"
        outside.write_text("x", encoding="utf-8")
        os.chmod(outside, 0o600)

        self.path.symlink_to(outside)
        with self.assertRaisesRegex(PrivateStateError, "not_regular"):
            atomic_replace_json(self.path, {"state": "NO"})
        self.path.unlink()

        os.link(outside, self.path)
        with self.assertRaisesRegex(PrivateStateError, "hardlinked"):
            atomic_replace_json(self.path, {"state": "NO"})
        self.path.unlink()

        os.mkfifo(self.path, 0o600)
        with self.assertRaisesRegex(PrivateStateError, "not_regular"):
            atomic_replace_json(self.path, {"state": "NO"})
        self.path.unlink()

        self.path.write_text("{}\n", encoding="utf-8")
        os.chmod(self.path, 0o644)
        with self.assertRaisesRegex(PrivateStateError, "wrong_mode"):
            atomic_replace_json(self.path, {"state": "NO"})

    def test_failure_before_rename_preserves_old_value_and_cleans_temp(self) -> None:
        atomic_replace_json(self.path, {"state": "OLD"})
        with mock.patch("ops.atomic_private_state.os.replace", side_effect=OSError("synthetic replace failure")):
            with self.assertRaisesRegex(PrivateStateError, "replace_failed"):
                atomic_replace_json(self.path, {"state": "NEW"})
        self.assertEqual(json.loads(self.path.read_text(encoding="utf-8"))["state"], "OLD")
        self._assert_no_generated_temps()

    def test_parent_replacement_before_rename_fails_without_redirecting_state(self) -> None:
        atomic_replace_json(self.path, {"state": "OLD"})
        displaced = self.base / "private-old"
        from ops import atomic_private_state as module
        real_verify = module._verify_parent_binding
        raced = False

        def racing_verify(parent, expected):
            nonlocal raced
            if not raced:
                raced = True
                self.root.rename(displaced)
                self.root.mkdir(mode=0o700)
                os.chmod(self.root, 0o700)
            return real_verify(parent, expected)

        with mock.patch("ops.atomic_private_state._verify_parent_binding", side_effect=racing_verify):
            with self.assertRaisesRegex(PrivateStateError, "parent_changed"):
                atomic_replace_json(self.path, {"state": "NEW"})
        self.assertTrue(raced)
        self.assertFalse(self.path.exists())
        self.assertEqual(json.loads((displaced / "state.json").read_text(encoding="utf-8"))["state"], "OLD")
        self._assert_no_generated_temps(displaced)

    def test_parent_replacement_after_rename_is_detected_without_retry_into_new_parent(self) -> None:
        atomic_replace_json(self.path, {"state": "OLD"})
        displaced = self.base / "private-old"
        from ops import atomic_private_state as module
        real_verify = module._verify_parent_binding
        calls = 0

        def racing_verify(parent, expected):
            nonlocal calls
            calls += 1
            if calls == 2:
                self.root.rename(displaced)
                self.root.mkdir(mode=0o700)
                os.chmod(self.root, 0o700)
            return real_verify(parent, expected)

        with mock.patch("ops.atomic_private_state._verify_parent_binding", side_effect=racing_verify):
            with self.assertRaisesRegex(PrivateStateError, "parent_changed"):
                atomic_replace_json(self.path, {"state": "NEW"})
        self.assertFalse(self.path.exists())
        self.assertEqual(json.loads((displaced / "state.json").read_text(encoding="utf-8"))["state"], "NEW")
        self.assertFalse((self.root / "state.json").exists())

    def test_success_fsyncs_file_and_directory_metadata(self) -> None:
        real_fsync = os.fsync
        calls = []

        def recording_fsync(fd):
            calls.append(fd)
            return real_fsync(fd)

        with mock.patch("ops.atomic_private_state.os.fsync", side_effect=recording_fsync):
            atomic_replace_json(self.path, {"state": "SYNCED"})
        self.assertGreaterEqual(len(calls), 2)

    def test_one_shot_marker_is_durable_and_never_overwrites(self) -> None:
        atomic_create_json_once(self.path, {"marker": "FIRST"})
        first = self.path.read_bytes()
        with self.assertRaisesRegex(PrivateStateError, "already_exists"):
            atomic_create_json_once(self.path, {"marker": "SECOND"})
        self.assertEqual(self.path.read_bytes(), first)
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)
        self._assert_no_generated_temps()

    def test_concurrent_replacements_never_leave_partial_json_or_generated_temp(self) -> None:
        atomic_replace_json(self.path, {"writer": -1})

        def writer(index: int) -> str:
            try:
                atomic_replace_json(self.path, {"writer": index, "payload": "x" * 64})
                return "ok"
            except PrivateStateError:
                return "raced"

        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(writer, range(32)))
        self.assertIn("ok", results)
        payload = json.loads(self.path.read_text(encoding="utf-8"))
        self.assertIn(payload["writer"], range(32))
        self.assertEqual(payload["payload"], "x" * 64)
        self._assert_no_generated_temps()


if __name__ == "__main__":
    unittest.main()
