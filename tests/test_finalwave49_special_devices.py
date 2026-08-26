from __future__ import annotations

import os
import unittest
from pathlib import Path

from ops.posix_fs import FilesystemSafetyError, open_directory_fd, open_regular_at, safe_remove_tree
from tests.posix_attack_harness import PosixAttackHarness


@unittest.skipUnless(os.name == "posix", "POSIX filesystem tests")
class FinalWave49SpecialDeviceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.h = PosixAttackHarness(self)

    def test_character_device_is_rejected_after_nonblocking_descriptor_open(self) -> None:
        device = Path("/dev/null")
        if not device.exists():
            self.skipTest("/dev/null unavailable")
        parent_fd, _ = open_directory_fd(device.parent)
        try:
            with self.assertRaisesRegex(FilesystemSafetyError, "not a regular file"):
                open_regular_at(parent_fd, device.name, os.O_RDONLY)
        finally:
            os.close(parent_fd)

    def test_cleanup_unlinks_fifo_and_socket_as_leaves(self) -> None:
        if not hasattr(os, "mkfifo"):
            self.skipTest("mkfifo unavailable")
        tree = self.h.private_dir("cleanup-tree")
        os.mkfifo(tree / "pipe", 0o600)
        self.h.unix_socket(tree / "sock")
        safe_remove_tree(tree)
        self.assertFalse(tree.exists())


if __name__ == "__main__":
    unittest.main()
