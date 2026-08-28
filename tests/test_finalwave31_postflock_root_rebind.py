# -*- coding: utf-8 -*-
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from ops import deploy_release
from ops import deployment_lock_policy
from ops.release_guard import SafetyError


@unittest.skipUnless(
    os.name == "posix" and hasattr(os, "O_NOFOLLOW") and hasattr(os, "O_DIRECTORY"),
    "descriptor-bound POSIX deployment lock primitives required",
)
class FinalWave31PostFlockRootRebindTests(unittest.TestCase):
    def test_root_replacement_during_postflock_leaf_rebind_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "control"
            root.mkdir(mode=0o700)
            os.chmod(root, 0o700)
            moved = Path(td) / "moved-control"
            real_leaf_stat = deployment_lock_policy._relative_leaf_stat
            calls = {"count": 0}

            def racing_leaf_stat(root_fd, leaf):
                calls["count"] += 1
                # First call is the pre-open leaf probe. The second occurs only
                # after flock, immediately before leaf/inode rebinding.
                if calls["count"] == 2:
                    root.rename(moved)
                    root.mkdir(mode=0o700)
                    os.chmod(root, 0o700)
                return real_leaf_stat(root_fd, leaf)

            with mock.patch.object(
                deployment_lock_policy,
                "_relative_leaf_stat",
                side_effect=racing_leaf_stat,
            ):
                with self.assertRaises(SafetyError):
                    with deploy_release._deployment_lock(root):
                        self.fail("post-flock root replacement must not enter critical section")

            self.assertGreaterEqual(calls["count"], 2)
            self.assertFalse((root / deploy_release.TRANSACTION_LOCK).exists())
            self.assertTrue((moved / deploy_release.TRANSACTION_LOCK).exists())


if __name__ == "__main__":
    unittest.main()
