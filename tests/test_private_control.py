# -*- coding: utf-8 -*-
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from ops import private_control
from ops.release_guard import SafetyError


@unittest.skipUnless(os.name == "posix" and hasattr(os, "O_NOFOLLOW") and hasattr(os, "O_DIRECTORY"), "POSIX private-control primitives required")
class PrivateControlTests(unittest.TestCase):
    def root(self, td):
        root = Path(td) / "private"
        root.mkdir(mode=0o700)
        os.chmod(root, 0o700)
        return root

    def file(self, root, name="value", content="safe", mode=0o600):
        path = root / name
        path.write_text(content, encoding="utf-8")
        os.chmod(path, mode)
        return path

    def test_secure_read_accepts_private_regular_file(self):
        with tempfile.TemporaryDirectory() as td:
            root = self.root(td); path = self.file(root, content="hello")
            self.assertEqual("hello", private_control.read_private_text(root, path))

    def test_read_identity_can_bind_later_transition(self):
        with tempfile.TemporaryDirectory() as td:
            root = self.root(td); path = self.file(root, content="hello")
            text, identity = private_control.read_private_text_with_identity(root, path)
            self.assertEqual("hello", text)
            private_control.verify_private_file_identity(root, path, identity)
            replacement = Path(td) / "replacement"; replacement.write_text("hello", encoding="utf-8"); os.chmod(replacement, 0o600)
            path.unlink(); replacement.rename(path)
            with self.assertRaises(SafetyError):
                private_control.verify_private_file_identity(root, path, identity)

    def test_broad_root_and_file_modes_fail_closed(self):
        with tempfile.TemporaryDirectory() as td:
            root = self.root(td); path = self.file(root)
            os.chmod(path, 0o644)
            with self.assertRaises(SafetyError):
                private_control.read_private_text(root, path)
            os.chmod(path, 0o600); os.chmod(root, 0o755)
            with self.assertRaises(SafetyError):
                private_control.read_private_text(root, path)

    def test_symlink_and_hardlink_fail_closed(self):
        with tempfile.TemporaryDirectory() as td:
            root = self.root(td); target = self.file(root, "target")
            link = root / "link"; link.symlink_to(target)
            with self.assertRaises((SafetyError, OSError)):
                private_control.read_private_text(root, link)
            hard = root / "hard"; os.link(target, hard)
            with self.assertRaises(SafetyError):
                private_control.read_private_text(root, target)

    def test_private_nested_directory_required(self):
        with tempfile.TemporaryDirectory() as td:
            root = self.root(td); nested = root / "nested"; nested.mkdir(); os.chmod(nested, 0o700)
            path = self.file(nested)
            self.assertEqual("safe", private_control.read_private_text(root, path))
            os.chmod(nested, 0o755)
            with self.assertRaises(SafetyError):
                private_control.read_private_text(root, path)

    def test_path_escape_fails_closed(self):
        with tempfile.TemporaryDirectory() as td:
            root = self.root(td); outside = Path(td) / "outside"; outside.write_text("safe"); os.chmod(outside, 0o600)
            with self.assertRaises(SafetyError):
                private_control.read_private_text(root, outside)

    def test_inode_replacement_between_precheck_and_open_fails(self):
        with tempfile.TemporaryDirectory() as td:
            root = self.root(td); path = self.file(root, content="original")
            replacement = Path(td) / "replacement"; replacement.write_text("replacement"); os.chmod(replacement, 0o600)
            real_open = os.open
            triggered = {"done": False}

            def racing_open(target, flags, *args, **kwargs):
                if target == "value" and kwargs.get("dir_fd") is not None and not triggered["done"]:
                    triggered["done"] = True
                    path.unlink()
                    replacement.rename(path)
                return real_open(target, flags, *args, **kwargs)

            with mock.patch.object(private_control.os, "open", side_effect=racing_open):
                with self.assertRaises(SafetyError):
                    private_control.read_private_text(root, path)
            self.assertTrue(triggered["done"])

    def test_private_json_no_clobber_creates_owner_only_file(self):
        with tempfile.TemporaryDirectory() as td:
            root = self.root(td); out = root / "evidence.json"
            identity = private_control.write_private_json_no_clobber(root, out, {"safe": True})
            self.assertTrue(out.is_file())
            self.assertEqual(0o600, out.stat().st_mode & 0o777)
            self.assertEqual(private_control.private_identity_sha256(identity), private_control.private_identity_sha256(identity))
            with self.assertRaises(SafetyError):
                private_control.write_private_json_no_clobber(root, out, {"safe": False})

    def test_private_write_rejects_root_and_final_symlinks_or_hardlinks(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td); target_root = base / "target"; target_root.mkdir(mode=0o700); os.chmod(target_root, 0o700)
            alias = base / "alias"; alias.symlink_to(target_root, target_is_directory=True)
            with self.assertRaises(SafetyError):
                private_control.write_private_json_no_clobber(alias, alias / "evidence.json", {"safe": True})
        with tempfile.TemporaryDirectory() as td:
            root = self.root(td); outside = Path(td) / "outside"; outside.write_text("unchanged", encoding="utf-8"); os.chmod(outside, 0o600)
            final = root / "evidence.json"; final.symlink_to(outside)
            with self.assertRaises(SafetyError):
                private_control.write_private_json_no_clobber(root, final, {"safe": True})
            self.assertEqual("unchanged", outside.read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as td:
            root = self.root(td); outside = Path(td) / "outside"; outside.write_text("unchanged", encoding="utf-8"); os.chmod(outside, 0o600)
            final = root / "evidence.json"; os.link(outside, final)
            with self.assertRaises(SafetyError):
                private_control.write_private_json_no_clobber(root, final, {"safe": True})

    def test_preexisting_predicted_temp_symlink_cannot_be_followed(self):
        with tempfile.TemporaryDirectory() as td:
            root = self.root(td); final = root / "evidence.json"; outside = Path(td) / "outside"; outside.write_text("unchanged", encoding="utf-8"); os.chmod(outside, 0o600)
            token = "ab" * 12
            predicted = root / f".{final.name}.{token}.tmp"
            predicted.symlink_to(outside)
            with mock.patch.object(private_control.secrets, "token_hex", return_value=token):
                with self.assertRaises(SafetyError):
                    private_control.write_private_json_no_clobber(root, final, {"safe": True})
            self.assertEqual("unchanged", outside.read_text(encoding="utf-8"))

    def test_private_write_detects_directory_replacement(self):
        with tempfile.TemporaryDirectory() as td:
            root = self.root(td); final = root / "evidence.json"; moved = Path(td) / "moved"
            real_lstat = os.lstat
            calls = {"root": 0}
            def racing_lstat(path, *args, **kwargs):
                if Path(path) == root:
                    calls["root"] += 1
                    if calls["root"] == 2:
                        root.rename(moved)
                        root.mkdir(mode=0o700); os.chmod(root, 0o700)
                return real_lstat(path, *args, **kwargs)
            with mock.patch.object(private_control.os, "lstat", side_effect=racing_lstat):
                with self.assertRaises(SafetyError):
                    private_control.write_private_json_no_clobber(root, final, {"safe": True})
            self.assertGreaterEqual(calls["root"], 2)
            self.assertFalse(final.exists())

    def test_secure_executable_success_nonzero_and_timeout(self):
        with tempfile.TemporaryDirectory() as td:
            root = self.root(td)
            ok = self.file(root, "ok", "#!/bin/sh\nexit 0\n", 0o700)
            bad = self.file(root, "bad", "#!/bin/sh\nexit 7\n", 0o700)
            slow = self.file(root, "slow", "#!/bin/sh\nsleep 1\n", 0o700)
            self.assertEqual(0, private_control.run_private_executable(root, ok, timeout=2))
            self.assertEqual(7, private_control.run_private_executable(root, bad, timeout=2))
            self.assertEqual(-1, private_control.run_private_executable(root, slow, timeout=0.1))

    def test_non_executable_file_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            root = self.root(td); path = self.file(root)
            with self.assertRaises(SafetyError):
                private_control.open_private_fd(root, path, require_executable=True)

    def test_bounded_text_rejects_large_file(self):
        with tempfile.TemporaryDirectory() as td:
            root = self.root(td); path = self.file(root, content="x" * 100)
            with self.assertRaises(SafetyError):
                private_control.read_private_text(root, path, max_bytes=16)


if __name__ == "__main__":
    unittest.main()
