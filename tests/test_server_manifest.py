# -*- coding: utf-8 -*-
import os
import tempfile
import unittest
from pathlib import Path

from ops import server_manifest
from ops.release_guard import SafetyError


class ServerManifestTests(unittest.TestCase):
    def write(self, root: Path, rel: str, data: bytes = b"x") -> Path:
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def candidate(self, root: Path):
        self.write(root, "passenger_wsgi.py", b"from bridge.app import application\n")
        self.write(root, "install_server.sh", b"")
        self.write(root, "bridge/app.py", b"application = object()\n")
        self.write(root, "tests/test_app.py", b"def test_x(): pass\n")
        self.write(root, "ops/helper.py", b"x = 1\n")
        self.write(root, "tools/helper.py", b"x = 1\n")
        self.write(root, "requirements.txt", b"pkg==1\n")
        self.write(root, "docs/README.md", b"safe\n")
        self.write(root, "README.md", b"safe\n")

    def test_hash_only_manifest_classifies_reviewed_files(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); self.candidate(root)
            result = server_manifest.collect_server_manifest(root)
            rows = {item["path"]: item for item in result["files"]}
            self.assertEqual("wsgi_startup", rows["passenger_wsgi.py"]["category"])
            self.assertEqual("empty_extra", rows["install_server.sh"]["category"])
            self.assertEqual("application_source", rows["bridge/app.py"]["category"])
            self.assertEqual("dependency_input", rows["requirements.txt"]["category"])
            self.assertEqual(64, len(rows["bridge/app.py"]["sha256"]))
            self.assertNotIn("content", rows["bridge/app.py"])

    def test_private_runtime_directories_are_not_entered_or_serialized(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); self.candidate(root)
            self.write(root, "var/private.sqlite3", b"private")
            self.write(root, "sessions/account.session", b"private")
            result = server_manifest.collect_server_manifest(root)
            encoded = str(result)
            self.assertNotIn("private.sqlite3", encoded)
            self.assertNotIn("account.session", encoded)

    def test_private_file_at_public_root_fails_closed(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); self.candidate(root)
            self.write(root, "private_config.json", b"{}")
            with self.assertRaises(SafetyError):
                server_manifest.collect_server_manifest(root)

    def test_unreviewed_file_class_fails_closed(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); self.candidate(root)
            self.write(root, "mystery.bin", b"opaque")
            with self.assertRaises(SafetyError):
                server_manifest.collect_server_manifest(root)

    def test_nonempty_install_server_fails_closed(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); self.candidate(root)
            self.write(root, "install_server.sh", b"echo mutate\n")
            with self.assertRaises(SafetyError):
                server_manifest.collect_server_manifest(root)

    def test_symlink_file_fails_closed(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); self.candidate(root)
            target = root / "bridge" / "app.py"
            (root / "bridge" / "link.py").symlink_to(target)
            with self.assertRaises(SafetyError):
                server_manifest.collect_server_manifest(root)

    def test_hardlink_file_fails_closed(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); self.candidate(root)
            os.link(root / "bridge" / "app.py", root / "bridge" / "copy.py")
            with self.assertRaises(SafetyError):
                server_manifest.collect_server_manifest(root)

    def test_casefold_collision_fails_closed(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); self.candidate(root)
            self.write(root, "bridge/App.py", b"other")
            with self.assertRaises(SafetyError):
                server_manifest.collect_server_manifest(root)

    def test_unknown_directory_file_fails_closed(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); self.candidate(root)
            self.write(root, "unknown/item.py", b"x")
            with self.assertRaises(SafetyError):
                server_manifest.collect_server_manifest(root)


if __name__ == "__main__":
    unittest.main()
