"""Reusable adversarial filesystem fixtures for POSIX security tests."""
from __future__ import annotations

import os
import socket
import tempfile
import unittest
from pathlib import Path


class PosixAttackHarness:
    """Create private roots and deterministic same-UID topology attacks."""

    def __init__(self, case: unittest.TestCase) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        case.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self._case = case

    def private_dir(self, name: str = "private") -> Path:
        path = self.base / name
        path.mkdir(mode=0o700)
        os.chmod(path, 0o700)
        return path

    def replace_directory(self, path: Path) -> Path:
        moved = path.with_name(path.name + "-moved")
        path.rename(moved)
        path.mkdir(mode=0o700)
        os.chmod(path, 0o700)
        return moved

    def unix_socket(self, path: Path) -> socket.socket:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._case.addCleanup(sock.close)
        sock.bind(str(path))
        return sock
