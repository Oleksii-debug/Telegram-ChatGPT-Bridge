# -*- coding: utf-8 -*-
"""FINALWAVE-41 regression for hash-only server-manifest public stdout."""
from __future__ import annotations

import contextlib
import io
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tools import collect_server_manifest as server_cli


class PrivatePathOSError(OSError):
    pass


class FinalWave41ServerManifestPrivacyTests(unittest.TestCase):
    def test_failure_stdout_never_contains_exception_class_message_or_path(self):
        failure = PrivatePathOSError("/private/path/server-tree-canary")
        failure.private_path = "/private/path/server-tree-canary"
        output = io.StringIO()
        with tempfile.TemporaryDirectory() as td:
            with mock.patch.object(server_cli.Path, "home", return_value=Path(td)):
                with mock.patch.object(server_cli, "collect_server_manifest", side_effect=failure):
                    with contextlib.redirect_stdout(output):
                        rc = server_cli.main()
        self.assertEqual(2, rc)
        self.assertEqual("SERVER_MANIFEST_BLOCKED\n", output.getvalue())
        self.assertNotIn(type(failure).__name__, output.getvalue())
        self.assertNotIn(str(failure), output.getvalue())
        self.assertNotIn(failure.private_path, output.getvalue())


if __name__ == "__main__":
    unittest.main()
