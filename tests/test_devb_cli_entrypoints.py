# -*- coding: utf-8 -*-
from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SHA = "a" * 40
H1 = "1" * 64
H2 = "2" * 64
CANONICAL_WSGI = (
    "from pathlib import Path\n"
    "from bridge.app import application\n"
    "from ops.passenger_evidence_hook import collect_if_armed\n"
    "_here = Path(__file__).resolve()\n"
    "collect_if_armed(app_root=_here.parent, wsgi_file=_here)\n"
    "__all__ = ['application']\n"
)


class DevBSupportCliTests(unittest.TestCase):
    def _candidate(self, root: Path) -> None:
        root.mkdir(mode=0o700)
        os.chmod(root, 0o700)
        (root / "passenger_wsgi.py").write_text(CANONICAL_WSGI, encoding="utf-8")
        (root / "requirements.txt").write_text("Telethon==1.42.0\n", encoding="utf-8")
        (root / "requirements.lock").write_text(
            "Telethon==1.42.0 \\\n"
            f"    --hash=sha256:{H1} \\\n"
            f"    --hash=sha256:{H2}\n"
            f"pyaes==1.6.1 --hash=sha256:{H1}\n",
            encoding="utf-8",
        )

    @staticmethod
    def _clean_env() -> dict[str, str]:
        env = os.environ.copy()
        env.pop("PYTHONPATH", None)
        return env

    def test_documented_preflight_cli_works_from_non_repository_cwd(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            candidate = base / "candidate"
            evidence = base / "evidence"
            outside = base / "outside"
            self._candidate(candidate)
            evidence.mkdir(mode=0o700); os.chmod(evidence, 0o700)
            outside.mkdir(mode=0o700); os.chmod(outside, 0o700)
            output = evidence / "candidate_runtime_preflight.json"
            result = subprocess.run(
                [
                    sys.executable,
                    str(REPO_ROOT / "tools" / "validate_candidate_runtime_preflight.py"),
                    "--candidate-root", str(candidate),
                    "--candidate-sha", SHA,
                    "--output", str(output),
                ],
                cwd=outside,
                env=self._clean_env(),
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
            )
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertEqual("CANDIDATE_RUNTIME_PREFLIGHT_PASS", result.stdout.strip())
            self.assertEqual("", result.stderr)
            self.assertTrue(output.is_file())
            self.assertEqual(0o600, stat.S_IMODE(output.stat().st_mode))
            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(SHA, payload["candidate_sha"])
            self.assertTrue(payload["preflight_pass"])
            self.assertFalse(payload["promotion_authorized"])

    @unittest.skipUnless(os.name == "posix", "private descriptor arming is POSIX-only")
    def test_documented_arm_cli_works_from_non_repository_cwd(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            candidate = base / "candidate"
            evidence = base / "evidence"
            control = base / "control"
            outside = base / "outside"
            self._candidate(candidate)
            for directory in (evidence, control, outside):
                directory.mkdir(mode=0o700); os.chmod(directory, 0o700)
            preflight = evidence / "candidate_runtime_preflight.json"

            preflight_result = subprocess.run(
                [
                    sys.executable,
                    str(REPO_ROOT / "tools" / "validate_candidate_runtime_preflight.py"),
                    "--candidate-root", str(candidate),
                    "--candidate-sha", SHA,
                    "--output", str(preflight),
                ],
                cwd=outside,
                env=self._clean_env(),
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
            )
            self.assertEqual(0, preflight_result.returncode, preflight_result.stderr)

            command = [
                sys.executable,
                str(REPO_ROOT / "tools" / "arm_passenger_evidence.py"),
                "--preflight", str(preflight),
                "--challenge-sha256", H1,
                "--control-root", str(control),
            ]
            arm_result = subprocess.run(
                command,
                cwd=outside,
                env=self._clean_env(),
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
            )
            self.assertEqual(0, arm_result.returncode, arm_result.stderr)
            self.assertEqual("PASSENGER_EVIDENCE_ARMED_FOR_EXACT_CANDIDATE", arm_result.stdout.strip())
            self.assertEqual("", arm_result.stderr)
            marker = control / "collect_passenger_runtime_evidence.once"
            self.assertTrue(marker.is_file())
            self.assertEqual(0o600, stat.S_IMODE(marker.stat().st_mode))
            payload = json.loads(marker.read_text(encoding="ascii"))
            self.assertEqual(SHA, payload["candidate_sha"])
            self.assertRegex(payload["expected_wsgi_sha256"], r"^[0-9a-f]{64}$")
            self.assertEqual(H1, payload["request_challenge_sha256"])

            # No-clobber semantics are part of the documented one-shot contract.
            repeated = subprocess.run(
                command,
                cwd=outside,
                env=self._clean_env(),
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
            )
            self.assertEqual(2, repeated.returncode)
            self.assertEqual("PASSENGER_EVIDENCE_ARM_BLOCKED", repeated.stdout.strip())
            self.assertEqual("", repeated.stderr)


if __name__ == "__main__":
    unittest.main()
