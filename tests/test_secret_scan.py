# -*- coding: utf-8 -*-
import gzip
import hashlib
import io
import json
import subprocess
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

from tools import secret_scan


class SecretScanTests(unittest.TestCase):
    def make_repo(self):
        tmp = tempfile.TemporaryDirectory()
        repo = Path(tmp.name)
        subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
        subprocess.run(["git", "config", "user.name", "Synthetic Test"], cwd=repo, check=True)
        subprocess.run(["git", "config", "user.email", "synthetic@example.invalid"], cwd=repo, check=True)
        (repo / "README.md").write_text("synthetic test repository\n", encoding="utf-8")
        subprocess.run(["git", "add", "README.md"], cwd=repo, check=True)
        subprocess.run(["git", "commit", "-qm", "initial"], cwd=repo, check=True)
        return tmp, repo

    def commit_all(self, repo, message):
        subprocess.run(["git", "add", "-A", "-f"], cwd=repo, check=True)
        subprocess.run(["git", "commit", "-qm", message], cwd=repo, check=True)

    def write_allowlist(self, repo, path, data):
        payload = {
            "entries": [
                {
                    "path": path,
                    "sha256": hashlib.sha256(data).hexdigest(),
                    "reason": "Synthetic reviewed non-secret fixture.",
                }
            ]
        }
        (repo / secret_scan.ALLOWLIST_FILE).write_text(json.dumps(payload) + "\n", encoding="utf-8")

    def secret_line(self, name, value="synthetic-value-1234567890"):
        return name + "=" + value + "\n"

    def zip_bytes(self, member, content):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr(member, content)
        return buffer.getvalue()

    def tar_bytes(self, member, content, mode="w"):
        buffer = io.BytesIO()
        encoded = content.encode("utf-8")
        with tarfile.open(fileobj=buffer, mode=mode) as archive:
            info = tarfile.TarInfo(member)
            info.size = len(encoded)
            archive.addfile(info, io.BytesIO(encoded))
        return buffer.getvalue()

    def test_current_tree_matrix_rejects_policy_artifacts(self):
        tmp, repo = self.make_repo(); self.addCleanup(tmp.cleanup)
        for name in (".env.production", "private.key", "BRIDGE_KEYS_SECRET.txt", "Credentials.JSON", "runtime.log", "cookies.txt"):
            (repo / name).write_text("safe fixture\n", encoding="utf-8")
        variable = "TG_" + "API_HASH"
        value = "synthetic-value-1234567890"
        structured_variable = "GOOGLE_DRIVE_" + "CLIENT_SECRET"
        structured = "synthetic-json-1234567890"
        (repo / "config.txt").write_text(variable + "=" + value + "\n", encoding="utf-8")
        (repo / "config.json").write_text('{"' + structured_variable.lower() + '": "' + structured + '"}\n', encoding="utf-8")
        self.commit_all(repo, "add synthetic policy violations")
        joined = "\n".join(secret_scan.scan_current_tree(repo))
        for token in (".env.production", "private.key", "BRIDGE_KEYS_SECRET.txt", "Credentials.JSON", "runtime.log", "cookies.txt", variable, structured_variable):
            self.assertIn(token, joined)
        self.assertNotIn(value, joined); self.assertNotIn(structured, joined)

    def test_generic_credential_aliases_are_detected_and_redacted(self):
        tmp, repo = self.make_repo(); self.addCleanup(tmp.cleanup)
        aliases = ["api_" + "id", "api_" + "hash", "session_" + "string", "two_factor_" + "password", "password", "bearer_" + "token", "access_" + "token", "refresh_" + "token", "client_" + "secret"]
        lines = []
        values = []
        for index, alias in enumerate(aliases):
            value = str(100000 + index) if alias == "api_id" else f"synthetic-generic-{index}-1234567890"
            lines.append(alias + "=" + value)
            values.append(value)
        (repo / "generic.conf").write_text("\n".join(lines) + "\n", encoding="utf-8")
        self.commit_all(repo, "generic aliases")
        joined = "\n".join(secret_scan.scan_current_tree(repo))
        for alias in aliases:
            self.assertIn(alias.upper(), joined)
        for value in values:
            self.assertNotIn(value, joined)

    def test_safe_environment_references_and_placeholders_pass(self):
        alias = "password"
        safe = ["<SECRET>", "${{ secrets.EXAMPLE }}", "${PASSWORD}", "$PASSWORD", "replace-me", "os.getenv('PASSWORD')", "os.environ['PASSWORD']"]
        for value in safe[:5]:
            self.assertTrue(secret_scan.is_placeholder(value), value)
        for value in safe[5:]:
            self.assertTrue(secret_scan.is_safe_reference(value), value)
        for value in ("prefix-${HOME}-suffix", "literal-secret-123456"):
            self.assertFalse(secret_scan.is_placeholder(value), value)
        finding = "\n".join(secret_scan.scan_text(alias + "=prefix-${HOME}-suffix\n", "config.txt", "test"))
        self.assertIn(alias.upper(), finding)

    def test_history_detects_removed_canary(self):
        tmp, repo = self.make_repo(); self.addCleanup(tmp.cleanup)
        variable = "BRIDGE_" + "TOKEN"; value = "synthetic-history-1234567890"
        leak = repo / "temporary-config.txt"; leak.write_text(variable + "=" + value + "\n", encoding="utf-8")
        self.commit_all(repo, "introduce synthetic canary"); leak.unlink(); self.commit_all(repo, "remove synthetic canary")
        current = "\n".join(secret_scan.scan_current_tree(repo)); history = "\n".join(secret_scan.scan_history(repo))
        self.assertNotIn(variable, current); self.assertIn(variable, history); self.assertNotIn(value, history)

    def test_history_detects_commit_message_canary(self):
        tmp, repo = self.make_repo(); self.addCleanup(tmp.cleanup)
        variable = "SETUP_" + "KEY"; value = "synthetic-commit-message-1234567890"
        subprocess.run(["git", "commit", "--allow-empty", "-qm", variable + "=" + value], cwd=repo, check=True)
        history = "\n".join(secret_scan.scan_history(repo))
        self.assertIn(variable, history); self.assertIn("<commit-message>", history); self.assertNotIn(value, history)

    def test_allowlisted_oversized_text_cannot_bypass_secret_content(self):
        tmp, repo = self.make_repo(); self.addCleanup(tmp.cleanup)
        variable = "BRIDGE_" + "TOKEN"; value = "synthetic-oversized-1234567890"
        data = (b"A" * 5_100_000) + ("\n" + variable + "=" + value + "\n").encode()
        path = "large.txt"; (repo / path).write_bytes(data); self.write_allowlist(repo, path, data)
        subprocess.run(["git", "add", "-f", path, secret_scan.ALLOWLIST_FILE], cwd=repo, check=True)
        joined = "\n".join(secret_scan.scan_current_tree(repo)); self.assertIn(variable, joined); self.assertNotIn(value, joined)

    def test_allowlisted_binary_cannot_bypass_private_key_marker(self):
        tmp, repo = self.make_repo(); self.addCleanup(tmp.cleanup)
        marker = ("-----BEGIN " + "OPENSSH " + "PRIVATE " + "KEY-----").encode("ascii")
        data = b"\x00BIN\x01" + marker + b"\x02END"; path = "fixture.bin"
        (repo / path).write_bytes(data); self.write_allowlist(repo, path, data)
        subprocess.run(["git", "add", "-f", path, secret_scan.ALLOWLIST_FILE], cwd=repo, check=True)
        self.assertIn("private key marker", "\n".join(secret_scan.scan_current_tree(repo)))

    def test_disguised_zip_cannot_use_binary_allowlist(self):
        tmp, repo = self.make_repo(); self.addCleanup(tmp.cleanup)
        variable = "BRIDGE_" + "TOKEN"; value = "synthetic-disguised-zip-1234567890"
        data = self.zip_bytes("config.txt", self.secret_line(variable, value)); path = "reviewed.bin"
        (repo / path).write_bytes(data); self.write_allowlist(repo, path, data)
        subprocess.run(["git", "add", "-f", path, secret_scan.ALLOWLIST_FILE], cwd=repo, check=True)
        joined = "\n".join(secret_scan.scan_current_tree(repo)); self.assertIn(variable, joined); self.assertNotIn(value, joined)

    def test_disguised_tar_and_gzip_tar_are_detected_by_content(self):
        for suffix, mode in (("payload.dat", "w"), ("payload.bin", "w:gz")):
            with self.subTest(suffix=suffix):
                tmp, repo = self.make_repo(); self.addCleanup(tmp.cleanup)
                variable = "TG_" + "API_HASH"; value = "synthetic-tar-1234567890"
                data = self.tar_bytes("nested/config.txt", self.secret_line(variable, value), mode=mode)
                (repo / suffix).write_bytes(data); self.write_allowlist(repo, suffix, data)
                subprocess.run(["git", "add", "-f", suffix, secret_scan.ALLOWLIST_FILE], cwd=repo, check=True)
                joined = "\n".join(secret_scan.scan_current_tree(repo)); self.assertIn(variable, joined); self.assertNotIn(value, joined)

    def test_raw_gzip_disguised_as_binary_fails_closed(self):
        tmp, repo = self.make_repo(); self.addCleanup(tmp.cleanup)
        data = gzip.compress(b"synthetic compressed content"); path = "compressed.bin"
        (repo / path).write_bytes(data); self.write_allowlist(repo, path, data)
        subprocess.run(["git", "add", "-f", path, secret_scan.ALLOWLIST_FILE], cwd=repo, check=True)
        self.assertIn("unsupported compressed/archive signature", "\n".join(secret_scan.scan_current_tree(repo)))

    def test_nested_disguised_archive_is_recursively_scanned(self):
        tmp, repo = self.make_repo(); self.addCleanup(tmp.cleanup)
        variable = "TG_" + "API_HASH"; value = "synthetic-nested-1234567890"
        inner = self.zip_bytes("config.txt", self.secret_line(variable, value))
        outer = self.zip_bytes("payload.dat", inner)
        (repo / "outer.zip").write_bytes(outer); subprocess.run(["git", "add", "-f", "outer.zip"], cwd=repo, check=True)
        joined = "\n".join(secret_scan.scan_current_tree(repo)); self.assertIn(variable, joined); self.assertNotIn(value, joined)

    def test_extension_signature_mismatch_fails_closed(self):
        tmp, repo = self.make_repo(); self.addCleanup(tmp.cleanup)
        data = self.zip_bytes("safe.txt", "safe"); (repo / "wrong.tar").write_bytes(data)
        subprocess.run(["git", "add", "-f", "wrong.tar"], cwd=repo, check=True)
        self.assertIn("extension-signature mismatch", "\n".join(secret_scan.scan_current_tree(repo)))

    def test_archive_path_traversal_fails_closed(self):
        tmp, repo = self.make_repo(); self.addCleanup(tmp.cleanup)
        data = self.zip_bytes("../escape.txt", "safe"); (repo / "bad.zip").write_bytes(data)
        subprocess.run(["git", "add", "-f", "bad.zip"], cwd=repo, check=True)
        self.assertIn("unsafe archive member path", "\n".join(secret_scan.scan_current_tree(repo)))

    def test_tar_special_members_fail_closed(self):
        tmp, repo = self.make_repo(); self.addCleanup(tmp.cleanup)
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w") as archive:
            info = tarfile.TarInfo("link")
            info.type = tarfile.SYMTYPE; info.linkname = "target"
            archive.addfile(info)
        (repo / "special.tar").write_bytes(buffer.getvalue())
        subprocess.run(["git", "add", "-f", "special.tar"], cwd=repo, check=True)
        self.assertIn("tar special member rejected", "\n".join(secret_scan.scan_current_tree(repo)))

    def test_reviewed_hash_allowlist_allows_nonsecret_binary_only(self):
        tmp, repo = self.make_repo(); self.addCleanup(tmp.cleanup)
        data = b"\x00synthetic-nonsecret-binary\x01"; path = "fixture.bin"
        (repo / path).write_bytes(data); self.write_allowlist(repo, path, data)
        subprocess.run(["git", "add", "-f", path, secret_scan.ALLOWLIST_FILE], cwd=repo, check=True)
        self.assertNotIn(path, "\n".join(secret_scan.scan_current_tree(repo)))

    def test_shallow_repository_fails_closed(self):
        source_tmp, source = self.make_repo(); self.addCleanup(source_tmp.cleanup)
        (source / "second.txt").write_text("second\n"); self.commit_all(source, "second")
        clone_tmp = tempfile.TemporaryDirectory(); self.addCleanup(clone_tmp.cleanup)
        clone = Path(clone_tmp.name) / "clone"
        subprocess.run(["git", "clone", "-q", "--depth", "1", source.resolve().as_uri(), str(clone)], check=True)
        self.assertTrue(secret_scan._is_shallow(clone))
        self.assertIn("repository checkout is shallow", "\n".join(secret_scan.scan_history(clone)))


if __name__ == "__main__":
    unittest.main()
