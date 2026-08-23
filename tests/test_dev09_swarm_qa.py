from __future__ import annotations

import ast
import json
import tempfile
import threading
import unittest
from io import BytesIO
from pathlib import Path

from bridge.app import BridgeApplication, ReadAppConfig
from bridge.integrated_app import UnifiedBridgeApplication
from bridge.security import BearerGuard, RateLimitDecision
from bridge.errors import HiddenNotFound
from ops.candidate_contracts import (
    candidate_acceptance_coverage,
    integrated_api_inventory,
    validate_candidate_acceptance_coverage,
    validate_integrated_api_inventory,
)
from ops.write_endpoint_policy import FixedWindowEndpointLimiter


ROOT = Path(__file__).resolve().parents[1]
TOKEN = "q" * 32


class _AllowReadLimiter:
    def check(self, actor: str) -> RateLimitDecision:
        del actor
        return RateLimitDecision(True, remaining=99)


class _ExplodingInput:
    def __init__(self) -> None:
        self.read_calls = 0

    def read(self, *_args, **_kwargs):
        self.read_calls += 1
        raise AssertionError("private request body was read before authorization/configuration gate")


class _FakeWriter:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []
        self._lock = threading.Lock()

    def send(self, target, text):
        with self._lock:
            self.calls.append((str(target), str(text)))
        return {"operation": "SEND", "message_ids": [101], "chat_id": 202, "count": 1}


def _call(app, path: str, body: dict, *, token: str | None = TOKEN):
    raw = json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    environ = {
        "REQUEST_METHOD": "POST",
        "PATH_INFO": path,
        "CONTENT_TYPE": "application/json",
        "CONTENT_LENGTH": str(len(raw)),
        "wsgi.input": BytesIO(raw),
    }
    if token is not None:
        environ["HTTP_AUTHORIZATION"] = f"Bearer {token}"
    captured: dict[str, object] = {}

    def start_response(status, headers):
        captured["status"] = status
        captured["headers"] = dict(headers)

    payload = json.loads(b"".join(app(environ, start_response)).decode("utf-8"))
    return int(str(captured["status"]).split()[0]), payload, captured["headers"]


class ArtifactBoundaryTests(unittest.TestCase):
    """Independent oracle for repository-CI versus immutable-artifact test closure."""

    _GIT_HELPERS = {"_blob", "_path_exists", "_verify_overlap_matrix", "verify_repository"}

    def test_all_git_dependent_dev_a_provenance_methods_are_repository_only(self):
        path = ROOT / "tests" / "test_dev_a_provenance.py"
        tree = ast.parse(path.read_text(encoding="utf-8"))
        checked = 0
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) or not node.name.startswith("test_"):
                continue
            names = {child.func.id for child in ast.walk(node) if isinstance(child, ast.Call) and isinstance(child.func, ast.Name)}
            if not (names & self._GIT_HELPERS):
                continue
            decorators = {d.id for d in node.decorator_list if isinstance(d, ast.Name)}
            self.assertIn("requires_repository_git", decorators, node.name)
            checked += 1
        self.assertGreaterEqual(checked, 7)

    def test_git_tracked_path_manifest_check_is_repository_only(self):
        path = ROOT / "tests" / "test_server_manifest.py"
        tree = ast.parse(path.read_text(encoding="utf-8"))
        target = next(
            node for node in ast.walk(tree)
            if isinstance(node, ast.FunctionDef) and node.name == "test_every_current_git_tracked_path_has_reviewed_category"
        )
        decorators = {d.id for d in target.decorator_list if isinstance(d, ast.Name)}
        self.assertIn("requires_repository_git", decorators)

    def test_prepare_still_executes_exported_artifact_tests(self):
        source = (ROOT / "ops" / "deploy_release.py").read_text(encoding="utf-8")
        self.assertIn("git_export(repo, sha, source)", source)
        self.assertIn('[str(py), "-m", "unittest", "discover", "-s", "tests", "-v"]', source)
        self.assertIn("cwd=source", source)


class AcceptanceAndRouteTruthTests(unittest.TestCase):
    def test_all_67_criteria_remain_conservative(self):
        rows = candidate_acceptance_coverage()
        counts = validate_candidate_acceptance_coverage(rows)
        self.assertEqual(len(rows), 67)
        self.assertEqual(
            counts,
            {"LIVE_EXTERNAL_REQUIRED": 17, "REAL_SOURCE_REQUIRED": 13, "SYNTHETIC_EXECUTABLE": 37},
        )
        self.assertTrue(all(row["product_pass"] is False for row in rows))
        by_id = {row["criterion"]: row for row in rows}
        for criterion in ("H1", "H2", "I1", "I4", "I6", "K1", "K2", "K3", "K4", "K5"):
            self.assertEqual(by_id[criterion]["evidence_class"], "LIVE_EXTERNAL_REQUIRED")
        self.assertTrue(by_id["K5"]["explicit_write_approval_required"])

    def test_current_19_route_inventory_is_bounded_and_private_setup_free(self):
        rows = integrated_api_inventory()
        validate_integrated_api_inventory(rows)
        self.assertEqual(len(rows), 19)
        keys = {(row["method"], row["path"]) for row in rows}
        self.assertEqual(len(keys), 19)
        for row in rows:
            path = row["path"]
            self.assertTrue(path.startswith("/"))
            self.assertNotIn("..", path)
            self.assertNotIn("\\", path)
            self.assertNotIn("?", path)
            lowered = path.casefold()
            for forbidden in ("setup", "login", "session", "2fa"):
                self.assertNotIn(forbidden, lowered)
            if path != "/health":
                self.assertIn(row["auth_policy"], {"BEARER", "BEARER_OR_SIGNED"})


class AuthAndMalformedRequestTests(unittest.TestCase):
    def test_bearer_guard_fuzz_rejects_non_exact_variants(self):
        guard = BearerGuard(TOKEN)
        bad = (
            {},
            {"HTTP_AUTHORIZATION": ""},
            {"HTTP_AUTHORIZATION": f"bearer {TOKEN}"},
            {"HTTP_AUTHORIZATION": f"Bearer  {TOKEN}"},
            {"HTTP_AUTHORIZATION": f"Bearer {TOKEN} "},
            {"HTTP_AUTHORIZATION": "Basic " + TOKEN},
            {"HTTP_AUTHORIZATION": "Bearer " + ("x" * 600)},
            {"HTTP_AUTHORIZATION": 123},
        )
        for environ in bad:
            with self.subTest(environ_type=type(environ.get("HTTP_AUTHORIZATION")).__name__):
                with self.assertRaises(HiddenNotFound):
                    guard.require(environ)
        guard.require({"HTTP_AUTHORIZATION": f"Bearer {TOKEN}"})

    def test_unauthorized_write_never_reads_private_body(self):
        read_app = BridgeApplication(
            config=ReadAppConfig(auth_secret=TOKEN),
            rate_limiter=_AllowReadLimiter(),
        )
        app = UnifiedBridgeApplication(read_app=read_app)
        exploding = _ExplodingInput()
        environ = {
            "REQUEST_METHOD": "POST",
            "PATH_INFO": "/api/v1/messages/send/preview",
            "CONTENT_TYPE": "application/json",
            "CONTENT_LENGTH": "999999999",
            "wsgi.input": exploding,
        }
        captured = {}
        out = b"".join(app(environ, lambda status, headers: captured.update(status=status, headers=headers)))
        self.assertEqual(str(captured["status"]).split()[0], "404")
        self.assertEqual(exploding.read_calls, 0)
        self.assertNotIn(TOKEN.encode("utf-8"), out)

    def test_authenticated_but_unconfigured_write_store_fails_before_body_read(self):
        read_app = BridgeApplication(
            config=ReadAppConfig(auth_secret=TOKEN),
            rate_limiter=_AllowReadLimiter(),
        )
        app = UnifiedBridgeApplication(read_app=read_app)
        exploding = _ExplodingInput()
        environ = {
            "REQUEST_METHOD": "POST",
            "PATH_INFO": "/api/v1/messages/send/preview",
            "CONTENT_TYPE": "application/json",
            "CONTENT_LENGTH": "999999999",
            "wsgi.input": exploding,
            "HTTP_AUTHORIZATION": f"Bearer {TOKEN}",
        }
        captured = {}
        out = b"".join(app(environ, lambda status, headers: captured.update(status=status, headers=headers)))
        self.assertEqual(str(captured["status"]).split()[0], "503")
        self.assertEqual(exploding.read_calls, 0)
        payload = json.loads(out.decode("utf-8"))
        self.assertEqual(payload["error"]["code"], "write_store_unconfigured")


class MockedWriteSequenceTests(unittest.TestCase):
    def test_preview_commit_replay_has_exactly_one_mock_external_effect(self):
        with tempfile.TemporaryDirectory() as td:
            writer = _FakeWriter()
            read_app = BridgeApplication(
                config=ReadAppConfig(auth_secret=TOKEN, private_root=Path(td)),
                rate_limiter=_AllowReadLimiter(),
            )
            app = UnifiedBridgeApplication(
                read_app=read_app,
                write_adapter=writer,
                write_limiter=FixedWindowEndpointLimiter(limit=50, window_seconds=60),
            )
            status, preview, _ = _call(
                app,
                "/api/v1/messages/send/preview",
                {"chat": "peer:qa", "text": "synthetic qa payload"},
            )
            self.assertEqual(status, 200)
            self.assertEqual(writer.calls, [])
            token = preview["data"]["preview_token"]

            commit_body = {
                "preview_token": token,
                "idempotency_key": "dev09-exact-replay-1",
                "explicit_user_command": True,
            }
            status1, first, _ = _call(app, "/api/v1/messages/send/commit", commit_body)
            status2, second, _ = _call(app, "/api/v1/messages/send/commit", commit_body)
            self.assertEqual((status1, status2), (200, 200))
            self.assertEqual(len(writer.calls), 1)
            self.assertFalse(first["data"]["idempotent_replay"])
            self.assertTrue(second["data"]["idempotent_replay"])
            self.assertEqual(first["data"]["request_fingerprint"], second["data"]["request_fingerprint"])

    def test_unknown_preview_field_is_controlled_and_has_no_external_effect(self):
        with tempfile.TemporaryDirectory() as td:
            writer = _FakeWriter()
            read_app = BridgeApplication(
                config=ReadAppConfig(auth_secret=TOKEN, private_root=Path(td)),
                rate_limiter=_AllowReadLimiter(),
            )
            app = UnifiedBridgeApplication(
                read_app=read_app,
                write_adapter=writer,
                write_limiter=FixedWindowEndpointLimiter(limit=50, window_seconds=60),
            )
            status, payload, _ = _call(
                app,
                "/api/v1/messages/send/preview",
                {"chat": "peer:qa", "text": "synthetic", "unexpected": "blocked"},
            )
            self.assertEqual(status, 400)
            self.assertEqual(payload["error"]["code"], "unknown_field")
            self.assertEqual(writer.calls, [])


if __name__ == "__main__":
    unittest.main()
