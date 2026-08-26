from __future__ import annotations

import hashlib
import hmac
import io
import json
import tempfile
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from bridge.app import BridgeApplication, ReadAppConfig
from bridge.audit import AuditLog
from bridge.errors import HiddenNotFound
from bridge.security import BearerGuard, FileSigner, RateLimitDecision


AUTH_VALUE = "fixture-bearer-value-" + ("a" * 32)
SIGNING_VALUE = "fixture-signing-value-" + ("b" * 32)
FILE_REF = "file_ref_0123456789abcdef"


class CountingLimiter:
    def __init__(self, *, allowed: bool = True) -> None:
        self.allowed = allowed
        self.actors: list[str] = []

    def check(self, actor: str) -> RateLimitDecision:
        self.actors.append(actor)
        if self.allowed:
            return RateLimitDecision(True, remaining=7)
        return RateLimitDecision(False, retry_after_seconds=5, remaining=0)


def call_app(
    app: BridgeApplication,
    *,
    path: str,
    method: str = "GET",
    authorization: object | None = None,
    query: str = "",
) -> dict[str, object]:
    environ: dict[str, object] = {
        "REQUEST_METHOD": method,
        "PATH_INFO": path,
        "QUERY_STRING": query,
        "CONTENT_TYPE": "application/json",
        "CONTENT_LENGTH": "0",
        "wsgi.input": io.BytesIO(b""),
    }
    if authorization is not None:
        environ["HTTP_AUTHORIZATION"] = authorization
    seen: dict[str, object] = {}

    def start_response(status: str, headers: list[tuple[str, str]]) -> None:
        seen["status"] = status
        seen["headers"] = dict(headers)

    chunks = app(environ, start_response)
    seen["body"] = b"".join(chunks)
    return seen


class BearerParsingFuzzTests(unittest.TestCase):
    def setUp(self) -> None:
        self.guard = BearerGuard(AUTH_VALUE)

    def assert_allowed(self, header: object) -> None:
        self.guard.require({"HTTP_AUTHORIZATION": header})

    def assert_hidden(self, header: object | None) -> None:
        environ = {} if header is None else {"HTTP_AUTHORIZATION": header}
        with self.assertRaises(HiddenNotFound):
            self.guard.require(environ)

    def test_exact_canonical_bearer_serialization_is_accepted(self) -> None:
        self.assert_allowed(f"Bearer {AUTH_VALUE}")

    def test_case_and_extra_space_variants_fail_closed_by_contract(self) -> None:
        variants = (
            f"bearer {AUTH_VALUE}",
            f"BEARER {AUTH_VALUE}",
            f"BeArEr {AUTH_VALUE}",
            f"Bearer  {AUTH_VALUE}",
            f"Bearer     {AUTH_VALUE}",
        )
        for header in variants:
            with self.subTest(header=header[:20]):
                self.assert_hidden(header)

    def test_ambiguous_or_non_space_separators_fail_closed(self) -> None:
        variants = (
            f" Bearer {AUTH_VALUE}",
            f"Bearer\t{AUTH_VALUE}",
            f"Bearer {AUTH_VALUE} ",
            f"Bearer {AUTH_VALUE}\t",
            f"Bearer {AUTH_VALUE},Bearer {AUTH_VALUE}",
            f"Bearer {AUTH_VALUE}, Bearer {AUTH_VALUE}",
            f"Basic {AUTH_VALUE}",
            "Bearer ",
            "Bearer",
            "",
            None,
            [f"Bearer {AUTH_VALUE}"],
        )
        for header in variants:
            with self.subTest(header=repr(header)):
                self.assert_hidden(header)

    def test_wrong_token_and_header_controls_fail_closed(self) -> None:
        self.assert_hidden("Bearer " + ("c" * 40))
        self.assert_hidden("Bearer " + AUTH_VALUE + "\r\nX-Test: injected")
        self.assert_hidden("Bearer " + ("x" * 1025))


class SignedFileTokenFuzzTests(unittest.TestCase):
    def test_file_ref_is_bound_and_cross_file_reuse_fails(self) -> None:
        now = 2_000_000_000
        signer = FileSigner(SIGNING_VALUE, clock=lambda: now)
        exp = now + 60
        signature = signer.signature(FILE_REF, exp)
        self.assertTrue(signer.verify(FILE_REF, str(exp), signature))
        self.assertFalse(signer.verify(FILE_REF + "x", str(exp), signature))

    def test_v1_unscoped_signature_is_rejected_by_scoped_verifier(self) -> None:
        now = 2_000_000_000
        signer = FileSigner(SIGNING_VALUE, clock=lambda: now)
        exp = now + 60
        legacy = hmac.new(
            SIGNING_VALUE.encode("utf-8"),
            f"v1:{FILE_REF}:{exp}".encode("ascii"),
            hashlib.sha256,
        ).hexdigest()
        self.assertFalse(signer.verify(FILE_REF, str(exp), legacy))

    def test_exact_expiry_boundary_is_expired(self) -> None:
        now = 2_000_000_000
        signer = FileSigner(SIGNING_VALUE, clock=lambda: now)
        signature = signer.signature(FILE_REF, now)
        self.assertFalse(signer.verify(FILE_REF, str(now), signature))

    def test_verifier_rejects_valid_hmac_beyond_product_max_ttl(self) -> None:
        now = 2_000_000_000
        signer = FileSigner(SIGNING_VALUE, clock=lambda: now)
        exp = now + 3_601
        signature = signer.signature(FILE_REF, exp)
        self.assertFalse(signer.verify(FILE_REF, str(exp), signature))

    def test_noncanonical_exp_and_malformed_signature_fail_closed(self) -> None:
        now = 2_000_000_000
        signer = FileSigner(SIGNING_VALUE, clock=lambda: now)
        exp = now + 60
        signature = signer.signature(FILE_REF, exp)
        for raw_exp in (f"0{exp}", f"+{exp}", f" {exp}", f"{exp} ", "-1", "", None):
            with self.subTest(exp=raw_exp):
                self.assertFalse(signer.verify(FILE_REF, raw_exp, signature))
        for malformed in (
            None,
            "",
            "0" * 63,
            "0" * 65,
            "g" * 64,
            signature.upper(),
            signature + "x",
            "0" * 4096,
        ):
            with self.subTest(signature=repr(malformed)[:100]):
                self.assertFalse(signer.verify(FILE_REF, str(exp), malformed))

    def test_replay_is_bounded_by_ttl_and_not_silently_single_use(self) -> None:
        clock = [2_000_000_000]
        signer = FileSigner(SIGNING_VALUE, clock=lambda: clock[0])
        exp = clock[0] + 30
        signature = signer.signature(FILE_REF, exp)
        self.assertTrue(signer.verify(FILE_REF, str(exp), signature))
        self.assertTrue(signer.verify(FILE_REF, str(exp), signature))
        clock[0] = exp
        self.assertFalse(signer.verify(FILE_REF, str(exp), signature))

    def test_restart_reconstruction_preserves_in_ttl_capability(self) -> None:
        now = 2_000_000_000
        first = FileSigner(SIGNING_VALUE, clock=lambda: now)
        exp = now + 30
        signature = first.signature(FILE_REF, exp)
        restarted = FileSigner(SIGNING_VALUE, clock=lambda: now)
        self.assertTrue(restarted.verify(FILE_REF, str(exp), signature))

    def test_concurrent_verification_is_stateless_and_deterministic(self) -> None:
        now = 2_000_000_000
        signer = FileSigner(SIGNING_VALUE, clock=lambda: now)
        exp = now + 30
        signature = signer.signature(FILE_REF, exp)
        with ThreadPoolExecutor(max_workers=8) as pool:
            outcomes = list(pool.map(lambda _: signer.verify(FILE_REF, str(exp), signature), range(128)))
        self.assertEqual(outcomes, [True] * 128)

    def test_issuer_ttl_and_type_bounds_remain_fail_closed(self) -> None:
        signer = FileSigner(SIGNING_VALUE, clock=lambda: 2_000_000_000)
        for ttl in (0, -1, 3_601, True, 1.5, "60"):
            with self.subTest(ttl=repr(ttl)):
                with self.assertRaises(ValueError):
                    signer.issue(
                        base_url="https://example.invalid",
                        route_prefix="/api/v1/files",
                        file_ref=FILE_REF,
                        ttl_seconds=ttl,  # type: ignore[arg-type]
                    )

    def test_bad_clock_fails_closed_without_exception(self) -> None:
        for value in (float("nan"), float("inf"), float("-inf")):
            with self.subTest(clock=repr(value)):
                signer = FileSigner(SIGNING_VALUE, clock=lambda value=value: value)
                self.assertFalse(signer.verify(FILE_REF, "2000000060", "0" * 64))


class SignedFileApplicationInteractionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.audit = AuditLog()
        self.limiter = CountingLimiter()
        self.app = BridgeApplication(
            config=ReadAppConfig(
                auth_secret=AUTH_VALUE,
                file_signing_secret=SIGNING_VALUE,
                private_root=Path(self.tempdir.name),
                public_base_url="https://example.invalid",
                signed_file_ttl_seconds=3_600,
            ),
            rate_limiter=self.limiter,
            audit=self.audit,
        )

    def _path(self) -> str:
        return f"/api/v1/files/{FILE_REF}"

    def _signed_query(self, *, exp: int | None = None) -> str:
        assert self.app.signer is not None
        current = int(time.time())
        expires = exp if exp is not None else current + 60
        return f"exp={expires}&sig={self.app.signer.signature(FILE_REF, expires)}"

    def test_valid_signed_request_is_rate_limited_even_when_file_is_missing(self) -> None:
        result = call_app(self.app, path=self._path(), query=self._signed_query())
        self.assertTrue(str(result["status"]).startswith("404"))
        self.assertEqual(self.limiter.actors, ["private-file-read"])

    def test_signed_replay_hits_rate_limiter_on_every_request(self) -> None:
        query = self._signed_query()
        call_app(self.app, path=self._path(), query=query)
        call_app(self.app, path=self._path(), query=query)
        self.assertEqual(self.limiter.actors, ["private-file-read", "private-file-read"])

    def test_signed_request_honors_rate_limit_denial(self) -> None:
        limiter = CountingLimiter(allowed=False)
        app = BridgeApplication(config=self.app.config, rate_limiter=limiter, audit=self.audit)
        assert app.signer is not None
        now = int(time.time())
        query = f"exp={now + 60}&sig={app.signer.signature(FILE_REF, now + 60)}"
        result = call_app(app, path=self._path(), query=query)
        self.assertTrue(str(result["status"]).startswith("429"))
        self.assertEqual(dict(result["headers"])["Retry-After"], "5")
        self.assertEqual(limiter.actors, ["private-file-read"])

    def test_product_max_ttl_is_enforced_during_verification(self) -> None:
        assert self.app.signer is not None
        now = int(time.time())
        exp = now + 3_601
        query = f"exp={exp}&sig={self.app.signer.signature(FILE_REF, exp)}"
        result = call_app(self.app, path=self._path(), query=query)
        self.assertTrue(str(result["status"]).startswith("404"))
        self.assertEqual(self.limiter.actors, [])

    def test_oversized_signature_is_hidden_without_rate_budget(self) -> None:
        query = "exp=2000000060&sig=" + ("0" * 4096)
        result = call_app(self.app, path=self._path(), query=query)
        self.assertTrue(str(result["status"]).startswith("404"))
        self.assertEqual(self.limiter.actors, [])

    def test_duplicate_extra_missing_and_malformed_signed_fields_are_hidden(self) -> None:
        good = self._signed_query()
        exp, sig = good.split("&")
        variants = (
            "",
            exp,
            sig,
            good + "&x=1",
            exp + "&" + sig + "&" + sig,
            exp + "&sig=",
            "exp=not-a-time&" + sig,
            "exp=1&sig=" + ("0" * 64),
        )
        for query in variants:
            with self.subTest(query=query[:80]):
                result = call_app(self.app, path=self._path(), query=query)
                self.assertTrue(str(result["status"]).startswith("404"))

    def test_wrong_bearer_does_not_block_independently_valid_signed_url(self) -> None:
        result = call_app(
            self.app,
            path=self._path(),
            authorization="Bearer " + ("c" * 40),
            query=self._signed_query(),
        )
        self.assertTrue(str(result["status"]).startswith("404"))
        self.assertEqual(self.limiter.actors, ["private-file-read"])

    def test_ambiguous_bearer_header_cannot_authorize_without_signature(self) -> None:
        result = call_app(
            self.app,
            path=self._path(),
            authorization=f"Bearer {AUTH_VALUE}, Bearer {AUTH_VALUE}",
        )
        self.assertTrue(str(result["status"]).startswith("404"))
        self.assertEqual(self.limiter.actors, [])

    def test_auth_and_signature_values_never_enter_audit_metadata(self) -> None:
        query = self._signed_query()
        call_app(
            self.app,
            path=self._path(),
            authorization="Bearer " + ("c" * 40),
            query=query,
        )
        encoded = json.dumps(self.audit.events, sort_keys=True)
        self.assertNotIn(AUTH_VALUE, encoded)
        self.assertNotIn(SIGNING_VALUE, encoded)
        self.assertNotIn(query, encoded)
        self.assertNotIn(query.split("sig=", 1)[1], encoded)


if __name__ == "__main__":
    unittest.main()
