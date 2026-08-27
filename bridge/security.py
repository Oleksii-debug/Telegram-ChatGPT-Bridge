"""Read-side authentication, signing and rate-limit interfaces."""

from __future__ import annotations

import hashlib
import hmac
import re
import time
from dataclasses import dataclass
from typing import Callable, Protocol
from urllib.parse import quote

from .errors import BridgeError, HiddenNotFound


_PRIVATE_FILE_SCOPE = "private-file-read"
_CANONICAL_EXP = re.compile(r"[1-9][0-9]{0,10}\Z")
_HEX_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_MAX_SIGNED_FILE_TTL_SECONDS = 3_600


class RateLimiter(Protocol):
    def check(self, actor: str) -> "RateLimitDecision": ...


@dataclass(frozen=True)
class RateLimitDecision:
    allowed: bool
    retry_after_seconds: int | None = None
    remaining: int | None = None


class RejectingRateLimiter:
    """Fail-closed production default until a multi-process limiter is wired."""

    def check(self, actor: str) -> RateLimitDecision:
        del actor
        raise BridgeError("Rate limiter is not configured", status=503, code="rate_limiter_unconfigured")


class BearerGuard:
    def __init__(self, token: str) -> None:
        if not isinstance(token, str) or len(token) < 24 or len(token) > 512:
            raise ValueError("Bearer token must be injected and at least 24 characters")
        self._token = token

    def require(self, environ: dict) -> None:
        header = environ.get("HTTP_AUTHORIZATION") or ""
        if not isinstance(header, str) or len(header) > 1024:
            raise HiddenNotFound()
        # Preserve the accepted canonical API contract: exactly ``Bearer``
        # followed by one ASCII SP and the configured opaque credential.
        # Case variants, extra whitespace and joined duplicate-header values
        # remain fail-closed rather than being normalized here.
        prefix = "Bearer "
        if not header.startswith(prefix):
            raise HiddenNotFound()
        candidate = header[len(prefix) :]
        if not candidate or not hmac.compare_digest(candidate, self._token):
            raise HiddenNotFound()


class FileSigner:
    def __init__(
        self,
        secret: str,
        *,
        clock: Callable[[], float] = time.time,
        max_ttl_seconds: int = _MAX_SIGNED_FILE_TTL_SECONDS,
    ) -> None:
        if not isinstance(secret, str) or len(secret) < 24 or len(secret) > 512:
            raise ValueError("File signer secret must be injected")
        if isinstance(max_ttl_seconds, bool) or not isinstance(max_ttl_seconds, int) or not 1 <= max_ttl_seconds <= 86_400:
            raise ValueError("max_ttl_seconds outside safe range")
        self._secret = secret.encode("utf-8")
        self._clock = clock
        self._max_ttl_seconds = max_ttl_seconds

    def signature(self, file_ref: str, exp: int) -> str:
        # Version and fixed purpose are authenticated alongside identity/time.
        # A private-file signature cannot be silently reused as a token for a
        # future protocol surface that happens to share the same secret.
        data = f"v2:{_PRIVATE_FILE_SCOPE}:{file_ref}:{int(exp)}".encode("ascii")
        return hmac.new(self._secret, data, hashlib.sha256).hexdigest()

    def issue(self, *, base_url: str, route_prefix: str, file_ref: str, ttl_seconds: int) -> tuple[str, int]:
        if isinstance(ttl_seconds, bool) or not isinstance(ttl_seconds, int):
            raise ValueError("ttl_seconds outside safe range")
        if ttl_seconds < 1 or ttl_seconds > self._max_ttl_seconds:
            raise ValueError("ttl_seconds outside safe range")
        exp = int(self._clock()) + ttl_seconds
        sig = self.signature(file_ref, exp)
        url = f"{base_url.rstrip('/')}{route_prefix}/{quote(file_ref)}?exp={exp}&sig={sig}"
        return url, exp

    def verify(self, file_ref: str, exp_raw: str | None, signature: str | None) -> bool:
        if not isinstance(exp_raw, str) or _CANONICAL_EXP.fullmatch(exp_raw) is None:
            return False
        if not isinstance(signature, str) or _HEX_SHA256.fullmatch(signature) is None:
            return False
        try:
            exp = int(exp_raw)
            now = int(self._clock())
        except (TypeError, ValueError, OverflowError):
            return False
        # Expiration is exclusive: at exp, the capability is already invalid.
        if exp <= now:
            return False
        # A valid HMAC must not turn a minting-policy mistake or backward clock
        # jump into a long-lived private-file capability.
        if exp - now > self._max_ttl_seconds:
            return False
        expected = self.signature(file_ref, exp)
        return hmac.compare_digest(expected, signature)
