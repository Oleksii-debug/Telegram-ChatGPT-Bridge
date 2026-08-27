"""Read-side authentication, signing and rate-limit interfaces."""

from __future__ import annotations

import hashlib
import hmac
import time
from dataclasses import dataclass
from typing import Callable, Protocol
from urllib.parse import quote

from .errors import BridgeError, HiddenNotFound


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
        prefix = "Bearer "
        if not header.startswith(prefix):
            raise HiddenNotFound()
        candidate = header[len(prefix) :]
        if not candidate or not hmac.compare_digest(candidate, self._token):
            raise HiddenNotFound()


class FileSigner:
    def __init__(self, secret: str, *, clock: Callable[[], float] = time.time) -> None:
        if not isinstance(secret, str) or len(secret) < 24 or len(secret) > 512:
            raise ValueError("File signer secret must be injected")
        self._secret = secret.encode("utf-8")
        self._clock = clock

    def signature(self, file_ref: str, exp: int) -> str:
        data = f"v1:{file_ref}:{int(exp)}".encode("ascii")
        return hmac.new(self._secret, data, hashlib.sha256).hexdigest()

    def issue(self, *, base_url: str, route_prefix: str, file_ref: str, ttl_seconds: int) -> tuple[str, int]:
        if ttl_seconds < 1 or ttl_seconds > 86_400:
            raise ValueError("ttl_seconds outside safe range")
        exp = int(self._clock()) + ttl_seconds
        sig = self.signature(file_ref, exp)
        url = f"{base_url.rstrip('/')}{route_prefix}/{quote(file_ref)}?exp={exp}&sig={sig}"
        return url, exp

    def verify(self, file_ref: str, exp_raw: str | None, signature: str | None) -> bool:
        try:
            exp = int(exp_raw or "")
        except (TypeError, ValueError):
            return False
        if exp < int(self._clock()):
            return False
        expected = self.signature(file_ref, exp)
        return hmac.compare_digest(expected, signature or "")
