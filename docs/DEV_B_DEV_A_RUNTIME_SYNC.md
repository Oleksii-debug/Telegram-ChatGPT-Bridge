# DEV_B -> DEV_A runtime integration guidance

Latest DEV_A DRAFT PR #9 head observed during this DEV_B run: `c5b63e779901db01d49fdb2aa90bc4870597a138`.

This document is guidance only. DEV_B does not modify DEV_A branch and does not authorize deployment.

## Compatible interfaces already present

- `bridge/app.py` exposes the expected callable `bridge.app.application`.
- Public `GET /health` is bounded JSON and exposes non-secret component readiness.
- Protected read routing includes `POST /api/v1/dialogs/list`.
- When the real Telegram backend is intentionally not configured, the read backend fails truthfully with stable code `telegram_backend_unconfigured`; this can be used as a bootstrap-stage authenticated smoke without a live Telegram request.
- DEV2 runtime/private-evidence/lifecycle files are present on the observed DEV_A head.

## Runtime/release mismatches still present on the latest observed head

1. Root `passenger_wsgi.py` is absent. HOSTiQ factual startup uses `passenger_wsgi.py`, and runtime evidence expects that file to import `bridge.app.application`. A release candidate cannot be called deployable until the exact startup file is part of the approved deployment payload or an equally explicit audited server-side mapping is proven.
2. Root `requirements.txt` / accepted immutable dependency input is absent. Dependency installation must be bound to the exact approved Python 3.11 environment and immutable dependency identity before production PREPARE can pass.
3. DEV_A still carries the older DEV2 `ops/hostiq_lifecycle.py`; DEV_B PR #11 has a stricter adapter and must be consumed semantically rather than overwritten in the opposite direction.

## DEV_B runtime adapter changes to integrate

- Health requires exact keys `ok`, `service`, `ready`, `components`.
- `service` must equal `telegram-bridge`.
- components must be exactly auth/backend/storage/rate_limit with configured/unconfigured states.
- `ready` must agree with component state. HTTP 200 alone and legacy `{status: ok}` do not pass.
- Strict mode fails `ready=false`. Explicit pre-Telegram bootstrap mode may accept truthful not-ready health only as `HEALTH_BOOTSTRAP_NOT_READY`.
- Authenticated bootstrap probe is fixed to `POST /api/v1/dialogs/list`. With a server-private bearer reference, exact structured 503 `telegram_backend_unconfigured` can count as authenticated-app proof only in explicit bootstrap mode. Wrong paths, write paths, arbitrary 4xx/5xx and malformed JSON fail.
- Private bearer/SHA/hook files are accessed through `ops/private_control.py` using descriptor-relative `O_NOFOLLOW`, pre-open metadata versus `fstat` identity checks, owner/mode/link validation and bounded reads. Private hooks execute from the already-opened fd through `/proc/self/fd` with stdout/stderr discarded.
- `ops/server_manifest.py` + `tools/collect_server_manifest.py` provide a hash-only first-hand application-root manifest collector; private/runtime directories are not entered and unreviewed root file classes fail closed.
- `ops/passenger_evidence_hook.py` is inert unless an owner-private one-time marker exists. When called by the actual audited `passenger_wsgi.py`, it writes a strong private report only if Python 3.11 + Passenger process context + `bridge.app.application` import are genuinely confirmed. CLI Python cannot substitute.
- Lifecycle tooling never invokes send/reply/forward/send-file/K5.
- OpenAPI/schema identity is not running release identity. Exact running SHA remains a separate private evidence check bound to the approved candidate.

## DEV_A integration action

After DEV_B PR #11 exact-head CI is green:

1. selectively integrate DEV_B runtime additions/adapter changes into DEV_A without reverting current application/read/write/QA code;
2. add audited root `passenger_wsgi.py` importing `bridge.app.application` and calling `collect_if_armed` as documented in `docs/HOSTIQ_ONE_TIME_SUPPORT_PACKAGE.md`;
3. add the immutable dependency input required by the existing hash-locked deployment tooling;
4. rerun full integrated CI, DEV_B runtime/readiness suites and DEV_C QA on the resulting exact candidate head;
5. keep PR DRAFT / no merge / no deployment until Independent Auditor reviews that exact integrated head.

No merge or production switch should occur from this guidance alone.
