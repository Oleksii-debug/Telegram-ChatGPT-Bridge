# DEV_B -> DEV_A runtime integration guidance

Observed DEV_A DRAFT PR #9 head during this DEV_B run: `c7dbcdbb19968b80575c0a87eae8c3b12800fd86`.

This document is guidance only. DEV_B does not modify DEV_A branch and does not authorize deployment.

## Compatible interfaces already present

- `bridge/app.py` exposes the expected callable `bridge.app.application`.
- Public `GET /health` is bounded JSON and exposes non-secret component readiness.
- Protected read routing includes `POST /api/v1/dialogs/list`.
- When the real Telegram backend is intentionally not configured, the read backend fails truthfully with the stable code `telegram_backend_unconfigured`; this can be used as a bootstrap-stage authenticated smoke without a live Telegram request.
- DEV2 runtime/private-evidence/lifecycle files are already present on the observed DEV_A head.

## Runtime/release mismatches that still require integration

1. The observed DEV_A root does not contain `passenger_wsgi.py`. HOSTiQ factual startup uses `passenger_wsgi.py`, and the runtime evidence schema expects that file to import `bridge.app.application`. A release candidate cannot be called deployable until the exact startup file is part of the approved deployment payload or an equally explicit audited server-side mapping is proven.
2. The observed DEV_A root does not contain `requirements.txt` or another root dependency lock accepted by the existing release tooling. Dependency installation must be bound to the exact approved Python 3.11 environment and immutable dependency input before production preparation can pass.
3. DEV2 `health_check()` was too permissive for the DEV_A health contract. DEV_B hardening requires exact keys `ok`, `service`, `ready`, `components`; service must be `telegram-bridge`; components must be exactly auth/backend/storage/rate_limit with configured/unconfigured states; the ready boolean must agree with component state. Arbitrary HTTP 200 or legacy `{status: ok}` does not pass.
4. Pre-Telegram bootstrap is explicit rather than silently green. `allow_bootstrap_not_ready=True` may accept a truthful `ready=false` health result while setup is intentionally incomplete, but the ordinary strict mode fails not-ready health.
5. DEV_B adds an authenticated bootstrap read probe fixed to `POST /api/v1/dialogs/list`. With a server-private bearer reference, exact structured 503 `telegram_backend_unconfigured` can count as authenticated-app proof only when `allow_backend_unconfigured=True`. Wrong paths, write paths, arbitrary 4xx/5xx, malformed JSON and other error codes fail.
6. Lifecycle tooling never invokes a send/reply/forward/send-file endpoint and does not provide K5/live-write authority.
7. OpenAPI/schema identity is not running release identity. Exact running SHA remains a separate private evidence check bound to the approved candidate.

## DEV_A integration action

When DEV_A refreshes its candidate, selectively integrate DEV_B PR #11 after its exact-head CI is green. Preserve DEV_A application/write/read changes, but consume DEV_B runtime adapter changes semantically rather than re-copying the older DEV2 `hostiq_lifecycle.py` over them. Add the approved `passenger_wsgi.py` startup envelope and immutable dependency input, then rerun the full integrated CI and DEV_B runtime/readiness suites on the resulting exact candidate head.

No merge or production switch should occur from this guidance alone; Independent Auditor approval remains mandatory.
