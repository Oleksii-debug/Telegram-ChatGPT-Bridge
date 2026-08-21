# Telegram Bridge — A–K acceptance harness

Source of truth: Drive document `04_ACCEPTANCE_TESTS — Telegram Bridge`.

This repository contains a machine-readable planning matrix in `ops/acceptance_harness.py` covering all 67 criteria A1–K5 exactly once.

Planning status is not a product verdict:
- `IMPLEMENTED_TEST` — reusable tooling-level test exists, but real application/live PASS is not implied.
- `READY_FOR_REAL_SOURCE` — harness contract is defined and waits for legitimately reconciled sanitized application source.
- `EXTERNALLY_BLOCKED` — proof requires unavailable authorized HOSTiQ/live/Telegram evidence.
- `NOT_IMPLEMENTED` — no usable harness exists yet.

Actual evidence uses a separate `PASS` / `FAIL` / `BLOCKED` result object. Every result must contain an exact 40-character code SHA, environment class and non-secret evidence reference. The evidence serializer rejects secret/private fields such as tokens, Telegram session material, API hashes, passwords/2FA, approval nonce, setup route, message bodies and private file/media content.

Current user-auth gate:
`USER_TELEGRAM_AUTH_NOT_YET_REQUIRED`

Reason: the factual sanitized production application source and actual Passenger runtime are not yet reconciled into the audited Git line. Telegram authorization must not be requested merely to make synthetic tests pass.

No live Telegram send is authorized by this harness. No acceptance criterion becomes final PASS until the evidence rule in `04_ACCEPTANCE_TESTS — Telegram Bridge` is satisfied against the applicable real source/runtime/deployed release.
