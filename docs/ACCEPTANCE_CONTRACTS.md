# Telegram Bridge — executable synthetic acceptance contracts

`ops/acceptance_contracts.py` advances A–K testability without pretending that synthetic behavior is the production application.

The module intentionally accepts only synthetic identifiers/content and no real Telegram credentials, sessions, server secrets or production private files.

Implemented deterministic contract families:

- authorization outcomes and path-traversal rejection;
- fixed-window rate limiting;
- credential-free Telegram setup state fakes for code request, optional 2FA, FloodWait and RPC failure outcomes;
- dialogs/history/search/filter/pagination/Unicode contracts;
- synthetic file/media hash validation, deduplicated bulk download, interruption/resume and private-serving decision;
- deterministic ZIP creation/validation with safe relative names and traversal rejection;
- send/reply/forward/send-file preview objects, hash-bound single-use commit, expiry/replay/idempotency behavior and body-free audit metadata;
- resumable job timeout/checkpoint/retry state;
- structural OpenAPI checks for protected operations, preview/commit write boundaries and private setup-route exclusion;
- structural HTML accessibility checks for labels, accessible button names, heading order and mouse-only controls;
- explicit K1–K5 scenario prerequisites with live Telegram/deployed-SHA/explicit-write-approval requirements where applicable.

`coverage_report()` covers all 67 acceptance criteria and emits only one of:

- `SYNTHETIC_EXECUTABLE`;
- `REAL_SOURCE_REQUIRED`;
- `LIVE_EXTERNAL_REQUIRED`.

These are coverage states, never product PASS. The final user scenarios remain blocked until real audited application/runtime/Telegram/ChatGPT evidence is available.
