# Telegram Bridge — executable QA / security / accessibility contracts

Source of truth for product acceptance remains Drive `04_ACCEPTANCE_TESTS — Telegram Bridge`. These repository contracts are deterministic prerequisite engineering; they are not production PASS.

## Security and malformed-input contracts

`ops/acceptance_contracts.py` now covers:

- bearer-header missing / malformed / wrong / valid outcomes without storing the expected secret;
- traversal rejection for `..`, absolute/UNC/Windows-drive forms, backslashes, percent-encoded and double-encoded separator/dot traversal, separator confusables, control characters and ambiguous relative forms;
- bounded UTF-8 JSON-object parsing with controlled 400/413 errors and content-length validation;
- real fixed-window synthetic rate-limit semantics with window rollover, actor isolation, boundary behavior and `retry_after_seconds`;
- credential-free Telegram timeout/FloodWait/RPC/session/lock/cancel/partial-media failure states that preserve a recoverable checkpoint;
- resumable synthetic bulk download that continues pending work after interruption;
- ZIP CRC validation, duplicate/casefold collision rejection, Unicode-safe names and member/aggregate limits;
- HMAC-signed synthetic private-file decisions for auth, expiry, tamper, file-id mismatch, path mismatch, deletion and download caps.

## Preview / commit / idempotency

Synthetic write contracts cover SEND, REPLY, FORWARD, SEND_FILE and SEND_FILES preview records. Commit semantics are now request-bound:

- an idempotency key is bound to a deterministic request fingerprint;
- repeating the same committed request returns the stored committed result even after the preview later expires;
- reusing the same idempotency key for a different target/payload/action returns `IDEMPOTENCY_CONFLICT`;
- used/expired/invalid preview keys fail safely;
- same-request concurrent commits are serialized by the synthetic store;
- export/import validates restart-state persistence before accepting prior idempotency records;
- audit metadata contains operation/hash/control state, never payload body.

## OpenAPI policy

The validator no longer treats optional self-declared `x-protected` / `x-write-operation` markers as authority. It supports a canonical `RoutePolicy` registry and otherwise applies fail-closed inference:

- only an explicit tiny public allowlist is public;
- all other operations are protected by default;
- registry/schema drift is an error;
- WRITE/COMMIT operations require an explicit protected PREVIEW pairing;
- private setup-route material is excluded from paths and other schema metadata;
- controlled error responses are checked for JSON structure and forbidden private diagnostic fields.

A synthetic schema check does not prove H1. Matching generated schema to deployed endpoints remains `REAL_SOURCE_REQUIRED` / live evidence as applicable.

## Accessibility policy

The structural analyzer now checks explicit/nested/ARIA labelling, accessible names, broken references, hidden/disabled controls, focusability, positive `tabindex`, essential-control reachability, heading progression, non-native clickable keyboard semantics, pointer-only handlers, live/status regions and error associations.

Its output is privacy-safe rule IDs plus pass/fail counts. It intentionally returns `structural_only=true` and `human_nvda_pass=false`.

Accordingly:

- I2, I3, I4, I5 and I7 may have synthetic structural contract coverage;
- I1 full keyboard operability remains `REAL_SOURCE_REQUIRED` because static HTML cannot prove the actual interaction flow;
- I6 NVDA-readable dynamic error/status behavior remains `REAL_SOURCE_REQUIRED` until real UI behavior is exercised;
- no automated structural result is represented as a human NVDA PASS.

## Coverage drift gate

`coverage_report()` covers all 67 A1–K5 criteria exactly once and emits only:

- `SYNTHETIC_EXECUTABLE`;
- `REAL_SOURCE_REQUIRED`;
- `LIVE_EXTERNAL_REQUIRED`.

Every `SYNTHETIC_EXECUTABLE` criterion must have at least one concrete test name in `CRITERION_TEST_MAP`. K1–K5 are always live external. Any missing/duplicate criterion, unmapped synthetic claim or synthetic K scenario fails the contract at import/test time.

No live Telegram write, credential, private message, media, session or production secret is required or permitted by these contracts.
