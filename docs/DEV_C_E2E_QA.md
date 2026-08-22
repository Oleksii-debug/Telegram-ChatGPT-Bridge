# DEV_C E2E QA / Action / Accessibility — Acceleration Round 1

Status: QA-only engineering package. No merge, deployment, Telegram authorization, or live Telegram write is authorized by this document.

## Exact predecessor inputs

The portable package was created from DEV1 engineering base `26a2df12c350f670a703b236edc3648f339b64a9` after fresh Drive/GitHub verification.

Reference inputs inspected read-only:

- DEV2 runtime/server: `19910ec89c85aec6d9ddd31abca0f4cab4dac6cb`
- DEV3 read/media: `4f2c162320c2cbd8e1b0fc2b91a62d2a50806653`
- DEV4 write/OpenAPI: `fc409c7e0bd782148df5cb1a00f9f624b7008548`
- DEV5 QA: `82643ade0f1b5157d311e06a700223a1501ae062`

DEV5 production-overlap files were not cherry-picked. Its adversarial ideas were adapted into non-overlapping DEV_C QA code/tests.

## DEV_A candidate state at package creation

No `work3` integration branch and no DEV_A integration pull request were present when this package was created. DEV_A's dedicated Drive report was still `WAITING_FOR_ACCELERATION_ROUND_1_START`. The package therefore runs safely on the exact DEV1 base and automatically discovers `bridge.routes` plus `ops.openapi_registry` when both later exist on an integrated validation head.

If neither integrated component exists, the discovery gate reports `INTEGRATED_CANDIDATE_NOT_PRESENT` rather than inventing integration evidence. If exactly one exists, it fails closed as partial integration. If both exist, router/OpenAPI drift and integration-interface compatibility become executable gates.

## 67-criterion truth boundary

`ops.devc_portable_qa.acceptance_plan()` maps every Drive A1-K5 criterion exactly once to one of only three coverage/evidence classes:

- `SYNTHETIC_EXECUTABLE`
- `REAL_SOURCE_REQUIRED`
- `LIVE_EXTERNAL_REQUIRED`

These labels are not product PASS. K1-K5 are always `LIVE_EXTERNAL_REQUIRED`. K5 additionally requires Independent Auditor write approval plus a fresh explicit user commit. Human keyboard/NVDA criteria I1/I4/I6 remain live/human evidence even when static HTML rules pass.

## Security and adversarial QA

The portable suite adds executable checks for:

- fixed-window rollover, retry-after, invalid/non-finite/backward time, actor capacity/pruning and same-actor concurrency against the DEV1 synthetic limiter;
- idempotency fingerprint conflict, committed retry after preview expiry, restart `RECONCILE_REQUIRED`, and non-reusable retention tombstones against the DEV1 synthetic write-state model;
- bearer-header syntax matrices without real credentials;
- percent/double-percent traversal, slash/backslash, Windows drive/UNC, NUL/control and Unicode separator-confusable paths while preserving valid Cyrillic/NFC filenames;
- public evidence summaries restricted to reviewed fields, hashes/counts/stable status codes rather than free-form private labels;
- a mocked list→history→search→media→download→archive→preview→commit-error sequence that emits only counts and a digest.

Synthetic QA does not prove real multi-process rate limiting, Telegram exactly-once effects, Passenger restart durability, or private-file behavior on production.

## DEV3 router ↔ DEV4 Action drift model

DEV3 exposes a canonical read registry with only `GET /health` public. Its Action-relevant POST routes are dialogs, history, search, media metadata, single/bulk/resume downloads, archive creation, and private file metadata.

DEV3 also has protected-or-signed `GET /api/v1/files/{file_ref}` for actual private file serving. DEV4's ChatGPT Action registry intentionally does not export that binary-serving GET and also does not export public health. DEV_C therefore uses an explicit non-Action allowlist for those two routes instead of a naive all-router-routes-equal-all-OpenAPI rule. Any additional unexplained router/schema route drift fails.

Write validation derives behavior from canonical route records, not optional self-declared schema markers: every Action operation is protected, preview and commit operations must pair by action, preview must be non-consequential, commit must be consequential, and commit must require an explicit current user command.

## Cross-lane interface probes

DEV1's stable `ops.integration_interfaces` predates the final DEV3/DEV4 vocabularies. Once both integrated components appear on a candidate head, DEV_C probes whether that interface can actually represent:

- DEV4 `SEND_FILES` rather than the older singular write kind;
- DEV3 dotted operation IDs such as `dialogs.list`;
- DEV4 camelCase Action operation IDs;
- DEV3 `protected_or_signed` private file-serving semantics.

These probes are intentionally deferred while the current DEV_C validation head remains the non-integrated DEV1 base. They are not silently assumed compatible.

## Accessibility prerequisite checks

The structural analyzer checks duplicate IDs, explicit/nested/ARIA labels, button/control accessible names, positive tabindex, hidden focusable controls, broken/self ARIA references, heading jumps, form submit semantics, invalid-input text association, pointer-only interaction, and non-native interactive roles without keyboard behavior.

A clean static result is prerequisite evidence only. It cannot establish I1 full keyboard completion, I4 actual logical focus behavior in the live page, or I6 real NVDA announcement behavior. Those remain human/live gates.

## Prepared live protocols — not executed

The code contains prepared protocols for H2 and K1-K5. Every protocol has `execute_now=False`. Public evidence is limited to counts/hashes/states; it must not record chat titles, person names, message bodies, filenames, destination identities, credentials, or setup-route material.

K5 must not run unless all of the following later exist: audited deployed SHA, verified Passenger runtime, private API auth readiness, Telegram authorization, Independent Auditor write approval, a safe destination confirmed privately, and a fresh explicit user commit for that exact preview.

## Current production truth

Authoritative HOSTiQ recovery facts remain external to this QA package: 42 live files / 9 directories inventoried, 39 old-manifest matches, known `passenger_wsgi.py` change, empty `install_server.sh`, private backup retained on HOSTiQ, old setup route rotated/invalidated, zero temporary recovery cron jobs, and Telegram authorization intentionally incomplete.

Still not proven here: exact live-tree→Git identity, Passenger Python 3.11 application context, exact deployed audited SHA, restart/health/unauthenticated+authenticated smoke/resume/rollback, real Telegram flows, deployed ChatGPT Action, or human NVDA evidence.

`USER_TELEGRAM_AUTH_NOT_YET_REQUIRED` remains the required state.
