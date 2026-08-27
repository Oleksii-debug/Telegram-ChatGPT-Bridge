# DEV5 Round 2 — QA / Accessibility / Security contract evidence

This document describes DEV5 adversarial QA work only. It is not an Auditor verdict, product PASS, production deployment evidence, live Telegram evidence or permission to merge/deploy.

## Provenance and isolation

DEV5 continues from the independently audited fan-out anchor `3c315a29558b7996070fa2c109dc2ff98f6de04d` on `work/qa-accessibility-security`. PR #3 is a DRAFT stacked on `recovery/deployment-package-hardening`. Parallel DEV1/DEV3 code was inspected read-only for interface compatibility; no parallel commit was merged or cherry-picked.

The stacked base has independently advanced in DEV1. Therefore integration conflicts are expected and are for the Independent Auditor to order after all lanes report. DEV5 must not erase that provenance by rebasing onto unaudited parallel work merely to make CI mergeable.

## Round-2 rate-limit oracle

`ops/dev5_round2_oracles.py::StrictFixedWindowOracle` defines the QA semantics expected from an integrated limiter:

- deterministic fixed window and exact boundary rollover;
- actor separation using hash-addressed identifiers;
- retry-after metadata;
- stale-bucket pruning and bounded active actors;
- rejection of NaN/infinite/negative/backward time;
- thread-safe same-actor concurrency so allowed operations never exceed the configured limit.

This remains a single-process oracle. It does not prove HOSTiQ multi-process/shared-state rate limiting. Acceptance B8 remains dependent on the real application/runtime implementation.

## Round-2 idempotency oracle

`CrashSafeIdempotencyOracle` adds the missing ambiguous external-call safety model:

- immutable request fingerprint;
- one durable `RESERVED` winner before external effect;
- restart/retry while reserved returns `RECONCILE_REQUIRED`, never automatic resend;
- mismatched request with the same key returns `IDEMPOTENCY_CONFLICT`;
- terminal committed retries return the prior result;
- terminal detail can age into a non-reusable hash tombstone; pruning never re-enables the key;
- serialized state has an integrity digest and rejects contradictory/corrupt entries;
- concurrent equal requests have one reservation winner; concurrent different requests cannot both reserve the same key.

This is a QA oracle for DEV1/DEV4 integration, not a Telegram send implementation. No live write was performed.

## DEV3 resumable-download compatibility

DEV3 PR #4 was inspected read-only. It provides `CheckpointStore` and `DownloadManager` with persistent checkpoint hashes and retryable resume. DEV5 adds semantic checkpoint assertions that should be applied after integration:

- result/failure keys must reference known item IDs and may not overlap;
- duplicate item IDs fail;
- expected size/hash metadata must remain valid;
- `complete`, `partial`, `pending` and `failed` statuses must agree with results/failures;
- a checkpoint result referencing a missing private file record is invalid;
- a completed checkpoint cannot silently lose a result or retain an unresolved failure.

DEV5 does not copy DEV3 application code into its branch.

## OpenAPI fail-closed drift oracle

`validate_openapi_drift()` checks a canonical route registry against the generated schema and rejects:

- undocumented schema operations or registered operations absent from schema;
- operationId mismatch or duplicate operation IDs;
- protected operations without security;
- public operations outside the tiny health allowlist;
- contradictory optional `x-*` self-markers;
- write/commit routes without a valid preview policy or preview route;
- unstructured JSON errors;
- setup-route/private-like material in paths, server URLs, descriptions or examples.

The validator is structural prerequisite evidence. H1 still requires comparison to the real generated/deployed schema.

## Accessibility truth boundary

Round 1 structural checks already cover labels, accessible names, heading order, tabindex/focus, pointer-only/non-native controls, live regions and error association. Round 2 adds edge checks for duplicate IDs, broken/self ARIA references, forms without submit semantics, pointer-only interactions and non-native role controls without keyboard handling.

Static structure is not a human NVDA test. I1 full keyboard operability and I6 actual NVDA status/error announcement behavior remain `REAL_SOURCE_REQUIRED`; the code must not emit a synthetic human PASS.

## Deterministic fuzz/property coverage

Round 2 adds matrices for:

- percent/double-encoded traversal, backslash/absolute/Windows-drive/dot/confusable separators;
- malformed JSON, UTF-8, top-level type, content-length and range boundaries;
- missing/malformed/wrong/correct bearer headers;
- semantic evidence reference/environment allowlists and namespaced private identifier hashing;
- ZIP casefold/Unicode-normalization collisions, member/total caps and CRC;
- idempotency concurrency for different requests sharing a key;
- acceptance-run summary rejection of private/unstructured evidence refs.

All values are synthetic. No private Telegram text, file contents, credentials or setup route values are used.

## Cross-lane status observed in this round

- DEV1 base commit `28afd5c33f6aca10dd62030ea9d4e4bc7820383d` overlaps rate-limit/idempotency/evidence work and exposes narrow integration protocols. Its implementation is not imported here.
- DEV3 PR #4 head `c196d49224108dd36f7d164ffbd65b55c7180c64` provides read/media/download candidate interfaces and is inspected read-only.
- DEV4 `work/write-telegram-openapi` was still identical to the common anchor when checked during this round, so no substantive DEV4 implementation was available for compatibility testing yet.

## Production boundary

No merge. No production promotion. No live Telegram write. No user Telegram authorization request. No secret/private value is intentionally introduced. Current state remains `USER_TELEGRAM_AUTH_NOT_YET_REQUIRED` until the Independent Auditor changes that gate.
