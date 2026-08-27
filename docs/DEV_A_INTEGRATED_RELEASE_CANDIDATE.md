# DEV_A integrated release candidate

## Scope

This document records the integration semantics for `work3/integration-release-candidate`. It is not a production PASS, merge authorization, deployment authorization, Telegram authorization request, or permission to send a live Telegram message.

The candidate is assembled from the audited/green predecessor heads recorded in Drive:

1. DEV1 integration/deployment/security base.
2. DEV3 read/media application and deterministic tests.
3. DEV4 persistent preview/commit, write adapter and OpenAPI/ChatGPT Action contracts, with one narrow DEV_A concurrency-classification override in `ops/write_safety.py`.
4. Selective DEV2 HOSTiQ baseline/runtime/private-evidence contracts.
5. Portable DEV5 adversarial/fuzz oracles only; DEV5 acceptance/evidence production files are intentionally not used to overwrite DEV1 controls.
6. Selective DEV_B release/runtime/package mechanisms, with later Round-2 synchronization and explicit DEV_A adaptations.
7. Selective DEV_C packaged-candidate QA oracles, with exact-path provenance and explicit DEV_A test adaptations.

## Unified application boundary

`bridge.app.BridgeApplication` remains the tested DEV3 read/media core. `bridge.integrated_app.UnifiedBridgeApplication` composes that core with DEV4 write safety.

The canonical production startup now uses the lazy `bridge.runtime_wsgi.application` wrapper. `bridge.app.application`, package-level `bridge.application`, and root `passenger_wsgi.py` resolve to that wrapper without constructing a Telegram client at import time. The wrapper builds the production dependency graph only on first request and returns a sanitized startup error if private configuration is incomplete or invalid.

The canonical Action/private-API operation table is `ops.openapi_registry.OPERATIONS`. At import/CI, `validate_unified_registry()` proves that every Action-visible READ method/path exactly matches the non-dynamic protected DEV3 runtime read registry. Write preview/commit dispatch is taken directly from `OPERATIONS`, so no duplicate write route table exists.

Two routes intentionally remain outside ChatGPT Action `OPERATIONS`:

- public `GET /health`;
- authenticated-or-signed raw private-file `GET /api/v1/files/{file_ref}`.

## Write safety

All write endpoints require the same bearer guard as protected reads before private JSON is parsed. The actor identity used for write rate limiting is a fixed non-secret service-class hash; it is not derived from the bearer token.

Public preview payload names are translated to the persistent write-store contract:

- send: `chat` -> `target`;
- reply: `chat` -> `target` plus `reply_to_message_id`;
- forward: `from_chat` -> `source`, `to_chat` -> `target`;
- send-files: `chat` -> `target`, public `file_ref` -> internal opaque file key.

Unknown top-level fields and unknown fields inside send-file references fail closed. Preview performs no Telegram call. Preview tokens are returned only to the authenticated caller and are never written to the metadata-only audit sink.

Commit requires all of:

- bearer authentication;
- matching canonical commit route/action;
- valid single-use preview token;
- bounded idempotency key;
- `explicit_user_command: true` for the current exact preview;
- configured write rate limiter;
- configured injected Telegram writer.

If no Telegram writer is configured, commit returns a controlled 503 before the persistent store reserves or consumes the preview. Once the external-effect boundary is crossed, the persistent transaction model preserves replay/ambiguity behavior rather than blindly resending.

The narrow DEV_A override in `ops/write_safety.py` preserves that model while correcting concurrent classification. Two same-key commits may both have observed the durable `RESERVED` state before either transitions it. If one wins `RESERVED -> CALLING`, the loser can then observe `CALLING` in `_transition_to_calling()`. That observation proves only that another concurrent writer currently owns the external-effect boundary; it is not, by itself, an unknown external outcome. The loser therefore receives fail-closed `409 write_in_progress`. A durable `AMBIGUOUS` state still yields `write_outcome_unknown_reconciliation_required`, and no path performs a blind resend. After the winning writer commits its durable result, a later same-key call returns the normal idempotent replay.

Send-file commit resolves only registered private Bridge file references. Registry lookup revalidates topology, size and SHA-256 before paths are handed to the Telegram adapter. Raw server paths are never accepted from the API/OpenAPI contract.

External Telegram receipts are reduced to bounded metadata (`operation`, positive `message_ids`, optional numeric `chat_id`, `count`) before being persisted/returned. Arbitrary adapter strings cannot become successful receipt payloads.

## Cross-lane compatibility repair

`ops.integration_interfaces` is now an explicit adapter vocabulary rather than a stale predecessor grammar. It represents DEV3 dotted runtime operation IDs, DEV4 camelCase Action IDs, `SEND_FILES`, and the DEV3 `PROTECTED_OR_SIGNED` private-file class. The adapter does not weaken writes: every `PROTECTED_WRITE` policy still requires `preview_commit_required=True`, and malformed/unknown operation IDs remain fail-closed.

All eight DEV4 preview/commit routes are dispatched by the unified WSGI layer and are covered by black-box mocked WSGI tests. DEV_C packaged-candidate QA is selectively represented in the canonical branch, but later moving DEV_C heads remain independent overlays until they explicitly revalidate the current exact DEV_A head.

## DEV5 fuzz adaptation

The original DEV5 fuzz file assumed helper APIs from DEV5 acceptance/evidence files that were intentionally rejected to preserve DEV1 production/control authority. DEV_A did not restore those helpers. Instead the adversarial vectors were adapted to the real integrated boundaries:

- actual DEV3 WSGI JSON/content-length/auth parsing;
- actual `BearerGuard` and strict integer/file-ref validation;
- DEV1 structured evidence refs/environment/fact schemas;
- actual private `FileRecordStore` + `ArchiveBuilder` limits and CRC;
- DEV3/DEV4 integration interface adapter;
- imported DEV5 crash-safe idempotency oracle.

Archive member naming was additionally hardened to Unicode NFC + casefold collision keys with deterministic disambiguation and post-build collision/CRC validation. This preserves Unicode while preventing equivalent member-name ambiguity across ZIP consumers.

## Packaged production candidate

Release-to-Live Round 2 closes the Auditor P1 package blocker at source level. The repository now carries the canonical package envelope required by the existing deploy engine:

- root `passenger_wsgi.py` with the reviewed production startup/evidence-hook contract;
- exact runtime dependency input `requirements.txt`;
- SHA-256 hash-locked `requirements.lock`;
- `ops.release_package` and `ops.candidate_runtime_preflight` package validation;
- `tools.verify_release_prepare` exact-candidate non-live PREPARE verification.

The runtime closure is deliberately small and exact: Telethon 1.44.0 plus its locked transitive runtime closure (`pyaes`, `rsa`, `pyasn1`). No test-only dependency set is required by the production release package. Private runtime/session/config artifacts are prohibited from the public candidate payload.

DEV_B mechanisms were not imported from an arbitrary latest moving head. The canonical provenance records the accepted semantic import, the later fixed Round-2 synchronization checkpoint `6f943ee15f053acc5b4f15167c16d431023a35d1`, paths that remain byte-exact to that checkpoint, and the narrow DEV_A adaptations needed for the canonical combined candidate. A newer moving DEV_B head is not silently promoted; it must be independently green and reviewed before any additional canonical import.

## Production runtime bootstrap

`bridge.runtime.build_production_application_from_env()` constructs the production dependency graph without Telegram network I/O. Private Telegram references are all-or-none and remain memory-only. The read backend and write adapter share the same owner-private Telegram session lock path so real read/write client lifecycles cannot concurrently mutate the same personal session.

Read and write endpoint rate limiting use one owner-private process-shared SQLite quota store. The store validates database/WAL/SHM topology and modes and now persists a clock high-water mark. If wall-clock time moves backward, quota acquisition fails closed with `rate_limit_clock_moved_backward`; the high-water fact survives a new store instance/worker, so a restart cannot reopen quota after a clock rollback. Once time catches up, the already-consumed fixed-window quota remains consumed rather than being reset by the rollback.

This hardening was added after DEV_C independently found a concrete rollback case at 120 -> 119 seconds. The canonical regression covers the same cross-window rollback, a new store instance on the same database, and recovery to forward time without quota reuse.

## DEV_C packaged-candidate QA provenance

The candidate includes only selected QA material from DEV_C source checkpoint `5758bfdcd9ecee4011fc3caaa3c68eb46ee2af19`, imported through semantic merge `df318aa089f754b7a14f624b7c27cca59758cbe8` whose parents are the recorded DEV_A checkpoint and that exact DEV_C source SHA.

Byte-exact DEV_C paths are now only:

- `docs/DEV_C_RELEASE_TO_LIVE_QA.md`;
- `ops/devc_release_qa.py`.

The two DEV_C tests are explicitly adapted and machine-classified as adaptations rather than exact copies:

- `tests/test_devc_release_qa.py` contains the prior canonical integration adaptation;
- `tests/test_devc_release_e2e.py` now accepts only the safe transient `409 write_in_progress` result for same-key concurrent commits, still requires exactly one external fake write, and then requires a successful idempotent replay after the concurrent writer has durably committed.

A later DEV_C Round-2 overlay independently reproduced the backward-clock finding and, after the canonical fix, that regression passed. Its separate bulk-download `500 internal_error` was traced to the QA fixture reading `source_ref` even though the canonical `ReadBackend.download_media` protocol supplies `file_ref`; DEV_A reported that exact fixture mismatch to DEV_C rather than changing production code to match a faulty mock. No DEV_C production application logic is imported through this QA overlay.

## Candidate API inventory and 67-criterion truth accounting

`ops.candidate_contracts` derives a 19-route integrated API inventory from the actual DEV3 runtime registry plus DEV4 `OPERATIONS`: 17 Action operations, public health, and protected-or-signed binary file serving. Each row maps method/path, runtime and Action operation IDs, safety class, authentication policy, rate class, audit policy, and applicable acceptance criteria. CI fails if the inventory drifts from the actual registries or if a private setup surface appears.

The same module provides an exact 67-criterion candidate evidence map. Counts are deliberately conservative:

- `SYNTHETIC_EXECUTABLE`: 37;
- `REAL_SOURCE_REQUIRED`: 13;
- `LIVE_EXTERNAL_REQUIRED`: 17.

Every row explicitly has `product_pass=false`. Deployed Action equality H1, human keyboard/NVDA criteria I1/I4/I6, Passenger/live deployment criteria, and K1-K5 remain `LIVE_EXTERNAL_REQUIRED`. K5 additionally requires later Independent Auditor write approval plus a fresh explicit user commit. This candidate-specific accounting supersedes any older synthetic planning label that could otherwise overstate those human/live criteria.

## Fail-closed defaults

The default unified application is intentionally not ready for production traffic until server-side dependencies are injected:

- no private root -> no persistent write store;
- no explicit write limiter -> write preview/commit fail with 503;
- no Telegram writer -> commit fails with 503 before preview consumption;
- missing read backend/rate limiter continue to fail closed under DEV3 behavior.

Unified `GET /health` includes non-secret configured/unconfigured status for auth, read backend/storage/rate limiting, write store/rate limiting and Telegram writer. It never exposes credentials, session material, paths or private Telegram content.

## Runtime and HOSTiQ boundary

No production deployment, Passenger restart, live Telegram authorization or live Telegram write is performed by this integration round. Current authoritative server facts remain the Drive `SERVER_RECOVERY_EVIDENCE` baseline. Real Passenger Python 3.11 application-context proof, exact full recovered-tree reconciliation, exact deployed audited SHA, authenticated/unauthenticated live smoke, rollback and real Telegram/ChatGPT E2E remain evidence-gated.

`USER_TELEGRAM_AUTH_NOT_YET_REQUIRED` remains authoritative until the Drive gate says server/source/runtime setup has advanced far enough that Telegram user input is the first remaining human blocker.

## Auditor focus

Independent audit should verify at least:

1. predecessor exact-head provenance and all semantic merge parents, including DEV_B sync and DEV_C QA source checkpoints;
2. no blind DEV5 overwrite of DEV1 acceptance/privacy/evidence controls;
3. no blind DEV2 overwrite of the DEV1 deploy engine;
4. canonical read/OpenAPI parity and write dispatch from `OPERATIONS`;
5. bearer-before-body behavior on write endpoints;
6. preview zero-side-effect behavior;
7. explicit-current-command commit requirement;
8. single-use/idempotent replay behavior;
9. same-key concurrent `CALLING` classification as `write_in_progress` without blind resend, while durable `AMBIGUOUS` remains reconciliation-only;
10. wrong-action/expired/used/invalid preview handling;
11. reply/forward target binding;
12. private file-ref/hash/size enforcement for send-files;
13. no private body/token/target in metadata-only audit events;
14. fail-closed defaults when limiter/store/writer are absent;
15. cross-lane interface vocabulary compatibility;
16. adapted DEV5 fuzz vectors against actual integrated modules;
17. package/startup/dependency-lock validation and exact-head non-live PREPARE;
18. process-shared SQLite rate-limit rollback high-water behavior across store instances;
19. selective DEV_C exact/adapted path accounting without production-logic import;
20. candidate 19-route inventory and exact 67-criterion truth accounting;
21. complete CI, current-tree secret scan and full-history secret scan;
22. preservation of the production no-merge/no-deploy/no-live-write gate.
