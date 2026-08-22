# DEV_A integrated release candidate

## Scope

This document records the integration semantics for `work3/integration-release-candidate`. It is not a production PASS, merge authorization, deployment authorization, Telegram authorization request, or permission to send a live Telegram message.

The candidate is assembled from the audited/green predecessor heads recorded in Drive:

1. DEV1 integration/deployment/security base.
2. DEV3 read/media application and deterministic tests.
3. DEV4 persistent preview/commit, write adapter and OpenAPI/ChatGPT Action contracts.
4. Selective DEV2 HOSTiQ baseline/runtime/private-evidence contracts.
5. Portable DEV5 adversarial/fuzz oracles only; DEV5 acceptance/evidence production files are intentionally not used to overwrite DEV1 controls.

## Unified application boundary

`bridge.app.BridgeApplication` remains the tested DEV3 read/media core. `bridge.integrated_app.UnifiedBridgeApplication` composes that core with DEV4 write safety.

The recovered HOSTiQ Passenger startup contract imports `bridge.app.application`. To preserve that import target without changing the known startup text, `bridge.__init__` replaces the module-level `bridge.app.application` attribute at package-import completion with the lazy unified entry point from `bridge.integrated_app`. The integration entry point constructs no Telegram client and performs no Telegram network I/O at import time.

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

If no Telegram writer is configured, commit returns a controlled 503 before the persistent store reserves or consumes the preview. Once the external-effect boundary is crossed, the DEV4 persistent transaction model preserves replay/ambiguity behavior rather than blindly resending.

Send-file commit resolves only registered private Bridge file references. Registry lookup revalidates topology, size and SHA-256 before paths are handed to the Telegram adapter. Raw server paths are never accepted from the API/OpenAPI contract.

External Telegram receipts are reduced to bounded metadata (`operation`, positive `message_ids`, optional numeric `chat_id`, `count`) before being persisted/returned. Arbitrary adapter strings cannot become successful receipt payloads.

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

1. predecessor exact-head provenance and semantic merge parents;
2. no blind DEV5 overwrite of DEV1 acceptance/privacy/evidence controls;
3. no blind DEV2 overwrite of the DEV1 deploy engine;
4. canonical read/OpenAPI parity and write dispatch from `OPERATIONS`;
5. bearer-before-body behavior on write endpoints;
6. preview zero-side-effect behavior;
7. explicit-current-command commit requirement;
8. single-use/idempotent replay behavior;
9. wrong-action/expired/used/invalid preview handling;
10. reply/forward target binding;
11. private file-ref/hash/size enforcement for send-files;
12. no private body/token/target in metadata-only audit events;
13. fail-closed defaults when limiter/store/writer are absent;
14. complete CI, current-tree secret scan and full-history secret scan;
15. preservation of the production no-merge/no-deploy/no-live-write gate.
