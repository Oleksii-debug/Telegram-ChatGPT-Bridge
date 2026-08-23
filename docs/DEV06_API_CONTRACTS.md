# DEV06 — API / OpenAPI / ChatGPT Action contract boundary

This document describes the source-only DEV06 contract layer. It does not authorize merge, HOSTiQ deployment, Passenger restart, Telegram authorization, a live Telegram write, or K5.

## Authority

`ops/dev06_api_contracts.py` is the DEV06 authoritative API contract registry for semantic integration. It models the full current runtime/API surface as exactly 19 routes:

- 1 public runtime-only health route;
- 9 bearer-protected read/media Action routes;
- 1 bearer-or-signed runtime-only private-file content route;
- 4 bearer-protected write preview Action routes;
- 4 bearer-protected write commit Action routes.

Exactly 17 routes are ChatGPT Action operations. `/health` and raw private-file serving are intentionally not Action operations.

The existing read router and the existing Action/write registry are implementations that are checked against this registry. Optional `x-*` fields are descriptive only. They are never the source of authentication, write classification, route membership, preview/commit pairing, or consequential semantics.

Unknown route, runtime operation, or Action operation identifiers fail closed.

## Authentication and exposure

Only `GET /health` is public. Every ChatGPT Action operation requires the `BearerAuth` security scheme globally and per operation. Raw private-file content is runtime-only and remains `BEARER_OR_SIGNED`; it is not exposed as an Action operation.

Private setup/bootstrap/login/2FA/session surfaces are not part of the canonical registry and are rejected by the Action validator. The schema also rejects secret-field names and obvious private-route examples.

## Write safety semantics

SEND, REPLY, FORWARD and SEND_FILES each have one preview operation and one commit operation. Pairing is reciprocal and registry-controlled.

Preview operations are non-consequential and perform no Telegram write. Commit operations are consequential and their request schemas must require all three gates:

- `preview_token`;
- `idempotency_key`;
- `explicit_user_command` with `const: true`.

The generated schema does not infer approval from a prior preview, draft, or earlier conversation turn.

The preview response intentionally exposes the opaque `preview_token` to the Action client because the matching explicit commit must send that exact value back. The token is ephemeral/single-use and must not be logged, but it is **not** declared `writeOnly` or `readOnly`: either directionality marker would misdescribe the actual preview→commit protocol in the effective Action document.

## Request contracts

DEV06 deliberately reuses the mature feature-lane request schemas from the pre-existing Action registry, then validates them through the authoritative route registry. This preserves current bounds for dialog/history/search, media refs, download lists, ZIP lists, write text, message IDs and SEND_FILES opaque file references without duplicating feature business logic.

All request objects remain `additionalProperties: false`.

## Runtime response parity

The old generic response declaration did not describe the actual WSGI envelope closely enough. DEV06 generates operation-specific success schemas matching the current source contract:

`ok=true`, `request_id`, and operation-specific `data`.

Read responses cover dialog/message pages, media metadata, private file metadata, download/resume state and archive results. Write preview responses include the preview token/id, action, request fingerprint, expiry and bounded preview. Write commit responses expose committed state, idempotent replay state, request fingerprint and bounded receipt metadata rather than private request content.

Errors match `BridgeError.public_payload()`:

`ok=false`, `request_id`, and nested `error` containing bounded `code`, `message`, optional `retry_after_seconds`, and bounded structured details.

The generated contract declares the source-visible controlled status family 400/404/409/413/415/429/500/502/503/504 for every Action operation. HTTP 429 also declares a bounded integer `Retry-After` response header, matching the WSGI error path.

`ops/dev06_runtime_conformance.py` adds a second independent boundary: it validates captured source-only WSGI JSON responses against the generated operation response schema. It also checks JSON content type and requires HTTP `Retry-After` on 429 to match the structured body value. The validator implements only the bounded JSON-Schema subset emitted by DEV06 and fails closed on malformed schema structures; it is not a general JSON Schema replacement.

No runtime-conformance test contacts Telegram or production. The write-path tests use the repository's deterministic fake Telegram client and verify zero effect at preview plus exactly one fake effect across commit+idempotent replay.

## Deployment-bound Action equality evidence for H1

`ops/dev06_deployed_action_evidence.py` and `tools/verify_dev06_deployed_action.py` prepare the later H1 comparison without pretending that source CI is a deployed Action test.

The tool is deliberately **offline**. It never fetches HOSTiQ, ChatGPT or Telegram. A later independently controlled live process must first capture the deployed/sanitized OpenAPI document and supply that local JSON file to the comparator together with the exact candidate SHA.

The comparator:

- regenerates the expected compatible Action document for the approved HTTPS origin;
- canonicalizes JSON deterministically and computes SHA-256 for expected and observed documents;
- checks exact path set, server origin, root security, operation count and all 17 operation contracts;
- runs the normal DEV06 Action compatibility validator against the observed document;
- detects bearer/security, operationId, request, response, consequential, status/header and private-surface drift through exact document/operation comparison plus the structural validator;
- applies a 1 MiB **ingestion safety bound only**. This is not represented as a current ChatGPT product/schema-size limit;
- reads the captured schema from one bounded regular single-link file using no-follow semantics where the platform supports it;
- emits only candidate SHA, schema/origin hashes, byte/count metrics, stable mismatch codes and booleans. It never emits the observed schema, local file path or secret values.

The `SOURCE_MOCK` / `DEPLOYED_CAPTURE` source classification is only caller-supplied provenance metadata. It cannot self-authorize anything. Even an exact comparison labelled `DEPLOYED_CAPTURE` always emits:

- `product_h1_pass=false`;
- `deployment_authorized=false`;
- `production_mutated=false`;
- `private_values_recorded=false`.

Therefore a future exact deployed match is evidence **input** to Independent Auditor H1 adjudication, not H1 PASS by itself.

## Drift tests

`tests/test_dev06_api_contracts.py` covers registry/OpenAPI positive and adversarial drift, including:

- exact 19 runtime routes / 17 Action operations;
- only-health-public policy;
- bearer protection on all Action operations;
- runtime router and legacy Action registry parity;
- private raw-file exclusion from Action;
- unknown route/operation fail-closed behavior;
- reciprocal preview/commit pairs;
- consequential semantics derived from registry class;
- exact success and structured-error envelopes;
- HTTP 429 `Retry-After` contract;
- request `additionalProperties: false`;
- commit-gate requirements;
- file/count/size bounds;
- missing/extra operation drift;
- operationId drift and duplication;
- bearer removal;
- consequential-marker tampering;
- response/status/error/header drift;
- private setup surface injection;
- secret-field injection;
- unsafe server URL/path injection.

`tests/test_dev06_runtime_conformance.py` additionally exercises actual source WSGI responses for protected read success, hidden unauthorized 404, rate-limited 429, 415 content-type failure, SEND preview, explicit commit and exact idempotent replay. Negative cases prove rejection of missing/extra response fields, wrong content type, missing/mismatched Retry-After, unknown operation IDs and undeclared statuses.

`tests/test_dev06_deployed_action_evidence.py` adversarially mutates bearer security, production origin, route set, operation count, consequential semantics, request schema and `Retry-After` response contract; validates deterministic hashing and bounded regular-file ingestion; rejects malformed candidate/source classification and oversized evidence input; and proves no summary mutation can promote H1/deployment authority.

## Cross-lane integration boundary

DEV06 does not duplicate DEV03/DEV04/DEV05 business logic. Current request schemas are deliberately consumed from the canonical feature-layer registry, while route/auth/classification/response safety remains DEV06-authoritative. When DEV01 semantically integrates newer DEV03 read, DEV04 storage/media, DEV05 write-state or DEV08 reliability changes, DEV06 parity and runtime-response tests must be rerun against that exact canonical combination before Action release.

Internal storage markers, private control/evidence state and setup/session material are not API surface merely because another lane implements them.

## Truth boundary

These tests are source/contract evidence only. They do not satisfy deployed H1/H2 by themselves. Final H1 still requires an independently attributable comparison to the exact deployed audited release. H2 requires a real deployed read-only ChatGPT Action call. Real Telegram and K1-K5 remain external/live gates, and K5 remains prohibited until the later independent write gate and a fresh explicit user commit.

`USER_TELEGRAM_AUTH_NOT_YET_REQUIRED` remains unchanged by this work.
