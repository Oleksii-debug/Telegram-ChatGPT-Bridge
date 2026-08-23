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

## Request contracts

DEV06 deliberately reuses the mature feature-lane request schemas from the pre-existing Action registry, then validates them through the authoritative route registry. This preserves current bounds for dialog/history/search, media refs, download lists, ZIP lists, write text, message IDs and SEND_FILES opaque file references without duplicating feature business logic.

All request objects remain `additionalProperties: false`.

## Runtime response parity

The old generic response declaration did not describe the actual WSGI envelope closely enough. DEV06 now generates operation-specific success schemas matching the current source contract:

`ok=true`, `request_id`, and operation-specific `data`.

Read responses cover dialog/message pages, media metadata, private file metadata, download/resume state and archive results. Write preview responses include the preview token/id, action, request fingerprint, expiry and the bounded preview. Write commit responses expose committed state, idempotent replay state, request fingerprint and bounded receipt metadata rather than private request content.

Errors match `BridgeError.public_payload()`:

`ok=false`, `request_id`, and nested `error` containing bounded `code`, `message`, optional `retry_after_seconds`, and bounded structured details.

The generated contract declares the source-visible controlled status family 400/404/409/413/415/429/500/502/503/504 for every Action operation. HTTP 429 also declares a bounded integer `Retry-After` response header, matching the WSGI error path.

## Drift tests

`tests/test_dev06_api_contracts.py` includes positive and adversarial checks for:

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
- x-consequential tampering;
- response/status/error/header drift;
- private setup surface injection;
- secret-field injection;
- unsafe server URL/path injection.

## Truth boundary

These tests are source/contract evidence only. They do not satisfy deployed H1/H2 by themselves. Final H1 still requires comparing the generated schema with the exact deployed audited release. H2 requires a real deployed read-only ChatGPT Action call. Real Telegram and K1-K5 remain external/live gates, and K5 remains prohibited until the later independent write gate and a fresh explicit user commit.

`USER_TELEGRAM_AUTH_NOT_YET_REQUIRED` remains unchanged by this work.
