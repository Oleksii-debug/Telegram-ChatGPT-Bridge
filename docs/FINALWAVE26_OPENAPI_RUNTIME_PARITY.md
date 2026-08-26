# FINALWAVE-26 — OpenAPI / runtime request parity

Status: isolated specialist evidence for canonical integration. This document does not authorize merge, deployment, Passenger restart, Telegram authorization, live Telegram operations, K5, or production PASS.

## Canonical anchor

This lane started from canonical PR #9 exact head `84691967e5363bc4b88dfae97371d7bf329c105d` and only writes to `finalwave26/26-openapi-runtime-parity`.

The canonical source model at that anchor has 19 WSGI/runtime routes and 17 ChatGPT Action operations. `/health` and the authenticated-or-signed raw-file GET are intentionally runtime-only. All 17 Action operations are protected POST operations; the eight write operations form four preview/commit pairs for SEND, REPLY, FORWARD, and SEND_FILES. No setup/login/session/2FA route is Action-visible.

## Defects reproduced

Three request-boundary gaps remained after the static route/OpenAPI work was already strong:

1. Write preview normalization could silently coerce JSON values that the generated OpenAPI rejects. Examples included a float/numeric string becoming an integer ID, a non-string target becoming text, and a string such as `"false"` becoming truthy for `voice_note`.
2. The core JSON reader interpreted explicit `Content-Length: 0` as an unknown-length read and could consume bytes exposed by a non-conforming upstream stream. WSGI/HTTP semantics require zero to mean zero entity bytes.
3. Authenticated malformed/unknown write attempts reached body parsing before the semantic `WriteEndpointPolicy.authorize()` call. Consequently, repeatedly invalid bodies did not consume the write operation quota.

A suspected Passenger phantom-write route was separately falsified before repair: `passenger_wsgi.py` retains the recovered `from bridge.app import application` contract, while package initialization aliases `bridge.app.application` to `bridge.runtime_wsgi.application`. Existing and FINALWAVE-26 tests require that identity and require import to remain Telethon/network-free.

## Repair

`bridge.action_request_guard.ActionRequestGuard` is now placed around the application created by the lazy production runtime WSGI builder.

The guard does four narrowly scoped things:

- resolves a request through the same `ops.openapi_registry` operation registry used to generate the Action schema;
- for write preview/commit operations only, authenticates first and consumes a separate persistent `request-attempt:<operationId>` quota before content-type/body parsing;
- parses the bounded JSON once, validates its exact JSON types/required fields/additional-property policy/ranges/patterns/array constraints against the canonical request schema, and returns a stable value-free `invalid_request_contract` error on mismatch;
- treats explicit `Content-Length: 0` as exactly zero bytes before any downstream parser can inspect the stream.

After validation, the body is canonically re-encoded into the WSGI environment and passed to the existing unified application. The existing semantic preview/commit rate-limit bucket remains separate and still authorizes the operation. Preview still performs no Telegram write; commit still requires its valid preview/idempotency/explicit-user-command controls.

The guard stores or logs no request values. Authentication failures retain the existing hidden-404 behavior and do not consume an authenticated write-attempt bucket. Unknown/non-Action routes continue through the canonical application, which fails closed as before.

## Runtime and persistence model

Production `bridge.runtime.build_production_application_from_env()` already supplies a persistent SQLite write limiter under the owner-private runtime root. FINALWAVE-26 deliberately reuses that limiter for request-attempt buckets rather than adding process-local counters.

Therefore request-attempt quota survives application reconstruction/restart and shares the existing SQLite transaction/concurrency/failure policy. A limiter outage fails closed with HTTP 503 before preview creation. The request-attempt bucket uses a fixed non-private actor digest and operation ID; bearer values, Telegram identifiers, message text, filenames, and other private request content are not rate-limit keys.

## Executable matrix

`tests/test_finalwave26_openapi_runtime_parity.py` covers:

- exact 19-runtime / 17-Action inventory and bidirectional registry/OpenAPI parity;
- absence of private setup/login/session/2FA surface in the Action document;
- strict rejection of float/string integer coercion, non-string targets, string file size, and string boolean `voice_note` before preview/effect;
- strict commit `explicit_user_command` boolean/const semantics;
- valid SEND preview still succeeds while creating no external Telegram write;
- explicit `Content-Length: 0` ignores bytes outside the declared entity body;
- malformed/unknown authenticated bodies consume the pre-body attempt quota and then rate-limit;
- unauthorized writes retain hidden 404 and do not consume the authenticated attempt bucket;
- unknown write-like paths fail closed without preview/effect.

`tests/test_finalwave26_request_guard_persistence.py` covers:

- malformed request-attempt quota surviving a new application/limiter instance over the same private SQLite state;
- two independent spawned processes contending for a limit-1 request-attempt bucket with exactly one allowed result;
- persistent limiter failure returning 503 before preview/writer need.

`tests/test_finalwave26_wsgi_guard_wiring.py` covers:

- the lazy production runtime builder being wrapped exactly once;
- the recovered Passenger import contract still resolving to `bridge.runtime_wsgi.application` without importing Telethon.

All tests are synthetic/source/runtime tests and never contact Telegram or production.

## Integration recommendation

Canonical integrator should semantically select the narrow `bridge/action_request_guard.py` plus `bridge/runtime_wsgi.py` wiring and the FINALWAVE-26 tests/documentation after exact-head CI and independent review. Preserve the single-source request schema relationship with `ops.openapi_registry`; do not replace the guard with duplicated ad-hoc write field coercion.

If canonical PR #9 advances before integration, re-run the adversarial tests against the new exact canonical head first. If another accepted lane introduces equivalent strict request validation or pre-body persistent attempt throttling, prefer the single coherent implementation and retain these tests as the falsification suite.

A generic Recovery Guard failure caused solely by isolated-overlay provenance is not permission to weaken provenance, approval, secret, deployment, or Recovery Guard controls.
