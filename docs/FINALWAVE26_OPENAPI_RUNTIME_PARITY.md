# FINALWAVE-26 — OpenAPI / runtime request parity

Status: isolated specialist evidence for canonical integration. This document does not authorize merge, deployment, Passenger restart, Telegram authorization, live Telegram operations, K5, or production PASS.

## Canonical anchor

This lane started from canonical PR #9 exact head `84691967e5363bc4b88dfae97371d7bf329c105d` and writes only to `finalwave26/26-openapi-runtime-parity`.

The exact anchor has 19 WSGI/runtime routes and 17 ChatGPT Action operations. `/health` and authenticated-or-signed raw-file GET are intentionally runtime-only. All 17 Action operations are protected POST operations. Eight write operations are four reciprocal preview/commit pairs for SEND, REPLY, FORWARD and SEND_FILES. No setup/login/session/2FA route is Action-visible.

## Fresh defect reconstruction

Static route/OpenAPI parity was already strong. Three request-boundary gaps were independently reproduced from the exact anchor:

1. **B21-01 — strict write JSON type drift.** Runtime normalization can coerce values rejected by generated OpenAPI: float/numeric-string message IDs, non-string targets, string file size and string `voice_note`.
2. **B21-02 — explicit Content-Length zero framing.** The core JSON reader can treat `Content-Length: 0` as unknown-length input and inspect stream bytes outside the declared entity body.
3. **B21-03 — malformed authenticated write attempts before B8.** Invalid write bodies can fail before semantic operation authorization/rate limiting.

A suspected Passenger phantom-write route was separately falsified. `passenger_wsgi.py` retains the recovered `from bridge.app import application` contract, while package initialization intentionally rebinds `bridge.app.application` to lazy `bridge.runtime_wsgi.application`. Existing and FINALWAVE-26 tests require that exact identity and require import to remain Telethon/network-free.

## Domain convergence with parallel specialist lanes

After the reproducer was written, two stronger non-overlapping specialist repairs appeared from the same exact canonical parent:

- FINALWAVE-46 / PR #83 directly hardens `BridgeApplication._read_json()` and owns B21-02 plus the wider parser/framing/Unicode/non-finite-number fuzz boundary.
- FINALWAVE-22 / PR #67 directly adds an authenticated pre-parse persistent write request bucket in `UnifiedBridgeApplication` and owns B21-03 plus production SQLite multi-process/restart B8 semantics.

FINALWAVE-26 therefore removed its temporary duplicate zero-length and pre-body-rate-limit implementation/tests. Canonical integration should use the strongest single owner for each control instead of stacking duplicate wrappers.

## FINALWAVE-26 repair — B21-01 only

`bridge.action_request_guard.ActionRequestGuard` is wired around the application created by the lazy production runtime WSGI builder.

For canonical write preview/commit operations only, it:

1. resolves the route through the same `ops.openapi_registry` registry that generates the Action document;
2. preserves the existing hidden-404 authentication boundary and does not read an unauthorized request body;
3. parses the body with the canonical bounded parser;
4. validates exact JSON types, required/additional-property policy, ranges, patterns, array constraints, enum and const semantics against the same canonical request schema used for generated OpenAPI;
5. returns stable value-free `invalid_request_contract` on mismatch;
6. canonically re-encodes a validated body and then delegates to existing `UnifiedBridgeApplication`, preserving preview/commit/idempotency/effect semantics.

The validator rejects Python/JSON boolean values where the schema says integer, so `true` cannot masquerade as an integer. Public error details expose only a mismatch count; request values are not logged or persisted by this layer.

Read operations and unknown/non-Action routes pass through unchanged. Unknown routes still fail closed in the canonical application.

## Executable FINALWAVE-26 matrix

`tests/test_finalwave26_openapi_runtime_parity.py` covers:

- exact 19-runtime / 17-Action inventory and bidirectional registry/OpenAPI parity;
- absence of private setup/login/session/2FA surface from the Action document;
- all eight write operations having concrete canonical request schemas;
- all four preview families rejecting representative type coercions before preview/effect;
- all four commit families requiring exact boolean `true` for `explicit_user_command` rather than `1`, `"true"` or `false`;
- all four valid preview families retaining 200 + preview-token + zero-external-effect semantics;
- unauthorized write hidden 404 before guard body read;
- read Action pass-through;
- unknown write-like route hidden/fail-closed with no external effect.

`tests/test_finalwave26_wsgi_guard_wiring.py` covers:

- the lazy production runtime builder being wrapped exactly once;
- the recovered Passenger import contract resolving to `bridge.runtime_wsgi.application` without importing Telethon.

FINALWAVE-54 / PR #79 independently provides the broader all-17-operation generated-request-schema -> actual WSGI -> declared-response-schema matrix, restart/idempotency/concurrency and 429 conformance. Canonical integrator should retain that independent exhaustive oracle rather than duplicating it here.

All FINALWAVE-26 tests are synthetic/source/runtime tests and never contact Telegram or production.

## Integration recommendation

Do not merge specialist PRs wholesale. On a fresh canonical SHA, semantically compose:

1. FINALWAVE-26 `bridge/action_request_guard.py` + `bridge/runtime_wsgi.py` wiring + strict write-schema regressions for B21-01;
2. FINALWAVE-46 direct core parser fix/tests for B21-02 if independently accepted;
3. FINALWAVE-22 direct `UnifiedBridgeApplication` pre-parse quota + production SQLite limiter hardening/tests for B21-03 if independently accepted;
4. FINALWAVE-54 exhaustive 17-operation WSGI Action oracle for cross-layer regression coverage.

Preserve `ops.openapi_registry` as the single request-schema truth source. Do not replace this with duplicated ad-hoc field coercion. Register exact selected paths/source SHAs in canonical provenance, then run one exact-SHA Recovery Guard, exact-ref PREPARE, current-tree/full-history secret scans and independent audit.

If canonical advances first or another accepted lane introduces equivalent strict request-schema validation, rerun the FINALWAVE-26 adversarial matrix against that exact head and prefer one coherent implementation.

Generic Recovery Guard failure caused by isolated-overlay provenance or the inherited canonical A01-11 deployment-recovery defect is not permission to weaken provenance, approval, secret, deployment, or recovery controls.
