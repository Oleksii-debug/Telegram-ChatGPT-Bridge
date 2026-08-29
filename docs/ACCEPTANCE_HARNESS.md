# Telegram Bridge — A–K acceptance harness

Source of truth: Drive document `04_ACCEPTANCE_TESTS — Telegram Bridge`.

The repository contains a machine-readable planning matrix in `ops/acceptance_harness.py` covering all 67 criteria A1–K5 exactly once. Planning status is not a product verdict:

- `IMPLEMENTED_TEST` — reusable tooling-level test exists; real application/live PASS is not implied.
- `READY_FOR_REAL_SOURCE` — a contract or test boundary is ready but legitimately reconciled sanitized application source is still required.
- `EXTERNALLY_BLOCKED` — proof requires unavailable authorized HOSTiQ/live/Telegram/ChatGPT evidence.
- `NOT_IMPLEMENTED` — no usable harness exists yet.

## Evidence privacy and authority contract — schema v3

Actual acceptance evidence uses a separate `PASS` / `FAIL` / `BLOCKED` result object. Every result must contain an exact 40-character code SHA, a bounded environment class, a compact non-secret primary evidence reference and one or more typed authority references.

`ops/acceptance_policy.py` is the single policy table used by the 67-row inventory, result validation and serialization. It defines each criterion's evidence class, allowed environment/provider, mandatory authority classes and mandatory typed facts. A planning label or synthetic execution can never substitute for live, independent-human, auditor or fresh-user-confirmation authority.

The authority classes are `SYNTHETIC_TEST`, `SOURCE_CI`, `LIVE_RUNTIME`, `INDEPENDENT_AUDITOR`, `INDEPENDENT_HUMAN` and `USER_CONFIRMATION`. Each authority reference has its own validated evidence reference; provider-to-authority mappings are fail-closed.

`ops/evidence_privacy.py` is deliberately fail-closed and positive-schema based. Public/Drive evidence does **not** accept arbitrary free-form `facts` dictionaries. A criterion may emit only explicitly allowlisted typed facts such as:

- booleans (`success`, `authorized`, `state_preserved`, `preview_only`);
- bounded integers/counts/status codes/timeouts;
- exact 40-character Git SHAs;
- exact SHA-256 hashes and bounded lists of SHA-256 hashes;
- short allowlisted enum/status/reason identifiers.

Unknown fact keys, nested dictionaries, bytes/custom objects, unbounded lists/strings and unsupported object types are rejected. Aggregate evidence size, dictionary size, list length and nesting depth are bounded.

Defense-in-depth content checks reject obvious private-key markers, concrete setup-route material, bearer/authorization values, cookie values, JWT-like opaque values and secret-like assignments even when a caller attempts to place them under a neutral key. Long opaque token-like strings are also rejected unless they are valid expected hashes.

Every `PASS` requires `success=true`. Live criteria additionally require the exact deployed SHA to equal `code_sha`; H1/H2/J criteria that depend on observed identity require `observed_sha` to equal the same code SHA. C1/I1/I4/I6 require independent human evidence, with C1 and I6 explicitly requiring NVDA verification. K5 requires W10 approval, safe destination, exact preview/text, single-use idempotency, a matching fingerprint, fresh user confirmation, exactly one external effect and zero replay duplicates.

`build_result()` validates the complete finalized payload. `serialize_result()` independently validates the same canonical policy again, so a prebuilt or later-mutated unsafe object cannot be serialized by bypassing the builder.

Exception messages and subprocess stdout/stderr are never copied into public evidence by the provided sanitizers. The helpers record only safe class/status/presence metadata.

Raw Telegram message text, chat/person names, phone numbers, login codes, 2FA values, sessions, API credentials, setup routes, private file/media contents and runtime secret values are outside this evidence schema. Use hashes/counts/status identifiers instead.

## Telegram user-authorization gate

The auth flag is computed by `evaluate_telegram_auth_gate()` rather than asserted as a literal. It accepts only boolean control-plane readiness facts and returns a state plus stable non-secret reason codes.

`USER_TELEGRAM_AUTH_REQUIRED` is returned only when all of these are true:

1. a legitimately sanitized real application source is ready;
2. the actual Passenger runtime is verified;
3. server-side setup is ready;
4. Telegram setup/session input is the first remaining human-dependent blocker;
5. the operation is not synthetic-only testing.

Otherwise the state is `USER_TELEGRAM_AUTH_NOT_YET_REQUIRED` with reason codes such as `SANITIZED_SOURCE_PENDING`, `PASSENGER_RUNTIME_PENDING`, `SERVER_SETUP_NOT_READY`, `HUMAN_INPUT_NOT_FIRST_BLOCKER` or `SYNTHETIC_TEST_ONLY`.

Current planning state remains:

`USER_TELEGRAM_AUTH_NOT_YET_REQUIRED`

Real authorization must not be requested merely to make synthetic or server-preparation tests pass.

## Product-PASS boundary

No live Telegram send is authorized by this harness. No A–K criterion becomes final PASS until the evidence rule in the Drive acceptance document is satisfied against the applicable real source/runtime/deployed release and independently audited.

The H1/H2 source-bound tooling is documented in `docs/SWARM10_W09_ACTION_EVIDENCE.md`. Its output always sets `product_h1_pass=false` or `product_h2_pass=false` and cannot authorize deployment, Telegram access or a write.
