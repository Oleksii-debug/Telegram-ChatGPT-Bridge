# DEV_B HOSTiQ production-readiness contract

Status: non-production tooling. It does not authorize merge, deployment, Passenger restart, Telegram authorization, or a live Telegram write.

## Factual baseline preserved

The accepted first-hand HOSTiQ recovery evidence remains the starting point: 42 live files / 9 directories were inventoried; 39 working files matched the old controlled manifest; `passenger_wsgi.py` is the known changed tracked startup and imports `bridge.app.application`; `install_server.sh` is an empty extra; a private backup exists only on HOSTiQ; the old setup gate was rotated/invalidated; the setup page rendered; command cron and temporary recovery jobs were zero; Telegram authorization remains incomplete.

The shared-host `/usr/bin/python3` result is shell evidence only. It is not Passenger Python App proof. No tool in this lane upgrades CLI Python, CI Python, cPanel text, or a reference ZIP into application-context evidence.

## Evidence taxonomy

Every runtime/reconciliation/lifecycle input must be classified as exactly one of:

- `FIRST_HAND_LIVE` — direct bounded evidence from the actual running application/server context.
- `PRIVATE_SERVER_EVIDENCE` — bounded private server-side evidence returned through the approved one-time HOSTiQ path; eligible for Auditor review but not self-approval.
- `TEST_SIMULATION` — deterministic tests/fakes/staged temporary directories only; never satisfies a live prerequisite.
- `REFERENCE_ONLY` — analytical material such as the sanitized v0.4 snapshot/provenance; never deploy authority.

Unknown classifications fail closed.

## Integrated predecessor input

DEV_B starts from DEV1 head `26a2df12c350f670a703b236edc3648f339b64a9` and selectively ports the exact 15-file DEV2 runtime input from `19910ec89c85aec6d9ddd31abca0f4cab4dac6cb`. A comparison from the common audited anchor to DEV1 showed that DEV1's later eight commits do not modify those 15 DEV2 paths, so the port preserves newer DEV1 M9/M10/M11/L4 changes instead of reverting them.

The v0.4 package remains `REFERENCE_ONLY / NOT DEPLOY AUTHORITY`. No 42-live-file ↔ 44-package-file bijection is claimed.

## One-time support-return schema

`ops.production_readiness.validate_support_return()` accepts only an exact bounded JSON schema containing:

- exact candidate Git SHA-40;
- separate source/runtime/lifecycle evidence classifications;
- server manifest artifact hash, manifest hash and file count;
- reconciliation artifact hash, counts, exact-accounting status, unreviewed difference count and startup-accounted boolean;
- runtime artifact hash, collector context, Python major/minor, application-context compliance, import/Passenger presence booleans and WSGI hash;
- lifecycle mode plus bounded statuses for backup, restart, running identity, meaningful health, unauthenticated smoke, authenticated smoke, resume and rollback;
- privacy booleans proving the returned summary copied neither private values nor raw responses.

Arbitrary notes, paths, logs, response bodies, environment dumps, headers, exception text and extra keys are not part of the schema and fail closed.

Semantic contradictions also fail closed: an exact reconciliation cannot contain unreviewed differences; a strong Python 3.11 claim requires `APPLICATION_PROCESS`, Passenger context and successful application import; a `TEST_SIMULATION` lifecycle cannot carry a live evidence classification; a `NOT_EXECUTED` lifecycle cannot contain PASS execution claims; lifecycle candidate SHA must equal the top-level candidate SHA.

## Machine-readable production-switch checklist

`build_deployment_readiness()` returns only `PASS`, `BLOCKED_EXTERNAL`, or `NOT_APPLICABLE` prerequisite states. It never copies component artifact hashes or raw private evidence into the public-safe summary.

A source-reconciliation prerequisite can become structurally PASS only from live-eligible evidence with exact accounting, zero unreviewed differences and an accounted startup file. Passenger Python 3.11 can become structurally PASS only from live-eligible application-process evidence. Lifecycle can become structurally PASS only from a `LIVE_SERVER` run with backup, restart, running identity, meaningful health, unauthenticated smoke, authenticated smoke and resume all PASS. Rollback requires its own PASS.

`USER_TELEGRAM_AUTH_NOT_YET_REQUIRED` is represented as `NOT_APPLICABLE` in this current deployment prerequisite stage.

The Independent Auditor gate and production switch are deliberately always `BLOCKED_EXTERNAL` in Developer-generated output. `promotion_authorized` is hard-coded false and a mutated public-readiness object that self-authorizes fails validation.

## One-time HOSTiQ execution package

After an Independent Auditor approves a specific candidate SHA for a controlled server-side evidence/deployment attempt, HOSTiQ/support or an approved private runner should perform one logical transaction:

1. Record the exact approved candidate SHA and validate the private control root.
2. Create/verify a recoverable private backup before changing application code.
3. Collect a fresh bounded live-server manifest and run exact path/hash/size/category reconciliation. Do not export raw private/runtime files.
4. Stage the exact approved candidate separately; validate immutable artifact/dependency identity using the existing release tooling.
5. Collect runtime evidence from the real Passenger application process. A CLI collector result remains candidate context only.
6. Install dependencies only in the actual application Python 3.11 environment.
7. Restart Passenger through the owner-only private restart hook.
8. Verify exact running candidate identity.
9. Run meaningful JSON health; HTTP 200 without the expected health shape fails.
10. Run unauthenticated smoke and prove rejection/no leak.
11. Run authenticated smoke using only a private server-side credential reference; no credential value may enter command arguments, public output, GitHub, Drive, or chat.
12. Verify serving/resume state.
13. Exercise/verify the approved rollback path and last-known-good health as required by the Auditor gate. Any failed mandatory stage triggers rollback; unhealthy rollback is critical.
14. Return only the bounded support-return JSON described above plus the private artifact references/hashes required for Auditor verification. Do not return request/response bodies, environment values, setup route, private config, session material, or logs with Telegram content.

The public validator is:

`python -m tools.validate_hostiq_support_return --input <private-support-return.json> --output <public-readiness.json>`

The command prints only `HOSTIQ_SUPPORT_RETURN_READY_FOR_AUDITOR` or `HOSTIQ_SUPPORT_RETURN_BLOCKED`; it never prints private input or exception details.

## Passenger challenge transport safety

The one-time Passenger serving challenge is bound to the exact production HTTPS `/health` request. `ops.passenger_probe` must never follow HTTP redirects because standard redirect behavior can construct a second request and propagate caller headers to a different URL or origin. A 301/302/303/307/308 response is therefore a bounded `PROBE_REDIRECT_REJECTED` failure. Both cross-origin and same-origin redirects are rejected; the probe validates exactly one origin/path and never treats a redirect chain as Passenger proof.

The challenge remains in caller memory and the initial request header only. Public results contain only bounded status, HTTP status and reason code. Redirect `Location`, response bodies, exception text and the challenge itself are never returned as evidence. This is a source-level safety contract only; it does not claim that a real Passenger request has been executed.

## Current boundary

No authorized HOSTiQ/SSH/cPanel execution connector is available in this Developer environment. Therefore exact live manifest reconciliation, actual Passenger Python 3.11 application-context identity, deployed/running audited SHA, restart/health/unauth/auth/resume and rollback remain external facts until the one-time server-side action is legitimately executed. No duplicate support request is needed while no newer HOSTiQ reply exists.
