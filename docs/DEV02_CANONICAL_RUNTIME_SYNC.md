# DEV02 canonical runtime sync contract

Status: source/non-live verification only. This contract never authorizes merge,
production deployment, Passenger restart, Telegram authorization, or a live
Telegram operation.

## Why this exists

The canonical release lane can move faster than its human-readable provenance
ledger. A stale ledger must not be confused with a runtime-code regression, and
a green source checkout must not be confused with proof that the reviewed
Passenger/runtime protocol is present.

DEV02 therefore pins the reviewed runtime protocol boundary to exact commit:

`8f2044d7bca9487815f754d614ab781555671a4b`

That SHA includes the challenged Passenger serving-request protocol, terminal
consumed receipt, private-control hardening, candidate/runtime/WSGI binding and
redirect-rejecting challenge transport.

## Machine checks

`ops.dev02_canonical_sync.verify_candidate_runtime_sync()` accepts only one full
candidate SHA. It requires:

1. the DEV02 protocol SHA to be an ancestor of the candidate;
2. byte-exact identity for the critical runtime/evidence files listed in
   `CRITICAL_RUNTIME_PATHS`;
3. the canonical `integration/release_to_live_v1.json` to bind the reviewed
   protocol SHA and account for every critical path.

The verifier intentionally allows canonical adaptations outside the byte-exact
critical set, for example the broader `ops/server_manifest.py` category
accounting needed by an integrated release. Those adaptations remain subject to
their own tests, provenance and audit.

The output distinguishes four bounded states:

- `READY_FOR_CANONICAL_REVALIDATION` — ancestry, critical bytes and ledger agree.
- `BLOCKED_LEDGER_STALE` — reviewed runtime bytes are present, but the canonical
  ledger has not caught up.
- `BLOCKED_RUNTIME_DRIFT` — one or more critical runtime/evidence files differ or
  are missing.
- `BLOCKED_PROTOCOL_ANCESTRY` — the candidate is not descended from the reviewed
  DEV02 protocol SHA.

`promotion_authorized` is always false and summary validation rejects mutation
to true.

CLI:

`python tools/verify_dev02_canonical_sync.py --repo . --candidate-sha <SHA40>`

The CLI emits only bounded JSON or
`DEV02_CANONICAL_RUNTIME_SYNC_BLOCKED`; subprocess stderr and arbitrary Git
errors are never copied to output.

## Current factual observation

During the 2026-08-23 DEV02 run, canonical PR #9 first reached
`c609adfc9a1116aae635a0b14d632a5e59b6c2af`. That candidate was already a
descendant of the reviewed DEV02 protocol SHA and retained the critical runtime
bytes, but its provenance/ledger accounting was stale. Recovery Guard failed
with `unexpected post-import mutation: DEV2:ops/private_evidence.py` even though
direct blob comparison showed `ops/private_evidence.py` identical at the DEV02
protocol boundary and the canonical candidate.

DEV01 then advanced canonical PR #9 to
`cb058b74fcb9fc8afdff52a294b94b54a1c36b71`. The release ledger now explicitly
contains `dev_b_terminal_sync.sha =
8f2044d7bca9487815f754d614ab781555671a4b` and accounts the critical DEV02
runtime paths. The DEV02 verifier therefore recognizes `dev_b_terminal_sync` as
the current canonical spelling, while retaining `dev02_runtime_sync` as a
future-compatible spelling and `dev_b_round2_sync` as a legacy fallback.

This source compatibility result still requires the canonical exact-head CI,
provenance and PREPARE gates to pass. It is not production evidence.

## Production boundary

Even `READY_FOR_CANONICAL_REVALIDATION` is only a prerequisite for rerunning the
canonical source/package/PREPARE gates. Production remains blocked until an
independent runtime/release gate authorizes one exact candidate and fresh
HOSTiQ evidence proves source reconciliation, Passenger application-process
Python 3.11 identity, exact running SHA, candidate-specific backup, staging,
dependency installation, restart, meaningful health, unauthenticated and
harmless authenticated smoke, private-state survival/resume and rollback.
