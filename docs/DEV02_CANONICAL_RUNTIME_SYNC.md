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

At the 2026-08-23 DEV02 run, canonical PR #9 head
`c609adfc9a1116aae635a0b14d632a5e59b6c2af` was observed as a descendant of the
reviewed DEV02 protocol SHA. Critical Passenger/runtime evidence files were
unchanged from that protocol boundary. However the canonical release ledger
still named the older `dev_b_round2_sync.sha =
6f943ee15f053acc5b4f15167c16d431023a35d1` and omitted later critical paths.
That is a ledger/provenance-accounting defect, not evidence of post-DEV02
runtime-code drift.

The same canonical CI run failed earlier at integration provenance with
`unexpected post-import mutation: DEV2:ops/private_evidence.py`, while direct
blob comparison showed `ops/private_evidence.py` identical to the reviewed
DEV02 protocol version. DEV01 owns repair of canonical provenance accounting.

## Production boundary

Even `READY_FOR_CANONICAL_REVALIDATION` is only a prerequisite for rerunning the
canonical source/package/PREPARE gates. Production remains blocked until an
independent runtime/release gate authorizes one exact candidate and fresh
HOSTiQ evidence proves source reconciliation, Passenger application-process
Python 3.11 identity, exact running SHA, candidate-specific backup, staging,
dependency installation, restart, meaningful health, unauthenticated and
harmless authenticated smoke, private-state survival/resume and rollback.
