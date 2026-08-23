# DEV02 canonical runtime sync contract

Status: source/non-live verification only. This contract never authorizes merge,
production deployment, Passenger restart, Telegram authorization, or a live
Telegram operation.

## Why this exists

The canonical release lane can move faster than its human-readable provenance
ledger. A stale ledger must not be confused with a runtime-code regression, and
a green source checkout must not be confused with proof that the reviewed
Passenger/runtime protocol is present.

DEV02 pins the current reviewed runtime protocol boundary to exact commit:

`12c9036eef907012590691fc0ecdaccbe17d6550`

That SHA contains the prior challenged Passenger serving-request protocol,
terminal consumed receipt, private-control hardening, candidate/runtime/WSGI
binding and redirect-rejecting challenge transport, plus the later one-shot
failure-recovery hardening: all deterministic transport validation occurs before
arming; post-dispatch ambiguous outcomes retain the marker; terminal artifacts
are cross-bound to the actual marker inode; and an existing attempt can be
inspected without deleting or re-arming state.

The subsequent DEV02 commit that updates this document/oracle does not modify a
critical runtime path. The protocol SHA therefore remains an immutable ancestor
whose critical blobs can be compared byte-for-byte with later candidates.

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

## Historical synchronization observation

Earlier on 2026-08-23, canonical PR #9 first reached
`c609adfc9a1116aae635a0b14d632a5e59b6c2af`. That candidate was already a
descendant of the then-reviewed DEV02 boundary `8f2044d7...`, but its ledger was
stale. DEV01 later explicitly accounted that boundary through
`dev_b_terminal_sync` and restored same-SHA provenance/PREPARE success.

That history remains useful because it proves why ancestry, critical blob
identity and ledger binding must be separate checks. It does not make the older
`8f2044d7...` boundary current after the failure-recovery changes in
`12c9036...`.

At the time this update was written, canonical PR #9 had advanced beyond the old
boundary without yet importing the new `12c9036...` critical bytes. Such a
candidate must be reported as stale/drift relative to the new DEV02 boundary
until DEV01 performs an exact semantic sync and reruns its own same-SHA gates.

## Production boundary

Even `READY_FOR_CANONICAL_REVALIDATION` is only a prerequisite for rerunning the
canonical source/package/PREPARE gates. Production remains blocked until an
independent runtime/release gate authorizes one exact candidate and fresh
HOSTiQ evidence proves source reconciliation, Passenger application-process
Python 3.11 identity, exact running SHA, candidate-specific backup, staging,
dependency installation, restart, meaningful health, unauthenticated and
harmless authenticated smoke, private-state survival/resume and rollback.
