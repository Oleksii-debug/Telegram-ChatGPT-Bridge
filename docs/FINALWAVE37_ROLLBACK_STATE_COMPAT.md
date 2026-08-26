# FINALWAVE-37 — rollback / persistent-state compatibility

Status: non-deploying specialist evidence. This document does not authorize merge or production promotion.

## Exact anchors

- Candidate anchor inspected at start: `84691967e5363bc4b88dfae97371d7bf329c105d` (live PR #9 head at FINALWAVE-37 start).
- Compatibility reference: `00684e834a523f55ea3b61c1a12cb9dc54cfd947`.
- The compatibility reference is **not** asserted to be the production last-known-good release.
- The real rollback target must be the exact previous deployed SHA obtained from private live deployment identity/evidence and independently approved.

## State matrix

| Domain | Persistent state | Candidate/reference evidence | Ordinary code rollback |
| --- | --- | --- | --- |
| files | `state/files.sqlite3`, private `files/` | candidate startup adds nullable `origin_key` and unique partial index; exact reference predecessor can open/write the migrated DB | preserve current state |
| downloads | `state/downloads.sqlite3`, `tmp/downloads/` | checkpoint payload remains schema 1; exact reference predecessor can load/save a candidate-created checkpoint | preserve current state |
| writes | `state/writes.sqlite3` | exact reference and candidate use identical `ops/write_safety.py`; AMBIGUOUS/COMMITTED knowledge is duplicate-send safety state | preserve current state; never blind-restore older DB |
| rate | `state/rate_limit.sqlite3` | exact reference and candidate use identical runtime quota/high-water implementation | preserve current state; never reset quota/high-water via code rollback |
| reliability | private deployment transaction state plus shared persistent roots | failed-smoke code rollback must reverify previous SHA while shared state remains at the newer durable value | preserve current state |
| session | server-side Telegram session/private configuration | exact reference and candidate session-lock source identity matches; secret values are never copied into evidence | preserve exactly |
| audit | private append-only metadata stream | line format is append-compatible, but the reference writer lacks current fail-closed topology hardening | preserve current evidence; old reference is not accepted as a safe LKG solely from format compatibility |

## Why broad state restore is forbidden

A release symlink rollback is a code rollback, not a time-travel operation for external/shared state. Restoring an older private state tree can:

- erase `COMMITTED` or `AMBIGUOUS` write knowledge and permit a duplicate Telegram effect;
- reset rate-limit quota or monotonic high-water state;
- overwrite or lose Telegram session/private configuration;
- erase append-only audit evidence;
- create file-registry/private-payload divergence;
- discard download checkpoint progress and cause repeated work.

Accordingly, ordinary rollback preserves all current shared state. Any targeted files/download restoration is a distinct audited migration operation. Critical writes/rate/reliability/session/audit state is preserve-only for ordinary code rollback.

## Exact-SHA migration / rollback plan

A future canonical integrator must satisfy this sequence before any production rollback claim:

1. Bind the candidate to the exact audited candidate SHA and record the exact currently deployed previous SHA from live deployment identity. Do not infer the live previous SHA from Git history, a branch name, PR history, or this compatibility reference.
2. Confirm the requested rollback target equals that observed previous deployed SHA.
3. Inventory the exact persistent-state contract for that target: files, downloads, writes, rate, reliability/control state, Telegram session/private config, and audit evidence.
4. Truthfully declare the candidate file-registry schema migration. A candidate that can add `origin_key` must not use a `data_schema_change=false` claim merely because the migration is additive.
5. Prove the **actual rollback target**, not only `00684e83…`, can start against candidate-mutated shared state. At minimum exercise file registry, download checkpoint, write-idempotency, rate-high-water, session-lock/runtime construction boundary, and audit append/security behavior.
6. Quiesce before any backup or switch. Capture recoverable consistent DB/WAL/SHM sets and the private files required for recovery. Backup existence does not authorize an automatic whole-tree restore.
7. Run the candidate with the same external persistent roots. If forced smoke fails, switch code back to the exact previous SHA, restart it, verify running identity, run unauthenticated/authenticated safety smoke, and resume it **without rewinding shared persistent state**.
8. Assert post-rollback invariants: candidate-mutated state is still present; AMBIGUOUS/COMMITTED write knowledge is not lost; rate-limit high-water/quota is not reduced; session/private config is unchanged; audit evidence is not truncated; file/download state remains internally consistent.
9. If the actual old code cannot operate on candidate-mutated files/download state, define a narrowly targeted restore/migration for only the affected area, with consistent SQLite DB/WAL/SHM snapshot evidence. Do not restore writes/rate/session/audit wholesale.
10. Clear any rollback-target security regression independently. In particular, the evidence predecessor `00684e83…` has a weaker audit file topology writer than the candidate and therefore is blocked as a production rollback target until an exact-target security review says otherwise.
11. Obtain independent Auditor approval bound to the candidate SHA, rollback target SHA, migration declaration, compatibility evidence, backup contract, and forced-smoke plan.
12. Only then may live rollback evidence be collected under the normal production gate: backup, exact release identity, Passenger restart/reload, health, unauthenticated/authenticated smoke, security checks, rollback verification, and recorded running SHA.

Even a complete non-live matrix is not production PASS.

## Integration ordering

At the FINALWAVE-37 start, canonical Recovery Guard #529 had the separate A01-11 runtime-manifest recovery failure. The deployment-recovery specialist lane (`finalwave26/01-a01-11-deploy-recovery`, PR #66) is responsible for that source repair. FINALWAVE-37 intentionally does not duplicate or weaken provenance/recovery controls. Canonical integration should first reconcile the latest A01-11 repair, then transplant this rollback-state contract/tests and rerun the combined exact-head suite.

## External blockers deliberately preserved

- Actual production last-known-good/deployed previous SHA is not established by this specialist source evidence.
- No live HOSTiQ rollback, Passenger restart, authenticated production smoke, Telegram read/write, or K5 was performed.
- `USER_TELEGRAM_AUTH_NOT_YET_REQUIRED` remains unchanged.
