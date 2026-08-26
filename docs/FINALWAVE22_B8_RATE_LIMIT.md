# FINALWAVE-22 — Production B8 rate-limit policy and evidence

Status: isolated specialist evidence for canonical integration. This document does not authorize merge, deployment, Passenger restart, Telegram authorization, live Telegram operations, K5, or production PASS.

## Canonical anchor audited

The work started from canonical PR #9 exact head `84691967e5363bc4b88dfae97371d7bf329c105d`. The production-facing limiter is the SQLite implementation in `bridge/runtime.py`, not the older synthetic in-memory acceptance limiter.

## Production topology

When `BRIDGE_PRIVATE_ROOT` is configured, runtime creates one owner-private `state/rate_limit.sqlite3` and injects the same `_SQLiteFixedWindowStore` into both `SQLiteReadRateLimiter` and `SQLiteWriteRateLimiter`.

The database is outside the Git-managed application payload. Its parent must be canonical, owner-controlled mode `0700`; the database and SQLite WAL/SHM sidecars must be single-link regular files owned by the runtime user and mode `0600`. Existing broad-mode, symlink, hardlink, wrong-owner, special-file, or unsafe sidecar topology fails closed.

SQLite uses WAL, `synchronous=FULL`, a bounded 5-second busy timeout, and `BEGIN IMMEDIATE` for every quota mutation. Separate Passenger processes therefore serialize updates through the shared database rather than through process-local memory.

## Fixed-window semantics

Windows are epoch-aligned fixed windows:

`window_start = floor(now / window_seconds) * window_seconds`

`window_end = window_start + window_seconds`

A blocked request returns `Retry-After = max(1, window_end - now)`. At the exact boundary a new window begins and the quota resets. FINALWAVE-22 makes the write limiter's successful `reset_at` use the same `window_end` produced by the atomic store decision; the previous implementation returned `now + window_seconds`, which could point beyond the real fixed-window boundary and was computed from a second clock sample.

## Actor and operation policy

Read and write traffic have independent namespaces in the same persistent database.

Read runtime uses one fixed non-private service actor class, `authenticated-read-api`, and one aggregate operation class, `read-api`. Missing or wrong bearer authentication is rejected before the read limiter is consumed.

Write runtime uses a fixed non-private SHA-256 service actor identity. Write quotas are intentionally operation-scoped by canonical operation ID, so preview/commit/action operation classes do not consume each other's rows. The bearer value, client address, Telegram chat/person, message text, filenames, and other private content are not stored as rate-limit keys. Store keys are SHA-256 digests.

The current production defaults are a shared window of 60 seconds, read limit 120, and write limit 20, with bounded environment overrides. These are source defaults only; live HOSTiQ configuration is not asserted by this specialist run.

## Restart and clock policy

Quota rows and a singleton high-water wall-clock value are persistent. Creating a new application/store instance, or starting another Passenger worker, does not reset quota state.

The high-water clock advances only forward. If a later request observes wall time lower than the persisted high-water value, the transaction rolls back and the limiter fails closed. A large forward clock jump can therefore intentionally make later backward correction unavailable until wall time catches up; silently resetting quota on backward time is not allowed.

## Retention and pruning

The quota table stores at most one current row for each `(namespace, actor_hash, operation_hash)` primary key. On each mutation, rows with `window_start < current_window_start - 2 * window_seconds` are deleted. This removes inactive stale actors/operations while retaining the current and recent safety horizon. The monotonic high-water row is never pruned.

Production actor/operation cardinality is bounded by fixed service actors and the canonical operation registry; private user-controlled strings are not used as production actor keys.

## Failure policy

Database busy beyond the bounded SQLite timeout, corruption, malformed schema access, or SQLite errors fail closed as `rate_limiter_unavailable` / HTTP 503 through the read or write adapter. Quota is never bypassed because the state database is unavailable.

Unsafe database or sidecar topology also fails closed during bootstrap/use. No fallback in-memory production limiter is used when private runtime state exists.

## Executable FINALWAVE-22 matrix

`tests/test_finalwave22_rate_limit_multiprocess.py` covers:

- 2 processes, same actor: exactly one success at limit 1;
- 10 processes, same actor: exact quota with no oversubscription;
- 10 processes, different actors: independent quotas;
- 10-process fresh database bootstrap race;
- restart persistence and exact epoch-window rollover/retry-after;
- forward clock jump followed by backward correction, including a new store instance;
- real SQLite writer-busy failure;
- corrupted database restart failure;
- malicious WAL sidecar topology rejection;
- safe stale-row pruning;
- read/write namespace isolation;
- write `reset_at` alignment with the actual fixed-window boundary.

These are non-live source/runtime tests. They can establish B8 implementation behavior on the tested filesystem/process model, but they are not substitutes for candidate-bound Passenger/HOSTiQ live evidence or final production acceptance.

## Integration recommendation

Canonical integrator should semantically select the narrow `bridge/runtime.py` outcome/reset-boundary change plus this test/documentation package only after exact-head CI and independent review. Do not cherry-pick unrelated specialist history, do not weaken integration provenance, and do not treat a generic Recovery Guard provenance failure on this isolated overlay as permission to relax canonical guards.
