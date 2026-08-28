# FINALWAVE-40 — timeout, cancellation and liveness review

This document records the isolated FINALWAVE-40 specialist review started from canonical PR #9 head `84691967e5363bc4b88dfae97371d7bf329c105d`. It is not a production approval and does not authorize merge, deploy, Passenger restart, Telegram authorization, or a live Telegram write.

## Scope

Reviewed blocking/liveness boundaries across:

- WSGI request paths and private-file streaming;
- Telethon-compatible read connect/auth/read/download lifecycle;
- Telethon-compatible write connect/auth/resolve/preflight/send lifecycle;
- bulk download checkpoints and per-job POSIX locking;
- ZIP creation and validation;
- SQLite busy waits for file/download/write state;
- Telegram session locking;
- Passenger challenged health probing;
- deployment subprocess helpers and `git archive | tar` materialization.

The existing canonical deployment recovery failure `test_runtime_manifest_change_is_ambiguous_before_candidate_resume` is outside this specialist ownership. FINALWAVE-26-01 owns that transaction-recovery seam; this branch does not alter it.

## Fixed in this isolated overlay

### ZIP cooperative deadline and cancellation

`bridge.archive.ArchiveBuilder` now has a bounded `ArchiveLimits.max_build_seconds` policy (default 120 seconds, accepted range 0.1..600 seconds) and an optional fail-closed cancellation callback.

Liveness checks run while resolving inputs, before and after local file chunks, between members, during CRC verification, before the atomic final move, and immediately before the file-registry commit boundary. ZIP CRC verification is performed by bounded chunk reads rather than one monolithic `ZipFile.testzip()` call so cooperative cancellation/deadline checks remain reachable.

Pre-effect cancellation or timeout removes partial `.part` and unregistered final files. Cancellation-check failures and malformed cancellation state fail closed without surfacing callback exception text.

### Explicit post-effect rule

The last cancellation/deadline check occurs immediately before `FileRecordStore.add()`. Once the registry commit starts, the builder does not report cancellation afterward. This avoids a false cancelled response after a durable local result, which could otherwise cause a caller to retry an already-completed effect.

This is cooperative local-I/O governance, not a claim that Python can preempt a single blocked POSIX `read`, `write`, compression call, filesystem rename, SQLite call, or hash calculation.

## Executable evidence added

`tests/test_finalwave40_liveness.py` covers:

- ZIP deadline before effect with no residual archive artifacts;
- cancellation during multi-chunk ZIP streaming and partial cleanup;
- cancellation callback failure/non-boolean state fail-closed behavior;
- cancellation arriving at the registry boundary returns durable success instead of false cancellation;
- bounded ZIP deadline configuration;
- a hung asynchronous read fake cut off by the existing Telethon-read operation timeout;
- write pre-effect timeout with zero fake external writes;
- bounded SQLite busy wait using a real competing `BEGIN IMMEDIATE` transaction.

The specialist CI also reruns archive security, read-backend, Telegram session-lock, and Passenger-probe regressions plus both repository secret scans.

## Proven existing liveness controls

### Telethon read operation

The canonical `TelethonReadBackend._run()` wraps one complete operation in `asyncio.wait_for` using a validated 1..120 second request timeout. A hung read iterator is therefore cut off in executable synthetic evidence.

### Telegram write operation

The canonical write adapter bounds connect, authorization and the operation body with `asyncio.wait_for`. Existing write-safety persistence transitions to `CALLING` before the external callback and conservatively records an unexpected callback failure as `AMBIGUOUS`, requiring reconciliation rather than blind resend.

### Download job lock and resume state

Download jobs use a nonblocking POSIX flock and return `job_busy` instead of waiting indefinitely on another holder. Checkpoints are saved before/after item processing, and deterministic final paths plus registry origin keys support recovery across process-loss windows. Media network work inherits the read backend timeout.

### SQLite

File/download checkpoint stores use SQLite connect timeout 8 seconds. `PersistentWriteStore` validates and applies a bounded busy timeout up to 60 seconds. New executable evidence verifies a real competing writer does not wait indefinitely.

### Telegram session lock

The session lock uses nonblocking flock polling with a validated 0..60 second acquisition deadline and releases on context exit. Existing tests cover second-holder timeout, release/reacquire and unsafe topology.

### Passenger probe

The challenged HTTPS Passenger probe requires a bounded 0.1..20 second timeout, disables redirects, limits response body size, and maps network failure to bounded non-secret evidence.

## Residual findings for canonical integration

### HIGH FW40-R1 — cleanup can outlive Telethon request timeout

Both the read backend and write adapter execute `client.disconnect()` in `finally` without a separate cleanup deadline. `asyncio.wait_for` cancels the operation at its deadline, but task cancellation can remain pending while an async context-manager/finally block waits on a hung disconnect. The configured request timeout therefore is not a hard upper bound on the caller's wall time.

Canonical recommendation: add a short bounded cleanup timeout for disconnect, preserve cancellation propagation, and test a fake whose disconnect never completes. For write operations, do not reclassify a post-effect timeout as safely retryable; preserve the existing conservative ambiguous-outcome contract unless phase evidence proves no external effect occurred.

### HIGH FW40-R2 — `git_export()` deployment subprocess pipeline is unbounded

`ops.deploy_release.git_export()` launches `git archive` with `Popen`, runs `tar -x` without timeout, then calls `archive.wait()` without timeout. A stuck child can therefore hold a deployment process/serialization lock indefinitely even though the generic `run()` and `command_output()` helpers have bounded timeouts.

Canonical recommendation: replace this pipeline with bounded child-process handling that terminates, escalates to kill when necessary, closes pipes, and reaps both children on timeout/error. A timeout before any live switch must fail in a truthful pre-live state. Add hung-git, hung-tar and child-exit-order tests. This specialist branch does not alter deployment transaction code because that seam has concurrent ownership and the canonical PR currently has an independent deployment-recovery red.

### MEDIUM FW40-R3 — synchronous local I/O is cooperatively, not forcibly, bounded

ZIP now checks a deadline at chunk/member boundaries, but an individual filesystem read/write/compression/hash/SQLite call cannot be interrupted by the in-process callback. Private file serving and download final hashing have the same class of limitation.

Canonical recommendation: if a hard wall-clock SLA is required for large archives/hashes, execute heavy local work in a supervised worker/subprocess with kill/reconcile semantics instead of claiming the cooperative deadline is preemptive.

### MEDIUM FW40-R4 — no application cancellation endpoint for download/archive jobs

The archive builder now exposes an internal cancellation hook, but the WSGI API does not expose or persist archive cancellation state. Download jobs expose start/resume, not cancel. Client disconnect alone is not a reliable cancellation signal in synchronous WSGI/Passenger execution.

Canonical recommendation: when jobs become asynchronous, persist cancellation intent as a non-secret job state, honor it only at documented pre-effect/checkpoint boundaries, and make completed/durable effects win over late cancellation.

### LOW FW40-R5 — storage busy errors rely on outer generic error mapping

SQLite waits are bounded, but some lower storage/checkpoint `sqlite3.OperationalError` failures are not normalized locally into structured retryable Bridge errors. This is not an indefinite-wait defect, but canonical error classification can be improved without extending busy waits.

## Integration recommendation

Safe integration order after the canonical recovery seam is green:

1. Cherry-pick/merge the ZIP deadline+cancellation changes and their focused tests.
2. Preserve the post-registry effect boundary exactly or replace it with a stronger transactional equivalent.
3. Fix bounded Telethon disconnect cleanup with phase-aware write semantics.
4. Fix `git_export()` subprocess termination/reaping in the deployment owner lane and rerun the full transaction/recovery suite.
5. Keep production promotion blocked until independent exact-SHA audit and live HOSTiQ/Telegram/OpenAPI acceptance evidence exist.
