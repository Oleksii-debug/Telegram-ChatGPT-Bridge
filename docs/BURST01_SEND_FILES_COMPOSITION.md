# BURST01-07 SEND_FILES semantic composition contract

Status: non-live specialist integration candidate. This document does not authorize merge, deploy, Telegram authorization, Passenger restart, or a live Telegram write.

## Exact source inputs

- Canonical integration base: `2480d74b623283eeebfdb74c711cbc229d89cd14` (PR #9).
- DEV04 immutable upload snapshot source: PR #50 head `506e5d75857cbb6481d4e5ff15f672b7289c604e`, specifically `bridge/file_access.py`.
- DEV05 phase-aware write source: PR #39 head `540322ef6749b973718de3e35939cb9198cf0c7f`, specifically the phase-aware app/adapter plus secure structured write store.

The two specialist PRs are not copied wholesale. The integration branch selects only the code required to prove the SEND_FILES boundary and adds one explicit payload-to-snapshot translator.

## Finding fixed by this branch

DEV05's `upload_batch_factory` receives commit-bound mappings with keys `file_id`, `sha256`, and `size`. DEV04's `open_verified_upload_batch` accepts only `UploadFileIdentity(file_ref, sha256, size)` objects. Directly wiring the two advertised interfaces therefore fails before Telegram instead of producing a batch. `bridge.send_files_snapshot_factory.open_commit_bound_upload_batch` is the explicit translation boundary.

The mapper changes the private field name only: `file_id -> file_ref`. The value remains the same opaque Bridge file reference. It never resolves or exposes a server path.

## Required state/effect phases

1. PREVIEW: normalize SEND_FILES and persist a fingerprint covering action, target, ordered file identities (`file_id`, SHA-256, size), caption, optional reply target, and voice-note flag. Preview performs zero Telegram writes.
2. COMMIT RESERVATION: require authenticated explicit commit and idempotency key. The exact persisted preview payload is the only material supplied to the external callback.
3. SNAPSHOT PRE-EFFECT: translate each persisted identity into DEV04 `UploadFileIdentity`; descriptor-open the registered private file; verify topology/size/hash; copy it into an owner-private unnamed temporary stream; verify the copied size/hash again. All files must snapshot successfully before the Telegram adapter is entered. Partial failure closes already-created snapshots.
4. TELEGRAM PREFLIGHT: DEV05 accepts only a homogeneous batch of read-only seekable `io.BufferedIOBase` snapshots, records proof of their opaque ref/hash/size/name and position zero, resolves target/reply, then rechecks the same exact stream objects immediately before the effect boundary.
5. EFFECT BOUNDARY: cross the boundary immediately before `client.send_file`. The exact snapshot objects are supplied to the client. There is no `str()` conversion, pathname reopen, or stream rematerialization.
6. POST-BOUNDARY: timeout, FloodWait/RPC failure, cancellation, receipt uncertainty, state-persistence failure, or any other uncertain result must be durable `AMBIGUOUS`/reconciliation-required and must never trigger a blind resend. The snapshot batch is closed in `finally` on success and failure/cancellation.
7. COMMITTED REPLAY: after a receipt is validated and the result is durably committed, exact retry/restart returns the cached committed result and performs no second Telegram effect.

## Byte-identity invariants

- The approved `(file_ref, sha256, size)` tuple is checked against the registry and against the copied snapshot before effect.
- Replacing the registered pathname after snapshot creation cannot redirect the upload.
- Mutating the registered inode after snapshot creation cannot change the upload.
- Mutation during snapshot copying must either still yield the exact approved hash/size or fail before Telegram; mixed bytes are never approved merely because the original lookup once succeeded.
- Multiple files retain commit order, and the whole batch is acquired before the first external effect.
- A configured snapshot factory may not return pathname strings; mixed path/snapshot batches fail closed.

## Restart/idempotency invariants

- COMMITTED + same preview/idempotency key: cached replay, zero external callbacks.
- AMBIGUOUS + same preview/idempotency key: reconciliation-required, zero external callbacks.
- CALLING orphan recovery remains the DEV08 reliability layer's responsibility and must compose outside the structured/secure DEV05 store; it may only resolve uncertainty toward AMBIGUOUS, never toward an automatic resend.

## Integration recommendation to DEV01

Semantically select the reviewed DEV04 snapshot implementation and reviewed DEV05 phase-aware modules, retain their provenance separately, include `open_commit_bound_upload_batch`, instantiate/configure the phase-aware runtime with this factory, and keep DEV08's process-shared reliability wrapper around the secure/structured write store. Remove or make unreachable the legacy pathname SEND_FILES fallback in the production-selected configuration; a production claim is not valid while a path-string fallback can be selected accidentally.

Before canonical merge, rerun the BURST01-07 cross-lane regression suite plus the source DEV04/DEV05 specialist suites, canonical write/OpenAPI tests, both secret scans, deterministic provenance, and independent Auditor review. No live send is needed for this source-level closure.
