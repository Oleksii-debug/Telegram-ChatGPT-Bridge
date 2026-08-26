# DEV04 media / downloads / storage / ZIP hardening

This document describes DEV04 source/synthetic hardening only. It is not production, Telegram, deployment, or acceptance PASS evidence.

## Exact ownership

DEV04 owns media/download/storage/archive mechanics and private-file byte identity. It does not own Telegram read/search semantics, write preview/commit/idempotency/effect classification, deployment tooling, OpenAPI authority, or production runtime state.

## Canonical baseline already integrated

DEV01 has already semantically integrated the prior DEV04 package into canonical ancestry. That baseline includes durable download crash recovery, serialized `origin_key` migration, Unicode/filename/ZIP hardening, descriptor-verified ZIP input and descriptor-bound private serving. The old specialist PR #37 is historical evidence for that accepted package and is not the merge vehicle for this new delta.

## New snapshot-safe SEND_FILES seam

Current DEV05 preflight validates a private file record and then carries an ordinary filesystem pathname toward `client.send_file`. A pathname can be replaced after validation, and even a pinned descriptor alone does not prevent another process from modifying the same inode in place. For a consequential SEND_FILES commit, the exact bytes approved before the Telegram effect must remain stable.

DEV04 therefore adds a media-owned pre-effect snapshot interface in `bridge.file_access`:

- `UploadFileIdentity(file_ref, sha256, size)` binds an opaque private ref to the exact approved hash and positive byte size.
- `open_verified_upload_batch(...)` defaults to the canonical private send bounds: at most 10 files, 100 MiB per file and 250 MiB total.
- Every source is first opened through canonical `open_verified_file`, preserving owner-private directory, no-follow, regular-file, single-link, size and SHA-256 checks.
- Before any Telegram effect, source bytes are copied into an owner-private unnamed `TemporaryFile` while SHA-256 and size are recomputed again. The verified source descriptor is then closed.
- A completed `VerifiedUploadFile` is a read-only `io.BufferedIOBase` snapshot. Later pathname replacement or later in-place mutation of the registered source cannot change the bytes consumed by the external uploader.
- Snapshot fds are reduced to owner-only mode where POSIX permissions are available.
- The upload object exposes safe `name`, opaque `file_ref`, SHA-256, size and MIME type, but no filesystem path and no `FileRecord` object.
- Duplicate refs, invalid shape and byte-limit violations fail before any file open.
- If any member fails open, topology, snapshot copy or exact identity checks, all source/snapshot handles created so far are closed before control returns.
- `VerifiedUploadBatch` owns snapshot lifetime and closes every member on normal exit and consumer exceptions.

## Stale download-origin recovery closure

The integrated origin-key crash recovery had one further durability edge case. A registry commit can survive while its private file later disappears before the checkpoint acquires the registered `file_ref`. In that state `get_by_origin()` could not return a valid record, but the unique `origin_key` row remained. A later resume then downloaded the file again, collided with the stale unique origin row, removed the new unregistered file and could repeat that redownload/collision cycle.

DEV04 now makes `FileRecordStore.get_by_origin()` self-heal only this narrowly proven stale state:

- origin-key records are eligible for pruning only when their stored path is a single root-level POSIX leaf, matching the deterministic download layout;
- a missing leaf is checked with `lstat`, not `exists`, so dangling symlinks are treated as existing topology and are never mistaken for absence;
- the same row identity and file absence are rechecked after `BEGIN IMMEDIATE` before deletion;
- any existing object, symlink, I/O uncertainty, absolute/nested/traversal-shaped path or changed registry row remains fail-closed and is not deleted;
- after a genuinely stale row is pruned, normal resume may redownload once and register the same deterministic origin again;
- regression coverage requires the following resume to remain complete without a second backend download and requires exactly one current origin row.

This is registry self-heal, not a general retention/cleanup mechanism and not permission to delete suspicious private files.

## DEV05 / DEV01 composition contract

The write owner remains authoritative for preview/commit/idempotency, target/reply preflight, the precise external-effect boundary and AMBIGUOUS/no-blind-resend behavior.

The intended integration is:

1. After the commit payload is approved but still before the Telegram effect boundary, convert its already-bound private file entries to `UploadFileIdentity` values.
2. Call `open_verified_upload_batch` while failure is still provably pre-effect.
3. A `None` result means private bytes/topology could not be proven and must fail before `client.send_file`. Invalid shape/size policy raises before file opening.
4. Pass `batch.files` directly as file-like inputs. Do not recover or reconstruct `record.path`.
5. Keep the batch alive through DEV05 target/reply preflight and the actual `client.send_file` call.
6. Close the batch in `finally`. Any uncertain exception after DEV05 crosses the mutating boundary remains AMBIGUOUS and must never cause a blind resend.

DEV04 does not modify or activate the DEV05 write state machine in this branch.

## Telethon compatibility boundary

Telethon 1.44 documents `send_file` as accepting file-like objects or sequences and uses file-like `.name`. Its upload path consumes streams; image handling also recognizes standard `io.IOBase` objects for stream-position preservation. `VerifiedUploadFile` deliberately subclasses `io.BufferedIOBase` for this compatibility. This is source-contract compatibility only, not live Telegram evidence.

## Existing bounded-operation limits

- single download: 100 MiB default;
- bulk download: 100 files / 500 MiB default;
- verified SEND_FILES snapshot: 10 files / 100 MiB each / 250 MiB total by default;
- ZIP: 200 members / 750 MiB uncompressed default.

These are per-operation bounds, not a global multi-process retention/storage quota. Global reservation, retention and cleanup remain a DEV08 coordination topic; DEV04 does not add a racy directory-size quota.

## Cross-lane boundaries

- DEV03 owns dialogs/history/search/read semantics; DEV04 preserves the existing opaque media/file-ref boundary.
- DEV05 owns write safety and must integrate snapshot inputs without weakening its effect-boundary or no-blind-resend invariants.
- DEV07 should adversarially re-audit snapshot/file topology, metadata privacy and path-free boundaries.
- DEV08 retains global shared-state/concurrency/recovery/retention stress ownership. DEV04's stale-origin pruning is deliberately limited to deterministic missing download leaves and does not become a general quota/retention engine.
- DEV09 should absorb the new snapshot and stale-origin regressions into exact-canonical E/G/K QA after canonical integration.
- DEV01 owns semantic import and deterministic canonical provenance.

## Remaining evidence boundary

This new seam is not yet canonical write-path integration and is not product PASS. Still unproven are the exact combined DEV04+DEV05 canonical implementation, real Telegram media/download/SEND_FILES behavior, HOSTiQ private serving, Passenger restart persistence, live ZIP delivery and final K3/K5 scenarios. No live Telegram action is performed by this slice.
