# DEV04 media / downloads / storage / ZIP hardening

This document describes the isolated DEV04 swarm slice. It is source/synthetic hardening only and is not production, Telegram, deployment, or acceptance PASS evidence.

## Exact ownership

DEV04 owns media/download/storage/archive mechanics. This slice deliberately does not change Telegram read search semantics, Telegram write preview/commit logic, deployment tooling, OpenAPI authority, or production runtime state.

## Hardened invariants

- Telegram/user supplied filenames are normalized to Unicode NFC before use as display/archive metadata.
- Traversal components, ASCII control/Windows-invalid characters and bidi override/isolate controls are neutralized.
- Windows device names such as CON/PRN/AUX/NUL/COM1..9/LPT1..9 are not emitted as raw archive/display names.
- Public `file_ref` values remain opaque and never expose server paths; private recovery-origin markers are derived from the random job identity plus item identity and are never returned in public metadata.
- Integrity/size/topology/limit failures are non-retryable for an immutable download checkpoint item, preventing repeated redownload loops. Availability/FloodWait/RPC-style failures remain retryable.
- Normal registry failures clean unregistered completed downloads/ZIPs instead of leaking ordinary exception-path orphans.
- Hard process loss after a download has been moved into private storage, or after registry commit but before checkpoint result save, can be recovered on resume without a second Telegram download. Legacy file registries are migrated in place with a private unique origin marker.
- Legacy `origin_key` schema migration is serialized with `BEGIN IMMEDIATE` before schema inspection. Two Passenger/process workers cannot both observe the old schema and race the same `ALTER TABLE`; a deterministic two-process regression covers this interleaving.
- ZIP source data is opened with `O_NOFOLLOW` where supported and validated by descriptor topology/size.
- ZIP generation streams from that descriptor and recomputes SHA-256/size while writing. A source swap or same-size content mutation after registry lookup fails closed.
- ZIP member collisions are resolved under Unicode NFC + casefold and the finished archive is still checked for member count, traversal, collision and CRC integrity.
- Private file serving is descriptor-bound. After opaque-ref registry validation, the file is opened beneath owner-private directory descriptors with `O_NOFOLLOW` where available, topology/owner/size/SHA-256 are independently revalidated on that exact descriptor, and WSGI streams from the pinned handle rather than reopening the pathname.
- Replacing the registered leaf path after verified open cannot redirect the current bearer/signed response to the replacement inode. Symlink/hardlink or broad-permission private-root/nested-directory topology fails closed.
- The verified serving descriptor is closed on normal iterator completion and on `start_response` failure.
- SEND_FILES-style file selection now has a media-owned descriptor-pinning interface: `UploadFileIdentity`, `VerifiedUploadFile`, `VerifiedUploadBatch`, and `open_verified_upload_batch`.
- The upload batch accepts only exact opaque-ref + SHA-256 + size identities, enforces bounded unique references, opens every file through the same descriptor-bound verifier, and keeps all descriptors alive as one lifetime boundary. If any member fails verification, every previously opened handle is closed before control returns.
- `VerifiedUploadFile` exposes a safe display `name`, opaque `file_ref`, hash, size and MIME type plus read/seek/file-descriptor behavior, but no server-path or `FileRecord` property. A consumer must receive the object itself; converting it back to a pathname would be a contract violation.
- Path replacement after upload-batch creation cannot change the bytes read by a later external consumer. Batch context exit closes every handle even when the consumer raises.

## Existing limits preserved

- single download: 100 MiB default;
- bulk download: 100 files / 500 MiB default;
- ZIP: 200 members / 750 MiB uncompressed default;
- private staging and lock directories remain owner-only where POSIX permissions are available.

These are bounded-operation limits, not a global retention quota. A global multi-process retention/quota policy should be coordinated with DEV08 because it needs atomic shared-state reservation/cleanup semantics rather than a racy directory-size check.

## Cross-lane interfaces

- DEV03/read supplies `(chat, message_id, Telegram file_ref)` and media metadata. DEV04 continues to verify that the opaque ref matches the exact message before Telegram download through the existing backend contract.
- DEV05/send-files consumes registered private `file_ref` values and owns preview/commit, error classification, the explicit Telegram effect boundary and no-blind-resend semantics. Current DEV05 preflight verifies `FileRecordStore.get()` and then passes ordinary paths; that leaves a cross-lane file-identity TOCTOU before `client.send_file` opens the path. DEV04 now supplies the path-free pinned upload objects needed to close that seam. DEV05/DEV01 integration should widen the file-input contract to accept these already-open file-like objects, keep the `VerifiedUploadBatch` alive until `send_file` returns or raises, and only then close it. DEV04 does not activate or modify that write-state machine here.
- DEV07 should adversarially re-audit filename/path/archive/private-serving/upload-handle topology boundaries and public/private metadata separation.
- DEV08 identified the concurrent legacy `origin_key` migration race; DEV04 closes it with an immediate SQLite migration transaction and a two-process regression. DEV08 retains broader shared-state/concurrency/retention stress ownership.
- DEV09 should include the DEV04 regressions in exact-head E1-E6/G4-G5 QA after DEV01 canonical integration. Synthetic tests are not product PASS.

## Integration contract for descriptor-safe SEND_FILES

The intended composition is deliberately narrow:

1. The write owner validates preview/commit/idempotency and remains strictly before the Telegram effect boundary.
2. Convert the already-approved public file selection to `UploadFileIdentity(file_ref, sha256, size)` values.
3. Call `open_verified_upload_batch` before crossing the mutating boundary. `None` is a proven pre-effect file-identity/topology failure; invalid batch shape fails before any open.
4. Pass `batch.files` directly as file-like upload inputs. Do not extract or reconstruct server paths.
5. Keep the batch open while target/reply preflight and the actual `client.send_file` call execute. The write owner decides exactly when the effect boundary is crossed.
6. Close the batch in `finally`, including Telegram timeout/RPC/cancellation/error paths. An uncertain error after the mutating boundary remains AMBIGUOUS under DEV05 rules and must never trigger a blind resend.

This source interface is a composition candidate, not proof that current Telethon production wiring has already adopted file-like objects. Canonical integration and exact combined tests remain DEV01/DEV05 responsibilities.

## Current source/synthetic evidence

The authoritative evidence for this document is the latest DEV04 specialist workflow on the current PR merge ref. Exact run/head/base identifiers are recorded in PR #37 and role issue #26 after every completed DEV04 run; stale identifiers in older checkpoints are historical only.

The dedicated DEV04 workflow compiles the media/storage/private-serving/upload interfaces, runs adversarial upload-handle tests plus inherited storage/archive/read-app and send-files policy regressions, validates the Action/OpenAPI import surface, scans current tree and full history for secrets, and verifies no-deploy markers.

The ordinary canonical Recovery Guard is expected to reject unregistered DEV04 post-import mutations until DEV01 explicitly reviews/imports them into deterministic provenance. DEV04 never weakens that gate to obtain green CI.

## Remaining evidence boundary

Real Telegram media download, real interrupted-job recovery under the production runtime, authenticated/signed private serving on HOSTiQ, descriptor-safe SEND_FILES integrated into the canonical write path, storage persistence across Passenger restart, live ZIP delivery, and final K3 remain external/live or canonical-integration evidence. No live Telegram action is performed by this slice.
