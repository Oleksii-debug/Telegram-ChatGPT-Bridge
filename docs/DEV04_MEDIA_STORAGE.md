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
- ZIP source data is opened with `O_NOFOLLOW` where supported and validated by descriptor topology/size.
- ZIP generation streams from that descriptor and recomputes SHA-256/size while writing. A source swap or same-size content mutation after registry lookup fails closed.
- ZIP member collisions are resolved under Unicode NFC + casefold and the finished archive is still checked for member count, traversal, collision and CRC integrity.

## Existing limits preserved

- single download: 100 MiB default;
- bulk download: 100 files / 500 MiB default;
- ZIP: 200 members / 750 MiB uncompressed default;
- private staging and lock directories remain owner-only where POSIX permissions are available.

These are bounded-operation limits, not a global retention quota. A global multi-process retention/quota policy should be coordinated with DEV08 because it needs atomic shared-state reservation/cleanup semantics rather than a racy directory-size check.

## Cross-lane interfaces

- DEV03/read supplies `(chat, message_id, Telegram file_ref)` and media metadata. DEV04 continues to verify that the opaque ref matches the exact message before Telegram download through the existing backend contract.
- DEV05/send-files consumes only registered private `file_ref` values. DEV04 does not expose server paths and does not weaken `FileRecordStore.get()` integrity/topology revalidation.
- DEV07 should adversarially re-audit filename/path/archive topology boundaries and public/private metadata separation.
- DEV08 should stress same-job locking, cross-job storage concurrency, crash interleavings and future atomic retention/quota policy.
- DEV09 should include the DEV04 regressions in exact-head E1-E6/G4-G5 QA. Synthetic tests are not product PASS.

## Remaining evidence boundary

Real Telegram media download, real interrupted-job recovery under the production runtime, authenticated/signed private serving, storage persistence across Passenger restart, live ZIP delivery, and final K3 remain external/live evidence. No live Telegram action is performed by this slice.
