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

## Existing limits preserved

- single download: 100 MiB default;
- bulk download: 100 files / 500 MiB default;
- ZIP: 200 members / 750 MiB uncompressed default;
- private staging and lock directories remain owner-only where POSIX permissions are available.

These are bounded-operation limits, not a global retention quota. A global multi-process retention/quota policy should be coordinated with DEV08 because it needs atomic shared-state reservation/cleanup semantics rather than a racy directory-size check.

## Cross-lane interfaces

- DEV03/read supplies `(chat, message_id, Telegram file_ref)` and media metadata. DEV04 continues to verify that the opaque ref matches the exact message before Telegram download through the existing backend contract.
- DEV05/send-files consumes registered private `file_ref` values. DEV04 preserves that contract and the inherited 53 send-files/file-policy regressions. DEV04 does not redefine preview/commit or Telegram effect-boundary semantics; any future descriptor/snapshot transport into SEND_FILES must compose with DEV05's pre-effect validation and no-blind-resend rules rather than bypass them.
- DEV07 should adversarially re-audit filename/path/archive/private-serving topology boundaries and public/private metadata separation.
- DEV08 identified the concurrent legacy `origin_key` migration race; DEV04 closes it with an immediate SQLite migration transaction and a two-process regression. DEV08 retains broader shared-state/concurrency/retention stress ownership.
- DEV09 should include the DEV04 regressions in exact-head E1-E6/G4-G5 QA after DEV01 canonical integration. Synthetic tests are not product PASS.

## Current source/synthetic evidence

On DEV04 head `294ed43bcb74f9255dce8aa83801ecf98730d7bd`, GitHub tested the PR merge ref `c445f63adbb015fcf212a0e40f75a9cc375c94ed` against canonical DEV01 `c609adfc9a1116aae635a0b14d632a5e59b6c2af`.

- DEV04 media/storage/private-serving/migration plus inherited read-app regressions: 97/97 PASS.
- Existing send-files/private-file policy compatibility: 53/53 PASS.
- Targeted total: 150/150 PASS.
- Offline OpenAPI validation: PASS.
- Current-tree and full-history secret scans: PASS.
- No-deploy safety markers: PASS.

The ordinary canonical Recovery Guard remains intentionally fail-closed at deterministic integration provenance because this is a specialist post-import overlay. On this merge ref the first failure is `unexpected post-import mutation: DEV3:bridge/app.py`; downstream broad regression/PREPARE is therefore not claimed.

## Remaining evidence boundary

Real Telegram media download, real interrupted-job recovery under the production runtime, authenticated/signed private serving on HOSTiQ, storage persistence across Passenger restart, live ZIP delivery, and final K3 remain external/live evidence. Canonical DEV01 semantic integration/provenance registration and exact integrated regression/PREPARE are still required. No live Telegram action is performed by this slice.
