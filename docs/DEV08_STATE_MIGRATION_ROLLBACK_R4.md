# DEV08 R4/R5 — persistent-state migration / rollback compatibility contract

Status: specialist reliability evidence only. This document does **not** authorize merge, production deployment, Passenger restart, Telegram authorization, live Telegram read/write, K5, or any restoration of private production state.

## Exact reviewed canonical anchor

This specialist refresh is rebuilt directly on canonical `work3/integration-release-candidate` exact SHA:

`38e33b829748cbdf255d66aba847aed81f6662c8`

This anchor includes the separately owned A01-11 authoritative post-switch recovery integration. The persistent-state specialist overlay remains a separate DRAFT PR and does not mutate canonical directly.

Exact reviewed blobs:

- `ops/release_guard.py` — `c77a7f5f2aa902359359fb7921970e3845714c7c`
- `ops/deploy_release.py` — `95e5a2d8d4b60d3f08f27875fed4b066c9b3c776`
- `bridge/storage.py` — `90cf1d74779d7947ea197010b8ea3011a5a6a705`
- `bridge/app.py` — `95a4882fe24e75a3d4141bc1730d185ab70b793d`
- `bridge/runtime.py` — `202dd8e84e045641ebb3a73744f657ebaf1dd265`
- `bridge/integrated_app.py` — `31b2eb39acb532d5db833cae9caf6b29fe2d172a`
- `ops/write_safety.py` — `bd78e1eb62cb067f880010c84ac1db440ad9d04b`
- `bridge/audit.py` — `eb3b35f329d44622d9fc2977bf1ddc78aa7f0ab6`

## Finding 1 — release approval and runtime behavior disagree

`ops/release_guard.py::load_external_approval()` intentionally accepts only `data_schema_change == false`. Any declared schema-changing release is rejected with `schema-changing deployment requires a separate audited migration plan`.

The canonical runtime nevertheless performs a persistent schema migration during application construction:

1. `BridgeApplication` constructs `FileRecordStore(private/state/files.sqlite3, private/files)`.
2. `FileRecordStore.__init__()` opens SQLite in WAL mode with `synchronous=FULL`.
3. It begins `BEGIN IMMEDIATE`.
4. It creates the current table if absent.
5. It inspects `PRAGMA table_info(files)`.
6. On the legacy schema it executes `ALTER TABLE files ADD COLUMN origin_key TEXT`.
7. It creates `files_origin_key_unique`.
8. It commits.

The preceding fully green predecessor `00684e834a523f55ea3b61c1a12cb9dc54cfd947` had the seven-column `files` table and no `origin_key`.

Therefore an external approval carrying `data_schema_change=false` can be valid under the current approval parser while candidate serving startup changes the shared persistent SQLite schema. This is a truthful-release-contract defect and remains deployment-blocking for a release that can encounter the legacy schema.

**Required canonical integration rule:** do not reinterpret the current migration as “no schema change”. The release must be declared schema-changing and must remain blocked until an exact-SHA audited migration-plan path is implemented. Do not weaken the fail-closed approval semantics by accepting an unbound or generic migration.

## Finding 2 — the current `origin_key` migration is specifically backward compatible

The specialist tests load the exact predecessor `bridge/storage.py` from Git history, not a hand-written approximation.

The predecessor `FileRecordStore` uses explicit seven-column `INSERT` and six-column `SELECT` lists. The new `origin_key` column is nullable. After current code migrates a legacy database, the exact predecessor module can open the migrated database, insert a new row without `origin_key`, and read it successfully.

This is useful rollback evidence for **this one migration**. It does not create a general rule that additive migrations are always safe, and it does not make `data_schema_change=false` truthful.

Preferred rollback policy for this migration: preserve the migrated `files.sqlite3` state and prove old-code compatibility. A targeted SQLite restore is unnecessary for this specific additive change unless independent audit discovers a different incompatibility.

## Persistent state inventory and rollback rules

### 1. File registry — `state/files.sqlite3`

Medium: SQLite/WAL. Current behavior performs an implicit legacy→current migration by adding nullable `origin_key` and a partial unique index. There is no explicit `PRAGMA user_version` or meta schema version.

Rollback rule: old-code compatibility must be proven for every migration or a targeted, audited SQLite restore must be defined. Current `origin_key` migration has exact predecessor compatibility evidence.

### 2. Download checkpoints — `state/downloads.sqlite3`

Medium: SQLite/WAL. DB table is created if absent. Checkpoint JSON carries payload `schema=1`; DB schema itself has no explicit version.

Rollback rule: preserve by default. A future payload/DB migration needs a separate versioned migration contract; do not restore unrelated state to repair one checkpoint schema.

### 3. Write preview/idempotency — `state/writes.sqlite3`

Medium: SQLite/WAL. `PersistentWriteStore` has a `meta` table with `schema_version=1` and fails closed if an unsupported version is present.

Rollback rule: **preserve across code rollback**. Blind restoration can erase RESERVED/CALLING/COMMITTED/AMBIGUOUS knowledge and can therefore re-open duplicate-send risk after an external Telegram side effect. This store must never be rolled back merely because the code symlink is rolled back.

### 4. Rate limit — `state/rate_limit.sqlite3`

Medium: SQLite/WAL. Runtime creates quota and monotonic high-water clock tables if absent. The DB schema is currently implicit/unversioned. Transactions use `BEGIN IMMEDIATE`; WAL/SHM topology is validated and owner-private.

Rollback rule: preserve across code rollback by default. Restoring older quota/high-water state can weaken abuse protection or violate the monotonic-clock contract.

### 5. Private files — `files/`

Filesystem payloads referenced by `files.sqlite3`, verified by size/hash.

Rollback rule: preserve. Restore only explicitly selected artifacts with registry consistency proof; never replace the entire private content tree because code rollback occurred.

### 6. Download and archive staging — `tmp/downloads/`, `tmp/archives/`

Recoverable private temporary state.

Rollback rule: follow job/archive cleanup and resume protocols. They do not justify broad restoration of private state.

### 7. Telegram session and private configuration

Current runtime consumes Telegram API/session references from the private server environment and also treats session/private-config file forms as protected persistent state at the deployment boundary.

Rollback rule: preserve exactly. Never copy values into public evidence and never bulk-restore the private tree over a newer valid Telegram session/config.

### 8. Audit evidence

Optional private append-only metadata sink.

Rollback rule: never erase or roll it back simply because application code rolls back.

## Code rollback is not state rollback

Canonical deployment quiesces, creates code and persistent-state backups, switches the active release symlink, restarts, verifies candidate identity, runs unauthenticated/authenticated smoke, resumes, and records deployed state.

On a post-switch failure it restores the previous symlink and runs previous-release restart, exact identity verification, unauthenticated smoke, authenticated smoke, and resume. It does **not** automatically restore the persistent-state backup.

That is the correct default for session/idempotency/audit/rate-limit safety, but it means every state-mutating release needs an explicit compatibility or targeted-restore plan.

The fault oracle mutates synthetic shared persistent state immediately before candidate authenticated smoke fails. Canonical rollback returns `20`, restores the old release and records `ROLLED_BACK`, while the candidate-mutated state remains. A separate oracle verifies that rollback health includes exact previous-release identity, not merely HTTP success.

## SQLite transaction, interruption and concurrency evidence

`FileRecordStore` uses `BEGIN IMMEDIATE`, which serializes migration inspection and DDL across workers.

The interruption oracle injects a failure after `ALTER TABLE` but before index creation/commit. Closing the connection with the transaction still open rolls the DDL back; the database remains on the legacy schema. A normal retry then performs the migration successfully.

The concurrent-process oracle starts two separate POSIX processes against the same legacy database. Both constructors complete; final schema contains one `origin_key` column and the expected unique index.

## WAL/SHM and backup contract

Current SQLite stores use WAL and `synchronous=FULL`.

Canonical persistent-state backup is a tar filesystem snapshot, not SQLite's online-backup API. It recursively captures the state root and therefore can include `.sqlite3`, `-wal`, and `-shm` files. The specialist oracle holds a committed row in WAL with a reader preventing checkpoint, creates a quiescent backup, verifies DB/WAL/SHM are all in the archive, extracts the synthetic snapshot, and confirms the committed row is recoverable.

This proves one stable, no-writer snapshot case; it does **not** prove arbitrary live-copy safety. The production migration contract must require one of:

- a quiesce contract that proves all relevant SQLite writers are stopped and DB/WAL/SHM remain stable for the backup window; or
- a SQLite-aware consistent backup mechanism for DBs that need targeted restoration.

Copying only the main `.sqlite3` file while committed frames remain in WAL is not an accepted restore contract.

## Explicit audited migration-plan contract

A future canonical schema-changing approval must remain fail-closed and be exact-release bound. At minimum it must prove runtime schema mutation is declared; approval says `data_schema_change=true`; the migration plan is bound to exact candidate SHA/manifest; affected state areas and before/after versions are explicit; forward migration interruption/concurrency are tested; old-release compatibility is proven or a targeted restore is defined; targeted SQLite restore has DB/WAL/SHM consistency evidence; write/idempotency, rate-limit, Telegram session/config, and audit state are not overwritten by a generic restore; rollback health verifies previous release identity plus smoke; and independent Auditor still gates the migration.

The specialist classifier never sets `production_authorized=true`, even when these evidence booleans are complete. Canonical wiring and independent audit remain mandatory.

## Current decision for `origin_key`

- Runtime schema changed: **yes**.
- Current approval can truthfully say `data_schema_change=false`: **no**.
- Exact predecessor compatibility with migrated DB: **proven by specialist test**.
- Whole-private-tree restore required: **no; prohibited**.
- Preferred rollback state policy: preserve migrated `files.sqlite3`; preserve all other critical state.
- Canonical audited migration approval path exists today: **no**.
- Production authorized by this specialist work: **no**.

Therefore a release that can encounter the legacy files schema remains blocked from schema-changing production deployment until the canonical owner integrates a separately audited, exact-SHA migration-plan approval path (or removes the runtime schema mutation).

## A01-11 interaction

At this refreshed anchor, the separately owned A01-11 crash seam is no longer merely an oracle: canonical `ops/deploy_release.py` imports and invokes `classify_deployment_recovery()` for `BACKED_UP + active==candidate`, with candidate revalidation and fail-closed rollback/ambiguity handling. That change does not alter this persistent-state conclusion: recovery/rollback still changes code identity while preserving shared persistent state by default.

This specialist lane does not claim independent closure of A01-11; it only re-ran its state/rollback compatibility tests on top of the new authoritative recovery code.

## Specialist test evidence

The focused matrix contains 25 credential-free tests covering approval truthfulness, all current persistent-state classes, serving-startup migration, interrupted migration, two-process concurrent migration, exact predecessor-on-migrated-schema compatibility, WAL/SHM snapshot recovery, failed-smoke code rollback retaining candidate-mutated shared state, previous-release identity verification, blind-private-tree restore rejection, exact-SHA migration-plan requirements and strict fail-closed evidence typing.

No production source, approval parser, runtime store, secret, HOSTiQ state, Telegram session, production endpoint, or canonical branch is modified by this specialist overlay.

`USER_TELEGRAM_AUTH_NOT_YET_REQUIRED` remains unchanged.
