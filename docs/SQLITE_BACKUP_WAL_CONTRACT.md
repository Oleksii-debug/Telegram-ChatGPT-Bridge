# SQLite persistent-state backup / WAL contract

Status: specialist implementation candidate for FINALWAVE-26-36. It is non-authorizing and does not permit merge, deployment, Passenger restart, Telegram authorization, live Telegram access, or K5.

## Canonical defect at the reviewed boundary

Exact reviewed canonical head: `84691967e5363bc4b88dfae97371d7bf329c105d`.

`ops/deploy_release.py` invokes the private quiesce hook and then archives the entire persistent-state directory with a recursive tar. That is only a valid SQLite backup when quiesce actually prevents all relevant database writes and DB/WAL/SHM topology stays stable for the complete tar walk. The deployment code does not independently prove that property. A DB file copied without its matching committed WAL frames is not a sufficient backup.

The current runtime uses WAL-mode SQLite state. The reviewed inventory includes:

- `state/files.sqlite3` — private file registry / migration state.
- `state/downloads.sqlite3` — resumable download checkpoints.
- `state/writes.sqlite3` — preview/commit/idempotency/external-effect knowledge.
- `state/rate_limit.sqlite3` — shared read/write quota and clock high-water state.

Restoring an old `writes.sqlite3` can erase COMMITTED/AMBIGUOUS effect knowledge and create duplicate-send risk. Restoring an old rate-limit DB can weaken quota/high-water security. This wave therefore improves backup consistency only; it does not introduce automatic broad state rollback.

## Candidate contract

`ops/sqlite_state_backup.py` builds a private staging snapshot before tar creation.

For each SQLite database it:

1. validates owner/topology and rejects symlink, hardlink and group/world-writable source state;
2. recognizes source `-wal` / `-shm` as SQLite sidecars and rejects orphan sidecars;
3. opens the source read-only and uses `sqlite3.Connection.backup()` rather than raw DB/WAL copying;
4. runs `PRAGMA quick_check` on source and destination;
5. normalizes the completed destination to `journal_mode=DELETE` and runs `quick_check` again, making the backup self-contained and independent of WAL/SHM files;
6. verifies the source database inode was not replaced during backup;
7. never copies source WAL/SHM into the staged snapshot.

For non-SQLite persistent files it performs descriptor-bound copying and fails if inode, size, mtime or ctime changes during the copy. Symlinks, hardlinks, special files, unsafe modes/owners and root overlap fail closed.

`create_private_state_archive()` stages under an owner-private `0700` backup root, creates a `0600` tarball, performs a real extract-and-SQLite-verify restore check, writes a `0600` SHA-256 companion, verifies the pair, and removes current-attempt partial/snapshot material on ordinary exceptions. On the next retry it can reap a same-name unpaired `0600` archive or stale `0700` snapshot left by process loss. Existing completed backup/hash pairs are never overwritten.

## Quiesce requirement remains

SQLite online backup makes each individual database a transaction-consistent snapshot even if a writer commits concurrently. It does **not** create one atomic transaction spanning multiple independent SQLite databases plus ordinary private files. The deployment quiesce hook therefore remains mandatory for cross-database/cross-file application invariants. The safe composition is:

`approval commit -> quiesce -> SQLite-aware persistent snapshot/archive -> archive restore verification -> BACKED_UP -> switch -> restart/smoke -> resume`

Do not weaken or remove quiesce merely because the per-database online backup tests pass.

## Canonical integration seam

The specialist helper must replace only the persistent-state backup implementation, not the code backup path. The canonical integrator should adapt `backup_persistent_state()` so that it calls `create_private_state_archive(state_root, backup_root, "state_predeploy_<sha>.tar.gz")`, maps `SQLiteStateBackupError` to the existing stable `SafetyError`, and returns the resulting archive path. Preserve the existing deployment lock, quiesce ordering, transaction journal, retention, approval, switch, smoke and rollback semantics.

No second deploy-capable entrypoint is added by this specialist branch.

## Validation contract before canonical acceptance

Canonical acceptance should require all of the following on the exact integrated SHA:

- committed row present only in active WAL is present after restored backup;
- concurrent writer produces a valid transaction-consistent SQLite snapshot;
- all four runtime SQLite databases are discovered and restore successfully;
- no source WAL/SHM is required by the archive;
- tar/archive crash and SQLite-backup failure leave no accepted partial backup;
- retry reaps incomplete same-name process-loss residue without overwriting a completed pair;
- archive and hash pair are mode `0600`; backup root/staging are `0700`;
- symlink, hardlink, special-file, broad-write mode, orphan sidecar and root-overlap cases fail closed;
- non-SQLite mutation during snapshot fails closed;
- restore extraction rejects unsafe member topology and every restored DB passes `quick_check`;
- exact canonical full regression, provenance, current-tree secret scan, history secret scan, no-autodeploy/recovery gates and real exact-ref PREPARE run to terminal state.

A synthetic green specialist branch is not production PASS. Production still requires the independent exact-SHA gate and live HOSTiQ lifecycle evidence.
