# State retention and cleanup policy

This document defines the fail-closed retention boundary for Telegram Bridge private state. Cleanup is maintenance, not a correctness shortcut. Disk pressure does not authorize deletion of knowledge needed for exactly-once writes, reconciliation, rate-limit rollback detection, audit, or crash recovery.

## Authoritative state: never space-pruned automatically

The following state is authoritative and is not deleted by `ops/state_retention.py`:

- every write `idempotency` row, including `COMMITTED`, `AMBIGUOUS`, `CALLING`, `RESERVED`, and `FAILED_SAFE` knowledge;
- consumed preview rows that are referenced by an idempotency row;
- committed/ambiguous tombstones and durable results needed for replay/reconciliation;
- rate-limit clock high-water state;
- retention clock high-water state;
- append-only audit history;
- pending/running/retryable download checkpoints;
- unleased archive `.part` files where liveness cannot be proven.

Audit disk growth therefore remains an operational capacity concern until there is an independently reviewed archival/rotation design that preserves durable history. This cleanup layer intentionally refuses to truncate or delete audit history.

## Reclaimable state

Only the following state may be reclaimed, with all preconditions rechecked at deletion time:

1. **Write previews** — the preview must be expired beyond the configured grace period, unconsumed, and have zero idempotency references. Cleanup runs in `BEGIN IMMEDIATE`, racing safely with preview/commit. The idempotency table is counted before/after and is never modified.
2. **Download checkpoints** — the checkpoint must be older than the retention age and semantically terminal. `complete` is terminal only when every item has a result. `partial`/`failed` is terminal only when every unresolved item has a recorded `retryable=false` failure. The cleaner acquires the exact per-job POSIX lock used by `DownloadManager`, then re-reads and integrity-checks the row inside `BEGIN IMMEDIATE` before deletion. Busy jobs are skipped. The empty lock leaf is removed descriptor-bound only after the checkpoint is deleted.
3. **Archive staging** — only staging created under the lease protocol can be reclaimed. `ArchiveBuilder` now creates and holds `archive_*.zip.part.lease` for the whole build. A hard process loss releases the POSIX lock but leaves the marker. Cleanup validates the marker/topology, acquires the marker lock non-blocking, enforces age, and then removes the part plus exact marker inode. Legacy/unmarked `.part` files are protected as ambiguous rather than guessed stale.

## Persistent clock rollback protection

Each destructive cleanup namespace persists a wall-clock high-water value in `retention_high_water`. A later cleanup observation below that high water fails with `retention_clock_moved_backward` before additional deletion. The high-water rows themselves are authoritative and never pruned.

This does not pretend to solve arbitrary forward wall-clock corruption. Retention ages must therefore remain conservative and operational clock discipline remains required. The important safety property is that a detected rollback never silently changes deletion eligibility.

## Multiprocess/crash rules

- SQLite state decisions use `BEGIN IMMEDIATE` and are rechecked in the same transaction that deletes.
- Download cleanup uses the same hash-derived job lock namespace as live resume; lock contention is a skip, never a force-unlock.
- Archive cleanup requires lease ownership evidence. Active builders hold the lease lock; process death releases it automatically.
- Leaf unlink uses descriptor/inode identity checks to reject replacement races.
- Corrupt checkpoint/lease material is not deleted. It is reported as protected/corrupt for manual investigation.
- No cleaner invokes Telegram, performs a write effect, deploys, restarts Passenger, or accesses credentials.

## Operational interface

The module provides narrow subcommands:

```text
python -m ops.state_retention writes <writes.sqlite3> --grace <seconds>
python -m ops.state_retention downloads <checkpoints.sqlite3> <.download-locks> --age <seconds>
python -m ops.state_retention staging <staging-dir> <retention-ledger.sqlite3> --age <seconds>
python -m ops.state_retention policy
```

No automatic scheduler is armed by this change. Production scheduling, retention durations, backup interaction, and capacity alerts remain subject to the independent exact-SHA release/deployment gate.

## Integration boundary

This isolated specialist branch is based on canonical PR #9 exact head `84691967e5363bc4b88dfae97371d7bf329c105d`. It does not change canonical deployment recovery, production configuration, or live state. The canonical Recovery Guard at that parent is independently known to have an unrelated A01-11 regression failure; specialist provenance must not be weakened to make an overlay appear canonical-green.
