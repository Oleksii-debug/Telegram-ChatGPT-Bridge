# BURST01-09 — reliability/concurrency composition checkpoint

Scope: multi-process Passenger composition only. This document does not replace DEV05 write business semantics or DEV04 media semantics and does not authorize merge/deploy/live Telegram.

## Exact reconstruction anchor

- canonical PR #9 anchor reviewed for this diagnostic branch: `84691967e5363bc4b88dfae97371d7bf329c105d`
- DEV08 reliability specialist: PR #44 @ `63d3592ecb950e4bba116f9a8740f8ead58c9b4e`
- DEV08 migration specialist: PR #51 @ `e25481b8030efe54d082c5fe16861dd85c6f8c70`
- DEV05 write specialist: PR #39 @ `540322ef6749b973718de3e35939cb9198cf0c7f`
- DEV04 media specialist: PR #50 @ `29a9d3bf30ac75999b86b51d694e6885b54b519a`

## Confirmed composition properties

### DEV05 secure store -> DEV08 reliability proxy

The intended wrapper order is structurally viable:

`SecurePersistentWriteStore -> RollbackSafeReliableWriteStoreProxy -> WriteCoordinator`

Lock/transaction ordering is non-cyclic in the reviewed code:

1. request-time clock observation uses a bounded SQLite `BEGIN IMMEDIATE` and releases it before the per-idempotency flock;
2. commit obtains the per-idempotency flock, then performs short SQLite transactions, and holds the flock across the external Telegram effect boundary;
3. startup recovery enumerates markers without holding SQLite while waiting for a flock, then uses non-blocking flock acquisition before opening the recovery transaction;
4. every recovery SQLite transaction is bounded and there is no reviewed path that blocks on the same per-idempotency flock while already owning a SQLite writer transaction.

This means the secure store and DEV08 proxy do not inherently create double transaction ownership or an obvious lock-order deadlock. The secure store's `_connect()` override is also inherited by DEV08, so DB/WAL/SHM topology validation remains active for DEV08 clock/guard tables.

### Crash windows around CALLING

The reviewed guard sequence is conservative:

- marker durable, RESERVED/no row, process death -> startup removes only the stale marker; no external effect was proven;
- marker + CALLING + dead process -> startup obtains the released flock and converts CALLING to AMBIGUOUS, never blind re-send;
- live process still holds flock -> another worker/recovery scan reports busy and does not mutate CALLING;
- external success followed by process death before COMMITTED -> CALLING+marker becomes AMBIGUOUS;
- terminal COMMITTED/FAILED_SAFE/AMBIGUOUS with stale marker -> marker can be cleared without reopening the effect.

### Clock rollback

`RollbackSafeReliableWriteStoreProxy` correctly separates request-time clock safety from startup crash classification. Preview/commit remain fail-closed on material backward time, while recovery uses `max(current_wall_time, durable_high_water)` so an orphaned CALLING row is not left permanently live solely because the wall clock moved backward.

### Shared rate limit state

Canonical `_SQLiteFixedWindowStore.take()` uses `BEGIN IMMEDIATE` around high-water + quota mutation. The clock high-water is persisted in `rate_limit.sqlite3`; rollback of this DB to an older snapshot would weaken quota/clock history and therefore must not be part of generic code rollback.

### Telegram session serialization

Canonical read and write clients share the same private `TelegramSessionLock` namespace. The read wrapper acquires before `connect()` and releases on connect failure, disconnect, cancellation/BaseException, or process death (OS flock release). The reviewed write composition therefore remains globally serialized at the Telegram session boundary. This is conservative for a shared StringSession, though it can create head-of-line blocking under concurrent writes.

### Deployment recovery

Canonical `84691967...` contains the hardened A01-11 authoritative recovery branch. It derives runtime-manifest evidence, validates committed marker evidence, re-verifies candidate bytes/bindings, checks previous-release availability, invokes the DEV08 classifier, and has fail-closed rollback paths when SWITCHED persistence fails. The deployment transaction itself remains serialized under the private deployment flock.

## New finding R09-01 — deterministic Passenger cold-start schema race

`ops.write_safety.PersistentWriteStore._init_schema()` creates tables and then performs:

1. `SELECT value FROM meta WHERE key='schema_version'`;
2. if no row: separate `INSERT INTO meta(...)`;

without a writer transaction spanning the read/insert decision.

Two Passenger processes starting against a new `writes.sqlite3` can both observe no schema-version row. One INSERT succeeds and the second raises `sqlite3.IntegrityError` on the primary key. The specialist oracle forces exactly this interleaving through the real `PersistentWriteStore` constructor and records one successful bootstrap plus one `IntegrityError`.

Risk: intermittent worker bootstrap failure on a fresh or recreated write DB. The risk exists in current canonical code and also occurs before DEV08 can construct its serialized reliability tables, so DEV08 cannot repair it after the fact.

Required production fix: serialize the entire base write-store schema/bootstrap decision (for example a bounded `BEGIN IMMEDIATE` transaction that includes schema creation/version decision), with rollback on failure and a multi-process regression proving all simultaneous constructors succeed. Do not weaken the schema-version mismatch check.

## New finding R09-02 — DEV08 integration is itself a persistent schema change

PR #44 constructors execute `CREATE TABLE IF NOT EXISTS dev08_write_clock` and `CREATE TABLE IF NOT EXISTS dev08_commit_guard` in `writes.sqlite3`. These are real persistent schema mutations but `PersistentWriteStore.SCHEMA_VERSION` remains `1` and the current release approval policy accepts only `data_schema_change=false` unless an audited migration plan exists.

Therefore selecting DEV08 reliability into runtime must be coordinated with PR #51's migration/release contract. It must not be represented as a schema-neutral code-only import. The extra tables are additive and older write-store code ignores them, but backward compatibility does not make `data_schema_change=false` truthful.

Required integration rule: exact-SHA migration declaration/plan must account for both the DEV04 `origin_key` migration and DEV08 write reliability tables (or the runtime schema mutation must be removed/relocated). Preserve `writes.sqlite3` across rollback; never restore an older copy that can erase COMMITTED/AMBIGUOUS knowledge.

## Known non-blocking/deferred reliability debts

- DEV08 per-idempotency lock leaves are intentionally not deleted during normal operation. This avoids unsafe lock-inode replacement races, but creates an unbounded inode-growth surface. Any future GC requires a separate global/namespace serialization proof; do not naively unlink lock files.
- canonical raw `PersistentWriteStore` still has no DEV08 startup orphan recovery. Until the proxy is selected into runtime, process loss in CALLING remains fail-closed but can stay stuck as `write_in_progress` rather than becoming durable AMBIGUOUS.
- DEV04 PR #50 ZIP/process-loss hardening is specialist-only until canonical selection; do not duplicate it in this lane.
- live HOSTiQ Passenger/process-death/session/Telegram evidence remains external and unproven.

## Safety status

No secret values, Telegram content, live Telegram calls, HOSTiQ mutation, production deploy, merge, or Passenger restart were used in this diagnostic round. `USER_TELEGRAM_AUTH_NOT_YET_REQUIRED` remains authoritative.
