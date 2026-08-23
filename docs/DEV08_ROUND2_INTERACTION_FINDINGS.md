# DEV08 Round 2 — reliability interaction findings

Status: isolated specialist reliability work. No merge, deployment, Passenger restart, Telegram authorization, live Telegram read/write or K5 is authorized by this document.

## Exact live context

DEV08 reconstructed current SWARM state before this round. Canonical DEV01/DEV_A PR #9 had advanced to `c609adfc9a1116aae635a0b14d632a5e59b6c2af`; the delta from the previous DEV08 validation checkpoint was dominated by DEV_B runtime/Passenger/private-control work and did not modify DEV08 reliability paths. DEV08 PR #44 remains a separate Draft overlay.

Relevant peer candidates remain separate Draft PRs:

- DEV04 PR #37: media/storage crash recovery using deterministic private download `origin_key` and in-place legacy registry migration.
- DEV05 PR #39: `SecurePersistentWriteStore`, an owner-private SQLite filesystem boundary compatible with the existing `PersistentWriteStore` API.

DEV01 remains the semantic integration owner.

## DEV08 finding R2-1 — recovery must not depend on rolled-back request time

The original DEV08 `ReliableWriteStoreProxy.recover_on_startup()` reused the normal request wall-clock high-water check. This is safe for preview expiry but can make crash recovery unavailable after a real backward clock movement: an orphaned guarded `CALLING` row remains blocked until wall time catches the prior high-water mark.

`ops/dev08_recovery_extensions.py` adds `RollbackSafeReliableWriteStoreProxy`:

- preview/commit request paths still fail closed on material backward time;
- startup recovery uses a timestamp no smaller than the durable high-water value;
- guarded dead-worker `CALLING` can therefore be classified `AMBIGUOUS` immediately;
- the external effect is never retried during recovery;
- the persistent high-water mark is never reduced.

This is a composition layer only; Telegram/write business semantics are unchanged.

## DEV08 finding R2-2 — DEV04 legacy migration has a multi-worker bootstrap race

DEV04 PR #37 correctly addresses the earlier file-registration/checkpoint crash windows using a deterministic private `origin_key`. However its current legacy schema migration follows this interaction pattern:

1. read `PRAGMA table_info(files)`;
2. if `origin_key` is absent, run `ALTER TABLE files ADD COLUMN origin_key TEXT`;
3. create the unique index.

Two Passenger workers can both observe the old schema before either `ALTER`. A deterministic two-connection oracle in `tests/test_dev08_round2.py` proves the result: one worker migrates successfully and the other receives SQLite `duplicate column name`.

The same test file proves the safe transaction topology: acquire `BEGIN IMMEDIATE` before the schema check, then perform the conditional migration while holding that write reservation. The second worker waits, re-reads the migrated schema, and completes normally.

DEV08 does not edit DEV04 storage business logic. DEV04/DEV01 should apply an equivalent serialized migration and retain DEV04's existing recovery tests.

## DEV05 composition

DEV05 PR #39 subclasses `PersistentWriteStore` and preserves the store interfaces consumed by DEV08 (`db_path`, `_connect`, idempotency state methods). The intended composition is therefore:

`SecurePersistentWriteStore` -> DEV08 reliable proxy -> existing `WriteCoordinator`.

DEV08 does not copy or replace DEV05 filesystem-security implementation. Canonical integration should exercise this exact composition after DEV01 imports both specialist slices.

## Adversarial coverage added this round

`tests/test_dev08_round2.py` covers:

- process death during guarded external write;
- backward clock during subsequent startup recovery;
- durable `CALLING -> AMBIGUOUS` classification with no blind resend;
- request-time expiry still failing closed after rollback-safe recovery;
- recovery clock initialization and invalid-clock rejection;
- deterministic reproduction of the DEV04 legacy migration duplicate-column race;
- deterministic proof that `BEGIN IMMEDIATE` serializes check-and-migrate safely.

All tests are credential-free and use synthetic local SQLite/process/thread state only.

## Integration boundary

DEV08 recommends DEV01 integrate only after reviewing current exact peer heads. Canonical provenance must explicitly account accepted specialist paths; no wildcard provenance bypass is acceptable. Production/live gates remain unchanged and `USER_TELEGRAM_AUTH_NOT_YET_REQUIRED` remains authoritative.
