# DEV08 — Reliability / Concurrency / Recovery / State

Status: isolated SWARM reliability candidate. This document is not an Auditor PASS, merge authorization, deployment authorization, Passenger restart authorization, Telegram authorization request, or live Telegram write authorization.

## Exact starting point

DEV08 reconstructed live state from Drive SWARM governance, issues #22/#30, current PRs and CI. The canonical integration branch moved during the run from `dde01436e9dff883997c560397788d5ac36d018d` to `f966cc5bffc19d597bf298799e39a9bbbe692b19`; DEV08 deliberately restarted its branch anchor at the newer exact head instead of developing from the stale parent.

At that anchor Recovery Guard #265 was still red only at the canonical `Real exact-head non-live release PREPARE` step; compile, package envelope validation, offline Action/OpenAPI, 67-criterion inventory, provenance, single deploy entrypoint, the full regression gate, current-tree secret scan, full-history secret scan, recovery marker and no-autodeploy checks were green. DEV08 does not own the PREPARE artifact seam and does not weaken it.

## System interaction findings

### R1 — unguarded CALLING state has no safe autonomous process-crash recovery

The current `PersistentWriteStore` commits `CALLING` before crossing the Telegram external-effect boundary. That is correct for ambiguity safety, but production bootstrap does not automatically invoke its recovery method. A process that dies after `CALLING` can therefore leave retries returning `write_in_progress` indefinitely.

Blindly calling the existing `mark_calling_transaction_ambiguous_on_recovery()` from every Passenger worker is not safe either: that method updates every `CALLING` row without proving that another worker is not still performing the external write.

DEV08 adds `ReliableWriteStoreProxy` as an isolated compatibility layer rather than changing SEND/REPLY/FORWARD/SEND_FILES semantics. It uses:

- one owner-private `flock` file per SHA-256 idempotency-key hash;
- a durable SQLite guard marker written before delegated commit;
- the same process lock held across the entire delegated external-write boundary;
- OS lock release as the process-death witness;
- startup recovery that changes `CALLING -> AMBIGUOUS` only when the durable marker exists and the corresponding process lock can be acquired;
- active locked writes are counted as busy and never mutated;
- legacy/unmarked `CALLING` rows are never automatically changed because ownership cannot be proven;
- terminal COMMITTED markers left by a crash are cleared and normal committed replay remains exactly-once.

No raw idempotency key, preview token, target, payload, Telegram content, credential or private path is added to the guard table or lock filename.

### R2 — preview/commit wall-clock rollback is not persistent-fail-closed

The underlying write store uses wall-clock integer timestamps for preview creation/expiry but does not persist a clock high-water mark. A backward system-clock movement across workers/restart can extend expiry semantics.

DEV08's proxy adds a persistent high-water table in the existing write database. Material backward movement fails closed before delegated preview/commit time is used. A small bounded skew tolerance is configurable for normal worker scheduling; deterministic tests use zero tolerance.

This is a compatibility wrapper. DEV01 must integrate the proxy atomically for all write coordinator traffic before R1/R2 can be considered canonical closure. Mixed guarded and unguarded commit workers are intentionally not claimed safe.

### R3 — active DEV04 download crash window between two SQLite stores

The current download flow has a distinct durability seam:

1. backend media is downloaded and validated;
2. final private file is moved into storage;
3. `FileRecordStore.add()` commits a new `files.sqlite3` row;
4. only afterwards does `CheckpointStore.save()` persist the item result in `downloads.sqlite3`.

A process death or checkpoint-save failure after step 3 but before step 4 leaves a valid registered private file that the job checkpoint does not know about. On resume, the same job lock is free again, the item still appears pending, the backend is called again, and another random final file / file_ref is registered. This violates the desired E3/E5/G4/G5 interaction invariant even though each store is individually valid.

`test_oracle_reproduces_file_registered_before_checkpoint_crash_window` deterministically injects this exact seam and currently proves two backend downloads and two registered file rows. The test is deliberately an executable finding, not a false closure. DEV08 does not replace DEV04 download business logic in this branch.

Recommended owner fix: DEV04/DEV01 should add a deterministic per-job/per-item durable identity or journal that permits checkpoint repair after file registration, so recovery either reuses the already registered result or safely rolls back the orphan. The repair must remain protected by the existing same-job process lock and must include crash-before-file-register, crash-after-file-register/before-checkpoint, checkpoint-save-error, restart, duplicate-resume and private-file topology tests.

## Adversarial regression matrix added

`tests/test_dev08_reliability.py` covers:

- real POSIX child-process death while a guarded write is durably CALLING;
- restart recovery to AMBIGUOUS with zero blind resend;
- process death after durable COMMITTED but before guard-marker cleanup;
- committed result replay after restart with zero second external effect;
- live same-key contention across independent store/proxy instances;
- proactive recovery refusing to mutate an actively locked external write;
- persistent backward wall-clock rejection across store restart;
- guard-state privacy: no plaintext idempotency key in the SQLite DB;
- process-shared fixed-window rate quota across independent SQLite store instances;
- read/write rate-limit namespace isolation;
- backward clock rejection across rate-limit store instances;
- concurrent limit-one contention with exactly one winner;
- Telegram session lock contention across independent instances;
- OS release of Telegram session lock after process death;
- same download job serialization and different-job independence;
- deterministic reproduction of the file-registration/checkpoint crash window.

All fault tests use synthetic payloads/fakes only. No real Telegram credentials, session, messages, media or live writes are used.

## Integration boundaries

- DEV08 owns the process/restart coordination candidate and adversarial evidence.
- DEV05 remains owner of write business semantics and Telegram write policy.
- DEV04 remains owner of media/download business behavior.
- DEV02 remains owner of HOSTiQ runtime/deployment mechanisms.
- DEV01 remains canonical semantic integration owner.
- This branch does not modify production deployment, Passenger startup, Telegram authorization, OpenAPI route definitions or live HOSTiQ state.

## Production truth

`USER_TELEGRAM_AUTH_NOT_YET_REQUIRED` remains unchanged. No merge, production deploy, Passenger restart, live Telegram operation, K5 execution, credential request or private server evidence is authorized by this work.
