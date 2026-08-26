# FINALWAVE-52 deployment crash/fault-injection audit

Status: isolated, non-authorizing specialist evidence. No merge, production deploy, Passenger restart, Telegram authorization, live Telegram operation, K5, or credential collection is authorized by this document or branch.

## Exact source identities

- Canonical base at creation: PR #9 `work3/integration-release-candidate` @ `84691967e5363bc4b88dfae97371d7bf329c105d`.
- Role01 source under falsification: PR #66 `finalwave26/01-a01-11-deploy-recovery` @ `c4a4f2f050cdab8937db97091844884bd1fb8f3f`.
- FINALWAVE-52 branch: `finalwave26/52-deploy-crash-fuzz`.

The dedicated workflow checks out role01 by immutable SHA and copies only the independent fuzz oracles into that detached tree. It does not merge or rewrite role01.

## What role01 genuinely fixes

Role01 correctly addresses the canonical Recovery Guard #529 failure where an invalid runtime manifest was rejected before active transaction reconciliation. It loads the transaction journal before semantic runtime-manifest validation and persists `CRITICAL_TRANSACTION_AMBIGUOUS / runtime_manifest_changed` when an active transaction exists. The independent oracle also verifies a valid-but-changed persistent-path manifest, preventing an empty-list-only repair.

Role01 additionally strengthens journal writes with file and parent-directory fsync and refuses to silently swallow failures while trying to persist critical terminal states.

## Residual HIGH findings

### FW52-H1 — fixed O_EXCL transaction temp strands restart recovery

Role01 writes `DEPLOYMENT_TRANSACTION.json.tmp` with `O_CREAT|O_EXCL`. A process loss after the temp is created/fsynced but before `os.replace()` leaves the temp file behind. The next journal write receives `EEXIST`; the same stale temp remains; repeated recovery cannot persist a terminal state. The active candidate is not switched again, but the transaction remains durably non-terminal and cannot converge without an out-of-band cleanup.

Required integration repair: under the deployment lock, make abandoned journal temp handling restart-safe. A safe implementation may use unique temp names plus bounded owner-private cleanup, or explicitly validate and remove only an abandoned fixed temp that is regular, owner-owned, private, single-link, under the validated control root, and never authoritative. Do not weaken symlink/hardlink/topology checks. Re-run process death before write, after temp creation, after file fsync, before rename, after rename, and before/after parent fsync.

### FW52-H2 — candidate restart dispatch is not exactly-once across process loss

The durable journal is `SWITCHED` before the Passenger restart hook is dispatched. If restart completes and the process dies before running-SHA evidence, recovery from the same `SWITCHED + active==candidate` snapshot dispatches restart again. The independent oracle proves two restart dispatches for one deployment transaction.

Required integration repair: add an explicit durable restart-dispatch ambiguity boundary or a separately proven idempotent/exactly-once restart protocol. A state written before dispatch must not cause automatic redispatch after process loss unless the hook has an audited idempotency key/receipt contract. If completion cannot be distinguished, fail closed to a durable/manual ambiguity rather than issuing a second physical restart.

### FW52-H3 — rollback restart dispatch is likewise replayed

After a post-switch verification failure, code restores the previous symlink and dispatches rollback restart while the journal still represents the switched transaction. If rollback restart completes and the process dies before subsequent evidence/terminalization, recovery observes `active==previous` and dispatches another rollback restart. The independent oracle proves two rollback restart dispatches before `ROLLED_BACK`.

Required integration repair: model rollback switch and rollback restart dispatch as explicit durable phases. The symlink restore is locally inspectable and may be reconciled without a second switch; restart completion is not locally inferable from the current journal. Ambiguous post-dispatch recovery must not automatically issue another restart unless an idempotency/receipt contract is proven.

### FW52-H4 — durable VERIFIED recovery replays already-completed mutating hooks

`VERIFIED` is written only after candidate restart, running-SHA verification, unauthenticated smoke, authenticated smoke, and resume/unquiesce all complete. Nevertheless recovery groups `VERIFIED` with `SWITCHED` and dispatches candidate restart and resume/unquiesce again before writing `DEPLOYED`. This is not an ambiguous-dispatch case: the durable state already proves the prior lifecycle completed.

Required integration repair: split recovery by durable phase. For `VERIFIED`, do not repeat mutating restart/resume hooks. Read-only identity/health/security rechecks may be performed if desired before terminal `DEPLOYED`, but any mutating hook must have its own explicit idempotency contract if replayed.

### FW52-H5 — pre-live recovery lifecycle has no durable progress boundary

When a committed pre-switch transaction fails after quiesce, recovery restarts and resumes the previous release and only then writes `PRELIVE_RECOVERED`. If the recovery restart completes and the process dies before terminalization, the original active state remains (for example `QUIESCED`), and the next recovery dispatches restart again. The same structural gap can replay resume/unquiesce after process loss later in that recovery lifecycle.

Required integration repair: make pre-live recovery lifecycle progress explicit or use an audited idempotency/receipt protocol for mutating hooks. A process loss after dispatch must converge to a safe durable/manual ambiguity without blind repeated mutation.

### FW52-H6 — SWITCHED/VERIFIED can become DEPLOYED with no previous release available

For `SWITCHED` or `VERIFIED` with the candidate active, role01 checks whether the previous release is available only when candidate verification fails and rollback is required. If the previous release directory has disappeared but the candidate is currently healthy, recovery completes the candidate lifecycle and writes `DEPLOYED`. The transaction is then terminal-successful even though its automated last-known-good rollback target is absent.

Required integration repair: before any post-switch recovery can terminalize `DEPLOYED`, require independently validated rollback availability bound to the transaction/backup evidence. Missing, symlinked, unsafe, or provenance-unverified previous release must block successful terminalization even if the candidate is healthy, unless an independently verified backup restoration path is available and transaction-bound.

### FW52-H7 — rollback accepts an unverified tampered previous release tree

The transaction journal binds only `previous_sha`; rollback resolves the directory named by that SHA and switches `active` to it without verifying its code bytes against a captured previous-release manifest or the predeploy code backup. The synthetic role01 harness can modify the previous tree while preserving the SHA-shaped directory name; when candidate verification is forced to fail, rollback switches to the modified previous tree, its hook-based identity check succeeds, and the journal terminalizes `ROLLED_BACK`.

Required integration repair: capture immutable previous-release provenance before mutation and bind it to the transaction/backup record. Before rollback switch/restart, verify the previous release's immutable application payload (and persistent-binding topology) against that durable provenance, or restore and verify from a transaction-bound backup whose archive/hash evidence is itself durably recorded. A directory name equal to a Git SHA is not sufficient rollback provenance.

### FW52-H8 — rc20/rc10 can report recovery while durable terminal journal write failed

Role01 changes `_best_effort_transaction` so persistence failures for `CRITICAL_*` states are no longer swallowed, but ordinary terminal states remain best-effort. If the physical rollback and verification succeed but the `ROLLED_BACK` journal write fails, `_best_effort_transaction` returns an in-memory fallback and execute still returns rc20; the on-disk journal remains `SWITCHED`. Likewise a failed `PRELIVE_RECOVERED` write can still return rc10 with durable state left at `QUIESCED`. A caller can therefore receive the normal recovery result without durable terminalization.

Required integration repair: no success-like recovery return code may be emitted unless its corresponding terminal transaction state is durably persisted and re-readable. If `ROLLED_BACK`, `PRELIVE_RECOVERED`, or another terminal write fails, attempt a legal durable critical/manual-ambiguity terminal if possible; otherwise return/raise a critical persistence failure, not rc20/rc10. Add retry tests proving no false terminal claim and no repeated physical mutation.

## Boundary matrix conclusion

The locally inspectable/durable boundaries are materially stronger than the uninspectable hook and rollback-provenance boundaries:

- approval consumption: committed marker is externally inspectable and duplicate consumption is blocked;
- materialize/final release: candidate tree and journal provenance are inspectable;
- backup: recovery does not re-run backup when journal remains `QUIESCED`/`BACKED_UP`, but exact backup path/hash is not currently journal-bound for automated recovery;
- candidate symlink switch: `active` target makes switch completion inspectable; no second candidate switch is needed;
- rollback symlink restore: `active==previous` makes physical link restoration inspectable, but previous-content authenticity is not proved;
- running identity, unauth smoke, auth smoke: read-only evidence may safely be repeated;
- restart/reload and resume/unquiesce: external mutations have no durable receipt/idempotency boundary and are replayed in several recovery paths;
- previous release: name/path existence is insufficient to prove last-known-good content integrity or rollback availability;
- terminal journal: critical-state write failures now propagate in role01, but ordinary recovery terminal writes can still be silently non-durable while rc20/rc10 is returned.

The existing A01-11 candidate symlink switch crash seam is substantially repaired: `BACKED_UP + active==candidate` is locally observable and recovered without a second candidate switch after marker/runtime/candidate/previous-release validation. Existing tests also cover missing/tampered committed markers, missing previous release in the BACKED_UP observed-switch classifier, candidate tamper rollback, lock contention, state-boundary process loss, and repeated terminal recovery. Those tests do not cover the post-SWITCHED healthy-candidate missing-previous case, previous-content tamper before rollback, or success-like return codes after noncritical terminal write failure.

Control-plane file topology tamper (for example missing/unsafe runtime or hook files) is validated before execute reconciliation and therefore fails closed without further physical deployment mutation; that is a safe manual-ambiguity boundary, not a claimed terminal recovery path.

The durability claim remains narrow: process loss on the same POSIX host/filesystem. No full host/power-loss durability claim is made here.

## Integration recommendation

Do not integrate PR #66 as complete durable-boundary closure yet. Preserve its valid runtime-manifest terminalization and fsync work, then address FW52-H1 through FW52-H8 and convert the FINALWAVE-52 falsification scenarios into positive safe-contract regressions. The preferred architecture is to keep inspectable physical transitions recoverable by observation, bind previous-release/backup provenance durably before the candidate switch, make every claimed terminal outcome truly durable before returning, and make non-inspectable mutating hook dispatches either idempotency-keyed/receipt-bound or fail closed to durable/manual ambiguity after an uncertain dispatch. Canonical provenance must explicitly account any selected source/tests; do not relax provenance to obtain green CI.

`USER_TELEGRAM_AUTH_NOT_YET_REQUIRED` remains authoritative.
