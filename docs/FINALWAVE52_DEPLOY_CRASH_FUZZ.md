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

## Boundary matrix conclusion

The locally inspectable/durable boundaries are materially stronger than the uninspectable hook boundaries:

- approval consumption: committed marker is externally inspectable and duplicate consumption is blocked;
- materialize/final release: candidate tree and journal provenance are inspectable;
- backup: recovery does not re-run backup when journal remains `QUIESCED`/`BACKED_UP`;
- candidate symlink switch: `active` target makes switch completion inspectable; no second candidate switch is needed;
- rollback symlink restore: `active==previous` makes physical link restoration inspectable; recovery need not restore the link a second time;
- running identity, unauth smoke, auth smoke: read-only evidence may safely be repeated;
- restart/reload and resume/unquiesce: external mutations have no durable receipt/idempotency boundary and are replayed in several recovery paths.

The existing A01-11 candidate symlink switch crash seam is substantially repaired: `BACKED_UP + active==candidate` is locally observable and recovered without a second candidate switch after marker/runtime/candidate/previous-release validation. Existing tests also cover missing/tampered committed markers, missing previous release, candidate tamper rollback, lock contention, state-boundary process loss, and repeated terminal recovery.

The durability claim remains narrow: process loss on the same POSIX host/filesystem. No full host/power-loss durability claim is made here.

## Integration recommendation

Do not integrate PR #66 as complete durable-boundary closure yet. Preserve its valid runtime-manifest terminalization and fsync work, then address FW52-H1 through FW52-H5 and convert the FINALWAVE-52 falsification scenarios into positive safe-contract regressions. The preferred architecture is to keep inspectable physical transitions recoverable by observation while making non-inspectable mutating hook dispatches either idempotency-keyed/receipt-bound or fail closed to durable/manual ambiguity after an uncertain dispatch. Canonical provenance must explicitly account any selected source/tests; do not relax provenance to obtain green CI.

`USER_TELEGRAM_AUTH_NOT_YET_REQUIRED` remains authoritative.
