# FINALWAVE-52 deployment crash/fault-injection audit

Status: isolated, non-authorizing specialist evidence. No merge, production deploy, Passenger restart, Telegram authorization, live Telegram operation, K5, or credential collection is authorized by this document or branch.

## Exact source identities

- Canonical base at branch creation: PR #9 `work3/integration-release-candidate` @ `84691967e5363bc4b88dfae97371d7bf329c105d`.
- Current role01 audit snapshot: PR #66 `finalwave26/01-a01-11-deploy-recovery` @ `cf2e56a0ed8cd1321a7c989232ad11b559d0062c`.
- FINALWAVE-52 branch: `finalwave26/52-deploy-crash-fuzz`.

The dedicated workflow checks out role01 by immutable SHA and copies only the independent fuzz oracles into that detached tree. It does not merge or rewrite role01.

## Accepted / superseded role01 work

Role01 genuinely fixes the canonical Recovery Guard #529 invalid-runtime-manifest terminalization defect. It also handles valid-but-changed runtime manifests, missing runtime/control-plane files during an active transaction, persists file + parent-directory fsync for journal transitions, and propagates critical terminal write failures.

An earlier FINALWAVE-52 finding against role01 head `c4a4f2f050cdab8937db97091844884bd1fb8f3f` identified a fixed `DEPLOYMENT_TRANSACTION.json.tmp` + `O_EXCL` crash-stranding bug. That finding is **SUPERSEDED/CLOSED on role01 head `cf2e56a0...`**: role01 now uses unique temp names. The FINALWAVE-52 oracle contains a positive stale-sibling control instead of continuing to report the old defect.

## Residual HIGH findings on role01 `cf2e56a0...`

### FW52-H2 — candidate restart dispatch is replayed after process loss

The durable journal is `SWITCHED` before the Passenger restart hook is dispatched. If restart completes and the process dies before running-SHA evidence, recovery from the same `SWITCHED + active==candidate` snapshot dispatches restart again. The oracle proves two restart dispatches for one transaction.

Required repair: add an explicit durable restart-dispatch ambiguity boundary or a separately proven idempotent/exactly-once restart receipt. If completion cannot be distinguished, fail closed rather than blindly issuing a second physical restart.

### FW52-H3 — rollback restart dispatch is likewise replayed

After a post-switch verification failure, code restores the previous symlink and dispatches rollback restart while the journal still represents the switched transaction. If rollback restart completes and the process dies before later evidence/terminalization, recovery observes `active==previous` and dispatches another rollback restart.

Required repair: model rollback switch and rollback restart dispatch as explicit durable phases, or use an audited idempotency/receipt contract. The symlink restore is inspectable; restart completion is not.

### FW52-H4 — durable VERIFIED recovery replays already-completed restart and resume

`VERIFIED` is written only after candidate restart, running-SHA verification, unauthenticated smoke, authenticated smoke, and resume/unquiesce all complete. Recovery nevertheless groups `VERIFIED` with `SWITCHED` and dispatches restart and resume again before `DEPLOYED`. Here there is no dispatch ambiguity: the durable state already proves those mutations completed.

Required repair: split `VERIFIED` recovery from `SWITCHED`. `VERIFIED` may re-run read-only identity/health/security checks, but must not replay mutating restart/resume hooks without an explicit idempotency contract.

### FW52-H5 — pre-live recovery lifecycle has no durable progress boundary

When a committed pre-switch transaction fails after quiesce, recovery restarts/resumes the previous release and only then writes `PRELIVE_RECOVERED`. If process loss occurs after recovery restart but before terminalization, the original active state remains and the next recovery dispatches restart again. The same structural gap can replay resume/unquiesce.

Required repair: make pre-live recovery lifecycle progress durable or receipt-bound. An uncertain post-dispatch state must converge to safe manual ambiguity rather than blind repeated mutation.

### FW52-H6 — SWITCHED/VERIFIED may become DEPLOYED with no previous release available

For a candidate-active `SWITCHED`/`VERIFIED` recovery, role01 checks previous-release availability only if candidate verification fails and rollback is needed. If the previous release has disappeared but the candidate is currently healthy, recovery can still terminalize `DEPLOYED`, leaving no verified automatic last-known-good rollback target.

Required repair: successful post-switch terminalization must require a transaction-bound, independently validated rollback target or verified backup restoration path.

### FW52-H7 — rollback accepts a tampered previous release without provenance validation

The journal binds `previous_sha`, but rollback resolves the directory with that SHA-shaped name without validating its code bytes against a captured previous-release manifest or transaction-bound predeploy backup. The oracle modifies previous-release code while preserving the directory name; candidate verification then fails, rollback switches to the modified tree, hook-based running identity succeeds, and the transaction reaches `ROLLED_BACK`.

Required repair: durably bind previous-release payload provenance and exact backup path/hash before candidate switch. Verify previous payload/topology before rollback, or restore and verify from that bound backup. A SHA-shaped directory name is not sufficient provenance.

### FW52-H8 — rc20/rc10 may be returned without durable terminal journal state

Role01 propagates persistence failures only for `CRITICAL_*` terminal states. If `ROLLED_BACK` persistence fails after physical rollback succeeds, `_best_effort_transaction` returns an in-memory fallback and execute still returns rc20 while the on-disk journal remains `SWITCHED`. Likewise failed `PRELIVE_RECOVERED` persistence can still return rc10 with durable state left at `QUIESCED`.

Required repair: no success-like recovery code may be returned unless its corresponding terminal transaction state is durably persisted and re-readable. On terminal-write failure, persist a legal critical/manual-ambiguity state if possible; otherwise return/raise a critical persistence failure.

## Boundary matrix conclusion

- approval consumption: committed marker is inspectable and duplicate consumption is blocked;
- lock: process loss releases flock; contention is covered;
- runtime/control-plane tamper: current role01 terminalizes active transactions before further deployment mutation;
- materialize/final candidate: existing provenance and recovery are materially strong;
- backup: backup failures recover pre-live, but exact backup path/hash is not journal-bound for later authenticated rollback provenance;
- candidate symlink switch: active target makes switch completion inspectable, avoiding a second candidate switch;
- rollback symlink restore: active target makes the physical link restoration inspectable, but previous-content authenticity is not proved;
- running identity / unauth / auth smoke: read-only evidence may safely be repeated;
- restart/reload and resume/unquiesce: mutating external effects lack durable receipt/idempotency boundaries and are replayed;
- terminal journal: critical terminal write failures propagate, but ordinary recovery terminal writes may still be non-durable while rc20/rc10 is emitted.

The durability claim remains narrow: process loss on the same POSIX host/filesystem. No host/power-loss durability claim is made.

## Integration recommendation

Do not integrate PR #66 as complete durable-boundary closure yet. Preserve its accepted runtime/control-plane terminalization, unique-temp writer and fsync work. Address FW52-H2 through FW52-H8, then invert the FINALWAVE-52 reproducer cases into positive safe-contract regressions. Bind previous-release/backup provenance durably before candidate switch; make every claimed terminal result durable before returning; and make non-inspectable mutating hooks either idempotency-keyed/receipt-bound or fail closed after uncertain dispatch. Canonical provenance must explicitly account any selected source/tests; do not relax provenance to obtain green CI.

`USER_TELEGRAM_AUTH_NOT_YET_REQUIRED` remains authoritative.
