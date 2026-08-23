# DEV08 deployment recovery round 3

Status: isolated reliability/concurrency candidate. No merge, deployment, Passenger restart, Telegram authorization, live Telegram operation, or K5 is authorized by this document.

## Exact anchor

DEV08 round 3 was cut from canonical `work3/integration-release-candidate` exact green head `00684e834a523f55ea3b61c1a12cb9dc54cfd947`. Recovery Guard #377 / run `32642219973` was SUCCESS on that canonical head before this overlay was created.

The older DEV08 PR #44 is preserved as round-1/round-2 evidence and is intentionally not rebased by merging peer branches after it became conflicting with the moving canonical base. DEV01 remains the only canonical semantic integration owner.

## R3-1 — atomic switch committed but SWITCHED journal write lost

Canonical deployment order around the live boundary is:

1. persistent-state and code backups complete;
2. journal is durably `BACKED_UP`;
3. candidate is reverified;
4. `atomic_switch_link(active_link, final)` moves the local active symlink to the exact candidate;
5. journal transitions to `SWITCHED`;
6. restart, running-SHA verification, unauthenticated smoke, authenticated smoke and resume run.

A process can terminate after step 4 and before step 5. The durable facts then are:

- journal state: `BACKED_UP`;
- committed approval marker exists;
- active symlink resolves to the candidate release;
- previous release is still locally available;
- the final candidate can be independently reverified from its immutable metadata/payload and persistent bindings.

Current `_reconcile_incomplete_transaction()` treats every `BACKED_UP` state as pre-switch. It has no branch for `BACKED_UP + active==candidate`. Because active is not the previous release and the state is not yet `SWITCHED`/`VERIFIED`, recovery falls through to `CRITICAL_TRANSACTION_AMBIGUOUS` with `active_target_mismatch`.

This is unnecessarily ambiguous. Unlike an uncertain remote Telegram write, the atomic symlink switch is a local inspectable effect. `BACKED_UP` is also the only legal journal state immediately preceding the switch in the canonical transition order.

## Proposed narrow integration rule

DEV08 does not mutate `ops/deploy_release.py` in this specialist PR. `ops/dev08_deploy_recovery.py` provides a pure classifier for DEV01/DEV02 review.

A lost SWITCHED journal write may be classified as `RECOVER_AS_SWITCHED` only when all are true:

- journal is exactly `BACKED_UP`;
- active resolves exactly to the journal candidate;
- committed approval marker validates;
- runtime manifest still matches the journal digest;
- candidate passes exact canonical reverification;
- previous release remains available for the normal rollback path.

The caller should then persist/reconcile the logical `SWITCHED` state and run the existing canonical post-switch recovery sequence. Any failed restart/identity/smoke/resume must still use the existing rollback path. Candidate reverification failure is `ROLLBACK_REQUIRED`, not success. Missing marker, runtime drift, missing previous release, an unrelated active target, or candidate-active under any earlier pre-switch state remains fail-closed/ambiguous.

This rule does not make deployment more permissive; it removes an avoidable manual ambiguity only when the local filesystem proves the atomic switch occurred at the one legal boundary where the journal write could be lost.

## Fault matrix

`tests/test_dev08_deploy_recovery.py` contains credential-free local fault injection:

- exact current-defect oracle: real canonical `atomic_switch_link` executes, then synthetic process loss occurs before `SWITCHED`; journal remains `BACKED_UP`, active is candidate, and current canonical restart escalates to `CRITICAL_TRANSACTION_AMBIGUOUS`;
- process loss after approval marker creation but before `APPROVAL_COMMITTED` journal transition: current canonical recovery safely restores/unquiesces previous release and reaches `PRELIVE_RECOVERED`;
- process loss after successful quiesce but before `QUIESCED` journal transition: current canonical recovery safely reaches `PRELIVE_RECOVERED`;
- strict positive classifier for only `BACKED_UP + candidate` with all proofs;
- negative matrices for missing approval marker, runtime-manifest drift, candidate reverification failure, missing previous release, unrelated active target, candidate-active before the backup boundary, terminal-state reopening, and malformed/non-boolean evidence;
- preservation of existing `SWITCHED`/`VERIFIED` candidate-resume and previous-release rollback semantics.

The positive surrounding-boundary tests are important: they demonstrate that this is one precise missing transaction edge rather than a claim that the whole deployment journal is broken.

## Integration ownership

- DEV02 owns HOSTiQ/runtime/deployment business implementation.
- DEV01 owns canonical semantic integration/provenance.
- DEV08 owns the cross-boundary crash/recovery oracle and deterministic classification contract.
- Auditor must independently verify any canonical implementation before production authorization.

After canonical integration, rerun this exact seam against the integrated SHA and require full canonical provenance, regression, both secret scans and real non-live PREPARE. Live deployment remains separately gated.

`USER_TELEGRAM_AUTH_NOT_YET_REQUIRED` remains authoritative.
