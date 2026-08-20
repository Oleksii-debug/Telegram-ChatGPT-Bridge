# Deployment transaction model — Telegram Bridge

Status: recovery/deployment guardrail documentation. This document does not authorize production promotion.

## Durable transaction states

A private server-side journal named `DEPLOYMENT_TRANSACTION.json` lives under the validated private control root. It contains only non-secret provenance, hashes, transaction state and timestamps. It never stores an approval nonce, Telegram credentials, bearer tokens, setup routes, private backup contents or Telegram data.

Normal state progression:

`READY_TO_COMMIT -> APPROVAL_COMMITTED -> QUIESCED -> BACKED_UP -> SWITCHED -> VERIFIED -> DEPLOYED`

The one-time approval marker is created at the approval commit boundary. A consumed approval is never silently reused.

## Restart reconciliation

Every EXECUTE invocation reconciles an incomplete journal before reading or materializing a new approval-bound release.

- Unconsumed `READY_TO_COMMIT` with the previous release still active is pre-approval work. The uncommitted candidate is quarantined and the transaction becomes terminal before a retry.
- A consumed approval with the previous release still active is treated conservatively as an interrupted pre-switch transaction. The previous service is restarted, its expected SHA is verified, unauthenticated/authenticated smoke checks run, the service is resumed, and the uncommitted candidate is quarantined. The transaction becomes `PRELIVE_RECOVERED`; the consumed approval may not be reused.
- A consumed approval with the candidate already active is treated as an interrupted post-switch transaction. The candidate's exact approved metadata/payload and persistent bindings are verified before restart/identity/smoke/resume. If this succeeds the transaction reaches `DEPLOYED`. If it fails, the active link is restored to the previous release, previous-service recovery is verified, and the candidate is quarantined.
- Impossible or ambiguous state/active-target combinations fail closed with a critical transaction state.

Quarantine is under the releases root in a hidden `.quarantine` directory. It removes the conflicting final SHA path without deleting persistent-state targets and prevents manual cPanel cleanup from becoming a normal requirement.

## Immutable release policy

New PREPARE output uses `immutable_permission_policy = no-write-bits-v1`.

After tests and dependency installation complete, all write bits are removed from immutable source and `.venv` paths. Mutable runtime state remains outside the release and is attached only through declared persistent bindings. Final materialization temporarily opens only copied staging directories long enough to attach those bindings, then reseals the immutable tree before atomic rename.

POSIX read-only mode is defense in depth, not a claim that the same owning HOSTiQ account UID is cryptographically incapable of changing its own files: an owner can normally chmod files it owns. To close the practical pre-switch mutation window, the exact approval-bound final metadata and immutable payload are recomputed after backups and immediately before the atomic active-link switch.

## Failure semantics

Catchable failures after approval commit but before active-link switch recover the previous service, quarantine the candidate and terminate as `PRELIVE_RECOVERED`. A fresh independently approved one-time retry can then proceed. Catchable failures after switch use the existing rollback lifecycle.

A hard process loss after approval marker creation is handled by the next invocation through the durable journal plus approval marker plus active-link identity. No consumed approval is silently reused.

## Audit evidence expected

CI must include:
- STARTED status-write failure recovery and fresh-approval retry;
- code-backup failure recovery and retry;
- persistent-state-backup failure recovery and retry;
- hard process loss immediately after real approval consumption followed by a second invocation;
- post-approval/pre-switch same-UID mutation detection;
- strict read-only prepared/final release checks;
- symmetric missing/tampered application and test lock failures;
- current-tree and full-history secret scans.

Production remains blocked until independent audit and the separate private HOSTiQ source/runtime/live lifecycle evidence requirements are satisfied.
