# Operations package — audited deployment boundary

Nothing in this directory authorizes an unapproved production promotion.

## Single supported deploy-capable entrypoint

`ops/deploy_release.py` is the only supported module/CLI that can PREPARE or EXECUTE a release. The former `deploy_release_legacy.py` and `deployment_hardening.py` split is removed so there is no alternate legacy deployment path that can bypass current recovery/security controls. CI fails if another Python module under `ops/` defines `execute_prepared_release`.

## PREPARE

PREPARE verifies an exact approved Git-ref head, exports the tracked source, rejects runtime/private artifacts, creates the Python 3.11 virtual environment, installs application and test dependencies using hash-locked files when present, compiles and runs tests, records the exact external interpreter identity, and seals immutable release files/directories with no write bits. Mutable runtime/session/database paths remain outside the immutable release.

## EXECUTE transaction model

EXECUTE validates topology and the private control plane, then acquires a non-blocking POSIX `flock` on `DEPLOYMENT_TRANSACTION.lock`. The lock is held before incomplete-transaction reconciliation and through the entire mutable deployment transaction and terminal return. A process crash releases the kernel lock automatically. A concurrent contender fails closed instead of racing the active link, backups, hooks, journal, quarantine, or approval state.

The versioned private journal `DEPLOYMENT_TRANSACTION.json` is persisted before final materialization. Active states are:

`MATERIALIZING -> MATERIALIZED -> READY_TO_COMMIT -> APPROVAL_COMMITTED -> QUIESCED -> BACKED_UP -> SWITCHED -> VERIFIED -> DEPLOYED`.

Legal transitions are explicitly enumerated; skipped, backward and terminal-to-active transitions fail closed. Recovery-only terminal states include `PREAPPROVAL_ABORTED`, `PRELIVE_RECOVERED`, `ROLLED_BACK` and explicit critical ambiguity/failure states.

Journal provenance binds repository, approved ref, target SHA, previous SHA, prepared manifest hash, prepared payload hash, sorted runtime entries, runtime-manifest digest, approval identity and the derived consumed-marker identity. An incomplete transaction is reconciled before any fresh deployment starts. A consumed approval is never silently reused.

## Materialization and orphan handling

Because journal state exists before `.finalize_<sha>` creation/copy/binding/sealing/final rename, process loss around materialization is recoverable on the next invocation. Staging cleanup and final-release quarantine are permitted only under the exact journal identity. A pre-existing final SHA directory is not removed merely because its name matches: metadata, approved hashes, runtime bindings and persistent-state bindings must prove it is the journal candidate before controlled quarantine/recovery.

## Approval marker trust

Consumed approval markers live only in the private control root. Recovery validates canonical private location, regular-file/non-symlink status, owner, mode, parseable JSON, exact `approval_id`, and timestamp shape. Missing/corrupt/inconsistent markers in committed states fail closed without guessing deployment state.

## Immutable release boundary

All write bits are removed from immutable code, PREPARED_RELEASE metadata, `.venv` code/package metadata and directories. Declared persistent symlink bindings are the only mutable boundary. POSIX ownership is not treated as cryptographic immutability: the same account UID could chmod a file, so the exact approved payload and permission policy are revalidated immediately before the atomic active-link switch.

## Durability contract

The current guarantee is explicitly `process-loss-same-host-v1`: restart/reconciliation after process termination while the same filesystem remains intact. The tooling does **not** claim recovery from host/power/storage loss because HOSTiQ filesystem durability/fsync behavior has not been independently proven. Critical files still use atomic replacement where appropriate, but no stronger power-loss guarantee is advertised.

## Backup and rollback

Code/state backups are created as `.partial` archives and promoted only after successful archive creation; hash sidecars are written atomically. Partial artifacts are not valid last-known-good backups. After switch, restart, running-SHA verification, unauthenticated smoke, authenticated smoke and resume are mandatory. Failure after switch restores the exact previous release and reruns restart/identity/smoke/resume; failure of rollback is recorded as a critical terminal state.

## Stream B / HOSTiQ boundary

`recovery_capture.py`, `baseline_reconcile.py` and `runtime_evidence.py` remain non-secret recovery/evidence tools. Actual sanitized HOSTiQ application source/runtime/live deployment evidence must come through an authorized private boundary. No public repo file contains production credentials, Telegram sessions, message bodies or private runtime state.

There is intentionally no active `.cpanel.yml` and no repository-controlled auto-deploy enable marker. Production promotion remains blocked until independent Auditor approval of the exact release and legitimate private HOSTiQ execution evidence.
