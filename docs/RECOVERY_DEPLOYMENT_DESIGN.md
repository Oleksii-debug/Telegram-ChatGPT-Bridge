# Telegram Bridge — recovery, release and live-deployment design

Status: **TWO-STREAM DEVELOPMENT / PREPARED FOR INDEPENDENT AUDIT / NO UNAPPROVED PRODUCTION PROMOTION**.

The project now advances in parallel:

- **Stream A — GitHub / application / code**: application source, security, tests, exact release payload, CI and approval evidence.
- **Stream B — HOSTiQ / live site**: recovered production baseline, Passenger/Python runtime evidence, controlled deployment, restart, smoke, resume and rollback.

The streams are synchronized by exact Git SHA and immutable prepared-release evidence. Green CI alone never authorizes production promotion.

## Current HOSTiQ evidence boundary

First-hand recovery evidence dated 2026-08-20 15:27 establishes that the production tree has been recovered, a private backup was created before recovery, and the previously exposed setup route was privately rotated/invalidated. The new route remains private and must never enter GitHub, Drive, chat, CI or documentation.

The recovered evidence also establishes that `passenger_wsgi.py` differs from the old controlled reference and currently uses the normal Passenger entry importing `bridge.app.application`; an empty `install_server.sh` is an additional server file. These HOSTiQ-specific facts must not be overwritten accidentally.

This repository still does **not** contain the complete sanitized recovered application tree. Exact per-file reconciliation therefore remains a server-side/audit task, not something to fabricate from the quarantined legacy ZIP.

## Recovery and baseline reconciliation

`ops/recovery_capture.py` remains recovery-only. It validates topology before output, makes a private full backup first, applies deterministic private/runtime exclusions plus a conservative source policy, runs the hardened scanner, writes path/size/SHA-256 evidence and never installs cron/deploy workers or transfers archives automatically.

`ops/baseline_reconcile.py` compares a sanitized recovered tree to an exact Git ref without recording raw file contents or secrets. It:

- refuses a recovered tree that fails the hardened scanner;
- exports the exact Git ref;
- compares SHA-256 manifests;
- records same/add/remove/change path sets and manifest hashes;
- explicitly signals a `passenger_wsgi.py` difference;
- emits only non-secret reconciliation evidence.

The private full backup remains on HOSTiQ only.

## Container and secret guard

`tools/secret_scan.py` performs current-tree and full-history scanning. Supported containers are probed by parsers before binary allowlisting, so legal prefixed/self-extracting ZIP files cannot fall through as ordinary binaries. ZIP/TAR ambiguity is treated as a polyglot and fails closed. Nested containers are recursively inspected within limits. ZIP Unix symlink/special metadata and TAR non-regular members fail closed. Reviewed binary allowlisting remains exact path + SHA-256 + reason and cannot override protected content.

## Exact audited source payload

Git-tracked application source is never silently dropped because a directory happens to be named `data`, `media`, `cache`, `uploads` or another runtime-like word. Legitimate source under those names remains byte-for-byte in the release payload.

A build fails instead when tracked material is itself a forbidden private/runtime artifact (for example `.env`, sessions, databases, logs, keys) or when a tracked path collides with a declared persistent runtime binding. The deployable source identity therefore corresponds to the audited Git commit rather than a silently filtered derivative.

## Deterministic PREPARE → AUDIT/APPROVAL → EXECUTE

`ops/deploy_release.py` now separates preparation from live execution.

### PREPARE

PREPARE:

1. verifies the requested full SHA is the exact head of the approved Git ref;
2. exports that exact commit;
3. validates exact source payload/runtime-binding compatibility;
4. validates the explicitly configured Python 3.11 executable;
5. creates a versioned `.venv` and independently verifies it is Python 3.11;
6. requires hash-locked dependencies when dependencies exist;
7. compiles and runs the mandatory application tests;
8. creates an exact payload manifest;
9. writes deterministic `PREPARED_RELEASE.json` with no runtime timestamp;
10. returns a stable SHA-256 for the immutable prepared manifest.

The prepared hash can therefore be independently audited and approved before execution.

### AUDIT / APPROVAL

The private approval lives outside Git and binds:

- exact full commit SHA;
- repository identity;
- exact approved ref;
- deterministic prepared-release manifest SHA-256;
- CI run identity;
- independent audit identity;
- approval ID and nonce;
- bounded issue/expiry time;
- explicit `data_schema_change=false` for generic deployment.

The approval is permission/owner checked and single-use.

### EXECUTE

EXECUTE does not rebuild the approval-bound artifact. Before live mutation it verifies:

- prepared manifest hash;
- exact current payload hash;
- repository/ref/SHA binding;
- exact approved-ref head policy again;
- unchanged runtime-binding declaration;
- private control-plane trust anchors.

Only then can the prepared payload be promoted into a versioned release.

## Shared mutable state

Versioned releases contain immutable application code + `.venv`. Telegram session/runtime/database/job/idempotency/private mutable state lives in one persistent private root outside releases. Releases bind only declared persistent entries. Code rollback never restores an older mutable-state copy, so post-switch writes remain authoritative.

Schema-changing releases are outside the generic deployer and require a separate audited migration/rollback plan.

## Private control-plane trust

The private control root and every deployment trust anchor are canonical/non-symlink, owned by the expected private account where UID checks are available, and not group/world accessible. Executable hooks must be owner-executable. The policy covers:

- runtime manifest;
- approval;
- approval-consumption directory;
- quiesce hook;
- resume/unquiesce hook;
- Passenger restart/reload hook;
- running-release identity hook;
- unauthenticated smoke hook;
- authenticated smoke hook;
- status file/directory.

Hook output is suppressed and all hooks have timeouts.

## Live lifecycle

Success path:

1. verify immutable prepared release + approval;
2. quiesce writes/jobs;
3. back up active immutable release and shared persistent state;
4. atomically switch complete release;
5. restart/reload Passenger/WSGI;
6. verify running full SHA;
7. unauthenticated smoke;
8. authenticated smoke;
9. mandatory resume/unquiesce;
10. only then write `DEPLOYED`.

Rollback path:

1. restore prior immutable release;
2. restart/reload;
3. verify prior running SHA;
4. run rollback unauthenticated/authenticated smoke;
5. mandatory rollback resume/unquiesce;
6. only then write `ROLLED_BACK`.

If failure occurs after quiesce but before a live switch, pre-live recovery also requires restart/identity/smokes and mandatory resume before `PRELIVE_FAILED`. Resume/restart/identity failure becomes a hard critical state rather than a false success.

## Runtime evidence

`ops/runtime_evidence.py` is a read-only, non-secret probe intended to run from the actual application/Passenger runtime context. It records only Python version/implementation, resolved executable and prefixes, venv-active flag, WSGI relative path/hash and application import identity. It explicitly records that no environment values, request data or secret values are collected.

`/usr/bin/python3` reporting 3.6.8 is not accepted as Passenger runtime evidence. Production promotion requires separate evidence from the actual Python App/Passenger context proving the intended Python 3.11 runtime.

## Retention and topology

Repository, releases, backups, shared state, private controls and optional public root must be canonical and safely disjoint. Active-link topology is validated before mutation. Backup archive/hash companions are retained/deleted together. Active and last-known-good releases are preserved. Stale stage directories are removed only after age checks and never while `ACTIVE_LOCK` exists.

## Current production gate

There is no active `.cpanel.yml` or Git-controlled auto-deploy arming marker in PR #2. The historical deployment branch remains superseded/non-deployable.

The old setup-route remediation and production-baseline recovery are no longer treated as unknown; they are recorded in newer first-hand server evidence and require independent Auditor validation. Remaining production gates include exact sanitized baseline reconciliation, actual Passenger/Python runtime evidence, application acceptance, audited prepared release, private deploy controls and live restart/smoke/resume/rollback proof.
