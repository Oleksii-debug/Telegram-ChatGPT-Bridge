# Telegram Bridge recovery and deployment design

Status: **PREPARED FOR INDEPENDENT AUDIT — NOT AUTHORIZED FOR PRODUCTION EXECUTION**.

The workflow has three strictly separated phases:

1. private production-baseline recovery;
2. independent reconciliation/audit;
3. later versioned deployment after PASS.

## 1. Recovery-only baseline capture

`ops/recovery_capture.py` is recovery-only. Before creating any output it validates path topology so the recovery root cannot equal, contain, or be contained by the live application root; optional repository/public roots are also kept disjoint. Symlink aliases fail closed.

The capture then:

- creates a private full backup first and writes its SHA-256 companion file;
- excludes built-in private/runtime/log/cookie/browser/session/database/key/config classes;
- uses a conservative positive source-file policy for the sanitized candidate; unknown non-source artifacts require private review rather than silently entering the candidate;
- runs the hardened scanner, including generic credential aliases and content-signature archive detection;
- writes path/size/SHA-256 manifest evidence;
- blocks candidate export on scanner findings, disguised/nested archives, unknown source artifacts, unsafe symlinks or other review-required conditions;
- creates a private candidate archive only after a clean gate;
- performs no email/automatic transfer, cron installation or deploy-worker installation.

The private full backup never becomes a public/Drive artifact.

## 2. Independent baseline reconciliation

After recovery capture, stop. The candidate must be sanitized, reconciled against Git and independently audited before application import or deployment. Old setup-gate remediation is also a private operator action and only non-secret completion evidence may return to Drive/GitHub.

## 3. Future versioned deployment

`ops/deploy_release.py` remains dry-run unless an authorized private operator explicitly uses `--execute`. Even then it fails closed unless all gates below are satisfied.

### Immutable release / shared mutable state boundary

- code plus `.venv` are versioned and immutable per release;
- mutable Telegram session, runtime, database, job/idempotency, upload/media/log/private-config state has one authoritative persistent root outside all release directories;
- releases reference approved persistent paths by symlink through a private runtime manifest outside Git;
- mutable state is never copied into a release and code rollback never restores an older copy of runtime state;
- the currently active release must already be bound to the same shared state before automated deployment is allowed;
- schema-changing deployment is blocked by the generic deployer and requires a separate independently audited quiesce/backup/migration/rollback plan.

### Path topology invariants

A central topology validator is used by recovery and deployment. Repository, releases, backups, persistent state and private control roots must be canonical, non-aliased and safely disjoint. The active symlink path must not sit inside those roots. Optional public/web roots cannot contain repository, releases, backups, state or private controls. Dangerous overlap fails before backup, copy, switch, retention or deletion.

### Python and dependency invariants

- release creation uses an explicitly configured executable and verifies Python 3.11 before creating the venv;
- the created venv is independently verified as Python 3.11 and non-secret version evidence is recorded;
- dependencies install only into the staged versioned environment;
- `requirements.txt` without hash-locked `requirements.lock` blocks deployment;
- lock installation uses `pip --require-hashes`;
- compile and application tests are mandatory; missing pytest/tests fail closed.

### Approval provenance

The private approval file lives under a private control root outside Git and is permission/owner/freshness checked. Approval binds all of:

- exact full commit SHA;
- repository identity;
- approved ref;
- deterministic release provenance/manifest SHA-256;
- CI run identity;
- independent audit identity;
- approval ID and one-time nonce;
- explicit declaration that no data-schema change is part of the generic deploy.

Approval is consumed once via an atomic private marker before any live switch. Reuse is rejected.

### Quiesce, restart and verification

Private executable hooks outside Git are mandatory for quiesce, Passenger/WSGI restart/reload, running-release identity, unauthenticated smoke and authenticated smoke. Hook output is suppressed and every hook has a timeout.

Deployment order after preflight/approval is:

1. quiesce writes;
2. back up current immutable release and shared persistent state;
3. atomically switch the active symlink;
4. restart/reload Passenger/WSGI;
5. verify the running release matches the expected non-secret full SHA;
6. run unauthenticated smoke;
7. run authenticated smoke.

No deployment reaches `DEPLOYED` before restart plus identity verification plus both smokes.

Rollback restores only the previous immutable code+.venv symlink. Shared mutable state remains authoritative and is deliberately not reverted, preventing post-switch writes from being silently lost. After rollback the previous release is restarted, its running SHA is verified, then both rollback smokes run. Failure produces hard `CRITICAL_ROLLBACK_FAILED` status.

### Retention

Release retention preserves active and last-known-good releases. Backup retention removes archive and `.sha256` companion as one unit. Stale `.stage_*` directories may be cleaned only after age checks and never when an `ACTIVE_LOCK` exists. Symlink artifacts fail closed.

## Current block

No active `.cpanel.yml` or Git-controlled auto-deploy arming marker exists in PR #2. No production execution is authorized. Current production source/diff, deployed SHA and live setup-gate remediation remain unverified, so `SECURITY_BLOCK`, `BLOCKED_EXTERNAL` and `DEPLOYMENT_BLOCK` remain.
