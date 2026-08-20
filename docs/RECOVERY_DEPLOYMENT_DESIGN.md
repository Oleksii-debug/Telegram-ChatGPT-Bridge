# Telegram Bridge recovery and deployment design

Status: **PREPARED FOR INDEPENDENT AUDIT — NOT AUTHORIZED FOR PRODUCTION EXECUTION**.

This design separates three phases that must not be collapsed:

1. private baseline recovery;
2. independent reconciliation/audit;
3. later versioned deployment.

## Phase 1 — private baseline recovery only

`ops/recovery_capture.py`:

- creates a private timestamped full backup before any other recovery action;
- creates a deterministic candidate tree that excludes built-in private/runtime path classes;
- never installs cron, workers or recurring deployment infrastructure;
- never sends email or automatically transfers an archive;
- runs the hardened scanner against the candidate;
- writes a file manifest with path, size and SHA-256;
- blocks candidate export when hidden/unusual secret content, nested contaminated archives, unsafe symlinks or other scanner findings exist;
- creates a private sanitized candidate archive only after a clean scanner result;
- leaves all artifacts server-side for private operator/auditor handling.

This phase does not remediate the old setup gate by itself because the current production application/configuration is still unknown. The authorized operator must remediate that gate privately and record only non-secret proof.

## Phase 2 — audit/reconciliation gate

No application deployment occurs after capture. The recovered candidate must first be sanitized, reconciled against the Git recovery line and independently audited. The production SHA and exact prior HOSTiQ repair remain unknown until this evidence exists.

## Phase 3 — versioned deployment, only after independent PASS

`ops/deploy_release.py` is dry-run-only unless `--execute` is explicitly supplied by an authorized private operator. Even with `--execute`, it refuses deployment unless all required gates are present.

Key invariants:

- the live application path must already be an operator-prepared symlink to a complete release directory;
- one release directory contains both code and its `.venv`, so switching/rollback changes code+environment together;
- dependencies are installed only into a new versioned environment; the live environment is never mutated in place;
- `requirements.txt` without a hash-locked `requirements.lock` blocks release;
- compile and the application test suite are mandatory; missing tests or missing pytest blocks release;
- protected runtime/session/config paths are built into code and do not depend on a repository preserve list;
- any symlink ambiguity in source/live state fails closed;
- a private external approval file outside the Git repository must contain the exact approved commit SHA and approval ID;
- authenticated and unauthenticated smoke hooks must also live outside the repository and are required;
- smoke output is suppressed to prevent accidental secret leakage;
- failed post-switch smoke restores the previous complete release;
- failed rollback is recorded as `CRITICAL_ROLLBACK_FAILED` and returns a hard non-zero status;
- structured status JSON records state without secret values;
- retention preserves the active release, previous last-known-good release and newest artifacts, preventing both unbounded growth and deletion of the only rollback candidate.

## Important current block

No `.cpanel.yml` exists in this audited package. No cron is installed. No server modifications are authorized. The previous public `bootstrap/cpanel-api-automation` line is superseded/non-deployable and must not be executed.
