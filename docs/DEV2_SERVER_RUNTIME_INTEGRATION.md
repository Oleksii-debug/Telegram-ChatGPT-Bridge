# DEV2 server/runtime integration controls

This lane prepares auditable Stream-B evidence and lifecycle tooling without arming public-Git deployment or modifying production.

## Baseline reconciliation

`ops/baseline_reconcile.py` now supports strict non-secret server/candidate manifests in addition to the prior sanitized-directory-vs-Git API. Manifest paths must be canonical NFC POSIX paths, unique under exact/case semantics, SHA-256 exact, size bounded and assigned to reviewed non-secret categories. Private/runtime paths and known private file types fail closed.

The output contains only path/hash/count/category differences, category counts and startup-file match state. Raw source/private content is not copied into the reconciliation result.

## Reference snapshot validation

`ops/snapshot_candidate.py` validates a sanitized ZIP before any candidate extraction: member topology, canonical path, duplicate/case/Unicode collision, special members, size limits, strict external manifest, per-file hashes, expected Passenger import semantics and empty `install_server.sh`. When run inside the repository it also requires the repository secret scanner. A candidate carries an explicit `REFERENCE_ONLY_NOT_DEPLOY_AUTHORITY` marker.

## Passenger/Python evidence boundary

`ops/runtime_evidence.py` schema v2 records a bounded runtime report: Python version/implementation, interpreter file SHA-256/owner/mode/link count, hashed prefix identities, virtual-environment state, WSGI relative path/hash, fixed import target, import success, reviewed dependency versions/metadata hashes and privacy flags.

Important: a normal CLI invocation is only `PYTHON_3_11_CANDIDATE_CONTEXT`, even if it runs on Python 3.11. It can never by itself prove the cPanel/Passenger Python App interpreter. Strong `PYTHON_3_11_APPLICATION_CONTEXT_CONFIRMED` requires all of: Python 3.11, collection from application-process mode, a Passenger context signal and successful import of `bridge.app.application`. That strong state still becomes factual production evidence only when independently run/attested on HOSTiQ.

The known `/usr/bin/python3` 3.6.8 shell observation therefore cannot be misreported as Passenger evidence.

`tools/collect_runtime_evidence.py` writes a private 0600 report under an owner-only 0700 private directory and prints only a stable result code. It accepts no credentials as CLI arguments and never dumps environment values.

## Private evidence ingestion

`ops/private_evidence.py` validates future runtime/server-manifest artifacts with exact schemas, list/depth/size limits, secret-pattern rejection and a canonical tamper hash. Public output is reduced to artifact hash, count/status/compliance booleans; server paths and arbitrary private text are not copied into the public summary.

## Lifecycle hooks

`ops/hostiq_lifecycle.py` is intentionally not auto-armed. Restart/rollback executable hooks, token references and running-SHA references must live under an owner-only private control root. Root/path components reject symlinks, broad permissions, wrong owner, hardlinks and unsafe topology.

Prepared checks:

1. private restart/rollback hook execution with timeout and suppressed stdout/stderr;
2. HTTPS-only production-host endpoint validation;
3. health check requiring HTTP 200 **and** a controlled JSON healthy shape;
4. unauthenticated smoke requiring rejection and scanning only for leak signatures without returning body text;
5. authenticated smoke reading bearer material from a private file at execution time and never returning it;
6. running identity check against exact expected Git SHA;
7. serving/resume state composition;
8. automatic rollback contract on restart/identity/health/unauth/auth failure;
9. critical status if rollback or rollback-health fails.

None of these hooks modifies production merely by existing in Git. No `.cpanel.yml`, cron, public auto-deploy arming file or server credential is added.

## One-time HOSTiQ bootstrap design

After Auditor approves an exact release and HOSTiQ provides the missing first-hand runtime evidence, the server-side bootstrap should create an owner-only private control root outside the Git checkout. HOSTiQ may place restart/rollback hooks and private bearer/running-SHA references there with owner-only permissions. The existing audited deploy transaction remains the only deploy-capable entrypoint; public Git may not directly arm it.

The deployment lifecycle remains: exact approved SHA/artifact → private backup → stage/verify → dependencies in actual Python 3.11 application environment → Passenger restart → running identity → health → unauthenticated smoke → authenticated smoke → resume/serving check → rollback on any failure → rollback-health verification.

The user is not a recurring cPanel operator.

## Remaining live blockers

This tooling does not fabricate the still-missing facts: exact 42-file live manifest/category accounting, actual Passenger Python 3.11 application-context report, exact deployed audited SHA, live restart/smoke/resume/rollback evidence and Telegram/OpenAPI/ChatGPT E2E.
