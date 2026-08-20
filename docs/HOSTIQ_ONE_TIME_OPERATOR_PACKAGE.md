# HOSTiQ one-time operator / integration package

Status: **RECOVERY EVIDENCE EXISTS; FUTURE DEPLOYMENT PREPARED IN CODE; NO UNAPPROVED PROMOTION**.

This package is for an authorized private application/server operator or an equivalent automated private integration. It is not a recurring cPanel procedure for the account owner.

Known non-secret identifiers:
- domain: `tg-api.rukadopomogy.org.ua`;
- production application root: `/home/rukadopo/telegram_bridge`;
- intended application runtime: Python 3.11;
- WSGI startup file: `passenger_wsgi.py`;
- WSGI application target: `bridge.app.application`.

## Recovery status already evidenced

A first-hand server recovery round on 2026-08-20 established, without publishing credentials, that:
- the production tree was recovered for baseline reconstruction;
- a full private backup was created before recovery and remains only on HOSTiQ;
- the previously exposed setup route was privately rotated and the obsolete route invalidated;
- the replacement route was not exported;
- the production setup flow renders through the current private route;
- Telegram authorization remains intentionally incomplete;
- command cron jobs and temporary recovery jobs were both zero at verification time;
- `passenger_wsgi.py` is the known HOSTiQ-specific changed startup file relative to the old controlled reference;
- an empty `install_server.sh` is an additional server file.

Do not repeat the old recovery request and do not copy the private backup or any setup route value into GitHub/Drive/chat.

## Remaining baseline reconciliation

The complete sanitized recovered raw tree is not currently present in public GitHub/normal Drive handoff. When it is available inside the private server integration, run `ops/baseline_reconcile.py` there against the exact approved Git ref. It produces only path/hash/count evidence, blocks secret-like recovered content, and explicitly signals startup-file differences.

Do not reconstruct a release by overwriting the server with the quarantined legacy ZIP. The HOSTiQ-specific `passenger_wsgi.py` behavior must be preserved until exact reconciliation is independently audited.

## Actual Passenger/Python runtime evidence

Do not treat `/usr/bin/python3` as proof of the Python App/Passenger runtime. The shell interpreter has been observed as Python 3.6.8, while the intended application runtime is Python 3.11.

Use the read-only `ops/runtime_evidence.py` from the actual application/Passenger runtime context. Return only its non-secret evidence: Python version/implementation, resolved executable/prefixes, venv-active flag, WSGI hash/relative path and application import identity. Never return environment values, Telegram credentials, session values or request data.

Production promotion remains blocked if the actual Passenger runtime is not independently shown to be the approved Python 3.11 environment.

## Future private deployment protocol

The repository deployment protocol is now deterministic:

1. **PREPARE** the exact approved Git-ref head using the approved Python 3.11 executable.
2. Build a versioned `.venv`, install only hash-locked dependencies, compile and run mandatory tests.
3. Produce the exact deployable payload plus deterministic `PREPARED_RELEASE.json`; no runtime timestamp is included in the approval-bound hash.
4. Return the prepared manifest hash, exact SHA and CI evidence for independent audit.
5. **AUDIT/APPROVE** that exact immutable prepared artifact outside Git. The approval is short-lived, owner/mode restricted, single-use and binds SHA/repository/ref/prepared hash/CI/audit identity.
6. **EXECUTE** verifies the same prepared artifact byte-for-byte and re-verifies that the SHA is still the exact head of the approved ref. It does not rebuild an approval-bound release.
7. Quiesce writes/jobs.
8. Back up active immutable code and shared persistent state privately.
9. Atomically switch the complete release.
10. Restart/reload Passenger/WSGI.
11. Verify the running full SHA.
12. Run unauthenticated smoke.
13. Run authenticated smoke.
14. Run mandatory resume/unquiesce.
15. Only then record `DEPLOYED`.

On failure after switch:
- restore previous immutable release;
- restart/reload;
- verify previous SHA;
- run both rollback smokes;
- run mandatory rollback resume/unquiesce;
- only then record `ROLLED_BACK`.

If failure occurs after quiesce but before switch, pre-live recovery also requires restart/identity/smokes plus resume before a non-critical failed state may be recorded. Resume/restart/identity failure is critical.

## Private control root

All deployment controls live outside Git and are canonical/non-symlink, owned by the expected private account where UID checks are supported, and inaccessible to group/world users. This includes runtime manifest, approval, consumption directory, quiesce/resume/restart/identity/smoke hooks and status path. Hook output is suppressed.

## Shared mutable state

Versioned releases contain immutable code + `.venv`. Mutable Telegram session/runtime/database/job/idempotency/private state lives in one shared private root outside releases and is bound only through an approved private runtime manifest. Code rollback does not roll mutable state backward. Schema/data migrations require a separate audited plan.

## Evidence returned to Auditor — never secret values

- recovered-baseline reconciliation manifest/hash and path-level diff;
- exact preserved HOSTiQ startup difference;
- actual Passenger Python executable/version/venv evidence;
- exact prepared Git SHA/ref and deterministic prepared manifest hash;
- CI run + independent audit identity;
- backup-created yes/no and non-secret integrity metadata;
- restart/running-SHA/smoke/resume result;
- rollback verification result if exercised;
- deployed SHA only after it is genuinely proven live.

The normal post-bootstrap user workflow remains Developer → GitHub/Drive → Auditor → approved release → automated private HOSTiQ deployment → live verification. The user must not be required to paste commands, edit server files or perform routine cPanel deployment.
