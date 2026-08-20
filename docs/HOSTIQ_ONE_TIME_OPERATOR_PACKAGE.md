# HOSTiQ one-time operator package

Status: **PREPARED, NOT EXECUTED**.

This package is for an authorized application developer/server operator who already has legitimate private HOSTiQ access. It is not a recurring cPanel procedure for the account owner and must not overwrite production with legacy or unreconciled code.

Known non-secret identifiers:

- domain: `tg-api.rukadopomogy.org.ua`;
- current known application root: `/home/rukadopo/telegram_bridge`;
- approved runtime family: Python 3.11;
- WSGI startup file: `passenger_wsgi.py`;
- WSGI entry point: `application`.

## Recovery-only order

1. Record operator/start time without credentials.
2. Choose canonical private recovery, repository and control roots outside the live app and public web roots. Validate topology before creating artifacts.
3. Run recovery-only capture. Private full backup must be created first. No mail, cron, deployment worker or public transfer is permitted.
4. Privately identify and disable/rotate/invalidate the old setup/auth gate associated with the quarantined legacy reference. Never copy old or replacement values to GitHub, Drive, chat, tickets or logs.
5. Verify the obsolete gate produces controlled denial/not-found/auth failure and record only non-secret result/time.
6. Keep the private full backup and candidate server-side. If scanner/source-policy findings exist, stop for private review.
7. Return only sanitized candidate manifest/hash and other non-secret evidence to Developer/Auditor.
8. Stop before application deployment until the recovered baseline is reconciled and independently audited.

## One-time migration to the future release layout

Only after independent approval of the recovered production baseline:

1. quiesce application writes through a private hook;
2. create a private backup of mutable/session/database/runtime state;
3. create one persistent private state root outside releases, repository, backups, public web roots and Git;
4. migrate approved mutable state to that root exactly once under an audited migration plan;
5. create a private runtime manifest listing only approved protected relative mount points;
6. make the current versioned release reference the persistent state root rather than owning copies;
7. verify current release behavior and restart Passenger/WSGI before enabling later automated versioned deployment.

The generic deployer refuses a schema-changing release. Any data/schema migration needs a separate audited migration and rollback design.

## Future deployment controls after independent PASS

The private control root must contain non-repository approval/runtime-manifest/quiesce/restart/running-identity/auth-smoke/unauth-smoke controls. They must not print secrets or private Telegram content.

The approval must be short-lived, permission-restricted and bind the exact SHA, repository/ref, release provenance hash, CI run and audit identity. It is single-use.

The deployer must:

- use the explicitly approved Python 3.11 executable;
- stage code and a new `.venv` without mutating the live environment;
- require hash-locked dependencies and mandatory tests;
- verify the active release already uses the shared persistent state;
- quiesce writes and back up both current code release and persistent state before switch;
- switch the complete code+.venv release atomically;
- restart Passenger/WSGI, verify the running full SHA, then run unauthenticated and authenticated smoke;
- on failure, restore the prior code+.venv symlink, restart it, verify its SHA and rerun rollback smoke;
- never roll shared mutable state back merely because code rolled back;
- expose hard failure status if restart/rollback verification fails.

## Evidence to return — never secret values

- execution start/end timestamp;
- private backup created: yes/no and private location category only;
- old setup gate remediated: yes/no;
- obsolete gate controlled-rejection result without route/key;
- sanitized candidate manifest/archive identifiers and SHA-256 when clean;
- Python/Passenger/WSGI facts;
- dependency manifest/hash information;
- exact prior HTTP 500 repair description if recoverable;
- persistent-state migration completed: yes/no, without private paths/values beyond approved non-secret category labels;
- production modified beyond authorized recovery/migration step: yes/no;
- deployed Git SHA if genuinely mapped, otherwise `UNKNOWN`.

If no authorized private server operator/access exists, stop and keep `BLOCKED_EXTERNAL`. Do not ask the account owner to paste secrets or perform recurring manual deployment work.
