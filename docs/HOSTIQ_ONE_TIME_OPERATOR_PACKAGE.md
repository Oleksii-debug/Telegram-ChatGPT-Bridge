# HOSTiQ one-time operator package

Status: **PREPARED, NOT EXECUTED**.

This package is for an authorized application developer/server operator who already has legitimate private HOSTiQ access. It is not a recurring cPanel procedure for the account owner. It must not be used to overwrite production with legacy or unreconciled code.

Known non-secret production identifiers:

- domain: `tg-api.rukadopomogy.org.ua`;
- current known application root: `/home/rukadopo/telegram_bridge`;
- Python: 3.11;
- WSGI startup file: `passenger_wsgi.py`;
- WSGI entry point: `application`.

## Required order

1. Record operator/start time without recording credentials.
2. Run the recovery-only capture path first. It must create the private full backup before any modification. It must not install cron, deployment workers or send mail.
3. Privately identify and disable/rotate/invalidate the old setup/auth gate associated with the previously exposed legacy reference. Never copy old or replacement values into GitHub, Drive, chat, ticket text or logs.
4. Verify the obsolete gate now produces controlled denial/not-found/auth failure. Record only the completion time and non-secret result.
5. Keep the captured candidate and private full backup server-side. Do not upload the private full backup anywhere.
6. Confirm the candidate scanner is clean and its manifest/hash are present. If contaminated, stop and retain only private evidence.
7. Return only sanitized/non-secret recovery evidence to the Developer/Auditor workflow.
8. Stop. Do not deploy application code until the recovered baseline is reconciled and independently audited.
9. After independent deployment PASS only, prepare the one-time symlink release layout required by `ops/deploy_release.py`, with the active path pointing to a complete release directory that contains both code and `.venv`.
10. Place the exact-SHA approval file and authenticated/unauthenticated smoke hooks outside the Git repository. They may contain private server-side logic but must not print credentials or message contents.
11. Execute the versioned deployer only for the independently approved full SHA. A failed preflight must not change live state; failed post-switch smoke must restore the prior complete release.

## Evidence to return — never secret values

- execution start/end timestamp;
- private backup created: yes/no and private location category only;
- old setup gate remediated: yes/no;
- obsolete gate verification result without route/key;
- sanitized candidate manifest identifier and SHA-256;
- sanitized candidate archive identifier and SHA-256 if scanner clean;
- Python/Passenger/WSGI facts;
- dependency manifest/hash information;
- exact prior HTTP 500 repair description if recoverable;
- production modified beyond gate remediation: yes/no;
- deployed Git SHA if genuinely mapped, otherwise `UNKNOWN`.

If no authorized private server operator/access exists, stop and keep `BLOCKED_EXTERNAL`. Do not ask the account owner to paste secrets or perform recurring manual deployment work.
