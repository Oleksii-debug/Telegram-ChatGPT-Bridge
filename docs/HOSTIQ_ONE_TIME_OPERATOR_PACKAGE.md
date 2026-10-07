# HOSTiQ one-time operator package

Status: **PREPARED, NOT EXECUTED**.

This package is for an authorized application developer/server operator who already has legitimate private access to the HOSTiQ account. It is not a recurring cPanel procedure for the account owner and it must not be used to overwrite the current application with legacy code.

Known production identifiers, not secrets:

- domain: `tg-api.rukadopomogy.org.ua`;
- application root: `/home/rukadopo/telegram_bridge`;
- Python: 3.11;
- WSGI startup file: `passenger_wsgi.py`;
- WSGI entry point: `application`.

## Required execution order

1. Record start time and operator identity/role without recording credentials.
2. Create a timestamped private server-side backup before any modification. The backup must stay outside GitHub/Drive/public web roots and must include enough state for rollback.
3. Inventory the current application code and runtime layout. Record a file manifest containing path, size and SHA-256 only. Do not publish secret files, session material, private Telegram data, environment values, runtime databases or private logs.
4. Privately identify the currently configured setup/auth gate corresponding to the previously exposed legacy setup reference. Disable, invalidate or rotate the old gate using a private server-side method. Never copy the old or replacement value into GitHub, Drive, chat, ticket text or CI logs.
5. Verify the obsolete gate is no longer usable. Record only non-secret evidence: completion time plus controlled denial/not-found/auth-failure result. Do not record the route/key value.
6. Produce a sanitized current-source snapshot or diff for audit. Exclude `.env*`, Telegram session files/strings, API hashes, 2FA values, bridge bearer/setup values, credentials/token files, private keys, runtime DBs, private logs, downloads/media and other user data.
7. Record current environment/deployment facts: Python executable/version, dependency manifest or `pip freeze` snapshot with no secrets, Passenger/WSGI configuration relevant to this app, and any known code/config changes that fixed the earlier HTTP 500 incident.
8. Do not deploy from GitHub yet. Return the sanitized source/diff and non-secret evidence to the Developer/Auditor workflow first. The recovered baseline must be scanned, reconciled and independently audited before any production deployment is authorized.

## Evidence to return — no secret values

- execution start/end timestamp;
- backup created: yes/no, with private location category only, not credentials or public URL;
- old setup gate remediated: yes/no;
- obsolete gate verification result: controlled denial/not-found/auth-failure, without the route/key;
- sanitized source snapshot/diff identifier and SHA-256;
- sanitized file-manifest identifier and SHA-256;
- Python version and WSGI/Passenger facts;
- dependency manifest identifier/hash;
- description of prior HTTP 500 repair if recoverable;
- production modified beyond gate remediation: yes/no;
- current deployed Git SHA if one genuinely exists; otherwise `UNKNOWN`.

If no authorized private server operator/access exists, stop and keep `BLOCKED_EXTERNAL`. Do not ask the account owner to paste secrets or perform recurring manual deployment work.
