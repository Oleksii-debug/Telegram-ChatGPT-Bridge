# DEV_B — one-time HOSTiQ server-side evidence/bootstrap package

Purpose: give HOSTiQ/support one bounded, non-secret server-side procedure that can establish the remaining factual runtime/source/lifecycle evidence without making the user a recurring cPanel operator.

Status: PREPARED ONLY. Do not execute until an Independent Auditor approves an exact candidate SHA and DEV_A has integrated the required startup/dependency envelope. This package never asks for or returns credentials/session/setup-route values.

## Preconditions

Support must receive from the Auditor/release owner only these non-secret identifiers:

- approved Git candidate SHA-40;
- approved repository/ref;
- approved application root `/home/rukadopo/telegram_bridge`;
- production host `tg-api.rukadopomogy.org.ua`.

Do not paste or return Telegram API values, session material, bearer values, private setup route, cPanel password, OAuth material, private logs, Telegram message/media content or environment dumps.

Before any production mutation, verify a recoverable private backup. The accepted recovery backup already exists, but a real promotion attempt still requires a fresh transaction-bound backup under the audited deployment workflow.

## A. Private control/evidence roots — one-time server setup

Run as the application account, not root unless HOSTiQ's managed runtime explicitly requires otherwise:

```sh
umask 077
install -d -m 700 "$HOME/.telegram_bridge_private_control"
install -d -m 700 "$HOME/.telegram_bridge_private_evidence"
```

No secret values are arguments to these commands.

## B. First-hand live source manifest — no source text exported

After staging the exact approved candidate tooling without switching production, run the manifest collector from the actual current application tree/tooling context. The collector hashes regular reviewed files, refuses symlinks/hardlinks/unreviewed classes, skips known private/runtime directories, rejects root-level private artifacts, and writes only path/hash/size/category facts to the owner-private evidence directory.

```sh
cd /home/rukadopo/telegram_bridge
python3 tools/collect_server_manifest.py
```

Important: this shell command is source-manifest collection only. Its `python3` executable is NOT Passenger runtime proof and must never be recorded as such.

Expected stdout is only:

`SERVER_MANIFEST_PRIVATE_REPORT_WRITTEN`

or a bounded blocked code containing only the exception class. The manifest remains private until `ops.baseline_reconcile` / `ops.private_evidence` produces an approved public-safe summary.

If the current live tree cannot run the collector without changing it, execute the exact approved collector from a separate private staging checkout while passing/using the actual live application root through the audited wrapper supplied with the release. Do not copy the live source tree into public GitHub or normal Drive.

## C. Passenger Python 3.11 application-process proof — no CLI substitution

DEV_B provides `ops.passenger_evidence_hook.collect_if_armed`. DEV_A must include an audited root `passenger_wsgi.py` that imports `bridge.app.application` and calls the hook from the real Passenger process. The required safe pattern is:

```python
from pathlib import Path
from bridge.app import application
from ops.passenger_evidence_hook import collect_if_armed

_here = Path(__file__).resolve()
collect_if_armed(app_root=_here.parent, wsgi_file=_here)
```

The hook is inert unless the following empty owner-private marker exists:

```sh
umask 077
: > "$HOME/.telegram_bridge_private_control/collect_passenger_runtime_evidence.once"
chmod 600 "$HOME/.telegram_bridge_private_control/collect_passenger_runtime_evidence.once"
```

Then use HOSTiQ's actual managed Passenger restart/reload action for this Python App. Do not substitute a shell Python invocation. On genuine Python 3.11 application context with Passenger signal and successful import, the process writes:

`$HOME/.telegram_bridge_private_evidence/passenger_runtime_evidence.json`

with mode 0600 and consumes the marker after the strong report is written. If Python is not 3.11, Passenger context is absent, or the application import fails, no strong report is produced and the marker remains for diagnosis/retry. The hook emits no secret/env/request values.

## D. Restart/rollback private hooks

DEV_B lifecycle execution accepts only fixed logical names `restart` and `rollback`. HOSTiQ must install the hosting-specific implementation under the owner-private control root with mode 0700, one link, no symlink, no group/world permission. Do not place credentials in hook filenames, arguments, stdout/stderr or repository files.

The connector environment cannot safely invent HOSTiQ's internal Passenger restart command. Support must map the fixed private hook to HOSTiQ's documented managed-Python restart operation. DEV_B executes the already-opened validated hook through `/proc/self/fd/<fd>` with `pass_fds`, discards stdout/stderr, applies a bounded timeout, and returns only status/code.

A rollback hook must restore the transaction-bound last-known-good release and trigger the same managed restart. It must not delete private runtime/session/config state.

## E. Candidate staging/dependency requirements before switch

The exact approved candidate must contain or bind all of the following before PREPARE can succeed:

1. root `passenger_wsgi.py` importing `bridge.app.application`;
2. immutable dependency input accepted by existing hash-locked release tooling;
3. candidate SHA/ref/artifact bound to approval;
4. staged import/startup verification under the exact approved Python 3.11 environment;
5. runtime/private/session/config paths excluded from code payload;
6. last-known-good/backup metadata outside the immutable code release.

At the latest DEV_A head observed by DEV_B during this run (`c5b63e779901db01d49fdb2aa90bc4870597a138`), items 1 and 2 were still absent, so do not execute a production switch from that candidate.

## F. Controlled live lifecycle after Auditor approval

Only after A-E and exact Auditor approval:

1. create/verify fresh transaction-bound backup;
2. stage exact approved SHA/artifact;
3. install verified dependencies in the actual Passenger Python 3.11 environment;
4. validate staged import/startup;
5. switch immutable code release while preserving private bindings;
6. run fixed private `restart` hook;
7. verify exact running SHA from the private identity reference;
8. run strict `GET /health` validation;
9. run unauthenticated protected-route smoke and require rejection/no leak;
10. run authenticated harmless read probe with server-private bearer reference only;
11. if Telegram setup is still intentionally incomplete, the bootstrap probe may accept only the exact structured `telegram_backend_unconfigured` result with explicit bootstrap mode; it does not contact Telegram and does not make Telegram authorization required;
12. verify serving/resume state;
13. verify the approved rollback path; any mandatory failure triggers rollback; unhealthy rollback is `CRITICAL_ROLLBACK_FAILED` and is never reported as success.

The deployment smoke never invokes send/reply/forward/send-file/K5.

## G. Support-return format and validation

Support returns only the bounded JSON schema documented in `ops/production_readiness.py` through the approved private evidence channel. It contains candidate SHA, evidence classifications, artifact hashes/counts/statuses/booleans, no source text/log bodies/credentials.

Validate privately/public-safe projection with:

```sh
python -m tools.validate_hostiq_support_return --input PRIVATE_SUPPORT_RETURN.json --output PUBLIC_READINESS.json
```

Expected stdout is only:

`HOSTIQ_SUPPORT_RETURN_READY_FOR_AUDITOR`

or `HOSTIQ_SUPPORT_RETURN_BLOCKED`.

Even a structurally complete package leaves `independent_auditor_gate` and `production_switch` as `BLOCKED_EXTERNAL`; Developer output cannot authorize promotion.

## H. Concise support request — use only when a new request is actually necessary

Hello HOSTiQ support. We are preparing an independently audited release of the existing Python application `tg-api.rukadopomogy.org.ua` at `/home/rukadopo/telegram_bridge`. Please perform one server-side evidence/bootstrap action for the exact audited candidate SHA we will provide after Auditor approval. We need: (1) a hash-only manifest of the current application source without exporting private/runtime/session/config content; (2) proof from the actual Passenger application process that it is running Python 3.11 and importing `bridge.app.application`; (3) installation/validation of fixed owner-private restart and rollback hooks using HOSTiQ's managed Python App mechanism; and, only after Auditor approval, (4) backup -> staged exact-SHA update -> dependency install in the real Python 3.11 environment -> Passenger restart -> exact running identity -> strict health -> unauthenticated/authenticated harmless smoke -> resume -> rollback verification. Please keep all credentials, Telegram session/config, bearer values, setup route and private logs server-side. Do not ask the account owner to perform recurring cPanel work and do not modify the WordPress site. Return only bounded non-secret hashes/counts/statuses as specified by our support-return schema.

DEV_B rechecked the existing support channel during this run and found no newer inbound HOSTiQ response after the accepted recovery evidence; therefore this request was prepared but intentionally not sent as a duplicate.
