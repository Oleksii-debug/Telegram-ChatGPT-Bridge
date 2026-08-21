# Production baseline reconciliation — evidence ledger

Status: **HOSTiQ baseline recovered; exact public Git reconciliation not yet completed; no production promotion authorized**.

This document records non-secret facts only. It must never contain setup-route values, Telegram credentials/sessions, bridge tokens, passwords, private backup bytes, cookies, message content or private logs.

## Newer first-hand HOSTiQ facts

The server recovery evidence dated 2026-08-20 15:27 supersedes earlier statements that the current production baseline and old setup-gate state were unknown.

Confirmed evidence:
- production root: `/home/rukadopo/telegram_bridge`;
- domain: `tg-api.rukadopomogy.org.ua`;
- production tree enumerated as 42 files and 9 directories for recovery reconstruction;
- all discovered server files were read for reconstruction; runtime/private/cache/temp material is excluded from public/sanitized export;
- recovered Python source passed syntax parsing;
- 39 working files match the old controlled manifest exactly;
- `passenger_wsgi.py` is the confirmed changed tracked startup file relative to the old controlled reference and currently imports `bridge.app.application` as the Passenger entry;
- `install_server.sh` is an empty additional file not represented by the old manifest;
- a full private backup was created first and remains only on HOSTiQ;
- the previously exposed setup route was privately rotated and the obsolete route invalidated; the replacement route was not exported;
- current setup flow rendered successfully through production after rotation;
- Telegram setup remains incomplete by design;
- command cron jobs: 0; temporary recovery jobs: 0 at the evidence checkpoint.

## Important boundary

These facts are sufficient to stop calling the production baseline “unknown,” but they are not a complete Git release manifest inside this repository. The sanitized recovered raw tree is not currently available to this public branch/normal Drive handoff, so an exact per-file Git comparison must not be fabricated from the legacy ZIP.

The quarantined legacy package is not source of truth and must not be deployed over production.

## Reconciliation mechanism

`ops/baseline_reconcile.py` is the required non-secret comparator once the sanitized recovered tree is accessible inside the private integration environment. It:
- hard-scans the recovered tree before comparison;
- exports the exact requested Git ref;
- compares file path/size/SHA-256 manifests;
- reports added/removed/changed/same paths;
- records manifest hashes and exact resolved Git SHA;
- flags whether `passenger_wsgi.py` differs;
- records neither raw file contents nor secret values.

The resulting reconciliation evidence can be returned to the independent Auditor. Raw private backup/runtime state remains server-side.

## Runtime reconciliation

The shell `/usr/bin/python3` has been observed as Python 3.6.8. That is explicitly not accepted as Passenger Python App runtime evidence.

`ops/runtime_evidence.py` is the read-only evidence contract for execution from the actual application/Passenger runtime context. Production release approval requires proof of the actual executable, Python major/minor, venv/prefix behavior, WSGI identity/hash and application import status. Intended runtime remains Python 3.11.

## Git state relationship

PR #1 remains the guardrail-only recovery line. PR #2 is the dependent recovery/deployment hardening line. Neither is currently the recovered production application release, and neither may be promoted merely because CI is green.

The future application baseline must preserve the recovered HOSTiQ startup behavior and be reconciled against the sanitized current tree before independent approval.
