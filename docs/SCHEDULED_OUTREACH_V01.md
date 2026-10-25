# Scheduled Outreach v0.1

Purpose: terminal-managed, restart-safe scheduling for the existing Telegram SEND pipeline.

## Safety/authority boundary

This module does not discover or scrape group members and does not send Telegram messages by itself. Recipients/chats must be supplied explicitly. Live sending remains behind the repository's existing preview/commit, idempotency and rate-limit controls.

## Implemented

- explicit recipient/chat list;
- duplicate recipient removal on campaign creation;
- global duplicate guard for the same message fingerprint + recipient;
- per-campaign daily limit;
- minimum interval between successful sends;
- local timezone and send window;
- SQLite WAL state;
- pause/resume;
- retry scheduling;
- inflight leases that recover after process interruption;
- preview/claim/status terminal commands.

## Example

Prepare UTF-8 files:

- `message.txt` — message body;
- `recipients.txt` — one explicit Telegram target per line.

Create campaign:

```powershell
python -m tools.outreach_cli --db state\outreach.sqlite3 create --campaign test-01 --message-file message.txt --recipients-file recipients.txt --daily-limit 20 --interval-seconds 900 --timezone Europe/Warsaw --window-start 09:00 --window-end 20:00
```

Read-only preview:

```powershell
python -m tools.outreach_cli --db state\outreach.sqlite3 preview --campaign test-01
```

Status:

```powershell
python -m tools.outreach_cli --db state\outreach.sqlite3 status --campaign test-01
```

## Next integration

The next step is an adapter that takes one claimed Delivery, invokes the existing SEND preview/commit pipeline, records success only after a confirmed receipt, and maps Telegram/FloodWait failures to `mark_failed`.

No second Telegram writer should be introduced.
