# FINALWAVE-42 — Public HTTP Error / Privacy Contract

Base audited for this isolated specialist overlay: PR #9 exact head `84691967e5363bc4b88dfae97371d7bf329c105d`.

This lane does not authorize merge, deployment, Passenger restart, live Telegram I/O, K5, or credential collection. It is source/synthetic evidence only.

## Contract

Public JSON errors are bounded and deterministic:

- application-controlled `code` and HTTP `status` only;
- no raw exception text, stack, SQL, server path, Telegram peer/message text, or subprocess/runtime diagnostic;
- `Retry-After` is emitted only for 429 and is bounded to 1..600 seconds;
- error `details` permit only bounded scalar metadata and identifier-like strings;
- foreign exceptions cannot forge `code`, `status`, or retry metadata by attaching attributes;
- reviewed EndpointPolicyError, WriteSafetyError, and TelegramContractError values are checked against exact code/status allowlists;
- missing/wrong bearer authentication is rejected before private JSON body parsing on protected read and write routes.

The canonical OpenAPI CLI now publishes the DEV06 runtime-conformance schema rather than the older registry response envelope. The schema declares the nested runtime error envelope and the full bounded error status set: 400, 404, 409, 413, 415, 429, 500, 502, 503, and 504.

## Adversarial coverage

`tests/test_finalwave42_public_error_privacy.py` covers malformed authenticated JSON, hostile unreadable bodies under unauthorized access, forged exception attributes, SQLite and filesystem failures, path traversal, Telethon RPC/FloodWait privacy, 500/502/503/504 contracts, bounded 429 metadata, concurrent forged errors, crash/restart reconciliation metadata, and OpenAPI error parity.

`tests/test_dev4_endpoint_policy.py` is updated so the obsolete foreign-attribute pass-through expectation is replaced by fail-closed tests for foreign and mismatched reviewed exceptions.

## Integration note

This specialist branch intentionally does not repair or weaken the unrelated canonical deployment-recovery failure in Recovery Guard #529. Canonical integration should take the error/privacy changes independently, rerun the full Recovery Guard on the eventual canonical head, and require the separate deployment-recovery owner to close that red test before release promotion.
