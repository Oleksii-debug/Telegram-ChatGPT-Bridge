# DEV4 — Telegram write safety and ChatGPT Action contracts

## Scope and provenance

This branch starts from independently audited anchor `3c315a29558b7996070fa2c109dc2ff98f6de04d` and is a stacked DEV4 lane. It does not merge, deploy, authorize Telegram, or perform a live Telegram write.

The sanitized HOSTiQ v0.4 project snapshot was inspected as **reference only** for the existing `app.py`, `security.py`, `telegram_backend.py`, `store.py`, `files.py`, and `tools/build_openapi.py` shapes. Snapshot content is not treated as live authority or deployment permission. The new modules are credential-free and use injected clients/fakes.

## Telegram adapter

`ops/telegram_write_adapter.py` isolates the Telethon-compatible lifecycle behind an injected client protocol. Runtime credentials remain private references; no credential value is committed. The adapter has distinct SEND and REPLY methods, strict write-target normalization, scoped reply preflight, ordered forward preflight, bounded file sends, voice-note semantics, explicit timeout/cancellation handling, safe error codes, bounded FloodWait metadata, and disconnect cleanup on every connected path.

A configured non-synthetic runtime must supply a process/session lock. `ops/telegram_session_lock.py` provides a strict POSIX lock intended for an owner-only private runtime directory outside Git. It rejects broad mode, non-empty content, symlink/special topology, hardlinks, wrong ownership, and contention beyond a bounded timeout. The lock itself is empty and contains no session data.

## Preview / commit / idempotency

`ops/write_safety.py` implements a SQLite-backed persistent write state machine:

`RESERVED -> CALLING -> COMMITTED`

Safe pre-effect failures become `FAILED_SAFE`. Any error after crossing the external-effect boundary becomes `AMBIGUOUS`; retries then require reconciliation and never blindly resend. Orphaned `CALLING` transactions are explicitly converted to `AMBIGUOUS` during startup recovery. A concurrent second commit sees `write_in_progress` and cannot mutate the active transaction.

Each preview binds the action plus canonical payload into an immutable SHA-256 request fingerprint. The idempotency key is stored only as a hash and binds to both fingerprint and preview identity. A successful retry returns the original durable result even after preview expiry. A never-committed expired preview fails. Reusing an idempotency key for a different preview/fingerprint fails with conflict.

Cleanup may remove only stale never-consumed preview payloads. It does not delete committed/ambiguous idempotency tombstones, so retention cleanup cannot re-enable duplicate sends.

Audit metadata is body-free: operation kind, request/payload/target/idempotency hashes, preview ID, counts, and status. It excludes chat/person names, message/caption text, file names/paths, preview tokens, raw Telegram exceptions, and private file contents.

## File-send policy

`ops/file_send_policy.py` supports opaque bridge file references and a validation-only HTTPS reference policy. It rejects arbitrary server paths. HTTPS references reject credentials, non-443 ports, localhost/private/link-local/reserved addresses, unsafe redirects, and unsafe DNS results. Callers must validate every resolved address and every redirect hop before fetching; a mixed public/private DNS answer fails closed. Size/count/total caps, safe names, hashes, MIME syntax, dedupe, and voice-note media rules are bounded.

No network fetch is performed by this module and no live URL is contacted by tests.

## Canonical OpenAPI / ChatGPT Action policy

`ops/openapi_registry.py` is the canonical route/operation registry. Safety classification derives from this registry, not from optional self-declared `x-*` markers. Unknown operations fail closed. All Action operations are protected by bearer auth and private setup/login/session routes are not representable.

SEND, REPLY, FORWARD, and SEND_FILES each have separate preview and commit operations. Commit schemas require all of:

- `preview_token`;
- `idempotency_key`;
- `explicit_user_command: true`.

Commit operations are consequential; preview operations are explicitly non-consequential and state that no Telegram write occurs. The validator performs an exact schema-vs-registry path/method/operationId diff, bearer checks, preview/commit pairing and gates, server-origin validation, and private/secret-content scanning. Removing optional `x-bridge-*` markers does not weaken validation.

`tools/build_action_openapi.py --validate-only` validates the schema offline and does not call the production server.

## Endpoint policy

`ops/write_endpoint_policy.py` applies the same canonical operation registry to runtime write authorization. It enforces bearer/authenticated context, a deterministic fixed-window actor+operation quota, and a current explicit-user-command gate before any commit reaches the persistent state machine. The coordinator derives the write action from the registry, so a REPLY preview cannot be committed through SEND, and vice versa.

Structured error serialization retains only stable error/status/retry metadata and drops exception messages/paths.

## Acceptance criteria advanced

Credential-free executable evidence materially advances F1-F8, G1-G4, H1/H3/H4/H5, K4 safety preconditions, and the non-live prerequisites for K5. It also strengthens C6 write-side FloodWait/error handling and B1/B2/B7/B8 write endpoint policy. These are **not** product PASS and do not replace real reconciled source, Passenger runtime, deployed SHA, live Telegram, ChatGPT Action E2E, or independently approved K5 evidence.

## Explicit boundaries

- NO LIVE TELEGRAM SEND.
- NO REAL TELEGRAM AUTHORIZATION.
- NO SECRET VALUES.
- NO PRODUCTION DEPLOYMENT.
- NO MERGE.
- Snapshot remains reference-only.
