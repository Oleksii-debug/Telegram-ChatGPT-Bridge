# DEV3 application/read/media boundary

This branch is a candidate read-side implementation built from the independently audited fan-out anchor `3c315a29558b7996070fa2c109dc2ff98f6de04d`. It is not a production claim, deployment package, or live Telegram proof.

## Reference reconciliation

The sanitized HOSTiQ v0.4 project snapshot was inspected only as analytical/reference input. Useful responsibility boundaries were identified in its `bridge/app.py`, `bridge/telegram_backend.py`, `bridge/security.py`, `bridge/store.py`, `bridge/files.py`, `bridge/setup.py`, and `bridge/config.py`. The snapshot contains a substantial existing application but mixes read, write, setup, export and worker concerns. DEV3 therefore preserves compatible behavioral ideas (lazy Telegram access, bearer protection, signed private files, bounded errors, private storage) while implementing a smaller dependency-injected read boundary. No snapshot file is treated as deployment authority.

Live/Drive evidence remains authoritative for server facts. In particular, the recovered HOSTiQ tree has 42 files / 9 directories, 39 old-manifest matches, a known changed `passenger_wsgi.py` importing `bridge.app.application`, and an empty extra `install_server.sh`; actual Passenger Python 3.11 identity and exact live source reconciliation remain external evidence tasks.

## Package boundaries

- `bridge.app`: WSGI routing, health, strict request parsing, bearer/rate guard orchestration and read-only API surface.
- `bridge.backend`: `ReadBackend` protocol plus a Telethon-compatible adapter. Telethon/client construction is injected and lazy; imports or application construction perform no Telegram network activity.
- `bridge.models`: stable dialog/message/media models and opaque scoped pagination cursor helpers.
- `bridge.validation`: strict JSON field, bounds, ISO-8601 timezone and opaque file-reference validation.
- `bridge.security`: constant-time bearer guard, signed-file HMAC helper and a `RateLimiter` protocol. The default rate limiter fails closed. DEV3 deliberately does not implement/replace the shared production multi-process limiter owned by the integration lane.
- `bridge.storage`: SQLite-backed opaque private file registry and integrity-checked persistent download checkpoints.
- `bridge.downloads`: single/bulk download orchestration, deduplication, byte/file caps, expected size/hash verification and resumable pending/failed work.
- `bridge.archive`: generated ZIP packaging with traversal-safe names, collision handling, member/size caps and CRC verification.
- `bridge.audit`: metadata-only audit events; no request/response message bodies, chat labels, filenames, bearer values or exception text.
- `bridge.errors`: bounded structured public errors that intentionally do not surface raw backend exception strings.

## Read-only HTTP contract

Public:

- `GET /health` — local configuration/readiness summary only. It does not call Telegram.

Protected POST routes under `/api/v1`:

- `/dialogs/list`
- `/history/read`
- `/search`
- `/media/metadata`
- `/downloads/single`
- `/downloads/bulk`
- `/downloads/resume`
- `/archives/create`
- `/files/get`

Private file bytes:

- `GET /api/v1/files/{opaque_file_ref}` accepts either the configured bearer or a valid short-lived HMAC reference. Missing/wrong/tampered credentials and unknown file IDs are hidden as not-found responses.

No send, reply, forward, send-files, setup-secret, or preview/commit write route is introduced by DEV3.

## Request and privacy rules

Protected JSON routes authenticate and rate-check before parsing private request content. JSON POSTs require `application/json`, an explicit bounded `Content-Length`, strict UTF-8, an object body, endpoint-specific allowlisted keys and bounded scalar/list values. Unknown fields fail closed. Search requires at least one narrowing filter and a bounded scan limit.

Search date boundaries are inclusive. Input timestamps must carry an explicit timezone and are normalized to UTC. Unicode/Cyrillic/emoji/combining sequences are preserved. Case-insensitive synthetic text matching uses Unicode `casefold()`; sender filtering uses stable sender ID and username, not mutable display names.

Public/API media references are deterministic logical identifiers, never server paths. Downloaded server files receive separate random opaque `FileRecordStore` references. Private path resolution rejects traversal, absolute-path substitution, symlink and hardlink topology, verifies recorded size and SHA-256, and never returns the server path in public metadata.

## Download / resume semantics

Bulk selection deduplicates `(chat, message_id, source_file_ref)`, enforces per-file/file-count/aggregate-byte limits and stores a persistent checkpoint before work. A checkpoint records completed opaque file refs plus bounded per-item error metadata. `resume(job_id)` skips already completed items and retries pending/failed items. Corrupt checkpoint JSON/hash/schema or out-of-set result IDs fail closed.

Temporary files live under a private staging directory, receive unique generated names and are cleaned after success/failure. A backend-returned path must remain inside the staging root. Expected size/hash mismatches are explicit controlled errors.

## ZIP semantics

ZIP creation operates only on registered private file refs. Archive names are reduced to safe basenames; duplicate names are deterministically disambiguated. Member count and uncompressed input bytes are capped. The generated archive is reopened, member paths are revalidated and `ZipFile.testzip()` must pass before registration. Generated files remain private and are only served through the authenticated/signed file route.

## Telegram reliability boundary

The Telethon-compatible adapter maps timeouts to `telegram_timeout`, FloodWait-like exceptions to `telegram_flood_wait` with a bounded retry-after value, and other RPC/backend failures to `telegram_rpc_error`. Raw exception strings are never copied into API responses or audit events. Real credentials and live Telegram authorization are intentionally not used in this branch; `USER_TELEGRAM_AUTH_NOT_YET_REQUIRED` remains the control-plane state.

## Known integration boundaries

- Production shared/multi-process rate limiting is injected through the `RateLimiter` interface and remains integration work with the lane that owns the current M10 finding.
- Write/idempotency/OpenAPI Action work belongs to DEV4 and is not duplicated here.
- Accessibility/OpenAPI adversarial coverage belongs to DEV5.
- HOSTiQ source/runtime/deployment reconciliation belongs to DEV2 plus Auditor-controlled live evidence.
- This branch must be audited and reconciled with the factual server source before any deployment promotion.
